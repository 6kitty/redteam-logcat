"""mTLS-only central collector and durable forward spool for approved evidence."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import random
import ssl
import stat
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from redteam_evidence_protocol import (EvidenceProtocolError, canonical_json, make_attachment_request,
                                       make_event, make_output_stream, validate_attachment_request)


COLLECT_PATH = "/v1/evidence"
MAX_REQUEST_BYTES = 96 * 1024


class CollectorError(RuntimeError):
    pass


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{random.randrange(1 << 32):x}.tmp")
    try:
        with open(temporary, "xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        # Windows does not support opening a directory for fsync.  The file
        # itself has already been flushed above; retain the POSIX directory
        # durability barrier where the platform supports it.
        if os.name == "nt":
            return
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_name(identifier: str) -> str:
    # Event IDs are hashes; this also keeps source IDs out of filenames.
    import hashlib
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()


def assert_root_owned_storage(path: Path) -> None:
    """Require a root-owned, private directory before starting a real collector."""
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
        raise CollectorError("collector storage must be an existing root-owned mode 0700 directory")


class CollectorStore:
    """Small durable store with source ordering and event-ID idempotence."""

    def __init__(self, root: Path, *, windows_endpoint_id: str | None = None) -> None:
        self.root = root
        self.windows_endpoint_id = windows_endpoint_id
        self._lock = threading.Lock()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _verify_final_stream(self, event: Mapping[str, Any], output: bytes) -> None:
        """Re-hash stored chunks before trusting a client's final stream commitment."""
        declared = event["evidence"]
        stream_id = declared["stream_id"]
        chunks: dict[int, tuple[Mapping[str, Any], bytes]] = {declared["chunk_index"]: (event, output)}
        for event_path in (self.root / "events").glob("*.json"):
            stored = json.loads(event_path.read_text("utf-8"))
            evidence = stored.get("evidence", {})
            if evidence.get("stream_id") != stream_id:
                continue
            index = evidence["chunk_index"]
            if index in chunks:
                raise EvidenceProtocolError("stream contains duplicate chunk index")
            artifact = self.root / "artifacts" / f"{stored['event_id']}.bin"
            if not artifact.is_file():
                raise EvidenceProtocolError("stream artifact is missing")
            chunks[index] = (stored, artifact.read_bytes())
        expected_indexes = set(range(declared["chunk_count"]))
        if set(chunks) != expected_indexes:
            raise EvidenceProtocolError("stream chunks are incomplete or out of range")
        digest = hashlib.sha256()
        total_length = 0
        for index in range(declared["chunk_count"]):
            chunk_event, chunk_output = chunks[index]
            chunk_evidence = chunk_event["evidence"]
            if (chunk_event["source_id"] != event["source_id"]
                    or chunk_event["endpoint_id"] != event["endpoint_id"]
                    or any(chunk_evidence[name] != declared[name] for name in
                           ("stream_id", "chunk_count", "stream_digest", "stream_byte_length"))):
                raise EvidenceProtocolError("stream chunk metadata is inconsistent")
            if (len(chunk_output) != chunk_evidence["byte_length"]
                    or hashlib.sha256(chunk_output).hexdigest() != chunk_evidence["digest"]):
                raise EvidenceProtocolError("stored stream chunk digest or byte length mismatch")
            digest.update(chunk_output)
            total_length += len(chunk_output)
        if total_length != declared["stream_byte_length"] or digest.hexdigest() != declared["stream_digest"]:
            raise EvidenceProtocolError("stream aggregate digest or byte length mismatch")

    def ingest(self, raw: Any, *, peer_cert_sha256: str | None = None) -> tuple[int, dict[str, Any]]:
        """Accept an event, optionally binding its source to an authenticated mTLS peer.

        ``peer_cert_sha256`` is the SHA-256 digest of the peer's DER certificate.
        The HTTP server always supplies it; direct store tests must supply an
        explicit test identity.
        """
        if peer_cert_sha256 is None:
            raise CollectorError("authenticated peer certificate fingerprint is required")
        if (len(peer_cert_sha256) != 64
                or any(character not in "0123456789abcdef" for character in peer_cert_sha256)):
            raise CollectorError("peer certificate fingerprint must be a lowercase SHA-256 hex digest")
        event, output, output_sha256, acknowledgement_id = validate_attachment_request(
            raw, windows_endpoint_id=self.windows_endpoint_id
        )
        encoded = canonical_json(event)
        event_path = self.root / "events" / f"{event['event_id']}.json"
        artifact_path = self.root / "artifacts" / f"{event['event_id']}.bin"
        with self._lock:
            source = self.root / "sources" / _safe_name(event["source_id"])
            state_path = source / "state.json"
            if state_path.exists():
                state: dict[str, Any] = json.loads(state_path.read_text("utf-8"))
                if "peer_cert_sha256" not in state:
                    return 409, {"error": "source has no mTLS certificate binding; migration is required"}
            else:
                # Do not let a new certificate claim a source left by a pre-binding
                # collector crash or a legacy store with event records but no state.
                for stored_event_path in (self.root / "events").glob("*.json"):
                    stored_event = json.loads(stored_event_path.read_text("utf-8"))
                    if stored_event.get("source_id") == event["source_id"]:
                        return 409, {"error": "source has events but no mTLS certificate binding; migration is required"}
                # This must precede artifact/event writes: a crash can at worst
                # reserve the source for this certificate, never another CA peer.
                state = {"sequence": 0, "event_hash": None, "peer_cert_sha256": peer_cert_sha256}
                _atomic_write(state_path, canonical_json(state))
            bound_fingerprint = state["peer_cert_sha256"]
            if peer_cert_sha256 != bound_fingerprint:
                return 403, {"error": "source is bound to a different mTLS client certificate"}
            if event_path.exists():
                if event_path.read_bytes() == encoded and artifact_path.exists() and artifact_path.read_bytes() == output:
                    return 200, {"accepted": True, "event_id": acknowledgement_id,
                                 "canonical_event_id": event["event_id"],
                                 "canonical_event_hash": event["event_hash"], "status": "accepted",
                                 "output_sha256": output_sha256}
                return 409, {"error": "event ID collision"}
            if event["sequence"] != state["sequence"] + 1 or event["previous_event_hash"] != state["event_hash"]:
                return 409, {"error": "source sequence or hash-chain mismatch"}
            if event["evidence"].get("final"):
                self._verify_final_stream(event, output)
            _atomic_write(artifact_path, output)
            _atomic_write(event_path, encoded)
            stream = event["evidence"]
            if stream.get("final"):
                _atomic_write(self.root / "manifests" / f"{stream['stream_id']}.json", canonical_json({
                    "stream_id": stream["stream_id"], "chunk_count": stream["chunk_count"],
                    "stream_digest": stream["stream_digest"], "stream_byte_length": stream["stream_byte_length"],
                    "final_event_id": event["event_id"], "final_event_hash": event["event_hash"]
                }))
            next_state: dict[str, Any] = {"sequence": event["sequence"],
                                          "event_hash": event["event_hash"],
                                          "peer_cert_sha256": peer_cert_sha256}
            _atomic_write(state_path, canonical_json(next_state))
        return 201, {"accepted": True, "event_id": acknowledgement_id,
                     "canonical_event_id": event["event_id"], "canonical_event_hash": event["event_hash"],
                     "status": "accepted", "output_sha256": output_sha256}


class _Handler(BaseHTTPRequestHandler):
    server: "CollectorHTTPServer"

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _reply(self, status: int, body: Mapping[str, Any]) -> None:
        encoded = canonical_json(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != COLLECT_PATH:
            self._reply(404, {"error": "not found"})
            return
        content_length = self.headers.get("Content-Length")
        if content_length is None or not content_length.isdigit() or int(content_length) > MAX_REQUEST_BYTES:
            self._reply(413, {"error": "invalid request size"})
            return
        try:
            body = json.loads(self.rfile.read(int(content_length)).decode("utf-8"))
            peer_certificate = self.connection.getpeercert(binary_form=True)
            if not peer_certificate:
                self._reply(403, {"error": "mTLS client certificate is required"})
                return
            status, reply = self.server.store.ingest(
                body, peer_cert_sha256=hashlib.sha256(peer_certificate).hexdigest()
            )
        except (UnicodeDecodeError, json.JSONDecodeError, EvidenceProtocolError) as error:
            self._reply(400, {"error": str(error)})
            return
        self._reply(status, reply)


class CollectorHTTPServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], store: CollectorStore) -> None:
        super().__init__(address, _Handler)
        self.store = store


def build_server(*, address: tuple[str, int], storage_dir: Path, server_cert: Path,
                 server_key: Path, client_ca: Path, endpoint_id: str) -> CollectorHTTPServer:
    """Build the production server; storage and mTLS files must be operator-provided."""
    assert_root_owned_storage(storage_dir)
    for path in (server_cert, server_key, client_ca):
        if not path.is_file():
            raise CollectorError(f"required TLS file is missing: {path}")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(str(server_cert), str(server_key))
    context.load_verify_locations(cafile=str(client_ca))
    server = CollectorHTTPServer(address, CollectorStore(storage_dir, windows_endpoint_id=endpoint_id))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


@dataclass(frozen=True)
class MTLSConfig:
    endpoint: str
    endpoint_id: str
    ca_cert: Path
    client_cert: Path
    client_key: Path

    def validated_url(self) -> tuple[str, int]:
        parsed = urlsplit(self.endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path != COLLECT_PATH or parsed.query:
            raise CollectorError(f"endpoint must be explicit https URL ending in {COLLECT_PATH}")
        for path in (self.ca_cert, self.client_cert, self.client_key):
            if not path.is_file():
                raise CollectorError(f"required mTLS file is missing: {path}")
        return parsed.hostname, parsed.port or 443


class EvidenceSpool:
    """Atomic on-disk queue. A record is claimed before I/O and retried with backoff."""

    def __init__(self, root: Path, config: MTLSConfig) -> None:
        self.root, self.config = root, config
        self.config.validated_url()
        for name in ("pending", "claimed", "acknowledged"):
            (root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        # A process crash after claiming must not strand evidence indefinitely.
        for claimed in (root / "claimed").glob("*.json"):
            pending = root / "pending" / claimed.name
            if not pending.exists():
                os.replace(claimed, pending)

    def enqueue(self, *, source_id: str, sequence: int, previous_event_hash: str | None,
                evidence: Mapping[str, Any], output: bytes) -> dict[str, Any]:
        event = make_event(endpoint_id=self.config.endpoint_id, source_id=source_id, sequence=sequence,
                           previous_event_hash=previous_event_hash, evidence=evidence)
        path = self.root / "pending" / f"{event['event_id']}.json"
        if not path.exists() and not (self.root / "acknowledged" / path.name).exists():
            _atomic_write(path, canonical_json({"request": make_attachment_request(event, output), "attempts": 0,
                                                "next_attempt_at": 0.0}))
        return event

    def enqueue_stream(self, *, source_id: str, sequence: int, previous_event_hash: str | None,
                       evidence: Mapping[str, Any], output: bytes) -> list[dict[str, Any]]:
        """Durably queue a complete output as independently verifiable bounded chunks."""
        requests = make_output_stream(endpoint_id=self.config.endpoint_id, source_id=source_id, sequence=sequence,
                                      previous_event_hash=previous_event_hash, evidence=evidence, output=output)
        for request in requests:
            event_id = request["event"]["event_id"]
            pending = self.root / "pending" / f"{event_id}.json"
            if not pending.exists() and not (self.root / "acknowledged" / pending.name).exists():
                _atomic_write(pending, canonical_json({"request": request, "attempts": 0, "next_attempt_at": 0.0}))
        return [request["event"] for request in requests]

    def _claim(self, now: float) -> Path | None:
        candidates: list[tuple[str, int, Path]] = []
        for pending in (self.root / "pending").glob("*.json"):
            try:
                item = json.loads(pending.read_text("utf-8"))
                if float(item["next_attempt_at"]) > now:
                    continue
                event = item["request"]["event"]
                candidates.append((event["source_id"], int(event["sequence"]), pending))
            except FileNotFoundError:
                continue
        for _, _, pending in sorted(candidates):
            try:
                claimed = self.root / "claimed" / pending.name
                os.replace(pending, claimed)
                return claimed
            except FileNotFoundError:
                continue
        return None

    def _post(self, request: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        host, port = self.config.validated_url()
        context = ssl.create_default_context(cafile=str(self.config.ca_cert))
        context.load_cert_chain(str(self.config.client_cert), str(self.config.client_key))
        connection = http.client.HTTPSConnection(host, port, context=context, timeout=10)
        try:
            connection.request("POST", COLLECT_PATH, body=canonical_json(request),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read().decode("utf-8"))
        finally:
            connection.close()

    def forward_once(self, *, now: float | None = None) -> bool:
        claimed = self._claim(time.time() if now is None else now)
        if claimed is None:
            return False
        item = json.loads(claimed.read_text("utf-8"))
        try:
            request = item["request"]
            status, reply = self._post(request)
            event_id = request["event"]["event_id"]
            event_hash = request["event"]["event_hash"]
            output_sha256 = request["output_sha256"]
            if (status in (200, 201) and reply.get("accepted") is True and reply.get("status") == "accepted"
                    and reply.get("event_id") == event_id and reply.get("canonical_event_id") == event_id
                    and reply.get("canonical_event_hash") == event_hash
                    and reply.get("output_sha256") == output_sha256):
                os.replace(claimed, self.root / "acknowledged" / claimed.name)
                return True
            raise CollectorError(f"collector did not acknowledge event: HTTP {status}")
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError, CollectorError) as error:
            attempts = int(item["attempts"]) + 1
            item["attempts"] = attempts
            item["next_attempt_at"] = (time.time() if now is None else now) + min(300, 2 ** min(attempts, 8))
            item["last_error"] = str(error)[:512]
            _atomic_write(claimed, canonical_json(item))
            os.replace(claimed, self.root / "pending" / claimed.name)
            return False


def main() -> None:
    parser = argparse.ArgumentParser(description="mTLS evidence collector (root-owned storage required)")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--storage-dir", type=Path, required=True)
    serve.add_argument("--server-cert", type=Path, required=True)
    serve.add_argument("--server-key", type=Path, required=True)
    serve.add_argument("--client-ca", type=Path, required=True)
    serve.add_argument("--endpoint-id", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8443)

    def add_client_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--spool-dir", type=Path, required=True)
        command.add_argument("--endpoint", required=True)
        command.add_argument("--endpoint-id", required=True)
        command.add_argument("--ca-cert", type=Path, required=True)
        command.add_argument("--client-cert", type=Path, required=True)
        command.add_argument("--client-key", type=Path, required=True)

    enqueue = commands.add_parser("enqueue")
    add_client_options(enqueue)
    enqueue.add_argument("--source-id", required=True)
    enqueue.add_argument("--sequence", type=int, required=True)
    enqueue.add_argument("--previous-event-hash")
    enqueue.add_argument("--kind", required=True)
    enqueue.add_argument("--digest", required=True)
    enqueue.add_argument("--byte-length", type=int, required=True)
    enqueue.add_argument("--retention-reference", required=True)
    enqueue.add_argument("--classification", required=True)
    enqueue.add_argument("--summary")
    enqueue.add_argument("--output-file", type=Path, required=True)
    forward = commands.add_parser("forward-once")
    add_client_options(forward)
    args = parser.parse_args()
    if args.command == "serve":
        build_server(address=(args.host, args.port), storage_dir=args.storage_dir, server_cert=args.server_cert,
                     server_key=args.server_key, client_ca=args.client_ca, endpoint_id=args.endpoint_id).serve_forever()
        return
    config = MTLSConfig(endpoint=args.endpoint, endpoint_id=args.endpoint_id, ca_cert=args.ca_cert,
                        client_cert=args.client_cert, client_key=args.client_key)
    spool = EvidenceSpool(args.spool_dir, config)
    if args.command == "enqueue":
        evidence: dict[str, Any] = {"kind": args.kind, "digest": args.digest,
                                    "byte_length": args.byte_length,
                                    "retention_reference": args.retention_reference,
                                    "classification": args.classification}
        if args.summary is not None:
            evidence["summary"] = args.summary
        print(json.dumps(spool.enqueue_stream(source_id=args.source_id, sequence=args.sequence,
                                              previous_event_hash=args.previous_event_hash, evidence=evidence,
                                              output=args.output_file.read_bytes()),
                         sort_keys=True))
        return
    raise SystemExit(0 if spool.forward_once() else 1)


if __name__ == "__main__":
    main()
