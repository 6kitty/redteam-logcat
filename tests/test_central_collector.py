from __future__ import annotations

import base64
import http.client
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

import central_collector
from central_collector import (COLLECT_PATH, CollectorError, CollectorHTTPServer, CollectorStore,
                               EvidenceSpool, MTLSConfig, assert_root_owned_storage)
from redteam_evidence_protocol import (EvidenceProtocolError, MAX_ARTIFACT_BYTES, make_attachment_request,
                                       make_event)


TEST_PEER_CERT_SHA256 = "1" * 64


@pytest.fixture()
def tls_material(tmp_path: Path) -> dict[str, Path]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is unavailable; mTLS harness skipped")

    def openssl(*args: str) -> None:
        subprocess.run(["openssl", *args], cwd=tmp_path, check=True, capture_output=True)

    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=test-ca",
            "-keyout", "ca.key", "-out", "ca.crt", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, subject in (("server", "/CN=localhost"), ("client", "/CN=authorized-client"),
                          ("client-2", "/CN=other-authorized-client")):
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", subject,
                "-keyout", f"{name}.key", "-out", f"{name}.csr")
        extensions = tmp_path / f"{name}.ext"
        extensions.write_text(
            "subjectAltName=DNS:localhost\n" if name == "server" else "extendedKeyUsage=clientAuth\n",
            encoding="ascii",
        )
        openssl("x509", "-req", "-days", "1", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", f"{name}.crt", "-extfile", extensions.name)
    return {name: tmp_path / name for name in ("ca.crt", "server.crt", "server.key", "client.crt", "client.key",
                                                "client-2.crt", "client-2.key")}


@pytest.fixture()
def collector(tls_material: dict[str, Path], tmp_path: Path):  # type: ignore[no-untyped-def]
    server = CollectorHTTPServer(("127.0.0.1", 0), CollectorStore(tmp_path / "store", windows_endpoint_id="test-collector"))
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(str(tls_material["server.crt"]), str(tls_material["server.key"]))
    context.load_verify_locations(cafile=str(tls_material["ca.crt"]))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def config(server: CollectorHTTPServer, material: dict[str, Path], *, client: str = "client") -> MTLSConfig:
    return MTLSConfig(endpoint=f"https://localhost:{server.server_port}{COLLECT_PATH}", endpoint_id="test-collector",
                      ca_cert=material["ca.crt"], client_cert=material[f"{client}.crt"],
                      client_key=material[f"{client}.key"])


def output() -> bytes:
    return b"bounded centrally viewable output\n"


def payload() -> dict[str, object]:
    return {"kind": "session-boundary", "digest": hashlib.sha256(output()).hexdigest(), "byte_length": len(output()),
            "retention_reference": "local://root-log/session-1", "classification": "internal"}


def test_mtls_ingestion_idempotence_and_authentication(collector: CollectorHTTPServer,
                                                        tls_material: dict[str, Path], tmp_path: Path) -> None:
    spool = EvidenceSpool(tmp_path / "spool", config(collector, tls_material))
    event = spool.enqueue(source_id="host-01", sequence=1, previous_event_hash=None, evidence=payload(), output=output())
    assert spool.forward_once()
    # Re-submit the exact retained record: collector acknowledges it idempotently.
    duplicate = tmp_path / "duplicate"
    duplicate.mkdir()
    duplicate_spool = EvidenceSpool(duplicate, config(collector, tls_material))
    duplicate_spool.enqueue(source_id="host-01", sequence=1, previous_event_hash=None, evidence=payload(), output=output())
    assert duplicate_spool.forward_once()
    assert (tmp_path / "spool" / "acknowledged" / f"{event['event_id']}.json").exists()

    unauthenticated = ssl.create_default_context(cafile=str(tls_material["ca.crt"]))
    with pytest.raises((ssl.SSLError, http.client.HTTPException, OSError)):
        connection = http.client.HTTPSConnection("localhost", collector.server_port, context=unauthenticated)
        connection.request("POST", COLLECT_PATH, body=b"{}")
        connection.getresponse()


def test_source_is_durably_bound_to_first_mtls_client_certificate(
        collector: CollectorHTTPServer, tls_material: dict[str, Path], tmp_path: Path) -> None:
    first = EvidenceSpool(tmp_path / "first", config(collector, tls_material))
    event = first.enqueue(source_id="host-01", sequence=1, previous_event_hash=None,
                          evidence=payload(), output=output())
    assert first.forward_once()

    expected_fingerprint = hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(tls_material["client.crt"].read_text(encoding="ascii"))
    ).hexdigest()
    state = json.loads(next((tmp_path / "store" / "sources").glob("*/state.json")).read_text())
    assert state["peer_cert_sha256"] == expected_fingerprint

    other = EvidenceSpool(tmp_path / "other", config(collector, tls_material, client="client-2"))
    other_event = other.enqueue(source_id="host-01", sequence=2, previous_event_hash=event["event_hash"],
                                evidence=payload(), output=output())
    assert not other.forward_once(now=1.0)
    rejected = json.loads((tmp_path / "other" / "pending" / f"{other_event['event_id']}.json").read_text())
    assert "HTTP 403" in rejected["last_error"]

    replay = EvidenceSpool(tmp_path / "replay", config(collector, tls_material, client="client-2"))
    replay_event = replay.enqueue(source_id="host-01", sequence=1, previous_event_hash=None,
                                  evidence=payload(), output=output())
    assert not replay.forward_once(now=1.0)
    replay_rejected = json.loads((tmp_path / "replay" / "pending" / f"{replay_event['event_id']}.json").read_text())
    assert "HTTP 403" in replay_rejected["last_error"]
    assert json.loads(next((tmp_path / "store" / "sources").glob("*/state.json")).read_text())["sequence"] == 1


def test_spool_retries_after_collector_becomes_available(tls_material: dict[str, Path], tmp_path: Path) -> None:
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    unavailable = MTLSConfig(endpoint=f"https://localhost:{port}{COLLECT_PATH}", endpoint_id="test-collector",
                             ca_cert=tls_material["ca.crt"], client_cert=tls_material["client.crt"],
                             client_key=tls_material["client.key"])
    spool = EvidenceSpool(tmp_path / "spool", unavailable)
    event = spool.enqueue(source_id="host-01", sequence=1, previous_event_hash=None, evidence=payload(), output=output())
    assert not spool.forward_once(now=100.0)
    retained = json.loads((tmp_path / "spool" / "pending" / f"{event['event_id']}.json").read_text())
    assert retained["attempts"] == 1 and retained["next_attempt_at"] == 102.0
    reservation.close()

    server = CollectorHTTPServer(("127.0.0.1", port), CollectorStore(tmp_path / "store", windows_endpoint_id="test-collector"))
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(str(tls_material["server.crt"]), str(tls_material["server.key"]))
    context.load_verify_locations(cafile=str(tls_material["ca.crt"]))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert spool.forward_once(now=102.0)
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_spool_recovers_a_claim_left_by_a_crashed_process(tls_material: dict[str, Path], tmp_path: Path) -> None:
    config = MTLSConfig(endpoint=f"https://localhost:1{COLLECT_PATH}", endpoint_id="test-collector",
                        ca_cert=tls_material["ca.crt"], client_cert=tls_material["client.crt"],
                        client_key=tls_material["client.key"])
    spool = EvidenceSpool(tmp_path / "spool", config)
    event = spool.enqueue(source_id="host-01", sequence=1, previous_event_hash=None, evidence=payload(), output=output())
    pending = tmp_path / "spool" / "pending" / f"{event['event_id']}.json"
    claimed = tmp_path / "spool" / "claimed" / pending.name
    os.replace(pending, claimed)
    EvidenceSpool(tmp_path / "spool", config)
    assert pending.exists() and not claimed.exists()


def test_spool_rejects_ack_with_wrong_canonical_hash(tls_material: dict[str, Path], tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    config = MTLSConfig(endpoint=f"https://localhost:1{COLLECT_PATH}", endpoint_id="test-collector",
                        ca_cert=tls_material["ca.crt"], client_cert=tls_material["client.crt"],
                        client_key=tls_material["client.key"])
    spool = EvidenceSpool(tmp_path / "spool", config)
    event = spool.enqueue(source_id="host-01", sequence=1, previous_event_hash=None,
                          evidence=payload(), output=output())
    monkeypatch.setattr(spool, "_post", lambda request: (201, {
        "accepted": True, "status": "accepted", "event_id": request["event"]["event_id"],
        "canonical_event_id": request["event"]["event_id"], "canonical_event_hash": "0" * 64,
        "output_sha256": request["output_sha256"],
    }))
    assert not spool.forward_once(now=1.0)
    assert (tmp_path / "spool" / "pending" / f"{event['event_id']}.json").exists()
    assert not (tmp_path / "spool" / "acknowledged" / f"{event['event_id']}.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="root ownership is a POSIX production-storage requirement")
def test_production_storage_must_be_root_owned_and_private(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    if tmp_path.stat().st_uid == 0:
        assert_root_owned_storage(tmp_path)
    else:
        with pytest.raises(CollectorError, match="root-owned"):
            assert_root_owned_storage(tmp_path)


def test_windows_spool_shape_is_adapted_and_artifact_is_verified(tmp_path: Path) -> None:
    artifact = output()
    output_sha256 = hashlib.sha256(artifact).hexdigest()
    windows_event = {"schema": "redteam-evidence/windows/v1", "id": "a" * 32,
                     "kind": "controlled-launch", "state": "ingested", "host": "windows-01",
                     "source_id": "windows-host-01", "sequence": 1, "previous_event_hash": None,
                     "output_sha256": output_sha256, "output_bytes": len(artifact)}
    request = {"schema": "redteam-evidence/windows/v1", "event": windows_event,
               "output_base64": base64.b64encode(artifact).decode("ascii"),
               "output_sha256": output_sha256}
    store = CollectorStore(tmp_path / "store", windows_endpoint_id="test-collector")
    status, ack = store.ingest(request, peer_cert_sha256=TEST_PEER_CERT_SHA256)
    assert status == 201
    assert ack["accepted"] is True and ack["event_id"] == "a" * 32
    assert ack["status"] == "accepted" and ack["output_sha256"] == output_sha256
    assert len(ack["canonical_event_id"]) == 64 and len(ack["canonical_event_hash"]) == 64
    assert next((tmp_path / "store" / "artifacts").glob("*.bin")).read_bytes() == artifact
    stored = json.loads(next((tmp_path / "store" / "events").glob("*.json")).read_text())
    assert stored["source_id"] == "windows-host-01" and stored["sequence"] == 1
    assert store.ingest(request, peer_cert_sha256=TEST_PEER_CERT_SHA256) == (200, ack)
    request["output_base64"] = base64.b64encode(b"tampered").decode("ascii")
    with pytest.raises(EvidenceProtocolError, match="SHA-256"):
        store.ingest(request, peer_cert_sha256=TEST_PEER_CERT_SHA256)


def test_genesis_certificate_binding_precedes_event_writes(tmp_path: Path,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    store = CollectorStore(tmp_path / "store", windows_endpoint_id="test-collector")
    event = make_event(endpoint_id="test-collector", source_id="host-01", sequence=1,
                       previous_event_hash=None, evidence=payload())
    request = make_attachment_request(event, output())
    writes: list[Path] = []
    atomic_write = central_collector._atomic_write

    def record_write(path: Path, data: bytes) -> None:
        writes.append(path)
        atomic_write(path, data)

    monkeypatch.setattr(central_collector, "_atomic_write", record_write)
    assert store.ingest(request, peer_cert_sha256=TEST_PEER_CERT_SHA256)[0] == 201
    assert writes[0] == tmp_path / "store" / "sources" / hashlib.sha256(b"host-01").hexdigest() / "state.json"
    assert writes.index(tmp_path / "store" / "artifacts" / f"{event['event_id']}.bin") > 0
    assert writes.index(tmp_path / "store" / "events" / f"{event['event_id']}.json") > 0


def test_legacy_unbound_source_state_is_migration_blocked(tmp_path: Path) -> None:
    store = CollectorStore(tmp_path / "store", windows_endpoint_id="test-collector")
    source = tmp_path / "store" / "sources" / hashlib.sha256(b"host-01").hexdigest()
    source.mkdir(parents=True)
    (source / "state.json").write_text(json.dumps({"sequence": 0, "event_hash": None}), encoding="utf-8")
    event = make_event(endpoint_id="test-collector", source_id="host-01", sequence=1,
                       previous_event_hash=None, evidence=payload())
    status, reply = store.ingest(make_attachment_request(event, output()), peer_cert_sha256=TEST_PEER_CERT_SHA256)
    assert status == 409 and "migration is required" in reply["error"]
    assert not (tmp_path / "store" / "events").exists()


def test_large_output_stream_is_chunked_ordered_and_finalized(collector: CollectorHTTPServer,
                                                               tls_material: dict[str, Path], tmp_path: Path) -> None:
    artifact = b"x" * (MAX_ARTIFACT_BYTES + 7)
    stream_payload = {"kind": "command-observation", "digest": hashlib.sha256(artifact).hexdigest(),
                      "byte_length": len(artifact), "retention_reference": "local://root-log/large-output",
                      "classification": "restricted"}
    spool = EvidenceSpool(tmp_path / "stream-spool", config(collector, tls_material))
    events = spool.enqueue_stream(source_id="host-01", sequence=1, previous_event_hash=None,
                                  evidence=stream_payload, output=artifact)
    assert len(events) == 2
    assert events[1]["previous_event_hash"] == events[0]["event_hash"]
    assert events[-1]["evidence"]["final"] is True
    assert spool.forward_once() and spool.forward_once()
    manifests = list((tmp_path / "store" / "manifests").glob("*.json"))
    assert len(manifests) == 1
    assert json.loads(manifests[0].read_text())["stream_digest"] == hashlib.sha256(artifact).hexdigest()


def test_windows_chunk_stream_uses_sealed_chain_and_final_manifest(tmp_path: Path) -> None:
    chunks = [b"windows ", b"output"]
    complete = b"".join(chunks)
    stream_id = hashlib.sha256(b"windows-stream-id").hexdigest()
    store = CollectorStore(tmp_path / "store", windows_endpoint_id="test-collector")
    predecessor = None
    for index, chunk in enumerate(chunks):
        chunk_digest = hashlib.sha256(chunk).hexdigest()
        raw_event = {"schema": "redteam-evidence/windows/v1", "id": f"{index + 1:032x}",
                     "kind": "controlled-launch", "state": "ingested", "host": "windows-01",
                     "source_id": "windows-host-01", "sequence": index + 1,
                     "previous_event_hash": predecessor, "output_sha256": chunk_digest,
                     "output_bytes": len(chunk), "stream_id": stream_id, "chunk_index": index,
                     "chunk_count": len(chunks), "stream_digest": hashlib.sha256(complete).hexdigest(),
                     "stream_byte_length": len(complete), "final": index == len(chunks) - 1}
        request = {"schema": "redteam-evidence/windows/v1", "event": raw_event,
                   "output_base64": base64.b64encode(chunk).decode("ascii"), "output_sha256": chunk_digest}
        status, ack = store.ingest(request, peer_cert_sha256=TEST_PEER_CERT_SHA256)
        assert status == 201 and ack["canonical_event_hash"]
        predecessor = ack["canonical_event_hash"]
    manifest = json.loads((tmp_path / "store" / "manifests" / f"{stream_id}.json").read_text())
    assert manifest["chunk_count"] == 2 and manifest["stream_digest"] == hashlib.sha256(complete).hexdigest()


def test_final_stream_rejects_false_aggregate_commitment_without_advancing_state(tmp_path: Path) -> None:
    store = CollectorStore(tmp_path / "store", windows_endpoint_id="test-collector")
    stream_id = hashlib.sha256(b"adversarial-stream").hexdigest()
    declared_digest = "0" * 64

    def request(index: int, output: bytes, predecessor: str | None) -> dict[str, object]:
        digest = hashlib.sha256(output).hexdigest()
        event = {"schema": "redteam-evidence/windows/v1", "id": f"{index + 10:032x}",
                 "kind": "controlled-launch", "host": "windows-01", "source_id": "windows-host-01",
                 "sequence": index + 1, "previous_event_hash": predecessor, "output_sha256": digest,
                 "output_bytes": len(output), "stream_id": stream_id, "chunk_index": index, "chunk_count": 2,
                 "stream_digest": declared_digest, "stream_byte_length": 2, "final": index == 1}
        return {"schema": "redteam-evidence/windows/v1", "event": event,
                "output_base64": base64.b64encode(output).decode("ascii"), "output_sha256": digest}

    _, first_ack = store.ingest(request(0, b"a", None), peer_cert_sha256=TEST_PEER_CERT_SHA256)
    with pytest.raises(EvidenceProtocolError, match="aggregate"):
        store.ingest(request(1, b"b", first_ack["canonical_event_hash"]),
                     peer_cert_sha256=TEST_PEER_CERT_SHA256)
    state = json.loads(next((tmp_path / "store" / "sources").glob("*/state.json")).read_text())
    assert state["sequence"] == 1
    assert not (tmp_path / "store" / "manifests").exists()
