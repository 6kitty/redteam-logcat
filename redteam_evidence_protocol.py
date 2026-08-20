"""Strict canonical metadata plus bounded, hash-verified output attachments.

This is not a general upload protocol: it admits only authorized evidence output
in fixed-size chunks that are bound to a canonical ordered event stream.
"""

from __future__ import annotations

import hashlib
import base64
import binascii
import json
import re
from typing import Any, Mapping


PROTOCOL_VERSION = "redteam-evidence/v1"
ATTACHMENT_SCHEMA = "redteam-evidence/attachment/v1"
WINDOWS_ATTACHMENT_SCHEMA = "redteam-evidence/windows/v1"
MAX_ARTIFACT_BYTES = 48 * 1024
GENESIS = None
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_KINDS = frozenset({"command-observation", "session-boundary", "integrity-alert"})
_CLASSIFICATIONS = frozenset({"internal", "restricted"})


class EvidenceProtocolError(ValueError):
    """Raised when an object is outside the deliberately narrow envelope."""


def canonical_json(value: Any) -> bytes:
    """Return the one UTF-8 JSON encoding used for identifiers and storage."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise EvidenceProtocolError("event is not canonical JSON") from error


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _required_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise EvidenceProtocolError(f"{name} must be a 1-128 character identifier")
    return value


def _evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) - {
        "kind", "digest", "byte_length", "retention_reference", "summary", "classification", "stream_id",
        "chunk_index", "chunk_count", "stream_digest", "stream_byte_length", "final"
    }:
        raise EvidenceProtocolError("evidence has unsupported fields")
    required = {"kind", "digest", "byte_length", "retention_reference", "classification"}
    if set(value) < required:
        raise EvidenceProtocolError("evidence is missing required fields")
    kind = value["kind"]
    digest = value["digest"]
    length = value["byte_length"]
    reference = value["retention_reference"]
    classification = value["classification"]
    summary = value.get("summary")
    if kind not in _EVIDENCE_KINDS:
        raise EvidenceProtocolError("evidence kind is not authorized")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise EvidenceProtocolError("evidence digest must be a SHA-256 hex digest")
    if not isinstance(length, int) or isinstance(length, bool) or not 0 <= length <= 2**63 - 1:
        raise EvidenceProtocolError("evidence byte_length is invalid")
    if not isinstance(reference, str) or not reference or len(reference) > 512:
        raise EvidenceProtocolError("evidence retention_reference is invalid")
    if classification not in _CLASSIFICATIONS:
        raise EvidenceProtocolError("evidence classification is invalid")
    if summary is not None and (not isinstance(summary, str) or len(summary) > 512):
        raise EvidenceProtocolError("evidence summary is invalid")
    stream_fields = {"stream_id", "chunk_index", "chunk_count", "stream_digest", "stream_byte_length", "final"}
    present_stream_fields = set(value) & stream_fields
    if present_stream_fields and present_stream_fields != stream_fields:
        raise EvidenceProtocolError("stream metadata must be complete")
    if present_stream_fields:
        if (not isinstance(value["stream_id"], str) or not _DIGEST.fullmatch(value["stream_id"])
                or not isinstance(value["chunk_index"], int) or not isinstance(value["chunk_count"], int)
                or not 0 <= value["chunk_index"] < value["chunk_count"] <= 1_000_000
                or not isinstance(value["stream_digest"], str) or not _DIGEST.fullmatch(value["stream_digest"])
                or not isinstance(value["stream_byte_length"], int) or value["stream_byte_length"] < length
                or not isinstance(value["final"], bool)
                or value["final"] != (value["chunk_index"] == value["chunk_count"] - 1)):
            raise EvidenceProtocolError("stream metadata is invalid")
    result = {"kind": kind, "digest": digest, "byte_length": length,
              "retention_reference": reference, "classification": classification}
    if summary is not None:
        result["summary"] = summary
    if present_stream_fields:
        result.update({name: value[name] for name in stream_fields})
    return result


def make_event(*, endpoint_id: str, source_id: str, sequence: int,
               previous_event_hash: str | None, evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Build a canonical event with stable ID and source-local hash-chain link."""
    endpoint_id = _required_text(endpoint_id, "endpoint_id")
    source_id = _required_text(source_id, "source_id")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise EvidenceProtocolError("sequence must be a positive integer")
    if previous_event_hash is not None and (not isinstance(previous_event_hash, str)
                                            or not _DIGEST.fullmatch(previous_event_hash)):
        raise EvidenceProtocolError("previous_event_hash is invalid")
    item = _evidence(evidence)
    identity = {"protocol": PROTOCOL_VERSION, "endpoint_id": endpoint_id, "source_id": source_id,
                "sequence": sequence, "previous_event_hash": previous_event_hash, "evidence": item}
    event_id = sha256_hex(canonical_json(identity))
    event_hash = sha256_hex(canonical_json({"event_id": event_id, **identity}))
    return {**identity, "event_id": event_id, "event_hash": event_hash}


def validate_event(value: Any) -> dict[str, Any]:
    """Validate and normalize a received event; never accept caller-chosen IDs."""
    if not isinstance(value, Mapping):
        raise EvidenceProtocolError("event must be an object")
    expected = {"protocol", "endpoint_id", "source_id", "sequence", "previous_event_hash",
                "evidence", "event_id", "event_hash"}
    if set(value) != expected:
        raise EvidenceProtocolError("event fields do not match protocol")
    if value["protocol"] != PROTOCOL_VERSION:
        raise EvidenceProtocolError("unsupported protocol")
    event = make_event(endpoint_id=value["endpoint_id"], source_id=value["source_id"],
                       sequence=value["sequence"], previous_event_hash=value["previous_event_hash"],
                       evidence=value["evidence"])
    if value["event_id"] != event["event_id"] or value["event_hash"] != event["event_hash"]:
        raise EvidenceProtocolError("event ID or hash does not match canonical envelope")
    return event


def make_attachment_request(event: Mapping[str, Any], output: bytes) -> dict[str, Any]:
    """Bind one bounded output artifact to an already canonical evidence event."""
    event = validate_event(event)
    if not isinstance(output, bytes) or len(output) > MAX_ARTIFACT_BYTES:
        raise EvidenceProtocolError("output artifact exceeds the explicit size limit")
    digest = sha256_hex(output)
    if event["evidence"]["digest"] != digest or event["evidence"]["byte_length"] != len(output):
        raise EvidenceProtocolError("output artifact does not match evidence digest or byte_length")
    return {"schema": ATTACHMENT_SCHEMA, "event": event,
            "output_base64": base64.b64encode(output).decode("ascii"), "output_sha256": digest}


def make_output_stream(*, endpoint_id: str, source_id: str, sequence: int,
                       previous_event_hash: str | None, evidence: Mapping[str, Any], output: bytes) -> list[dict[str, Any]]:
    """Split an output into independently verified chained chunks with a final marker."""
    if not isinstance(output, bytes) or not output:
        raise EvidenceProtocolError("stream output must be non-empty bytes")
    whole_digest = sha256_hex(output)
    if evidence.get("digest") != whole_digest or evidence.get("byte_length") != len(output):
        raise EvidenceProtocolError("stream output does not match original evidence")
    chunk_count = (len(output) + MAX_ARTIFACT_BYTES - 1) // MAX_ARTIFACT_BYTES
    stream_id = sha256_hex(canonical_json({"endpoint_id": endpoint_id, "source_id": source_id,
                                            "sequence": sequence, "digest": whole_digest, "length": len(output)}))
    requests: list[dict[str, Any]] = []
    predecessor = previous_event_hash
    for index in range(chunk_count):
        chunk = output[index * MAX_ARTIFACT_BYTES:(index + 1) * MAX_ARTIFACT_BYTES]
        chunk_evidence = dict(evidence)
        chunk_evidence.update({"digest": sha256_hex(chunk), "byte_length": len(chunk), "stream_id": stream_id,
                               "chunk_index": index, "chunk_count": chunk_count, "stream_digest": whole_digest,
                               "stream_byte_length": len(output), "final": index == chunk_count - 1})
        event = make_event(endpoint_id=endpoint_id, source_id=source_id, sequence=sequence + index,
                           previous_event_hash=predecessor, evidence=chunk_evidence)
        requests.append(make_attachment_request(event, chunk))
        predecessor = event["event_hash"]
    return requests


def _decode_output(value: Any, digest: Any) -> tuple[bytes, str]:
    if not isinstance(value, str) or not isinstance(digest, str) or not _DIGEST.fullmatch(digest.lower()):
        raise EvidenceProtocolError("output attachment encoding or digest is invalid")
    try:
        output = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as error:
        raise EvidenceProtocolError("output_base64 is invalid") from error
    if len(output) > MAX_ARTIFACT_BYTES or sha256_hex(output) != digest.lower():
        raise EvidenceProtocolError("output artifact exceeds limit or fails SHA-256 validation")
    return output, digest.lower()


def adapt_windows_attachment(value: Any, *, endpoint_id: str) -> tuple[dict[str, Any], bytes, str, str]:
    """Adapt the fixed Windows spool wire shape to a single-event canonical stream."""
    if not isinstance(value, Mapping) or set(value) != {"schema", "event", "output_base64", "output_sha256"}:
        raise EvidenceProtocolError("Windows attachment fields do not match protocol")
    if value["schema"] != WINDOWS_ATTACHMENT_SCHEMA or not isinstance(value["event"], Mapping):
        raise EvidenceProtocolError("unsupported Windows attachment schema")
    raw = value["event"]
    allowed = {"schema", "id", "kind", "state", "started_utc", "ended_utc", "user", "host", "file_path",
               "arguments", "exit_code", "output_path", "output_sha256", "output_bytes", "source_id", "sequence",
               "previous_event_hash", "stream_id", "chunk_index", "chunk_count", "stream_digest",
               "stream_byte_length", "final"}
    required = {"schema", "id", "kind", "host", "output_sha256", "output_bytes"}
    if set(raw) - allowed or not required <= set(raw) or raw["schema"] != WINDOWS_ATTACHMENT_SCHEMA:
        raise EvidenceProtocolError("Windows event fields do not match adapter contract")
    event_id = raw["id"]
    if not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", event_id):
        raise EvidenceProtocolError("Windows event id is invalid")
    if raw["kind"] != "controlled-launch" or not isinstance(raw["host"], str) or not raw["host"]:
        raise EvidenceProtocolError("Windows event kind or host is invalid")
    output, digest = _decode_output(value["output_base64"], value["output_sha256"])
    if raw["output_sha256"].lower() != digest or raw["output_bytes"] != len(output):
        raise EvidenceProtocolError("Windows event output metadata does not match attachment")
    chain_fields = {"source_id", "sequence", "previous_event_hash"}
    supplied_chain = set(raw) & chain_fields
    if supplied_chain and supplied_chain != chain_fields:
        raise EvidenceProtocolError("Windows chain metadata must be complete")
    # Legacy records lack a durable chain. They remain safe but cannot form a multi-event source stream.
    source_id = raw["source_id"] if supplied_chain else f"windows-{event_id.lower()}"
    sequence = raw["sequence"] if supplied_chain else 1
    predecessor = raw["previous_event_hash"] if supplied_chain else None
    stream_fields = {"stream_id", "chunk_index", "chunk_count", "stream_digest", "stream_byte_length", "final"}
    supplied_stream = set(raw) & stream_fields
    if supplied_stream and supplied_stream != stream_fields:
        raise EvidenceProtocolError("Windows stream metadata must be complete")
    evidence = {"kind": "command-observation", "digest": digest, "byte_length": len(output),
                "retention_reference": f"windows-spool://{event_id.lower()}",
                "classification": "restricted", "summary": "Windows controlled-launch output"}
    if supplied_stream:
        evidence.update({field: raw[field] for field in stream_fields})
    canonical = make_event(endpoint_id=endpoint_id, source_id=source_id, sequence=sequence,
                           previous_event_hash=predecessor,
                           evidence=evidence)
    return canonical, output, digest, event_id


def validate_attachment_request(value: Any, *, windows_endpoint_id: str | None = None) -> tuple[dict[str, Any], bytes, str, str]:
    """Return canonical event, verified artifact, digest, and acknowledgement ID."""
    if not isinstance(value, Mapping):
        raise EvidenceProtocolError("attachment request must be an object")
    if value.get("schema") == WINDOWS_ATTACHMENT_SCHEMA:
        if windows_endpoint_id is None:
            raise EvidenceProtocolError("Windows adapter requires configured endpoint_id")
        return adapt_windows_attachment(value, endpoint_id=windows_endpoint_id)
    if set(value) != {"schema", "event", "output_base64", "output_sha256"} or value.get("schema") != ATTACHMENT_SCHEMA:
        raise EvidenceProtocolError("attachment fields do not match protocol")
    event = validate_event(value["event"])
    output, digest = _decode_output(value["output_base64"], value["output_sha256"])
    if event["evidence"]["digest"] != digest or event["evidence"]["byte_length"] != len(output):
        raise EvidenceProtocolError("output artifact does not match canonical evidence")
    return event, output, digest, event["event_id"]


def verify_source_chain(events: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Re-validate an ordered replay without mutating it or contacting a collector."""
    previous_hash: str | None = None
    source_id: str | None = None
    endpoint_id: str | None = None
    expected_sequence = 1
    normalized: list[dict[str, Any]] = []
    for raw in events:
        event = validate_event(raw)
        if (event["source_id"] != source_id and source_id is not None) or (
                event["endpoint_id"] != endpoint_id and endpoint_id is not None):
            raise EvidenceProtocolError("replay contains more than one source or endpoint")
        if event["sequence"] != expected_sequence or event["previous_event_hash"] != previous_hash:
            raise EvidenceProtocolError("replay source sequence or hash-chain mismatch")
        source_id, endpoint_id = event["source_id"], event["endpoint_id"]
        previous_hash = event["event_hash"]
        expected_sequence += 1
        normalized.append(event)
    return normalized
