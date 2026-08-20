from __future__ import annotations

import copy

import pytest

from redteam_evidence_protocol import (EvidenceProtocolError, canonical_json, make_attachment_request, make_event,
                                       sha256_hex, validate_attachment_request, validate_event, verify_source_chain)


def evidence() -> dict[str, object]:
    return {
        "kind": "command-observation",
        "digest": "a" * 64,
        "byte_length": 12,
        "retention_reference": "local://root-log/session-1",
        "classification": "restricted",
        "summary": "approved command record",
    }


def test_event_is_canonical_stable_and_hash_linked() -> None:
    first = make_event(endpoint_id="collector-a", source_id="host-01", sequence=1,
                       previous_event_hash=None, evidence=evidence())
    same = make_event(endpoint_id="collector-a", source_id="host-01", sequence=1,
                      previous_event_hash=None, evidence=evidence())
    second = make_event(endpoint_id="collector-a", source_id="host-01", sequence=2,
                        previous_event_hash=first["event_hash"], evidence=evidence())
    assert first == same
    assert first["event_id"] != second["event_id"]
    assert validate_event(first) == first
    assert canonical_json({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'


def test_protocol_rejects_tampering_and_unbounded_payload() -> None:
    event = make_event(endpoint_id="collector-a", source_id="host-01", sequence=1,
                       previous_event_hash=None, evidence=evidence())
    altered = copy.deepcopy(event)
    altered["evidence"]["summary"] = "changed"
    with pytest.raises(EvidenceProtocolError, match="ID or hash"):
        validate_event(altered)
    unbounded = evidence()
    unbounded["payload"] = "not permitted"
    with pytest.raises(EvidenceProtocolError, match="unsupported"):
        make_event(endpoint_id="collector-a", source_id="host-01", sequence=1,
                   previous_event_hash=None, evidence=unbounded)


def test_hash_chain_verification_is_deterministic_and_replay_idempotent() -> None:
    first = make_event(endpoint_id="collector-a", source_id="host-01", sequence=1,
                       previous_event_hash=None, evidence=evidence())
    second = make_event(endpoint_id="collector-a", source_id="host-01", sequence=2,
                        previous_event_hash=first["event_hash"], evidence=evidence())
    replay = [first, second]
    assert verify_source_chain(replay) == replay
    assert verify_source_chain(replay) == replay
    with pytest.raises(EvidenceProtocolError, match="hash-chain mismatch"):
        verify_source_chain([second, first])


def test_attachment_is_bounded_and_digest_bound_to_canonical_event() -> None:
    output = b"authorized output only"
    event = make_event(endpoint_id="collector-a", source_id="host-01", sequence=1,
                       previous_event_hash=None,
                       evidence={"kind": "command-observation", "digest": sha256_hex(output),
                                 "byte_length": len(output), "retention_reference": "local://one",
                                 "classification": "restricted"})
    request = make_attachment_request(event, output)
    assert validate_attachment_request(request) == (event, output, sha256_hex(output), event["event_id"])
    request["output_sha256"] = "0" * 64
    with pytest.raises(EvidenceProtocolError, match="SHA-256"):
        validate_attachment_request(request)
