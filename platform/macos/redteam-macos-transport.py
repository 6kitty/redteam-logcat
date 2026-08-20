#!/usr/bin/env python3
"""macOS adapter from private OSC command boundaries to the shared mTLS spool."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from pathlib import Path

sys.path.insert(0, "/Library/Application Support/RedteamLogcat")
if not (Path("/Library/Application Support/RedteamLogcat") / "central_collector.py").exists():
    # Source-tree test mode; installed instances always use the root-owned copy.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from central_collector import EvidenceSpool, MTLSConfig


APP = Path("/Library/Application Support/RedteamLogcat")
ROOT = Path("/var/log/redteam/transport")


def config() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (APP / "transport.conf").read_text("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip().strip("'")
    return values


def enabled(values: dict[str, str]) -> bool:
    return values.get("MACOS_TRANSPORT_ENABLED") == "1"


def boundary(session: str, sequence: str, kind: str) -> bytes:
    return f"\x1b]777;redteam-logcat;{kind};{session};{sequence}".encode("ascii")


def command_output(session: str, sequence: str, output: Path) -> bytes | None:
    raw = output.read_bytes()
    start = raw.find(boundary(session, sequence, "start"))
    if start < 0:
        return None
    start_end = raw.find(b"\x07", start)
    if start_end < 0:
        return None
    end = raw.find(boundary(session, sequence, "end"), start_end + 1)
    if end < 0:
        return None
    return raw[start_end + 1 : end]


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "-", value)[:128]


def capture_once() -> int:
    values = config()
    if not enabled(values):
        return 0
    transport = ROOT
    for name in ("capture-pending", "artifacts", "pending", "claimed", "acknowledged"):
        (transport / name).mkdir(parents=True, exist_ok=True, mode=0o700)
    spool = EvidenceSpool(transport, MTLSConfig(endpoint=values["MACOS_TRANSPORT_ENDPOINT"], endpoint_id=values["MACOS_TRANSPORT_ENDPOINT_ID"], ca_cert=Path(values["MACOS_TRANSPORT_CA_CERT"]), client_cert=Path(values["MACOS_TRANSPORT_CLIENT_CERT"]), client_key=Path(values["MACOS_TRANSPORT_CLIENT_KEY"])))
    state_path = transport / "chain-state.json"
    state = json.loads(state_path.read_text("utf-8")) if state_path.exists() else {"sequence": 0, "event_hash": None, "outstanding": None}
    # One in-flight host event preserves strict ordering; later captures stay
    # in capture-pending until its predecessor receives a matching ACK.
    if state.get("outstanding"):
        return 0
    for job_path in sorted((transport / "capture-pending").glob("*.json")):
        job = json.loads(job_path.read_text("utf-8"))
        payload = command_output(job["session"], job["sequence"], Path(job["output_path"]))
        if payload is None:
            continue
        artifact = transport / "artifacts" / f"{job['session']}-{job['sequence']}.bin"
        artifact.write_bytes(payload)
        os.chmod(artifact, 0o600)
        digest = hashlib.sha256(payload).hexdigest()
        source = safe_id(f"macos-{platform.node()}")
        evidence = {"kind": "command-observation", "digest": digest, "byte_length": len(payload),
                    "retention_reference": f"macos-session://{job['session']}/{job['sequence']}",
                    "classification": "restricted", "summary": "macOS interactive command output"}
        events = ([spool.enqueue(source_id=source, sequence=int(state["sequence"]) + 1,
                                 previous_event_hash=state["event_hash"], output=payload, evidence=evidence)]
                  if not payload else spool.enqueue_stream(source_id=source, sequence=int(state["sequence"]) + 1,
                                                            previous_event_hash=state["event_hash"], output=payload,
                                                            evidence=evidence))
        event = events[-1]
        state["outstanding"] = {"event_id": event["event_id"], "event_hash": event["event_hash"], "sequence": event["sequence"]}
        state_path.write_text(json.dumps(state, sort_keys=True), "utf-8")
        os.chmod(state_path, 0o600)
        job_path.unlink()
    return 0


def reconcile_acknowledged(root: Path = ROOT) -> bool:
    """Advance a final chain checkpoint already acknowledged before a crash."""
    state_path = root / "chain-state.json"
    if not state_path.exists():
        return False
    state = json.loads(state_path.read_text("utf-8")); outstanding = state.get("outstanding")
    if not outstanding:
        return False
    acknowledged = root / "acknowledged" / f"{outstanding['event_id']}.json"
    if not acknowledged.exists():
        return False
    event = json.loads(acknowledged.read_text("utf-8"))["request"]["event"]
    if event["event_id"] != outstanding["event_id"] or event["event_hash"] != outstanding["event_hash"]:
        return False
    state.update({"sequence": outstanding["sequence"], "event_hash": outstanding["event_hash"], "outstanding": None})
    state_path.write_text(json.dumps(state, sort_keys=True), "utf-8"); os.chmod(state_path, 0o600)
    return True


def forward_once() -> int:
    values = config()
    if not enabled(values):
        return 0
    spool = EvidenceSpool(ROOT, MTLSConfig(endpoint=values["MACOS_TRANSPORT_ENDPOINT"], endpoint_id=values["MACOS_TRANSPORT_ENDPOINT_ID"], ca_cert=Path(values["MACOS_TRANSPORT_CA_CERT"]), client_cert=Path(values["MACOS_TRANSPORT_CLIENT_CERT"]), client_key=Path(values["MACOS_TRANSPORT_CLIENT_KEY"])))
    capture_once()
    # Drain a bounded batch so a chunked command does not wait one launchd
    # interval per 48 KiB. `False` means no due item or a retryable failure;
    # in either case stop to preserve shared spool backoff and ordering.
    accepted = False
    for _ in range(32):
        if not spool.forward_once():
            break
        accepted = True
    # Reconcile even when this invocation had no due item: a crash may have
    # happened after the shared spool atomically acknowledged the final chunk.
    reconciled = reconcile_acknowledged()
    return 0 if accepted or reconciled else 1


def offline_recovery_test() -> int:
    # No network I/O: prove an unacknowledged capture stays in the durable queue.
    values = config()
    if not enabled(values):
        print("transport disabled; offline recovery test skipped")
        return 0
    pending = ROOT / "pending"
    if not pending.is_dir() or not any(pending.glob("*.json")):
        print("offline recovery test: no queued evidence to inspect")
        return 0
    print("offline recovery test: pending evidence retained; no network attempt made")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("capture-once", "forward-once", "offline-recovery-test"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("redteam-macos-transport: run as root")
    return {"capture-once": capture_once, "forward-once": forward_once, "offline-recovery-test": offline_recovery_test}[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
