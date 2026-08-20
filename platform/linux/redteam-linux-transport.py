#!/usr/bin/env python3
"""Root-only Linux bridge from completed private OSC boundaries to mTLS.

This program never attaches to a terminal or reads terminal input.  It is run
by a systemd timer after the shell has written its output recording.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path

LIBRARY = Path("/usr/local/lib/redteam-logcat")
if LIBRARY.is_dir():
    sys.path.insert(0, str(LIBRARY))
else:  # Source-tree test mode only.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from central_collector import EvidenceSpool, MTLSConfig  # noqa: E402


CONFIG = Path("/etc/redteam/transport.conf")
RECORDING_CONFIG = Path("/etc/redteam/recording.conf")
ROOT = Path("/var/log/redteam/transport")
SESSIONS = Path("/var/log/redteam/sessions")
MARKER = re.compile(
    rb"\x1b]777;redteam-logcat;(start|end);([A-Za-z0-9_.:-]{1,128});([0-9]+)(?:;(-?[0-9]+))?\x07"
)
COMMAND_END = re.compile(rb"\[event=end\] \[session=([A-Za-z0-9_.:-]{1,128})\] \[seq=([0-9]+)\]")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class TransportError(RuntimeError):
    pass


def private_regular(path: Path, *, mode: int | None = None) -> None:
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
        raise TransportError(f"{path} must be a root-owned private regular file")
    if mode is not None and stat.S_IMODE(details.st_mode) != mode:
        raise TransportError(f"{path} must have mode {mode:04o}")


def root_owned_not_writable(path: Path) -> None:
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
        raise TransportError(f"{path} must be a root-owned non-writable regular file")


def private_directory(path: Path) -> None:
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
        raise TransportError(f"{path} must be a root-owned mode 0700 directory")


def atomic_write(path: Path, value: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with open(temporary, "xb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def read_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip().strip("'")
    return values


def transport_config() -> dict[str, str]:
    private_regular(CONFIG, mode=0o600)
    values = read_key_values(CONFIG)
    if values.get("LINUX_TRANSPORT_ENABLED") != "1":
        return values
    required = ("LINUX_TRANSPORT_ENDPOINT", "LINUX_TRANSPORT_ENDPOINT_ID", "LINUX_TRANSPORT_CA_CERT",
                "LINUX_TRANSPORT_CLIENT_CERT", "LINUX_TRANSPORT_CLIENT_KEY")
    if any(not values.get(name) for name in required):
        raise TransportError("enabled transport configuration is incomplete")
    if not IDENTIFIER.fullmatch(values["LINUX_TRANSPORT_ENDPOINT_ID"]):
        raise TransportError("transport endpoint ID is invalid")
    return values


def completed_output(session: str, sequence: str, output: Path) -> bytes | None:
    """Return precisely the bytes between one matching completed marker pair."""
    raw = output.read_bytes()
    active: dict[tuple[str, str], int] = {}
    for match in MARKER.finditer(raw):
        kind, found_session, found_sequence, result = match.groups()
        key = (found_session.decode("ascii"), found_sequence.decode("ascii"))
        if kind == b"start":
            active[key] = match.end()
        elif key == (session, sequence) and result is not None and key in active:
            return raw[active[key]:match.start()]
    return None


def ssh_command_output(output: Path) -> bytes | None:
    """Return the already captured output for a completed forced SSH command."""
    metadata = output.parent / "metadata"
    if not output.is_file() or output.is_symlink() or not metadata.exists():
        return None
    private_regular(output)
    private_regular(metadata)
    if "capture=ssh-command" not in metadata.read_text("utf-8", errors="strict").splitlines():
        return None
    return output.read_bytes()


def source_id() -> str:
    return "linux-" + re.sub(r"[^A-Za-z0-9_.:-]", "-", platform.node())[:122]


def state_path() -> Path:
    return ROOT / "chain-state.json"


def cursor_path() -> Path:
    return ROOT / "commands-cursor.json"


def load_state() -> dict[str, object]:
    path = state_path()
    if not path.exists():
        return {"sequence": 0, "event_hash": None, "outstanding": None, "source_id": source_id(),
                "endpoint_id": None}
    private_regular(path)
    state = json.loads(path.read_text("utf-8"))
    if not isinstance(state, dict):
        raise TransportError("chain state is invalid")
    if not IDENTIFIER.fullmatch(str(state.get("source_id", ""))):
        state["source_id"] = source_id()
    if state.get("endpoint_id") is not None and not IDENTIFIER.fullmatch(str(state["endpoint_id"])):
        raise TransportError("chain-state endpoint ID is invalid")
    return state


def save_state(state: dict[str, object]) -> None:
    atomic_write(state_path(), json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def setup_storage() -> None:
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(ROOT)
    for name in ("capture-pending", "captured", "artifacts", "pending", "claimed", "acknowledged"):
        directory = ROOT / name
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        private_directory(directory)


def queue_completed_end_events(user: str) -> None:
    """Read only newly appended command-log records, surviving normal rotation."""
    commands = Path("/var/log/redteam/commands.log")
    root_owned_not_writable(commands)
    cursor = {"inode": None, "offset": 0}
    if cursor_path().exists():
        private_regular(cursor_path())
        loaded = json.loads(cursor_path().read_text("utf-8"))
        if isinstance(loaded, dict):
            cursor.update(loaded)
    details = commands.stat()
    offset = int(cursor.get("offset", 0))
    if cursor.get("inode") != details.st_ino or offset < 0 or offset > details.st_size:
        offset = 0
    with commands.open("rb") as handle:
        handle.seek(offset)
        appended = handle.read()
    # Do not advance past a partially appended syslog line; it will be parsed
    # on the next timer run after rsyslog finishes writing it.
    complete, newline, _partial = appended.rpartition(b"\n")
    if newline:
        complete += newline
    else:
        complete = b""
    for session_raw, sequence_raw in COMMAND_END.findall(complete):
        session, sequence = session_raw.decode("ascii"), sequence_raw.decode("ascii")
        output = SESSIONS / user / session / "output.log"
        job_id = hashlib.sha256(f"{session}:{sequence}".encode("ascii")).hexdigest()
        pending = ROOT / "capture-pending" / f"{job_id}.json"
        captured = ROOT / "captured" / f"{job_id}.json"
        if not pending.exists() and not captured.exists() and output.is_file() and not output.is_symlink():
            atomic_write(pending, json.dumps({"session": session, "sequence": sequence,
                                               "output_path": str(output)}, sort_keys=True).encode("utf-8"))
    atomic_write(cursor_path(), json.dumps({"inode": details.st_ino, "offset": offset + len(complete)}, sort_keys=True).encode("utf-8"))


def capture_once(values: dict[str, str]) -> None:
    if values.get("LINUX_TRANSPORT_ENABLED") != "1":
        return
    setup_storage()
    root_owned_not_writable(RECORDING_CONFIG)
    recording = read_key_values(RECORDING_CONFIG)
    user = recording.get("REDTEAM_RECORD_USER", "")
    if not user or not IDENTIFIER.fullmatch(user):
        raise TransportError("recording user is invalid")
    queue_completed_end_events(user)
    state = load_state()
    endpoint_id = values["LINUX_TRANSPORT_ENDPOINT_ID"]
    if state.get("endpoint_id") not in (None, endpoint_id):
        raise TransportError("refusing to continue a source chain at a different endpoint ID")
    endpoint_was_unset = state.get("endpoint_id") is None
    if state.get("endpoint_id") is None:
        state["endpoint_id"] = endpoint_id
    if not state_path().exists() or endpoint_was_unset:
        # Host identity is generated once and stays in the durable chain state
        # even before the first completed command is queued.
        save_state(state)
    config = MTLSConfig(endpoint=values["LINUX_TRANSPORT_ENDPOINT"], endpoint_id=values["LINUX_TRANSPORT_ENDPOINT_ID"],
                        ca_cert=Path(values["LINUX_TRANSPORT_CA_CERT"]),
                        client_cert=Path(values["LINUX_TRANSPORT_CLIENT_CERT"]),
                        client_key=Path(values["LINUX_TRANSPORT_CLIENT_KEY"]))
    spool = EvidenceSpool(ROOT, config)
    if state.get("outstanding"):
        return
    for job_path in sorted((ROOT / "capture-pending").glob("*.json")):
        job = json.loads(job_path.read_text("utf-8"))
        session, command_sequence = str(job["session"]), str(job["sequence"])
        output_path = Path(str(job["output_path"]))
        payload = None
        if output_path.is_file() and not output_path.is_symlink():
            private_regular(output_path)
            payload = completed_output(session, command_sequence, output_path)
        if payload is None:
            payload = ssh_command_output(output_path)
        if payload is None:
            # Interactive records without a completed private boundary remain
            # outside the output-only adapter; do not infer command output.
            job_path.unlink()
            continue
        job_id = hashlib.sha256(f"{session}:{command_sequence}".encode("ascii")).hexdigest()
        captured = ROOT / "captured" / f"{job_id}.json"
        if captured.exists():
            job_path.unlink()
            continue
        artifact = ROOT / "artifacts" / f"{job_id}.bin"
        atomic_write(artifact, payload)
        digest = hashlib.sha256(payload).hexdigest()
        evidence = {"kind": "command-observation", "digest": digest, "byte_length": len(payload),
                    "retention_reference": f"linux-session://{session}/{command_sequence}",
                    "classification": "restricted", "summary": "Linux interactive command output"}
        events = spool.enqueue_stream(source_id=str(state["source_id"]), sequence=int(state["sequence"]) + 1,
                                      previous_event_hash=state["event_hash"], evidence=evidence, output=payload) if payload else [
            spool.enqueue(source_id=str(state["source_id"]), sequence=int(state["sequence"]) + 1,
                          previous_event_hash=state["event_hash"], evidence=evidence, output=payload)]
        final = events[-1]
        atomic_write(captured, json.dumps({"session": session, "command_sequence": command_sequence,
                                            "event_id": final["event_id"]}, sort_keys=True).encode("utf-8"))
        state["outstanding"] = {"event_id": final["event_id"], "event_hash": final["event_hash"],
                                "sequence": final["sequence"]}
        save_state(state)
        job_path.unlink()
        return  # One command at a time preserves the source hash-chain.


def forward_once() -> int:
    values = transport_config()
    if values.get("LINUX_TRANSPORT_ENABLED") != "1":
        return 0
    setup_storage()
    capture_once(values)
    config = MTLSConfig(endpoint=values["LINUX_TRANSPORT_ENDPOINT"], endpoint_id=values["LINUX_TRANSPORT_ENDPOINT_ID"],
                        ca_cert=Path(values["LINUX_TRANSPORT_CA_CERT"]),
                        client_cert=Path(values["LINUX_TRANSPORT_CLIENT_CERT"]),
                        client_key=Path(values["LINUX_TRANSPORT_CLIENT_KEY"]))
    spool = EvidenceSpool(ROOT, config)
    for _ in range(32):
        if not spool.forward_once():
            break
    state = load_state()
    outstanding = state.get("outstanding")
    if isinstance(outstanding, dict):
        acknowledged = ROOT / "acknowledged" / f"{outstanding.get('event_id')}.json"
        if acknowledged.exists():
            event = json.loads(acknowledged.read_text("utf-8"))["request"]["event"]
            if event.get("event_id") == outstanding.get("event_id") and event.get("event_hash") == outstanding.get("event_hash"):
                state.update({"sequence": outstanding["sequence"], "event_hash": outstanding["event_hash"], "outstanding": None})
                save_state(state)
    # An idle queue or a durable retry/backoff is expected timer state, not a
    # failed service.  Validation and storage errors still raise above.
    return 0


def check() -> int:
    if os.geteuid() != 0:
        raise TransportError("transport checks require root")
    values = transport_config()
    root_owned_not_writable(RECORDING_CONFIG)
    if values.get("LINUX_TRANSPORT_ENABLED") == "1":
        setup_storage()
        for name in ("LINUX_TRANSPORT_CA_CERT", "LINUX_TRANSPORT_CLIENT_CERT", "LINUX_TRANSPORT_CLIENT_KEY"):
            root_owned_not_writable(Path(values[name]))
        MTLSConfig(endpoint=values["LINUX_TRANSPORT_ENDPOINT"], endpoint_id=values["LINUX_TRANSPORT_ENDPOINT_ID"],
                   ca_cert=Path(values["LINUX_TRANSPORT_CA_CERT"]), client_cert=Path(values["LINUX_TRANSPORT_CLIENT_CERT"]),
                   client_key=Path(values["LINUX_TRANSPORT_CLIENT_KEY"])).validated_url()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("forward-once", "check"))
    command = parser.parse_args().command
    try:
        return check() if command == "check" else forward_once()
    except (OSError, ValueError, TransportError) as error:
        print(f"redteam-linux-transport: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
