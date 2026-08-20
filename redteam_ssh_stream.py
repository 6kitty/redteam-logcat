#!/usr/bin/env python3
"""Record a forced SSH command while preserving its stdout and stderr streams."""

from __future__ import annotations

import os
import pwd
import selectors
import subprocess
import sys
from pathlib import Path


def write_all(descriptor: int, data: bytes) -> bool:
    """Mirror bytes and report whether a pipe receiver remained connected."""
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except BrokenPipeError:
            return False
        if written <= 0:
            return False
        offset += written
    return True


def target_environment(account: pwd.struct_passwd) -> dict[str, str]:
    return {
        "HOME": account.pw_dir,
        "LOGNAME": account.pw_name,
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "SHELL": account.pw_shell,
        "SSH_CONNECTION": os.environ.get("REDTEAM_SSH_CONNECTION", "local"),
        "USER": account.pw_name,
    }


def drop_privileges(account: pwd.struct_passwd) -> None:
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 2:
        return 64

    session = Path(sys.argv[1])
    command_path = session / "command.txt"
    command = command_path.read_text(encoding="utf-8", errors="strict")
    account = pwd.getpwnam(os.environ["REDTEAM_SSH_RECORD_USER"])
    if not session.is_dir() or session.parent.name != account.pw_name:
        return 64

    output_descriptor = os.open(
        session / "output.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    os.close(os.open(session / "timing.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600))
    capture_stdin = os.environ.get("REDTEAM_SSH_CAPTURE_STDIN") == "1"
    input_descriptor: int | None = None
    try:
        if capture_stdin:
            input_descriptor = os.open(
                session / "input.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
            )
        process = subprocess.Popen(
            [account.pw_shell, "-c", command],
            cwd=account.pw_dir,
            env=target_environment(account),
            stdin=subprocess.PIPE if capture_stdin else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=lambda: drop_privileges(account),
        )
        assert process.stdout is not None and process.stderr is not None
        streams = selectors.DefaultSelector()
        streams.register(process.stdout, selectors.EVENT_READ, sys.stdout.fileno())
        streams.register(process.stderr, selectors.EVENT_READ, sys.stderr.fileno())
        stdin_open = capture_stdin
        child_stdin_open = capture_stdin
        pending_stdin = bytearray()
        source_stdin = sys.stdin.fileno()
        child_stdin = process.stdin
        if capture_stdin:
            assert input_descriptor is not None and child_stdin is not None
            os.set_blocking(child_stdin.fileno(), False)
            streams.register(source_stdin, selectors.EVENT_READ, "ssh-stdin")

        def close_child_stdin() -> None:
            nonlocal child_stdin_open
            if not child_stdin_open or child_stdin is None:
                return
            child_stdin_open = False
            try:
                streams.unregister(child_stdin.fileno())
            except KeyError:
                pass
            try:
                child_stdin.close()
            except (BrokenPipeError, OSError):
                pass

        while streams.get_map():
            for key, _ in streams.select():
                if key.data == "ssh-stdin":
                    data = os.read(source_stdin, 64 * 1024)
                    if not data:
                        streams.unregister(source_stdin)
                        stdin_open = False
                        if not pending_stdin:
                            close_child_stdin()
                        continue
                    assert input_descriptor is not None and child_stdin is not None
                    write_all(input_descriptor, data)
                    pending_stdin.extend(data)
                    try:
                        streams.register(child_stdin.fileno(), selectors.EVENT_WRITE, "child-stdin")
                    except KeyError:
                        pass
                    continue
                if key.data == "child-stdin":
                    assert child_stdin is not None
                    try:
                        written = os.write(child_stdin.fileno(), pending_stdin)
                    except BrokenPipeError:
                        pending_stdin.clear()
                        close_child_stdin()
                        continue
                    if written > 0:
                        del pending_stdin[:written]
                    if not pending_stdin:
                        streams.unregister(child_stdin.fileno())
                        if not stdin_open:
                            close_child_stdin()
                    continue
                data = os.read(key.fileobj.fileno(), 64 * 1024)
                if not data:
                    streams.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                write_all(output_descriptor, data)
                write_all(key.data, data)
            if process.poll() is not None:
                pending_stdin.clear()
                if capture_stdin:
                    try:
                        streams.unregister(source_stdin)
                    except KeyError:
                        pass
                close_child_stdin()
        return_code = process.wait()
        return return_code if return_code >= 0 else 128 - return_code
    finally:
        if input_descriptor is not None:
            os.close(input_descriptor)
        os.close(output_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
