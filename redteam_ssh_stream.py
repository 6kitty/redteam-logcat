#!/usr/bin/env python3
"""Record a forced SSH command while preserving its stdout and stderr streams."""

from __future__ import annotations

import os
import pwd
import selectors
import subprocess
import sys
from pathlib import Path


def write_all(descriptor: int, data: bytes) -> None:
    """Mirror bytes without allowing a disconnected client to discard evidence."""
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except BrokenPipeError:
            return
        if written <= 0:
            return
        offset += written


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
    try:
        process = subprocess.Popen(
            [account.pw_shell, "-c", command],
            cwd=account.pw_dir,
            env=target_environment(account),
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=lambda: drop_privileges(account),
        )
        assert process.stdout is not None and process.stderr is not None
        streams = selectors.DefaultSelector()
        streams.register(process.stdout, selectors.EVENT_READ, sys.stdout.fileno())
        streams.register(process.stderr, selectors.EVENT_READ, sys.stderr.fileno())
        while streams.get_map():
            for key, _ in streams.select():
                data = os.read(key.fileobj.fileno(), 64 * 1024)
                if not data:
                    streams.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                write_all(output_descriptor, data)
                write_all(key.data, data)
        return_code = process.wait()
        return return_code if return_code >= 0 else 128 - return_code
    finally:
        os.close(output_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
