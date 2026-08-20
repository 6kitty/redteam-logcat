# Redteam Logcat

A root-only live evidence viewer for authorized Linux red-team exercises.

`sudo logcat` groups each recorded shell command with the terminal output that
occurred before that command completed:

```text
[2026-08-20T07:11:52+09:00] kali /dev/pts/12 /home/kali
$ printf "proof\\n"
    proof

[2026-08-20T07:11:53+09:00] kali /dev/pts/12 /home/kali
$ false
    [exit 1]
```

## Install

Supported systems: Kali and Debian-derived systems with systemd.

```bash
git clone https://github.com/6kitty/redteam-logcat.git
cd redteam-logcat
sudo ./install.sh --user kali
```

The installer installs rsyslog, auditd, and OpenSSH server support when absent,
creates root-only evidence paths, configures one account's interactive Bash/Zsh
sessions **and its non-interactive SSH commands**, and installs `/usr/local/bin/logcat`.
It is safe to re-run: existing
`/var/log/redteam/commands.log` is preserved.

The installer is idempotent: when its audit rules for the selected account are
already active, it does not reload those equivalent rules again.

Start observing in one SSH terminal, then operate in another:

```bash
sudo logcat
```

Use `Ctrl-C` to stop viewing. `sudo logcat --history 20 --once` prints a
bounded structured history instead of following new events.

Colors emitted by the recorded command, such as Kali's coloured `ip addr`
output, are preserved automatically when logcat writes to a terminal. Use
`--color always` to force this, or `--no-color` for plain text.

## Platform support

| Component | Kali/Debian Linux | macOS | Windows |
| --- | --- | --- | --- |
| Python `logcat` viewer core | Supported and integration-tested | Unit-tested in CI | Unit-tested in CI |
| One-command evidence collector (`install.sh`) | Supported | Not provided | Not provided |

The collector relies on Linux systemd, rsyslog, auditd, and util-linux `script`.
Those mechanisms do not have compatible drop-in equivalents on macOS or Windows,
so `install.sh` deliberately rejects those operating systems rather than claiming
to create equivalent evidence. The GitHub Actions matrix runs the viewer's parser,
safe rendering, color handling, and platform-specific privilege check on Ubuntu,
macOS, and Windows with Python 3.11 and 3.13.

## Evidence produced

- `/var/log/redteam/commands.log`: structured command start/end records,
  including user, TTY, working directory, SSH connection, return code, session,
  and sequence ID.
- `/var/log/redteam/sessions/USER/SESSION/output.log`: raw terminal output.
- `/var/log/redteam/sessions/USER/SESSION/timing.log`: util-linux timing
  data for `scriptreplay` on interactive sessions. Non-interactive SSH command
  sessions use an empty timing file and a root-only `command.txt`; their output
  is streamed verbatim to `output.log` while preserving the command's stdout,
  stderr, and exit status for the SSH client.
- auditd rules with key `redteam_exec`: kernel-level `execve` evidence for
  the configured login UID.

The viewer uses a session-scoped private terminal boundary emitted by the shell
hook. It does not guess relationships from timestamps. Terminal control
sequences are removed before display, so recorded output cannot control the
reviewer's terminal. Output is shown as plain text, not as a terminal emulator.

For the configured account, the installer also adds an OpenSSH `Match User`
`ForceCommand` wrapper. This turns `ssh host 'command'` into one root-owned
evidence session without changing the command's output bytes or exit status.
The default SFTP subsystem is passed through unchanged, so SFTP remains
available but is not converted into a terminal-style command/output record.
Applying this rule restarts the SSH listener after `sshd -t` validation; active
SSH session children are not terminated on the supported Kali/Debian service.

## Security boundary

This tool is intended only for systems and accounts you are authorized to
monitor. The installed evidence files are root-owned and mode-restricted.

It deliberately does **not** enable `script --log-in` or `--log-io`.
Those options can record every keystroke, including passwords entered while
terminal echo is disabled. Commands themselves and terminal output may still
contain secrets; restrict access, follow the engagement's retention/redaction
policy, and use a separately approved TLS collector for off-host delivery.

The local files are evidence, not a tamper-proof chain of custody. For stronger
assurance, forward to an approved collector, preserve audit logs off-host, and
use storage controls appropriate to the engagement.

## Verify

```bash
sudo ./install.sh --check
sudo logcat --version
```

## Development

No runtime Python dependencies are required.

```bash
python3 -m py_compile redteam_logcat.py
python3 tests/test_redteam_logcat.py -v
bash -n install.sh
```

## License

MIT. See [LICENSE](LICENSE).
