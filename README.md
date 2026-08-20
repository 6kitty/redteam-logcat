# Redteam Logcat

A privileged evidence viewer and opt-in collectors for authorized red-team
exercises on Linux, macOS, and Windows.

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

## Install and view evidence

### Linux (Kali/Debian with systemd)

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

Live evidence is checked every 50 ms by default. Idle sessions are refreshed
only every 0.5 seconds, while a newly logged command immediately promotes its
session back to the fast path. Use `--interval SECONDS` to tune the active
refresh cadence when needed.

Colors emitted by the recorded command, such as Kali's coloured `ip addr`
output, are preserved automatically when logcat writes to a terminal. Use
`--color always` to force this, or `--no-color` for plain text.

### macOS

The macOS collector covers one local account's **interactive Bash and Zsh
sessions**, including Bash login sessions. Install and check it on the Mac being
observed:

```bash
sudo ./platform/macos/install-macos.sh --user "$USER"
sudo ./platform/macos/install-macos.sh --check
sudo logcat
```

`sudo logcat --history 20 --once` gives a bounded local history. The installer
uses output-only BSD `script` recording; it does not record terminal input.
Use `--dry-run` before changes or `--uninstall` to remove hooks and programs
while preserving evidence. See [the macOS collector guide](platform/macos/README.md)
for the full operating contract.

### Windows

Run PowerShell as Administrator from the repository checkout:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\platform\windows\Install-RedteamEvidence.ps1
.\platform\windows\Test-RedteamEvidence.ps1
.\platform\windows\Show-RedteamEvidence.ps1 -History 20
```

The Windows viewer reads protected sealed local records from `records/`,
`spool/`, and `sent/`; it does not claim a central acknowledgement is required
before local review. Use the controlled wrappers when output capture is required:

```powershell
.\platform\windows\Invoke-RedteamCmdCapture.ps1 -Command 'dir & echo proof'
.\platform\windows\Invoke-RedteamCapturedCommand.ps1 -FilePath powershell.exe -ArgumentList '-NoProfile', '-Command', 'Get-Date'
```

`Show-RedteamEvidence.ps1 -Once` prints a bounded view; omit `-Once` to follow
new sealed local records. To enable the optional SYSTEM transport worker after
configuring the named collector and its LocalMachine certificate, run:

```powershell
.\platform\windows\Set-RedteamEvidenceTransport.ps1 -Endpoint https://collector.example/v1/evidence -EndpointId engagement-a -ClientCertificateThumbprint THUMBPRINT
.\platform\windows\Install-RedteamEvidenceTransportTask.ps1 -PollSeconds 2
```

The scheduled worker runs as SYSTEM and is bounded to one oldest spool item at a
time. See [the Windows collector guide](platform/windows/README.md) for setup,
protected intake, retention, and transport details.

## Platform support

| Component | Kali/Debian Linux | macOS | Windows |
| --- | --- | --- | --- |
| Local collector | `install.sh` for systemd Kali/Debian | `install-macos.sh` for one account's interactive Bash/Zsh | Administrator PowerShell installer and controlled wrappers |
| Local viewer | `sudo logcat` | `sudo logcat` | `Show-RedteamEvidence.ps1` (Administrator; protected sealed local records) |
| Command/output coverage | Interactive sessions and configured non-interactive SSH commands | Interactive Bash/Zsh output only | PowerShell transcripts; 4688 process/command line; wrapper output |
| CI coverage | Portable parser and Linux installer syntax | Portable collector/static tests | Portable collector/static tests |

The Linux installer relies on systemd, rsyslog, auditd, and util-linux `script`;
it deliberately rejects macOS and Windows. The macOS and Windows collectors are
separate, narrower implementations—not drop-in equivalents. GitHub Actions runs
portable viewer, protocol, central-collector, and platform static tests on Ubuntu,
macOS, and Windows. It does not install OS audit policies, launch system services,
or claim hardware/production collector validation on hosted runners.

### Platform limits

- macOS has no SSH `ForceCommand` integration here, so remote non-interactive
  `ssh host command` capture is unsupported. OpenBSM is not claimed as kernel-exec
  coverage: it was deprecated in macOS 11 and disabled in macOS 14. EndpointSecurity
  requires an Apple-approved entitlement and system extension, neither of which this
  project installs.
- Windows PowerShell transcription is policy-controlled displayed-text evidence,
  and Security event 4688 supplies process provenance and command arguments only
  when process-creation auditing and command-line inclusion are enabled. Windows
  has no supported universal direct `cmd.exe` console-output policy; direct `cmd.exe`
  activity is process/command-line evidence unless a controlled wrapper captures
  stdout/stderr.

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
contain secrets. Restrict access, follow the engagement's retention/redaction
policy, and configure operating-system audit-log retention/forwarding before
relying on historical evidence. Windows retention deletes only with an explicit
`-Apply`; pending intake and spool records are deliberately retained.

The local files are evidence, not a tamper-proof chain of custody. For stronger
assurance, preserve audit logs off-host and use storage controls appropriate to
the engagement.

### Optional central mTLS transport

There is no default endpoint, credential, or generated key. Configure transport
only with an approved `https://…/v1/evidence` endpoint, endpoint ID, trusted CA,
and client certificate/key (or the Windows LocalMachine certificate). The macOS
installer requires all five explicit mTLS options before it enables its launchd
forwarder. On Windows, configure `Set-RedteamEvidenceTransport.ps1` with a named
endpoint and client certificate before installing the bounded SYSTEM task.

For Linux, pass every transport value to the normal installer; omission of any
one leaves off-host transport disabled:

```bash
sudo ./install.sh --user kali \
  --transport-endpoint https://collector.example/v1/evidence \
  --transport-endpoint-id engagement-a \
  --transport-ca-cert /etc/redteam/ca.crt \
  --transport-client-cert /etc/redteam/client.crt \
  --transport-client-key /etc/redteam/client.key
```

When configured, the Linux systemd timer invokes the forwarder every five
seconds. It forwards one oldest due item and advances the local source chain
only after a matching accepted ACK; failed or malformed acknowledgements leave
the evidence queued for retry.

[Central collector setup](docs/central-collector.md) defines the mTLS material,
root-owned storage, bounded artifact contract, acknowledgements, retries, and
retention responsibilities. Test material is never suitable for deployment;
protect private keys, evidence spools, and accepted collector storage under the
engagement's retention and access-control policy.

## Verify

```bash
sudo ./install.sh --check
sudo logcat --version
```

## Development

No runtime Python dependencies are required.

```bash
python3 -m py_compile redteam_logcat.py
python3 -m pytest -q
bash -n install.sh
```

## License

MIT. See [LICENSE](LICENSE).
