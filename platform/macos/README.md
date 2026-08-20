# macOS collector

`install-macos.sh` is an opt-in collector for one local account's **interactive**
zsh and bash sessions (including Bash login sessions). It writes the same local viewer shape used by `logcat`:
root-owned `/var/log/redteam/commands.log`, session `metadata`, `output.log`, and
private `OSC 777;redteam-logcat` start/end boundaries.

```bash
sudo ./platform/macos/install-macos.sh --user "$USER"
sudo ./platform/macos/install-macos.sh --check
sudo ./platform/macos/install-macos.sh --uninstall
```

Use `--dry-run` to print install/uninstall changes. Uninstall removes hooks and
programs but deliberately preserves evidence. The BSD `script` recorder uses
`-F` to flush output and deliberately never uses `-k`, which records terminal
input. Commands and output may still contain secrets and remain root-only.

The installer also places the repository viewer at `/usr/local/bin/logcat`.
An Administrator must use `sudo logcat` (or `sudo logcat --history 20 --once`)
to inspect the same `/var/log/redteam` command and session records safely.

Transport is disabled by default. To enable real-time central collection, supply
all five explicit mTLS values at install time: `--transport-endpoint` (an exact
`https://host/v1/evidence` URL), `--transport-endpoint-id`, `--transport-ca-cert`,
`--transport-client-cert`, and `--transport-client-key`. The installer writes the
root-only configuration and enables a 5-second launchd forwarder only then; the
interactive shell only writes a local job and never waits for network I/O.
Each launchd run forwards up to 32 due spool entries, stopping on the first
retryable failure, so a large chunked command is not artificially delayed by one
five-second interval per chunk.
Transport enablement fails if launchd cannot load the daemon; `--check` verifies
the enabled job with `launchctl print`.
Re-running the installer without transport arguments preserves an existing
enabled transport configuration. Use `--disable-transport` to explicitly stop
the launchd forwarder while preserving local spool and evidence. An endpoint-ID
change is rejected while host-chain state exists; disable transport and follow
the approved spool preservation/reset procedure before changing identities.

Completed command boundaries are converted into the shared `redteam-evidence/v1`
attachment envelope. The adapter retains root-only `capture-pending`, `pending`,
`claimed`, `acknowledged`, and `artifacts` directories under
`/var/log/redteam/transport`; each transmitted artifact carries its SHA-256 and
byte count. A persistent host-level source ID and sequence/hash state preserve the
ordered central chain. The shared mTLS client only moves an item to `acknowledged` after its
event ID and output hash are positively acknowledged. Failed requests return to
`pending` with backoff; use `sudo ./platform/macos/validate-hardware.sh
--offline-recovery-test` to safely verify that queued evidence remains retained
without making a network request. Per-artifact transport is capped at 49,152
bytes by the central contract. Larger output is sent as verified ordered chunks;
the local chain advances only after the final chunk's acknowledgement.

Noninteractive `ssh host command` is intentionally unsupported: macOS does not
receive a ForceCommand or sshd configuration change, so shell evidence must not
be interpreted as SSH command coverage. OpenBSM was deprecated in macOS 11 and
disabled in macOS 14, so it also must not be claimed as kernel-exec coverage.
A real kernel telemetry deployment requires an Apple-approved EndpointSecurity
entitlement and system extension, which this project neither installs nor fakes.
