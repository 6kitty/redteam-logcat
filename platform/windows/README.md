# Windows evidence collector

This package provides authorized Windows command/process evidence with the strongest built-in coverage available without keylogging or password capture. Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-RedteamEvidence.ps1
.\Test-RedteamEvidence.ps1
```

`Install-RedteamEvidence.ps1` is idempotent. It creates `C:\ProgramData\RedteamEvidence` and its command/output/records/spool directories as `SYSTEM`/Administrators-only storage, enables PowerShell transcription, enables Security event 4688 success auditing, and enables its command-line field. Use `-Check`, `-DryRun`, or `-Uninstall`; uninstall removes local evidence storage but intentionally leaves shared Windows audit/transcription policy settings unchanged.

Installation copies the SYSTEM worker and its operational scripts into the protected `program/` directory under the install root. The scheduled task runs only those ACL-protected, non-reparse copies, never a checkout path.

## Coverage and limits

* PowerShell transcription is the built-in, policy-controlled record of PowerShell input/output activity. It is **not keylogging** and must be protected because commands and output can contain secrets. `transcripts/` is a constrained drop directory: Authenticated Users can create/append transcript files but are not granted read, list, or delete access; `SYSTEM` and Administrators retain full control. A transcript creator remains its Windows owner, so this is peer-user protection rather than a tamper-proof barrier against that creator. Microsoft documents formatting/output omissions for complex objects, so it is evidence of displayed transcript text rather than a lossless serialization. Domain GPO can override this local policy.
* Security event 4688 gives process provenance and command arguments only when **both** Audit Process Creation success auditing and **Include command line in process creation events** are enabled. Command lines are plain text and can contain sensitive arguments. Events are in the Windows Security log and require appropriate audit-log retention/forwarding outside this package.
* Windows does not provide a supported, universal `cmd.exe` console-output policy. Direct `cmd.exe`, including internal commands such as `dir`, is therefore process/command-line evidence only. Run `Invoke-RedteamCmdCapture.ps1 -Command 'dir & echo proof'` to deliberately capture stdout/stderr and correlate it with a durable spool event.
* `Invoke-RedteamCapturedCommand.ps1` is the generic controlled launcher. Non-admin users create/append only in the constrained `intake/` drop path; run `Import-RedteamEvidenceIntake.ps1` elevated to hash, move, and seal those records into administrator-only `output/` and `records/`, whether or not transport is configured. Intake is deliberately marked `pending-intake` and is not tamper-proof until this handoff occurs. The launcher captures output only and never records keystrokes, passwords, or hidden input.

## Durable outbound handoff

The elevated intake importer always writes output under `output/` plus a protected sealed local record under `records/`, regardless of whether remote transport is configured. A transport-configured task later copies one ordered record at a time into `spool/`. `Publish-RedteamEvidenceSpool.ps1` forwards output without truncation: output over 48 KiB is split into independently hashed, deterministic-ID chunks at most 48 KiB each, with a stream ID, index/count, complete-output digest/length, and final marker. Protected `source-chain.json` is the authoritative in-flight state machine (`inflight_id`, next chunk, acknowledged hash/sequence, completion marker): a single atomic update after each strict ACK advances both chain and delivery progress. A restart reconciles that state, including final-ACK-before-move, without resending or skipping a chunk; the original event moves to `sent/` only after the final chunk ACK. `Publish-RedteamEvidenceSpool.ps1` requires an HTTPS endpoint and exactly one client certificate (`-ClientCertificatePath path.pfx [-ClientCertificatePassword ...]` or `-ClientCertificateThumbprint ...` from `LocalMachine\My`); it uses normal Windows/.NET trusted-root and hostname validation. It never hardcodes endpoints or credentials.

```json
{"schema":"redteam-evidence/windows/v1","event":{},"output_base64":"...","output_sha256":"..."}
```

The receiver must return JSON with `accepted: true` (or `status: "accepted"`), the matching Windows `event_id` and `output_sha256`, plus `canonical_event_id` and `canonical_event_hash`; only then does the sender atomically advance its source chain and move a file to `sent/`. Failures and malformed acknowledgments remain in `spool/` for retry. Use `-DryRun` to validate an offline queue without sending (it is the only mode that permits an HTTP mock).

## Real-time SYSTEM transport

There is no default endpoint and no embedded credential. An administrator first configures a named endpoint and a LocalMachine certificate, then installs a bounded task:

```powershell
.\Set-RedteamEvidenceTransport.ps1 -Endpoint https://collector.example/v1/evidence -EndpointId engagement-a -ClientCertificateThumbprint THUMBPRINT
.\Install-RedteamEvidenceTransportTask.ps1 -PollSeconds 2
```

Re-running configuration with the same endpoint ID is safe. The setup refuses to change `EndpointId` once this host has an accepted chain or an in-flight spool record: the receiving collector orders events by that identity. This package never silently resets a chain; use the same endpoint identity for the installed source.

The `RedteamEvidenceTransport` scheduled task starts a supervised `SYSTEM` watch worker immediately when installed and again at boot. By default it completes a local intake/import/seal/one-item-forward cycle every **2 seconds** (configure `-PollSeconds 1..60`), so an available configured collector is polled with no more than roughly two seconds of intentional worker delay. Every cycle ingests all eligible local intake into protected `records/`; this works even with no transport configuration or during an outage. When `transport.json` exists, it seals one oldest `local-only` record into the outbound spool and attempts that one item using the configured mTLS client certificate. If no transport is configured it makes no network request. Per-cycle errors are warned and retried next poll; Task Scheduler ignores duplicate instances and restarts an unexpectedly terminated worker up to three times at one-minute intervals. `source-chain.json` is only used for ordered outbound records: it supplies `source_id`, monotonic next `sequence`, and the last acknowledged `previous_event_hash`; only a matching accepted collector reply with the central canonical hash atomically advances it. Run the task only after the central collector's server identity is trusted by the local machine and the collector is configured with the matching endpoint ID and client CA.

## Live accepted-evidence viewer

Run `Show-RedteamEvidence.ps1` elevated to show the latest 20 sealed local records, or use `-History 100`, `-Once`, and `-IntervalSeconds 2`. It tails protected `records/` (local-only), `spool/` (before central delivery), and `sent/` (after acknowledgment), deduplicating by event ID so lifecycle changes are not replayed. It is not a live process monitor and excludes untrusted pending `intake/` records. Captured output is rendered as sanitized plaintext with each line indented; terminal-control sequences and unsafe control characters are removed rather than replayed. Output can contain sensitive material, and direct `cmd.exe` activity remains process-only unless it used the controlled wrapper.

## Retention

`retention_days` is recorded in `config.json`. `Invoke-RedteamEvidenceRetention.ps1` first previews expiry and deletes only with explicit `-Apply`; it handles `output/`, `transcripts/`, `records/`, `sent/`, and `failed/`, never pending `intake/` or `spool/` items. Test ACLs, correlation, retention, and offline recovery with `Test-RedteamEvidence.ps1`.

The installer and validation script query `wevtutil gl Security` to show `retention`, `autoBackup`, and `maxSize`. They do not assume Windows' default Security-log overwrite behavior is sufficient and do not change the global event-log policy. Configure a retention/auto-backup/forwarding setting approved for the engagement before relying on historical 4688 evidence.
