"""Portable contract tests for Windows collector assets (safe to run off Windows)."""
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1] / "platform" / "windows"


class WindowsCollectorContractTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8")

    def test_required_assets_exist(self) -> None:
        for name in (
            "Install-RedteamEvidence.ps1", "Invoke-RedteamCapturedCommand.ps1",
            "Invoke-RedteamCmdCapture.ps1", "Publish-RedteamEvidenceSpool.ps1",
            "Import-RedteamEvidenceIntake.ps1", "Seal-RedteamEvidenceOutbound.ps1", "Set-RedteamEvidenceTransport.ps1", "Install-RedteamEvidenceTransportTask.ps1", "Run-RedteamEvidenceTransport.ps1", "Invoke-RedteamEvidenceRetention.ps1", "Test-RedteamEvidence.ps1", "README.md",
            "Show-RedteamEvidence.ps1",
        ):
            self.assertTrue((ROOT / name).is_file(), name)

    def test_installer_is_idempotent_and_secures_storage(self) -> None:
        text = self.read("Install-RedteamEvidence.ps1")
        self.assertIn("Set-AdminOnlyAcl", text)
        self.assertIn("BUILTIN\\Administrators", text)
        self.assertIn("[switch]$DryRun", text)
        self.assertIn("[switch]$Uninstall", text)
        self.assertIn("RetentionDays", text)
        self.assertIn("Set-TranscriptDropAcl", text)
        self.assertIn("'program'", text)
        self.assertIn("Operational script is missing or a reparse point", text)

    def test_supported_evidence_is_explicit(self) -> None:
        text = self.read("Install-RedteamEvidence.ps1")
        self.assertIn("EnableTranscripting", text)
        self.assertIn("ProcessCreationIncludeCmdLine_Enabled", text)
        self.assertIn("auditpol.exe", text)
        self.assertIn("wevtutil.exe gl Security", text)
        self.assertIn("4688", self.read("README.md"))
        self.assertIn("both** Audit Process Creation", self.read("README.md"))

    def test_cmd_output_limit_and_controlled_wrapper_are_documented(self) -> None:
        docs = self.read("README.md").lower()
        self.assertIn("does not provide a supported, universal `cmd.exe` console-output policy", docs)
        self.assertIn("direct `cmd.exe`", docs)
        wrapper = self.read("Invoke-RedteamCmdCapture.ps1")
        self.assertIn("-FilePath cmd.exe", wrapper)
        self.assertIn("'/c'", wrapper)

    def test_no_keylogging_or_password_capture_claim(self) -> None:
        docs = self.read("README.md").lower()
        self.assertIn("without keylogging or password capture", docs)
        self.assertIn("never records keystrokes, passwords", docs)
        self.assertIn("formatting/output omissions for complex objects", docs)

    def test_spool_has_hash_and_retry_contract(self) -> None:
        launcher = self.read("Invoke-RedteamCapturedCommand.ps1")
        publisher = self.read("Publish-RedteamEvidenceSpool.ps1")
        self.assertIn("Get-FileHash", launcher)
        self.assertIn("output_sha256", launcher)
        self.assertIn("pending-intake", launcher)
        self.assertIn("-Encoding UTF8", launcher)
        self.assertIn("Invalid intake event identifier", self.read("Import-RedteamEvidenceIntake.ps1"))
        self.assertIn("Keeping", publisher)
        self.assertIn("Move-Item", publisher)
        self.assertIn("ClientCertificate", publisher)
        self.assertIn("HTTPS is required", publisher)
        self.assertIn("$ack.event_id -eq $chunkEvent.id", publisher)
        self.assertIn("$ack.output_sha256 -eq $chunkEvent.output_sha256", publisher)
        self.assertIn("MaxEvents", publisher)
        self.assertIn("$ChunkBytes = 48KB", publisher)
        self.assertIn("delivery_next_chunk", publisher)
        self.assertIn("inflight_id", publisher)
        self.assertIn("next_chunk", publisher)
        self.assertIn("completed", publisher)
        self.assertIn("authoritative local in-flight chain", publisher)
        self.assertIn("chunk_index", publisher)
        self.assertIn("chunk_count", publisher)
        self.assertIn("stream_digest", publisher)
        self.assertIn("stream_byte_length", publisher)
        self.assertIn("$chunkEvent.final", publisher)
        self.assertIn("Substring(0, 32)", publisher)

    def test_transcript_drop_and_explicit_retention_are_covered(self) -> None:
        installer = self.read("Install-RedteamEvidence.ps1")
        hardware_test = self.read("Test-RedteamEvidence.ps1")
        retention = self.read("Invoke-RedteamEvidenceRetention.ps1")
        self.assertIn("Authenticated Users", installer)
        self.assertIn("CREATOR OWNER", installer)
        self.assertIn("'intake'", installer)
        self.assertIn("does not grant peer read/list/delete", hardware_test)
        self.assertIn("[switch]$Apply", retention)
        self.assertIn("Do not delete pending spool entries", retention)

    def test_system_transport_and_source_chain_require_explicit_configuration(self) -> None:
        importer = self.read("Import-RedteamEvidenceIntake.ps1")
        sealer = self.read("Seal-RedteamEvidenceOutbound.ps1")
        setup = self.read("Set-RedteamEvidenceTransport.ps1")
        task = self.read("Install-RedteamEvidenceTransportTask.ps1")
        runner = self.read("Run-RedteamEvidenceTransport.ps1")
        self.assertIn("sealed-local", importer)
        self.assertIn("records", importer)
        self.assertNotIn("transport.json", importer)
        self.assertIn("transport.json", sealer)
        self.assertIn("Write-ChainState", sealer)
        self.assertIn("Write-ValidatedSpool", sealer)
        self.assertIn("inflight_id", sealer)
        self.assertIn("source_id", sealer)
        self.assertIn("previous_event_hash", sealer)
        self.assertIn("source-chain.json", sealer)
        self.assertIn("Select-Object -First 1", sealer)
        self.assertIn("Write-AcknowledgedSourceState", self.read("Publish-RedteamEvidenceSpool.ps1"))
        publisher = self.read("Publish-RedteamEvidenceSpool.ps1")
        self.assertIn("$ack.canonical_event_hash", publisher)
        self.assertIn("$ack.canonical_event_id", publisher)
        self.assertIn("/v1/evidence", setup)
        self.assertIn("ClientCertificateThumbprint", setup)
        self.assertIn("Refusing to change EndpointId", setup)
        self.assertIn("$existing.endpoint_id -ne $EndpointId", setup)
        self.assertIn("$nonGenesis", setup)
        self.assertIn("$outstanding", setup)
        self.assertIn("UserId 'SYSTEM'", task)
        self.assertIn("-AtStartup", task)
        self.assertIn("-Watch -PollSeconds", task)
        self.assertIn("RestartCount 3", task)
        self.assertIn("Start-ScheduledTask", task)
        self.assertIn("State -ne 'Running'", task)
        self.assertIn("'program\\Run-RedteamEvidenceTransport.ps1'", task)
        self.assertIn("ReparsePoint", task)
        self.assertIn("[switch]$Watch", runner)
        self.assertIn("Start-Sleep -Seconds $PollSeconds", runner)
        self.assertIn("MaxEvents 1", runner)
        self.assertIn("no default endpoint", runner)

    def test_accepted_evidence_viewer_is_admin_only_and_sanitizes_output(self) -> None:
        viewer = self.read("Show-RedteamEvidence.ps1")
        self.assertIn("Administrator privileges are required", viewer)
        self.assertIn("Join-Path $InstallRoot 'sent'", viewer)
        self.assertIn("Join-Path $InstallRoot 'spool'", viewer)
        self.assertIn("Join-Path $InstallRoot 'records'", viewer)
        self.assertIn("ConvertTo-SafePlaintext", viewer)
        self.assertIn("terminal controls", viewer)
        self.assertIn('"    $line"', viewer)
        self.assertIn("$seen.Add($id)", viewer)
        self.assertNotIn("'intake'", viewer)


if __name__ == "__main__":
    unittest.main()
