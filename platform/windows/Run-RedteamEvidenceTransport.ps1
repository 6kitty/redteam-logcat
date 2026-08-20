[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence",
    [switch]$Watch,
    [ValidateRange(1, 60)][int]$PollSeconds = 2
)

$ErrorActionPreference = 'Stop'
function Invoke-TransportCycle {
    try { & (Join-Path $PSScriptRoot 'Import-RedteamEvidenceIntake.ps1') -InstallRoot $InstallRoot }
    catch { Write-Warning "Intake import failed; the next poll will retry: $($_.Exception.Message)"; return }
    try { & (Join-Path $PSScriptRoot 'Seal-RedteamEvidenceOutbound.ps1') -InstallRoot $InstallRoot }
    catch { Write-Warning "Outbound sealing failed; local records remain protected: $($_.Exception.Message)"; return }
    $configPath = Join-Path $InstallRoot 'transport.json'
    if (-not (Test-Path -LiteralPath $configPath)) { return } # no default endpoint, credentials, or network activity
    try {
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        & (Join-Path $PSScriptRoot 'Publish-RedteamEvidenceSpool.ps1') -InstallRoot $InstallRoot -Endpoint $config.endpoint -ClientCertificateThumbprint $config.client_certificate_thumbprint -MaxEvents 1
    } catch { Write-Warning "Transport failed; sealed records and spool remain for retry: $($_.Exception.Message)" }
}

do {
    Invoke-TransportCycle
    if ($Watch) { Start-Sleep -Seconds $PollSeconds }
} while ($Watch)
