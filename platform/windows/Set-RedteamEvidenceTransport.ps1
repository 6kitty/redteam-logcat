[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$Endpoint,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')][string]$EndpointId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f ]{40,128}$')][string]$ClientCertificateThumbprint,
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence"
)

$ErrorActionPreference = 'Stop'
$admin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Administrator privileges are required to configure evidence transport.' }
if ($Endpoint.Scheme -ne 'https' -or $Endpoint.AbsolutePath -ne '/v1/evidence' -or $Endpoint.Query) { throw 'Endpoint must be an explicit HTTPS URL ending in /v1/evidence.' }
$existingConfigPath = Join-Path $InstallRoot 'transport.json'
$chainPath = Join-Path $InstallRoot 'source-chain.json'
if ((Test-Path -LiteralPath $existingConfigPath) -and (Test-Path -LiteralPath $chainPath)) {
    $existing = Get-Content -LiteralPath $existingConfigPath -Raw | ConvertFrom-Json
    $chain = Get-Content -LiteralPath $chainPath -Raw | ConvertFrom-Json
    $outstanding = $chain.inflight_id -or (Get-ChildItem -LiteralPath (Join-Path $InstallRoot 'spool') -Filter '*.json' -File -ErrorAction SilentlyContinue | Select-Object -First 1)
    $nonGenesis = [int64]$chain.sequence -gt 0 -or $null -ne $chain.previous_event_hash
    if ($existing.endpoint_id -ne $EndpointId -and ($nonGenesis -or $outstanding)) {
        throw 'Refusing to change EndpointId while this host has an accepted or in-flight source chain. This package never silently resets a chain; use the same endpoint identity for this installed source.'
    }
}
$thumbprint = $ClientCertificateThumbprint.Replace(' ', '').ToUpperInvariant()
if (-not (Test-Path -LiteralPath "Cert:\LocalMachine\My\$thumbprint")) { throw 'Client certificate thumbprint is not present in LocalMachine\\My.' }
$config = [ordered]@{ schema = 'redteam-evidence/windows-transport/v1'; endpoint = $Endpoint.AbsoluteUri; endpoint_id = $EndpointId; client_certificate_thumbprint = $thumbprint } | ConvertTo-Json -Compress
Set-Content -LiteralPath (Join-Path $InstallRoot 'transport.json') -Value $config -Encoding UTF8
Write-Host 'Transport configuration saved. Install the SYSTEM transport task separately with Install-RedteamEvidenceTransportTask.ps1.'
