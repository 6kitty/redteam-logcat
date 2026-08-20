[CmdletBinding()]
param([string]$InstallRoot = "$env:ProgramData\RedteamEvidence", [switch]$SkipTransportMock)

$ErrorActionPreference = 'Stop'
function Assert-Condition($Condition, [string]$Message) { if (-not $Condition) { throw "FAILED: $Message" }; Write-Host "PASS: $Message" }
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Assert-Condition $isAdmin 'administrator context'
Assert-Condition (Test-Path -LiteralPath $InstallRoot) 'install root exists'
$acl = Get-Acl -LiteralPath $InstallRoot
Assert-Condition (($acl.Access | Where-Object IdentityReference -match 'Everyone|Users' | Where-Object FileSystemRights -match 'Write|FullControl').Count -eq 0) 'no broad write ACL'
$transcriptAcl = Get-Acl -LiteralPath (Join-Path $InstallRoot 'transcripts')
$dropRule = $transcriptAcl.Access | Where-Object { $_.IdentityReference -match 'Authenticated Users' -and $_.FileSystemRights -match 'CreateFiles|AppendData' }
Assert-Condition ($null -ne $dropRule) 'non-admin transcript drop path allows create/append'
Assert-Condition (-not ($dropRule.FileSystemRights -match 'ReadData|ListDirectory|Delete')) 'transcript drop path does not grant peer read/list/delete'
$intakeAcl = Get-Acl -LiteralPath (Join-Path $InstallRoot 'intake')
$intakeRule = $intakeAcl.Access | Where-Object { $_.IdentityReference -match 'Authenticated Users' -and $_.FileSystemRights -match 'CreateFiles|AppendData' }
Assert-Condition ($null -ne $intakeRule) 'non-admin controlled-launch intake permits create/append without peer read/list/delete'
$config = Get-Content -LiteralPath (Join-Path $InstallRoot 'config.json') -Raw | ConvertFrom-Json
Assert-Condition ($config.retention_days -ge 1) 'retention is configured'
$transportConfig = Join-Path $InstallRoot 'transport.json'
$securityLog = (& wevtutil.exe gl Security 2>$null) -join "`n"
Assert-Condition ($securityLog -match 'maxSize:') 'Security event log configuration is readable'
if ($securityLog -match 'retention:\s+false') { Write-Warning 'Security log retention is overwrite-as-needed; configure approved retention, auto-backup, or forwarding before relying on 4688 history.' }

$wrapper = Join-Path $PSScriptRoot 'Invoke-RedteamCapturedCommand.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wrapper -FilePath powershell.exe -ArgumentList @('-NoProfile', '-Command', 'Write-Output correlated-proof') -InstallRoot $InstallRoot
& (Join-Path $PSScriptRoot 'Import-RedteamEvidenceIntake.ps1') -InstallRoot $InstallRoot
$latestRecord = Get-ChildItem -LiteralPath (Join-Path $InstallRoot 'records') -Filter '*.json' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
$event = Get-Content $latestRecord.FullName -Raw | ConvertFrom-Json
Assert-Condition ($event.state -eq 'sealed-local') 'local-only install seals intake into protected record storage'
Assert-Condition ((Get-Content -LiteralPath $event.output_path -Raw) -match 'correlated-proof') 'output is correlated to sealed local record'
Assert-Condition ((Get-FileHash -LiteralPath $event.output_path -Algorithm SHA256).Hash -eq $event.output_sha256) 'output hash matches local record'

$retentionProbe = Join-Path $InstallRoot 'failed\retention-validation.tmp'
Set-Content -LiteralPath $retentionProbe -Value 'test artifact' -Encoding ASCII
(Get-Item -LiteralPath $retentionProbe).LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(-2)
& (Join-Path $PSScriptRoot 'Invoke-RedteamEvidenceRetention.ps1') -InstallRoot $InstallRoot -RetentionDays 1 -Apply -Confirm:$false
Assert-Condition (-not (Test-Path -LiteralPath $retentionProbe)) 'explicit retention lifecycle removes expired test artifact'

if (Test-Path -LiteralPath $transportConfig) {
    $transport = Get-Content -LiteralPath $transportConfig -Raw | ConvertFrom-Json
    Assert-Condition ($transport.endpoint -match '^https://.*/v1/evidence$' -and $transport.endpoint_id) 'explicit HTTPS endpoint and endpoint ID are configured'
    & (Join-Path $PSScriptRoot 'Seal-RedteamEvidenceOutbound.ps1') -InstallRoot $InstallRoot
    $latest = Get-ChildItem -LiteralPath (Join-Path $InstallRoot 'spool') -Filter '*.json' | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    $outbound = Get-Content $latest.FullName -Raw | ConvertFrom-Json
    Assert-Condition ($outbound.source_id -and $outbound.sequence -ge 1) 'one ordered outbound spool event has source-chain fields'
    $chainState = Get-Content -LiteralPath (Join-Path $InstallRoot 'source-chain.json') -Raw | ConvertFrom-Json
    Assert-Condition ($chainState.sequence -eq 0 -and $null -eq $chainState.previous_event_hash) 'source-chain state does not advance before matching collector acknowledgement'
    & (Join-Path $PSScriptRoot 'Publish-RedteamEvidenceSpool.ps1') -Endpoint 'http://127.0.0.1:1/mock' -InstallRoot $InstallRoot -DryRun
    Assert-Condition (Test-Path -LiteralPath $latest.FullName) 'offline spool is retained for recovery'
    if (-not $SkipTransportMock) { Write-Warning 'Transport mock contract: use an HTTPS listener trusted by this host, present the configured client certificate, and return accepted/event_id/output_sha256/canonical_event_id/canonical_event_hash matching the posted event; only then files move from spool to sent and source-chain state advances.' }
} else {
    Write-Warning 'No transport configuration: local sealing and viewing were verified; outbound chain and transport mock are intentionally skipped.'
}
Write-Warning 'Direct cmd.exe and cmd internal commands are only guaranteed process provenance (Security 4688); use Invoke-RedteamCmdCapture.ps1 for output capture.'
