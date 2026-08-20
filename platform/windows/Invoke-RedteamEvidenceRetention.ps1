[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence",
    [ValidateRange(1, 3650)][int]$RetentionDays,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
if (-not $RetentionDays) {
    $RetentionDays = (Get-Content -LiteralPath (Join-Path $InstallRoot 'config.json') -Raw | ConvertFrom-Json).retention_days
}
$cutoff = [DateTime]::UtcNow.AddDays(-$RetentionDays)
# Do not delete pending spool entries: they are the durable offline delivery queue.
$targets = 'output', 'transcripts', 'records', 'sent', 'failed' | ForEach-Object { Join-Path $InstallRoot $_ }
$expired = Get-ChildItem -LiteralPath $targets -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -lt $cutoff }
if (-not $Apply) {
    $expired | Select-Object FullName, LastWriteTimeUtc, Length
    Write-Host "Retention preview: $(@($expired).Count) file(s) older than $RetentionDays days. Re-run with -Apply to remove them; spool is never auto-deleted."
    exit 0
}
foreach ($file in $expired) {
    if ($PSCmdlet.ShouldProcess($file.FullName, 'Delete expired evidence')) { Remove-Item -LiteralPath $file.FullName -Force }
}
