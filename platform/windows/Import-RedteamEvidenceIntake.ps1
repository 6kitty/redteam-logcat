[CmdletBinding()]
param([string]$InstallRoot = "$env:ProgramData\RedteamEvidence")

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges are required to ingest user intake evidence.' }
$intake = Join-Path $InstallRoot 'intake'
foreach ($eventFile in @(Get-ChildItem -LiteralPath $intake -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
    try {
        $event = Get-Content -LiteralPath $eventFile.FullName -Raw | ConvertFrom-Json
        if ([string]$event.id -notmatch '^[0-9a-fA-F]{32}$') { throw 'Invalid intake event identifier.' }
        $source = [string]$event.output_path
        $destination = Join-Path $InstallRoot "output\$($event.id).txt"
        $recordPath = Join-Path $InstallRoot "records\$($event.id).json"
        if (-not (Test-Path -LiteralPath $source) -and (Test-Path -LiteralPath $destination) -and (Test-Path -LiteralPath $recordPath)) {
            $event.output_path = $destination; $event.output_sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash; $event.output_bytes = (Get-Item -LiteralPath $destination).Length; $event.state = 'sealed-local'; $event.outbound_state = 'local-only'
            [IO.File]::WriteAllText($recordPath, ($event | ConvertTo-Json -Depth 6 -Compress), [Text.Encoding]::UTF8); Remove-Item -LiteralPath $eventFile.FullName -Force; continue
        }
        if (-not (Test-Path -LiteralPath $source) -or (Split-Path -Parent $source) -ne $intake) { throw 'Invalid or missing intake output path.' }
        if (-not (Test-Path -LiteralPath $recordPath)) {
            $staging = $event | Select-Object *; $staging.output_path = $destination; $staging.state = 'staging'; $staging.intake_source = $source
            [IO.File]::WriteAllText($recordPath, ($staging | ConvertTo-Json -Depth 6 -Compress), [Text.Encoding]::UTF8)
        }
        Move-Item -LiteralPath $source -Destination $destination -Force
        $event.output_path = $destination; $event.output_sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        $event.output_bytes = (Get-Item -LiteralPath $destination).Length; $event.state = 'sealed-local'; $event.outbound_state = 'local-only'
        [IO.File]::WriteAllText($recordPath, ($event | ConvertTo-Json -Depth 6 -Compress), [Text.Encoding]::UTF8)
        Remove-Item -LiteralPath $eventFile.FullName -Force
    } catch { Write-Warning "Keeping intake event $($eventFile.Name): $($_.Exception.Message)" }
}
