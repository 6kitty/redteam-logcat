[CmdletBinding()]
param([string]$InstallRoot = "$env:ProgramData\RedteamEvidence")

$ErrorActionPreference = 'Stop'
function Write-ChainState($Path, $Value) {
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 8 -Compress), [Text.Encoding]::UTF8)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}
function Write-ValidatedSpool($Path, $Event) {
    if ([string]$Event.id -notmatch '^[0-9a-fA-F]{32}$' -or $Event.kind -ne 'controlled-launch' -or -not $Event.output_path) { throw 'Recovery event is not a well-formed expected spool record.' }
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporary, ($Event | ConvertTo-Json -Depth 8 -Compress), [Text.Encoding]::UTF8)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}
$transportPath = Join-Path $InstallRoot 'transport.json'
if (-not (Test-Path -LiteralPath $transportPath)) { exit 0 } # local sealing remains available without transport
$statePath = Join-Path $InstallRoot 'source-chain.json'
if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }
else {
    $state = [pscustomobject]@{ source_id = "windows-$([guid]::NewGuid().ToString('N'))"; sequence = 0; previous_event_hash = $null; inflight_id = $null; next_chunk = 0; completed = $false }
    Write-ChainState $statePath $state
}
if ($state.inflight_id -and -not $state.completed) {
    # The state was committed before its spool file; rebuild that local queue entry on restart.
    $spoolPath = Join-Path $InstallRoot "spool\$($state.inflight_id).json"
    $valid = $false
    if (Test-Path -LiteralPath $spoolPath) { try { $candidate = Get-Content -LiteralPath $spoolPath -Raw | ConvertFrom-Json; $valid = (-not ((Get-Item -LiteralPath $spoolPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -and $candidate.id -eq $state.inflight_id -and $candidate.kind -eq 'controlled-launch' -and $candidate.output_path) } catch {} }
    if (-not $valid) {
        $recovery = Join-Path $InstallRoot "records\$($state.inflight_id).json"
        if (Test-Path -LiteralPath $recovery) {
            $event = Get-Content -LiteralPath $recovery -Raw | ConvertFrom-Json
            [void]$event.PSObject.Properties.Remove('outbound_state'); [void]$event.PSObject.Properties.Remove('delivery_next_chunk'); [void]$event.PSObject.Properties.Remove('intake_source')
            Write-ValidatedSpool $spoolPath $event
        }
    }
    exit 0
}
if ($state.inflight_id -and $state.completed) {
    # Publisher will retire a remaining spool entry; otherwise clear the completed marker before the next record.
    if (Test-Path -LiteralPath (Join-Path $InstallRoot "spool\$($state.inflight_id).json"))) { exit 0 }
    $state.inflight_id = $null; $state.next_chunk = 0; $state.completed = $false
    Write-ChainState $statePath $state
}
$recordFile = Get-ChildItem -LiteralPath (Join-Path $InstallRoot 'records') -Filter '*.json' -File | Sort-Object Name | Where-Object {
    try { (Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json).outbound_state -eq 'local-only' } catch { $false }
} | Select-Object -First 1
if (-not $recordFile) { exit 0 }
$event = Get-Content -LiteralPath $recordFile.FullName -Raw | ConvertFrom-Json
$event | Add-Member -NotePropertyName source_id -NotePropertyValue ([string]$state.source_id) -Force
$event | Add-Member -NotePropertyName sequence -NotePropertyValue ([int64]$state.sequence + 1) -Force
$event | Add-Member -NotePropertyName previous_event_hash -NotePropertyValue $state.previous_event_hash -Force
[void]$event.PSObject.Properties.Remove('outbound_state') # local scheduling state is never sent to the central adapter
[void]$event.PSObject.Properties.Remove('intake_source')
$state.inflight_id = $event.id; $state.next_chunk = 0; $state.completed = $false
Write-ChainState $statePath $state
Write-ValidatedSpool (Join-Path $InstallRoot "spool\$($event.id).json") $event
$record = Get-Content -LiteralPath $recordFile.FullName -Raw | ConvertFrom-Json
$record.outbound_state = 'queued'
[IO.File]::WriteAllText($recordFile.FullName, ($record | ConvertTo-Json -Depth 8 -Compress), [Text.Encoding]::UTF8)
