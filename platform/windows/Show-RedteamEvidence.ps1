[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence",
    [ValidateRange(0, 10000)][int]$History = 20,
    [ValidateRange(1, 60)][int]$IntervalSeconds = 2,
    [switch]$Once
)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges are required to view protected local evidence.' }
$spool = Join-Path $InstallRoot 'spool'
$sent = Join-Path $InstallRoot 'sent'
$records = Join-Path $InstallRoot 'records'
if (-not (Test-Path -LiteralPath $records) -or -not (Test-Path -LiteralPath $spool) -or -not (Test-Path -LiteralPath $sent)) { throw 'Sealed local evidence directories do not exist.' }

function ConvertTo-SafePlaintext([string]$Text) {
    # Never replay terminal controls from captured output into the operator console.
    $plain = $Text -replace '\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\a]*(?:\a|\x1B\\))', ''
    return $plain -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ''
}
function Show-Record($File) {
    try { $event = Get-Content -LiteralPath $File.FullName -Raw | ConvertFrom-Json } catch { Write-Warning "Skipping unreadable record $($File.Name)"; return }
    $arguments = if ($event.arguments) { @($event.arguments) -join ' ' } else { '' }
    Write-Output ("[{0}] {1} {2}" -f $event.ended_utc, $event.file_path, $arguments)
    $outputPath = [string]$event.output_path
    if (-not (Test-Path -LiteralPath $outputPath)) { Write-Output '    [captured output unavailable]'; return }
    $plain = ConvertTo-SafePlaintext ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($outputPath)))
    foreach ($line in ($plain -split "`r?`n")) { Write-Output "    $line" }
    Write-Output ''
}
function Get-RecordId($File) {
    try { return [string]((Get-Content -LiteralPath $File.FullName -Raw | ConvertFrom-Json).id) }
    catch { Write-Warning "Skipping unreadable record $($File.Name)"; return $null }
}
function Get-SealedRecords {
    return @(Get-ChildItem -LiteralPath $records, $spool, $sent -Filter '*.json' -File | Sort-Object LastWriteTimeUtc)
}

$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$initial = @(Get-SealedRecords)
foreach ($file in ($initial | Select-Object -Last $History)) {
    $id = Get-RecordId $file
    if ($id -and $seen.Add($id)) { Show-Record $file }
}
if ($Once) { exit 0 }
while ($true) {
    Start-Sleep -Seconds $IntervalSeconds
    foreach ($file in @(Get-SealedRecords)) {
        $id = Get-RecordId $file
        if ($id -and $seen.Add($id)) { Show-Record $file }
    }
}
