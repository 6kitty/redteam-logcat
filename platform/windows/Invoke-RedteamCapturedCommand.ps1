[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FilePath,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgumentList,
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence"
)

$ErrorActionPreference = 'Stop'
$id = [guid]::NewGuid().ToString('N')
$started = [DateTime]::UtcNow
$outputPath = Join-Path $InstallRoot "intake\$id.txt"
$eventPath = Join-Path $InstallRoot "intake\$id.json"
New-Item -ItemType Directory -Path (Split-Path $outputPath), (Split-Path $eventPath) -Force | Out-Null

try {
    # This is an explicit launcher: it captures stdout and stderr without recording input.
    & $FilePath @ArgumentList 2>&1 | Tee-Object -LiteralPath $outputPath -Encoding UTF8
    $exitCode = if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 }
} catch {
    $_ | Out-String | Tee-Object -LiteralPath $outputPath -Append -Encoding UTF8 | Write-Output
    $exitCode = 1
}

$bytes = [IO.File]::ReadAllBytes($outputPath)
$event = [ordered]@{
    schema = 'redteam-evidence/windows/v1'; id = $id; kind = 'controlled-launch'; state = 'pending-intake'
    started_utc = $started.ToString('o'); ended_utc = [DateTime]::UtcNow.ToString('o')
    user = [Security.Principal.WindowsIdentity]::GetCurrent().Name; host = $env:COMPUTERNAME
    file_path = $FilePath; arguments = @($ArgumentList); exit_code = $exitCode
    output_path = $outputPath; output_sha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
    output_bytes = $bytes.Length
}
[IO.File]::WriteAllText($eventPath, ($event | ConvertTo-Json -Depth 4 -Compress), [Text.Encoding]::UTF8)
exit $exitCode
