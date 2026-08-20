[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Command,
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence"
)

# cmd.exe has no supported global output-transcription policy. Use this wrapper
# whenever output correlation is required; direct cmd.exe/internal commands remain process-only evidence.
& (Join-Path $PSScriptRoot 'Invoke-RedteamCapturedCommand.ps1') -FilePath cmd.exe -ArgumentList @('/d', '/s', '/c', $Command) -InstallRoot $InstallRoot
exit $LASTEXITCODE
