[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(1, 60)][int]$PollSeconds = 2,
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence",
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$admin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Administrator privileges are required to manage the SYSTEM transport task.' }
$name = 'RedteamEvidenceTransport'
if ($Uninstall) { if ($PSCmdlet.ShouldProcess($name, 'Unregister scheduled task')) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue }; exit 0 }
$runner = Join-Path $InstallRoot 'program\Run-RedteamEvidenceTransport.ps1'
if (-not (Test-Path -LiteralPath $runner) -or ((Get-Item -LiteralPath $runner -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Protected installed transport runner is missing or unsafe; rerun Install-RedteamEvidence.ps1.' }
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$runner`" -InstallRoot `"$InstallRoot`" -Watch -PollSeconds $PollSeconds"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
if ($PSCmdlet.ShouldProcess($name, 'Register and start supervised SYSTEM transport watch worker')) {
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    try {
        if ((Get-ScheduledTask -TaskName $name).State -ne 'Running') { Start-ScheduledTask -TaskName $name }
    } catch { Write-Warning "Task was registered but could not be started immediately: $($_.Exception.Message)" }
}
