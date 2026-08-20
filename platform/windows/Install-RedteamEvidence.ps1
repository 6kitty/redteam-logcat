[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence",
    [ValidateRange(1, 3650)][int]$RetentionDays = 30,
    [switch]$Uninstall,
    [switch]$Check,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
if ($DryRun) { $WhatIfPreference = $true }

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-AdminOnlyAcl([string]$Path) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($principal in 'SYSTEM', 'BUILTIN\Administrators') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $principal, 'FullControl', $inheritance, $propagation, $allow))) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-TranscriptDropAcl([string]$Path) {
    # PowerShell itself writes transcript files as the interactive user.  Permit
    # only create/append in this directory; do not grant listing, reading, or deletion.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $none = [Security.AccessControl.PropagationFlags]::None
    $both = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($principal in 'SYSTEM', 'BUILTIN\Administrators') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', $both, $none, $allow))) | Out-Null
    }
    $dropRights = [Security.AccessControl.FileSystemRights]'CreateFiles, AppendData, WriteAttributes, WriteExtendedAttributes, Synchronize'
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Authenticated Users', $dropRights, [Security.AccessControl.InheritanceFlags]::None, $none, $allow))) | Out-Null
    # A transcript is written after creation, so its creator needs write/append on that file only.
    $fileOnly = [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('CREATOR OWNER', $dropRights, $fileOnly, $none, $allow))) | Out-Null
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-InstallState {
    $config = Join-Path $InstallRoot 'config.json'
    [pscustomobject]@{
        InstallRoot = $InstallRoot
        ConfigPresent = Test-Path -LiteralPath $config
        TranscriptionEnabled = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting -eq 1
        ProcessCreationAuditEnabled = ((& auditpol.exe /get /subcategory:'Process Creation' 2>$null) -join "`n") -match 'Success.*Enabled'
        CommandLineIncluded = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled -eq 1
        SecurityLogConfiguration = ((& wevtutil.exe gl Security 2>$null) | Where-Object { $_ -match 'retention:|autoBackup:|maxSize:' }) -join '; '
    }
}

if ($Check) { Get-InstallState | Format-List; exit 0 }
if (-not (Test-Administrator)) { throw 'Administrator privileges are required.' }

if ($Uninstall) {
    if (Test-Path -LiteralPath $InstallRoot) {
        if ($PSCmdlet.ShouldProcess($InstallRoot, 'Remove Redteam Evidence install directory')) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
    }
    Write-Warning 'Policy settings are intentionally retained: remove only after confirming no other approved collection relies on them.'
    exit 0
}

$directories = 'commands', 'transcripts', 'intake', 'output', 'records', 'spool', 'sent', 'failed', 'program'
if ($PSCmdlet.ShouldProcess($InstallRoot, 'Create secured evidence storage')) {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    foreach ($directory in $directories) {
        $path = Join-Path $InstallRoot $directory
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Set-AdminOnlyAcl $path
    }
    Set-AdminOnlyAcl $InstallRoot
    Set-TranscriptDropAcl (Join-Path $InstallRoot 'transcripts')
    Set-TranscriptDropAcl (Join-Path $InstallRoot 'intake')
    foreach ($name in 'Import-RedteamEvidenceIntake.ps1','Seal-RedteamEvidenceOutbound.ps1','Publish-RedteamEvidenceSpool.ps1','Run-RedteamEvidenceTransport.ps1') {
        $source = Join-Path $PSScriptRoot $name; $item = Get-Item -LiteralPath $source -Force
        if (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            $target = Join-Path $InstallRoot "program\$name"; $temporary = "$target.$([guid]::NewGuid().ToString('N')).tmp"
            Copy-Item -LiteralPath $source -Destination $temporary -Force; Move-Item -LiteralPath $temporary -Destination $target -Force
        } else { throw "Operational script is missing or a reparse point: $source" }
    }
    Set-AdminOnlyAcl (Join-Path $InstallRoot 'program')
}

$config = [ordered]@{
    schema = 'redteam-evidence/windows/v1'
    install_root = $InstallRoot
    retention_days = $RetentionDays
    installed_utc = [DateTime]::UtcNow.ToString('o')
    spool_contract = 'POST JSON requires matching accepted/event_id/output_sha256/canonical_event_id/canonical_event_hash acknowledgement'
} | ConvertTo-Json
if ($PSCmdlet.ShouldProcess((Join-Path $InstallRoot 'config.json'), 'Write collector configuration')) {
    Set-Content -LiteralPath (Join-Path $InstallRoot 'config.json') -Value $config -Encoding UTF8
    Set-AdminOnlyAcl $InstallRoot
}

if ($PSCmdlet.ShouldProcess('PowerShell transcription policy', 'Enable')) {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name EnableTranscripting -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name EnableInvocationHeader -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name OutputDirectory -Value (Join-Path $InstallRoot 'transcripts') -PropertyType String -Force | Out-Null
}
if ($PSCmdlet.ShouldProcess('Windows process creation auditing', 'Enable success auditing and command-line inclusion')) {
    & auditpol.exe /set /subcategory:'Process Creation' /success:enable | Out-Null
    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item -Path $auditKey -Force | Out-Null
    New-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
}

Write-Host "Installed Windows evidence collector at $InstallRoot"
Write-Host 'Run Test-RedteamEvidence.ps1 for validation; run Invoke-RedteamEvidenceRetention.ps1 explicitly for retention; read README.md for coverage limits.'
