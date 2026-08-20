[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$Endpoint,
    [string]$InstallRoot = "$env:ProgramData\RedteamEvidence",
    [string]$ClientCertificatePath,
    [securestring]$ClientCertificatePassword,
    [string]$ClientCertificateThumbprint,
    [ValidateRange(1, 100)][int]$MaxEvents = 1,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$ChunkBytes = 48KB
if (-not $DryRun -and $Endpoint.Scheme -ne 'https') { throw 'HTTPS is required for evidence delivery (HTTP is permitted only with -DryRun).' }
if (-not $DryRun -and (($ClientCertificatePath -and $ClientCertificateThumbprint) -or (-not $ClientCertificatePath -and -not $ClientCertificateThumbprint))) { throw 'Supply exactly one client certificate: -ClientCertificatePath (PFX) or -ClientCertificateThumbprint (LocalMachine\My).' }

function Get-Sha256Hex([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $hash.Dispose() }
}
function Get-ClientCertificate {
    if ($ClientCertificateThumbprint) { $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$($ClientCertificateThumbprint.Replace(' ', ''))" -ErrorAction Stop }
    elseif ($ClientCertificatePath) {
        if ($ClientCertificatePassword) { $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientCertificatePassword); try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr); $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ClientCertificatePath, $password) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
        else { $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ClientCertificatePath) }
    }
    if ($certificate -and -not $certificate.HasPrivateKey) { throw 'Client certificate must include a private key for mTLS.' }; return $certificate
}
function Write-AtomicJson([string]$Path, $Value) {
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 10 -Compress), [Text.Encoding]::UTF8)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}
function Write-AcknowledgedSourceState($Event, $Acknowledgement, [string]$OriginalId) {
    $statePath = Join-Path $InstallRoot 'source-chain.json'; $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($Event.source_id -ne $state.source_id -or [int64]$Event.sequence -ne ([int64]$state.sequence + 1) -or $Event.previous_event_hash -ne $state.previous_event_hash -or $OriginalId -ne $state.inflight_id) { throw 'Chunk does not extend the authoritative local in-flight chain.' }
    if ($Acknowledgement.canonical_event_hash -notmatch '^[0-9a-f]{64}$') { throw 'Receiver acknowledgement lacks a canonical_event_hash.' }
    Write-AtomicJson $statePath ([ordered]@{ source_id = $state.source_id; sequence = [int64]$Event.sequence; previous_event_hash = $Acknowledgement.canonical_event_hash; inflight_id = $state.inflight_id; next_chunk = [int]$Event.chunk_index + 1; completed = [bool]$Event.final })
}
function Send-Chunk($Payload, $Certificate) {
    $request = [Net.HttpWebRequest][Net.WebRequest]::Create($Endpoint); $utf8 = New-Object Text.UTF8Encoding($false)
    $request.Method = 'POST'; $request.ContentType = 'application/json'; $request.ContentLength = $utf8.GetByteCount($Payload); [void]$request.ClientCertificates.Add($Certificate)
    $writer = New-Object IO.StreamWriter($request.GetRequestStream(), $utf8); try { $writer.Write($Payload) } finally { $writer.Dispose() }
    $response = $request.GetResponse(); try { $reader = New-Object IO.StreamReader($response.GetResponseStream()); try { return $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() } } finally { $response.Dispose() }
}

$certificate = if ($DryRun) { $null } else { Get-ClientCertificate }
$spool = Join-Path $InstallRoot 'spool'
foreach ($eventFile in @(Get-ChildItem -LiteralPath $spool -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First $MaxEvents)) {
    try {
        $original = Get-Content -LiteralPath $eventFile.FullName -Raw | ConvertFrom-Json
        $recordPath = Join-Path $InstallRoot "records\$($original.id).json"; if (-not (Test-Path -LiteralPath $recordPath)) { throw 'Protected local delivery record is missing.' }
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json; $output = [IO.File]::ReadAllBytes($original.output_path)
        $state = Get-Content -LiteralPath (Join-Path $InstallRoot 'source-chain.json') -Raw | ConvertFrom-Json
        $count = [Math]::Max(1, [int][Math]::Ceiling($output.Length / [double]$ChunkBytes)); $index = [int]$state.next_chunk
        if ($state.inflight_id -ne $original.id) { throw 'Spool event is not the authoritative in-flight record.' }
        if ([int]$record.delivery_next_chunk -ne $index) { $record.delivery_next_chunk = $index; Write-AtomicJson $recordPath $record }
        if ($index -lt 0 -or $index -gt $count) { throw 'Persisted delivery progress is invalid.' }
        # A crash after the final ACK but before moving the original event is safe:
        # no chunk is resent and the completed original is simply retired to sent.
        if ($index -eq $count) {
            $record.outbound_state = 'acknowledged'; $record.state = 'sealed-local'; Write-AtomicJson $recordPath $record
            Move-Item -LiteralPath $eventFile.FullName -Destination (Join-Path $InstallRoot "sent\$($eventFile.Name)") -Force
            continue
        }
        $offset = $index * $ChunkBytes; $length = [Math]::Min($ChunkBytes, $output.Length - $offset); $chunk = New-Object byte[] $length
        if ($length) { [Array]::Copy($output, $offset, $chunk, 0, $length) }
        $chunkEvent = $original | Select-Object *
        $chunkEvent.id = if ($count -eq 1) { $original.id } else { (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes("$($original.id):$index"))).Substring(0, 32) }
        $chunkEvent.output_sha256 = Get-Sha256Hex $chunk; $chunkEvent.output_bytes = $length
        $chunkEvent.source_id = $state.source_id; $chunkEvent.sequence = [int64]$state.sequence + 1; $chunkEvent.previous_event_hash = $state.previous_event_hash
        $chunkEvent | Add-Member -NotePropertyName stream_id -NotePropertyValue (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes("$($original.id):$($original.output_sha256):$($original.output_bytes)"))) -Force
        $chunkEvent | Add-Member -NotePropertyName chunk_index -NotePropertyValue $index -Force
        $chunkEvent | Add-Member -NotePropertyName chunk_count -NotePropertyValue $count -Force
        $chunkEvent | Add-Member -NotePropertyName stream_digest -NotePropertyValue $original.output_sha256.ToLowerInvariant() -Force
        $chunkEvent | Add-Member -NotePropertyName stream_byte_length -NotePropertyValue ([int64]$output.Length) -Force
        $chunkEvent | Add-Member -NotePropertyName final -NotePropertyValue ($index -eq $count - 1) -Force
        $payload = [ordered]@{ schema = $chunkEvent.schema; event = $chunkEvent; output_base64 = [Convert]::ToBase64String($chunk); output_sha256 = $chunkEvent.output_sha256 } | ConvertTo-Json -Depth 10 -Compress
        if ($DryRun) { Write-Host "Would mutually-authenticated POST chunk $index/$count for $($original.id) to $Endpoint"; continue }
        $ack = Send-Chunk $payload $certificate
        $validAck = (($ack.accepted -eq $true -or $ack.status -eq 'accepted') -and $ack.event_id -eq $chunkEvent.id -and $ack.output_sha256 -eq $chunkEvent.output_sha256 -and $ack.canonical_event_id -match '^[0-9a-f]{64}$' -and $ack.canonical_event_hash -match '^[0-9a-f]{64}$')
        if (-not $validAck) { throw 'Receiver response was not a matching accepted chunk acknowledgement.' }
        Write-AcknowledgedSourceState $chunkEvent $ack $original.id
        # Record progress is a convenience projection only; source-chain.json is authoritative.
        $record.delivery_next_chunk = $index + 1
        if ($chunkEvent.final) { $record.outbound_state = 'acknowledged'; $record.state = 'sealed-local' }
        Write-AtomicJson $recordPath $record
        if ($chunkEvent.final) { Move-Item -LiteralPath $eventFile.FullName -Destination (Join-Path $InstallRoot "sent\$($eventFile.Name)") -Force }
    } catch { Write-Warning "Keeping $($eventFile.Name) in spool for retry: $($_.Exception.Message)" }
}
