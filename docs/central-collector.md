# Central evidence collector

`central_collector.py` is a deliberately narrow, standard-library-only mTLS HTTPS
lane for forwarding **authorized evidence envelopes** to a named collector. It is
not a remote-control channel or general upload API. It accepts only one explicitly
bounded output artifact attached to an authorized evidence event; it never collects
terminal input, credentials, arbitrary files, or unconstrained payloads.

## Endpoint capability contract

An installer or local evidence adapter may create an `EvidenceSpool` only with an
explicit `MTLSConfig`:

- `endpoint` must be a configured `https://host[:port]/v1/evidence` URL; there is
  no default destination and no redirect support.
- `endpoint_id`, the CA certificate, client certificate, and client key are all
  supplied by the operator. The code neither generates keys nor embeds private
  keys or certificates.
- A producer can enqueue only the v1 envelope: bounded metadata plus exactly one
  output artifact (at most 49,152 bytes), SHA-256 digest, byte length, and retention
  reference. The output bytes must exactly match the canonical event's digest/length.
  `EvidenceSpool.enqueue_stream` automatically splits larger complete output into
  independently hash-bound chunks, each chained by the canonical predecessor hash.
  Permitted kinds are `command-observation`, `session-boundary`, and
  `integrity-alert`; an arbitrary `payload` field is rejected.
- `source_id` and the producer-controlled positive `sequence` identify a single
  source stream. The caller provides the prior accepted event hash, and the protocol
  derives a stable event ID and hash-chain value from canonical JSON.

The collector requires a client certificate validated against its configured client
CA. On the first accepted event for a `source_id`, it persistently binds that source
to the SHA-256 fingerprint of the authenticated peer certificate. Later events,
including idempotent replays, must present that exact certificate; another valid
certificate from the same client CA cannot submit or replay that source's evidence.
The fingerprinted source genesis record is committed before its artifact or event
record, so a crash cannot leave the source available for another CA-valid client to
claim. Existing source state without a fingerprint is intentionally migration-blocked
rather than silently rebound.
It accepts only `POST /v1/evidence`, validates canonical IDs/hashes and the base64
artifact digest/length, enforces monotonic sequence/hash links per source, and
atomically stores the artifact beside its event. Every successful acknowledgement
contains `accepted: true`, `status: "accepted"`, `event_id`, `output_sha256`,
`canonical_event_id`, and `canonical_event_hash`.
An identical replay returns the same accepted acknowledgement, making retries
idempotent.

For a multi-chunk stream, each chunk carries immutable `stream_id`, `chunk_index`,
`chunk_count`, full-stream digest/length, and a `final` flag. The final chunk is only
accepted after all predecessor chunks because of the source hash chain; the collector
then re-reads every stored chunk, requires exactly indexes `0..chunk_count-1` with
consistent source/endpoint and stream metadata, and recomputes the full byte length
and SHA-256 before writing an atomic final manifest. A mismatch rejects the final
chunk without advancing source state. This keeps large output shippable without
increasing the attachment or request bounds.

## Durability and operation

`EvidenceSpool` writes event records atomically into `pending`, moves one record
atomically to `claimed` before a network attempt, and on a missing/bad ACK or network
failure records the failure, applies capped exponential backoff, and atomically returns
the item to `pending`. An acknowledged record moves to `acknowledged`; it is not
deleted by this module.

Start the real server only with pre-provisioned mTLS material and a storage directory
that already exists, is owned by UID 0, and has mode 0700 (or stricter):

```sh
python central_collector.py serve --storage-dir /var/lib/redteam-collector \
  --server-cert /etc/redteam/server.crt --server-key /etc/redteam/server.key \
  --client-ca /etc/redteam/client-ca.crt --endpoint-id collector-prod
```

The server refuses other storage configuration. Deployments should also restrict the
process account and filesystem ACLs according to their operating-system policy.

## Installer-facing surface

Platform installers need only use the OS-neutral `EvidenceSpool` library, or invoke
the corresponding narrow CLI. `enqueue` accepts a single bounded attachment;
`enqueue_stream` (used by the CLI) accepts the allowed envelope fields and
prints the derived `event_id` and `event_hash`; persist that hash as the next event's
`--previous-event-hash`. `forward-once` sends one due spool record and exits nonzero
when none could be acknowledged, allowing the platform scheduler to retry later.

```sh
python central_collector.py enqueue --spool-dir /var/lib/redteam-spool \
  --endpoint https://collector.example/v1/evidence --endpoint-id collector-prod \
  --ca-cert /etc/redteam/ca.crt --client-cert /etc/redteam/client.crt \
  --client-key /etc/redteam/client.key --source-id host-17 --sequence 1 \
  --kind command-observation --digest "$SHA256" --byte-length "$BYTES" \
  --retention-reference local://redteam/sessions/17 --classification internal \
  --output-file /var/log/redteam/approved-output.txt
python central_collector.py forward-once --spool-dir /var/lib/redteam-spool \
  --endpoint https://collector.example/v1/evidence --endpoint-id collector-prod \
  --ca-cert /etc/redteam/ca.crt --client-cert /etc/redteam/client.crt \
  --client-key /etc/redteam/client.key
```

For local read-only verification, `verify_source_chain(events)` validates canonical
event IDs, source sequence, endpoint/source consistency, and each predecessor hash;
it neither performs I/O nor sends data.

## Windows spool compatibility

The collector directly accepts the Windows publisher's fixed request shape:
`{"schema":"redteam-evidence/windows/v1","event":{...},"output_base64":"...","output_sha256":"..."}`.
It requires the Windows event's `id`, `kind: "controlled-launch"`, `host`,
`output_sha256`, and `output_bytes` to match the bounded attachment. A sealed Windows
importer should also supply all three persistent chain fields: `source_id`, positive
`sequence`, and `previous_event_hash` (`null` only for sequence 1). The configured
server `--endpoint-id` derives the canonical event from those fields and rejects a
partial chain tuple. Legacy records with none of the three are accepted only as a
safe isolated sequence-1 stream keyed by event ID. The original Windows ID is returned
in the ACK so the existing publisher can mark its spool record sent; its authoritative
next `previous_event_hash` is `canonical_event_hash` from that ACK (Windows must not
attempt to recreate Python canonical JSON). Other Windows
event fields are limited to: `schema`, `id`, `kind`, `state`, timestamps, `user`,
`host`, `file_path`, `arguments`, `exit_code`, `output_path`, output digest/length,
and the three chain fields.

For output above the attachment bound, the sealed Windows importer may additionally
include all six stream fields in every raw event: `stream_id` (64 lowercase hex),
`chunk_index`, `chunk_count`, `stream_digest` (64 lowercase hex),
`stream_byte_length`, and `final`. Every chunk has its own Windows `id`, output digest
and byte length, but shares a source and advances the acknowledged canonical hash.
The adapter rejects a partial stream tuple and maps a complete tuple into the canonical
stream metadata, so normal source-order validation and final-manifest persistence apply.

## Test harness

The focused tests generate a short-lived local CA and server/client certificates in a
pytest temporary directory **only** when `openssl` is available. They never write
keys into the repository. The harness verifies mTLS client authentication, durable
source-to-certificate binding (with two CA-valid client certificates), digest-verified
artifact ingestion, Windows-shape adaptation, idempotent acknowledgement, protocol
rejection, and atomic retry retention.
