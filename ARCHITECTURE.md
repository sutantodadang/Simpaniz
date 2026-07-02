# Simpaniz — Architecture

Simpaniz is a single-binary, S3-compatible object server written in Zig 0.15.x.
It is intentionally small, file-system backed, and terminates its own TLS
in-process (TLS 1.3); a reverse proxy (nginx, Caddy, traefik) is optional,
useful for RSA certs, TLS 1.2 clients, or LB fan-out.

## Module layout

```
src/
  main.zig          Entry point: loads Config, opens data dir, installs signals,
                    boots the TCP server. Test aggregator.
  config.zig        Arena-owned env config (host/port/data dir/limits/timeouts/
                    auth credentials/region).
  server.zig        Thread-per-connection TCP server. Per-request id, structured
                    JSON access log, /metrics endpoint, SigV4 enforcement, POSIX
                    SIGINT/SIGTERM graceful shutdown, body draining for
                    keep-alive.
  http.zig          HTTP/1.1 request parser (header-only) + response writer.
                    Streams request bodies through std.Io.Reader. Response body
                    is a tagged union (none / bytes / file slice for zero-copy).
  router.zig        Routes path-style (/bucket/key) and virtual-host-style
                    (bucket.host) requests to handlers; recognises subresources
                    (?delete, ?uploads, ?uploadId, ?partNumber); CORS preflight.
  handlers.zig      All S3 operation logic: bucket CRUD, object PUT (streaming,
                    optional Content-MD5 and SHA256 verification), GET (range,
                    conditional headers), HEAD, DELETE, CopyObject, Bulk Delete,
                    Multipart Initiate / UploadPart / Complete / Abort / List,
                    Health, Ready.
  storage.zig       Filesystem backend: atomic writes (tmp + fsync + rename),
                    paginated listing with delimiter / CommonPrefixes / max-keys
                    / continuation-token / start-after, multipart concatenation
                    with AWS-compatible composite ETag (md5-of-md5s "-N").
  auth.zig          AWS Signature V4 verification (Authorization header and
                    presigned URL forms), canonical request construction,
                    string-to-sign, derived signing key.
  xml.zig           S3 XML response builders (ListBuckets, ListObjectsV2,
                    Initiate/CompleteMultipartUpload, ListParts, CopyResult,
                    DeleteResult, Error).
  metrics.zig       Prometheus registry: counters for requests / bytes /
                    auth_failures / errors, in-flight gauge, latency histogram.
                    Renders to /metrics in text exposition format.
  util.zig          URL/AWS encoding, key/bucket validation, ISO8601 time,
                    request id generation, hex encoding helpers.
  iam.zig           Multi-user credential store (`<data_dir>/.simpaniz-iam/
                    users.json`) + AWS-style policy evaluation engine
                    (Effect/Action/Resource/Principal/Condition, explicit-
                    deny-wins). Wired into the request path after SigV4
                    verify, before handler dispatch.
  tls_server.zig    In-process TLS 1.3 server (Zig std has client only).
                    Reuses `std.crypto.tls` wire types. AES-128/256-GCM +
                    ChaCha20-Poly1305, x25519 only, ECDSA P-256 certs,
                    ALPN http/1.1. No client certs/resumption/0-RTT.
  events.zig        S3 event notifications. Per-bucket config drives a
                    background worker that POSTs S3-event-shaped JSON to a
                    configured webhook (`SIMPANIZ_NOTIFY_WEBHOOK`) on object
                    create/delete — best-effort, no retries.
  index.zig         Per-bucket LSM-lite metadata index (WAL + sorted segment
                    with sparse footer) under `<bucket>/.simpaniz-index/`.
                    Serves `ListObjectsV2` with flat memory on huge buckets;
                    falls back to FS-walk-and-sort with lazy bootstrap.
                    Single-node only — cluster listing still FS-walk.
  tiering.zig       Lifecycle `<Transition>` cold-storage tiering. Moves
                    on-disk bytes to `SIMPANIZ_TIER_DIR` (local) or a
                    SigV4-signed remote S3-compatible target
                    (`SIMPANIZ_TIER_URL`/`_BUCKET`/`_ACCESS_KEY`/`_SECRET_KEY`),
                    leaves a zero-byte stub, and transparently re-fetches on
                    GET/HEAD (spooled to a temp file).
  sts.zig           STS: `AssumeRole` (SigV4-signed) and
                    `AssumeRoleWithWebIdentity` (unsigned, OIDC JWT — ES256
                    fully verified, RS256 via bigint modexp; JWKS fetched
                    from `SIMPANIZ_OIDC_JWKS_URL`). Issues in-memory temp
                    credentials (`x-amz-security-token`); session `Policy`
                    intersects base permissions.
  admin.zig         Root-only REST under `/_admin/`: info, users CRUD,
                    policies CRUD, cluster, sanitized config. Never returns
                    secrets.
  admin_cli.zig     `simpaniz admin <cmd>` — SigV4-signed client for
                    `admin.zig`'s API, shipped in the same binary (no
                    separate `mc`-style tool).
  s3_client.zig     Minimal SigV4-signing HTTP client shared by
                    `admin_cli.zig` and `tiering.zig`'s remote mode.
```

## Request lifecycle

1. **Accept** — main loop calls `std.net.Server.accept()`. A new
   `std.Thread` is spawned per connection (detached).
2. **Parse** — `http.parseRequest` reads request line and headers via the
   stream's `std.Io.Reader`. Header bytes and count are bounded by config
   (`SIMPANIZ_MAX_HEADER_BYTES`, `SIMPANIZ_MAX_HEADERS`).
3. **Per-request arena** — a `std.heap.ArenaAllocator` is attached to the
   `Request`. All handler-scoped allocations live in this arena and are
   freed in one deinit.
4. **Auth (optional)** — when credentials are configured (`SIMPANIZ_ACCESS_KEY`
   set), the server requires SigV4 on every request. Header-form is
   verified by reconstructing the canonical request from the raw URI,
   sorted re-encoded query, signed headers, and the supplied
   `x-amz-content-sha256` (or `UNSIGNED-PAYLOAD`). Immediately after SigV4
   verification, `iam.zig` maps the request to an S3 action and evaluates
   bucket + user policy; a `Deny` (or missing `Allow` for a non-root
   authenticated user) short-circuits with `403` before routing.
5. **Routing** — `router.route` chooses handler by method + subresource.
6. **Streaming I/O** — PUT object writes go through a `std.Io.Reader →
   tmp file` pipeline that updates MD5 + SHA256 incrementally; the final
   `rename` is atomic on the same filesystem. GET object responses use a
   `Body.file` slice that the response writer streams with
   `std.Io.Reader.streamExact64`, never buffering the full payload.
7. **Body drain** — for keep-alive correctness, the server discards any
   unread `content_length - body_consumed` bytes after the handler
   returns.
8. **Logging + metrics** — one JSON access log line per request, latency
   recorded in a Prometheus histogram, byte counters incremented.

## On-disk layout

```
DATA_DIR/
  <bucket>/
    .simpaniz-meta/<key>.json     content type, etag, size, mtime
    .simpaniz-mp/<uploadId>/      multipart staging
      meta.json
      parts/
        000001
        000002
    .simpaniz-tmp/                in-flight uploads (auto-cleaned on failure)
    .simpaniz-index/              metadata index: WAL + sorted segment (single-node listing)
    <key>                       object data
    <prefix>/<key>              nested keys reflect on-disk hierarchy
  .simpaniz-peers.json           dynamically joined cluster peers (persisted across restarts)
```

Reserved prefixes (`.simpaniz-meta`, `.simpaniz-mp`, `.simpaniz-tmp`,
`.simpaniz-index`) are filtered out of bucket listings and bucket-empty
checks.

## Concurrency model

- **Threading** — one OS thread per connection (`std.Thread.spawn`,
  detached). This is simple and adequate up to a few thousand
  concurrent connections; an evented model is on the deferred list.
- **Per-request state** — confined to one thread; nothing crosses
  threads except the metrics registry (atomics) and the data dir
  handle (read-mostly).
- **Shutdown** — POSIX `SIGINT`/`SIGTERM` set an atomic flag; main
  loop exits after the current `accept()` unblocks; in-flight
  connections drain naturally (the test rig waits for them).

## Where it still deviates from MinIO

- No ACLs or LDAP; IAM/policy enforcement, in-process TLS, and STS
  (`AssumeRole`/`AssumeRoleWithWebIdentity`) are done (see `iam.zig`,
  `tls_server.zig`, `sts.zig`). STS credentials are in-memory only.
- SSE-KMS uses a local keyring, not an external/pluggable KMS. Versioning,
  Lifecycle, and Object Lock default-retention are now complete
  (`versioning.zig`, `lifecycle.zig`, `object_lock_config.zig`); see
  `COMPATIBILITY.md` for the exact matrix.
- Tiering (`tiering.zig`) supports a local cold dir or one remote
  S3-compatible target; no native GCS/Azure backend, no rehydration policy.
- Distributed erasure-coded mode has SWIM-lite membership + rebalance now
  (`membership.zig`, `rebalance.zig`), and PUT/GET/heal are stripe-streamed
  (no more full-object EC buffers). Still no Raft, no decommission.
- Event notifications support webhook only (no Kafka/NATS/AMQP/MQTT).
- Single-node listings are served from a per-bucket LSM-lite index
  (`index.zig`); cluster-mode listings are still walked in memory.
- Connection model is thread-per-conn, not evented.

These are the items that turn an "S3-compatible server" into a
"distributed object store" — they are real engineering investments,
not a weekend.


## Distributed mode

The cluster subsystem under `src/cluster/` adds the building blocks for
multi-node erasure-coded storage:

- `reed_solomon.zig` — Pure-Zig Reed-Solomon over GF(256). The
  encoding matrix is systematic Vandermonde: rows `0..k` are the
  identity (so data shards are themselves the first k of `k+m`
  shards), rows `k..k+m` are powers of distinct generators
  `1..m`. Decoding inverts any `k×k` submatrix using Gauss-Jordan
  elimination, then multiplies surviving shards by the inverse to
  recover any missing data shards.
- `rendezvous.zig` — Highest-Random-Weight hashing. Picks the top-N
  node ids for a given `bucket/key`. Adding or removing a non-owner
  node leaves placement undisturbed.
- `transport.zig` — Pluggable shard transport (vtable). The
  `LocalTransport` impl writes shards under one subdirectory per
  "node" and is what drives unit tests. The HTTP transport reaches
  peers over internal `/_simpaniz/...` endpoints and short-circuits
  self-node traffic to local disk.
- `orchestrator.zig` — End-to-end distributed object I/O. Stripe-streamed:
  encodes and ships one stripe (default 1 MiB chunk/shard/stripe) at a time,
  so cluster PUT/GET/heal memory stays ~one stripe ((k+m)·chunk ≈ few MB)
  regardless of object size, instead of buffering the full object. Maps each
  shard to a node via rendezvous and pushes via the transport with
  seq-validated idempotent chunk append. GET supports ranged shard reads —
  `Range` GET on cluster objects streams only the overlapping stripes. `heal`
  detects missing shards and re-pushes reconstructed copies. Back-compatible
  with the old single-stripe shard layout.
- `config.zig` — Boots cluster identity, peer list, EC params,
  and shared secret from environment variables. When
  `SIMPANIZ_NODE_ID` or `SIMPANIZ_PEERS` is empty the server falls
  back to standalone single-node behaviour.
- `membership.zig` — SWIM-lite cluster membership: active health probing
  (`SIMPANIZ_PROBE_INTERVAL_MS` default 2000, `SIMPANIZ_PROBE_FAILS` default
  3) drives alive/suspect/down states from local probe results only; the
  node list itself gossips piggybacked on `/_simpaniz/ping`. Dynamic node
  join (`SIMPANIZ_JOIN=1` + `POST /_simpaniz/join`) persists newly joined
  peers to `<data_dir>/.simpaniz-peers.json` so a restart doesn't forget
  them. Down nodes are fast-skipped on reads. No decommission in v1.
- `rebalance.zig` — Shard rebalance daemon (`SIMPANIZ_REBALANCE_INTERVAL_S`
  default 300, plus membership-change-triggered sweeps). Walks locally
  stored keys, recomputes HRW placement under the current node list, and
  migrates any shard no longer owned locally to its new owner
  (copy+verify+delete). May leave orphaned local meta after a migration.

Remaining distributed-mode gaps:

- No Raft; membership state (alive/suspect/down) is locally observed per
  node, not distributed-consensus voted. No node decommission.
- Advanced feature parity in cluster mode, including version listings, the
  full SSE/versioning/lifecycle/object-lock matrix, and the metadata index
  layer (cluster listing still FS-walk).
- Stronger replication conflict/ordering semantics. (Event notifications now
  exist standalone via `events.zig`, not yet cluster-aware.)
- Migrated shards from a rebalance sweep may leave orphaned local meta.
