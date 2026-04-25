# Simpaniz — Architecture

Simpaniz is a single-binary, S3-compatible object server written in Zig 0.15.x.
It is intentionally small (~3K lines), file-system backed, and designed to be
run behind a reverse proxy (nginx, Caddy, traefik) for TLS termination.

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
   `x-amz-content-sha256` (or `UNSIGNED-PAYLOAD`).
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
    <key>                       object data
    <prefix>/<key>              nested keys reflect on-disk hierarchy
```

Reserved prefixes (`.simpaniz-meta`, `.simpaniz-mp`, `.simpaniz-tmp`) are
filtered out of bucket listings and bucket-empty checks.

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

- No in-process TLS — terminate with a reverse proxy.
- No multi-user IAM, policy enforcement, ACLs, or STS.
- SSE-S3, Object Lock, Lifecycle, Versioning, and replication exist only for
  selected flows; see `COMPATIBILITY.md` for the exact matrix.
- Distributed erasure-coded mode exists, but uses static membership, has no
  rebalance/gossip/Raft, and still buffers full EC objects during cluster
  PUT/GET paths.
- No event notifications.
- Listings are walked in memory (no on-disk index).
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
- `orchestrator.zig` — End-to-end distributed object I/O. PUT
  encodes `data → k+m shards` (last data shard zero-padded to
  `shard_size = ceil(orig_size / k)`), maps each shard to a node
  via rendezvous, and pushes via the transport. GET fetches any
  `k` shards, RS-decodes, trims to `original_size`. `heal` detects
  missing shards and re-pushes reconstructed copies.
- `config.zig` — Boots cluster identity, peer list, EC params,
  and shared secret from environment variables. When
  `SIMPANIZ_NODE_ID` or `SIMPANIZ_PEERS` is empty the server falls
  back to standalone single-node behaviour.

Remaining distributed-mode gaps:

- Streaming EC encode/decode and response streaming instead of full-object
  buffers in the cluster PUT/GET path.
- Active health probing, topology changes, rebalance, and stronger membership.
- Advanced feature parity in cluster mode, including version listings and the
  full SSE/versioning/lifecycle/object-lock matrix.
- Event notifications and stronger replication conflict/ordering semantics.
