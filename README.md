# Simpaniz (simpaniz)

A small, single-binary, S3-compatible object server written in Zig.

**Status:** v0.2.0 — production-grade for single-node workloads behind a
reverse proxy. See [`COMPATIBILITY.md`](./COMPATIBILITY.md) for the S3
operation matrix and [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the design.

## Features

- **S3 API** — bucket CRUD, object PUT/GET/HEAD/DELETE, CopyObject,
  Bulk Delete (`POST ?delete`), `ListObjectsV2` with full pagination
  (`prefix`, `delimiter`, `max-keys`, `continuation-token`, `start-after`,
  `CommonPrefixes`), `Range` GET (`206 Partial Content`), conditional
  GET/HEAD (`If-Match` / `If-None-Match` / `If-Modified-Since` /
  `If-Unmodified-Since`), full **multipart upload** (Initiate /
  UploadPart / Complete / Abort / List, AWS-compatible composite
  ETag), virtual-host-style addressing, CORS preflight.
- **AWS Signature V4** — header form and presigned URL form, with
  region binding. Anonymous mode when no credentials are configured.
- **Streaming I/O** — PUT writes are streamed to disk (no full-body
  buffering), GET responses stream from disk via `std.Io.Reader`.
- **Atomic writes** — tmp + fsync + rename on the same filesystem;
  `Content-MD5` and `x-amz-content-sha256` digests are verified and
  return `400 BadDigest` on mismatch.
- **Operability** — Prometheus `/metrics`, structured JSON access
  log, per-request `x-amz-request-id`, `/healthz` (liveness), `/readyz`
  (data-dir writable), POSIX `SIGINT`/`SIGTERM` graceful shutdown.
- **Limits & guards** — request body / header / count caps, slowloris
  read timeout, keep-alive idle timeout.
- **Zero external dependencies** — pure Zig 0.15.x standard library.
- **Docker-ready** — multi-stage Alpine image, non-root user.

See [`SECURITY.md`](./SECURITY.md) for the threat model and deployment
guidance (TLS, IAM, encryption — all currently delegated to your
reverse proxy / disk encryption).

## Quick start

### Local

```bash
zig build -Doptimize=ReleaseSafe
./zig-out/bin/simpaniz
```

The server starts on `0.0.0.0:9000` by default.

### Docker

```bash
docker compose up -d
```

## Configuration

All configuration is via environment variables.

| Variable                   | Default        | Description                                                |
| -------------------------- | -------------- | ---------------------------------------------------------- |
| `SIMPANIZ_HOST`              | `0.0.0.0`      | Bind address.                                              |
| `SIMPANIZ_PORT`              | `9000`         | Listen port.                                               |
| `SIMPANIZ_DATA_DIR`          | `./data`       | Storage root directory.                                    |
| `SIMPANIZ_REGION`            | `us-east-1`    | AWS region used for SigV4 binding.                         |
| `SIMPANIZ_ACCESS_KEY`        | *(empty)*      | S3 access key. Auth required if non-empty.                 |
| `SIMPANIZ_SECRET_KEY`        | *(empty)*      | S3 secret key.                                             |
| `SIMPANIZ_MAX_BODY_BYTES`    | `5368709120`   | Per-request body cap (5 GiB). Larger requests get `413`.   |
| `SIMPANIZ_MAX_HEADER_BYTES`  | `16384`        | Total request-header bytes.                                |
| `SIMPANIZ_MAX_HEADERS`       | `64`           | Maximum number of header lines.                            |
| `SIMPANIZ_READ_TIMEOUT_MS`   | `30000`        | Per-connection read timeout (slowloris guard).             |
| `SIMPANIZ_IDLE_TIMEOUT_MS`   | `60000`        | Keep-alive idle timeout.                                   |
| `SIMPANIZ_MAX_CONNS`         | `256`          | Bounded worker pool. Connections beyond this wait for a slot. |
| `SIMPANIZ_MASTER_KEY`        | *(empty)*      | Base64 32-byte master key. Required to accept `x-amz-server-side-encryption: AES256`; used to wrap per-object DEKs. |
| `SIMPANIZ_SCRUB_INTERVAL_S`  | `0`            | Bitrot scrubber interval in seconds. `0` disables. Re-verifies object MD5 in the background. |
| `SIMPANIZ_LIFECYCLE_INTERVAL_S` | `0`         | Lifecycle sweeper interval in seconds. `0` disables. Expires objects per `?lifecycle` rules. |
| `SIMPANIZ_TLS_CERT`          | *(empty)*      | Path to TLS certificate (PEM). Setting either TLS var refuses startup until in-process TLS lands. |
| `SIMPANIZ_TLS_KEY`           | *(empty)*      | Path to TLS private key (PEM).                             |
| `SIMPANIZ_NODE_ID`           | *(empty)*      | This node's id when running in cluster mode (e.g. `node-1`). Empty disables cluster mode. |
| `SIMPANIZ_PEERS`             | *(empty)*      | Comma list of `id@host:port` peers; must include this node. Required in cluster mode. |
| `SIMPANIZ_EC_K`              | `4`            | Reed-Solomon data shards.                                  |
| `SIMPANIZ_EC_M`              | `2`            | Reed-Solomon parity shards. Tolerates losing any `m` of `k+m` shards. |
| `SIMPANIZ_CLUSTER_SECRET`    | *(empty)*      | Shared secret used by inter-node shard transfers (≥ 16 chars). Required in cluster mode. |
| `SIMPANIZ_HEAL_INTERVAL_S`   | `0`            | Self-heal daemon interval in seconds (cluster mode only). `0` disables. Walks local meta files and repairs missing shards. |
| `SIMPANIZ_CLUSTER_TIMEOUT_MS`| `5000`         | Send/recv timeout (ms) on inter-node TCP connections. |
| `SIMPANIZ_REPL_TARGETS`      | *(empty)*      | Comma list of `src-bucket=>http://host:port[/dst-bucket]` mappings. Enables async cross-cluster replication. |
| `SIMPANIZ_REPL_AUTH`         | *(empty)*      | Optional value sent verbatim as `Authorization` header on replication PUTs. |

## Endpoints

### S3 API

See [`COMPATIBILITY.md`](./COMPATIBILITY.md) for the full operation
matrix. Most clients (`curl`, `aws s3`, `boto3`, `aws-sdk-go`,
`mc`) work for object CRUD and multipart upload.

### Operability

| Path        | Method | Purpose                                            |
| ----------- | ------ | -------------------------------------------------- |
| `/healthz`  | GET    | Liveness — server process up.                      |
| `/readyz`   | GET    | Readiness — data directory writable.               |
| `/metrics`  | GET    | Prometheus exposition format.                      |

## Usage examples

```bash
# Bucket
curl -X PUT  http://localhost:9000/my-bucket
curl         http://localhost:9000/                       # ListBuckets
curl -I      http://localhost:9000/my-bucket              # HeadBucket
curl -X DELETE http://localhost:9000/my-bucket

# Object
curl -X PUT  --data-binary @file.bin -H "Content-Type: application/octet-stream" \
             http://localhost:9000/my-bucket/path/to/key
curl         http://localhost:9000/my-bucket/path/to/key
curl -H "Range: bytes=0-1023" http://localhost:9000/my-bucket/path/to/key
curl -I      http://localhost:9000/my-bucket/path/to/key
curl -X DELETE http://localhost:9000/my-bucket/path/to/key

# Listing
curl 'http://localhost:9000/my-bucket?list-type=2&prefix=path/&delimiter=/&max-keys=100'

# Bulk delete
curl -X POST -H "Content-Type: application/xml" \
  --data-binary '<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object></Delete>' \
  'http://localhost:9000/my-bucket?delete'

# Copy
curl -X PUT -H 'x-amz-copy-source: /my-bucket/source-key' \
  http://localhost:9000/my-bucket/dest-key
```

### With the AWS CLI

```bash
aws --endpoint-url http://localhost:9000 \
    --region us-east-1 \
    s3 mb s3://my-bucket
aws --endpoint-url http://localhost:9000 \
    s3 cp ./big.iso s3://my-bucket/big.iso
aws --endpoint-url http://localhost:9000 \
    s3 ls s3://my-bucket/
```

## Storage layout

```
DATA_DIR/
  <bucket>/
    .simpaniz-meta/<key>.json     content type, etag, size, mtime
    .simpaniz-mp/<uploadId>/      multipart staging
    .simpaniz-tmp/                in-flight uploads (auto-cleaned)
    <key>                       object data
    <prefix>/<key>              nested keys reflect on-disk hierarchy
```

## What's deferred (not in this release)

These are real engineering investments — they're documented as
future work, not "coming soon":

- **TLS in-process** — terminate at a reverse proxy.
- **Multi-user IAM, policies, ACLs.**
- **Server-side encryption** (SSE-S3, SSE-KMS, SSE-C). Use full-disk
  encryption.
- **Object Lock, Lifecycle, Versioning.**
- **Replication and event notifications.**
- **Distributed mode + erasure coding** (single-node only today).
- **Admin web console.**

These are what turn an "S3-compatible server" into a "distributed
object store like MinIO" — they're not blockers for single-node
production use behind a proxy.

## Requirements

- Zig 0.15.2
- Docker (optional)

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — module layout, request lifecycle,
  on-disk format, concurrency model.
- [`SECURITY.md`](./SECURITY.md) — threat model, deployment guidance,
  resource limits.
- [`COMPATIBILITY.md`](./COMPATIBILITY.md) — full S3 operation matrix.
