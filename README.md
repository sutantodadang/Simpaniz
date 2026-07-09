# Simpaniz (simpaniz)

A small, single-binary, S3-compatible object server written in Zig.

**Status:** v0.1.1 — production-grade for single-node, multi-tenant workloads.
TLS termination, IAM/policy enforcement, and SSE are all in-process; a reverse
proxy is optional (still useful for RSA certs, TLS 1.2 clients, or LB fan-out).
See [`COMPATIBILITY.md`](./COMPATIBILITY.md) for the S3 operation matrix and
[`ARCHITECTURE.md`](./ARCHITECTURE.md) for the design.

## Features

- **S3 API** — bucket CRUD, object PUT/GET/HEAD/DELETE, CopyObject,
  Bulk Delete (`POST ?delete`), `ListObjectsV2` with full pagination
  (`prefix`, `delimiter`, `max-keys`, `continuation-token`, `start-after`,
  `CommonPrefixes`), `Range` GET including suffix ranges (`206 Partial Content`), conditional
  GET/HEAD (`If-Match` / `If-None-Match` / `If-Modified-Since` /
  `If-Unmodified-Since`), full **multipart upload** (Initiate /
  UploadPart / Complete / Abort / List, AWS-compatible composite
  ETag), virtual-host-style addressing, CORS preflight.
- **AWS Signature V4** — header form and presigned URL form, with
  region binding. Anonymous mode when no credentials are configured.
- **STS** — `AssumeRole` (SigV4-signed) and `AssumeRoleWithWebIdentity`
  (unsigned, OIDC JWT, ES256/RS256) issue temporary credentials; see
  `SIMPANIZ_OIDC_*` below.
- **IAM / policy enforcement** — multi-user credential store at
  `<DATA_DIR>/.simpaniz-iam/users.json`; AWS-style bucket and inline user
  policy evaluation (explicit Deny wins, then Allow, default-deny for
  authenticated non-root users) enforced on every request.
- **In-process TLS 1.3** — no reverse proxy required; see
  `SIMPANIZ_TLS_CERT`/`SIMPANIZ_TLS_KEY` below, or use zero-config ACME
  (`SIMPANIZ_TLS_ACME`) for a Let's Encrypt certificate with no manual setup.
- **Event notifications** — webhook delivery of S3-event-shaped JSON on
  object create/delete; see `SIMPANIZ_NOTIFY_WEBHOOK` below.
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
guidance. TLS, IAM/policy enforcement, and SSE are handled in-process;
full-disk encryption is still recommended for defense-in-depth.

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
| `SIMPANIZ_ACCESS_KEY`        | *(empty)*      | S3 access key. Auth required if non-empty. If left empty, a root credential is generated on first launch and persisted to `<DATA_DIR>/.simpaniz-credentials` (printed to the log) so the web console works out of the box. Set `SIMPANIZ_ANONYMOUS=1` to opt out and run without auth.                 |
| `SIMPANIZ_SECRET_KEY`        | *(empty)*      | S3 secret key.                                             |
| `SIMPANIZ_ANONYMOUS`         | *(empty)*      | When `1` / `true` / `yes`, skip first-run credential bootstrap and run without authentication. |
| `SIMPANIZ_MAX_BODY_BYTES`    | `5368709120`   | Per-request body cap (5 GiB). Larger requests get `413`.   |
| `SIMPANIZ_MAX_HEADER_BYTES`  | `16384`        | Total request-header bytes.                                |
| `SIMPANIZ_MAX_HEADERS`       | `64`           | Maximum number of header lines.                            |
| `SIMPANIZ_READ_TIMEOUT_MS`   | `30000`        | Per-connection read timeout (slowloris guard).             |
| `SIMPANIZ_IDLE_TIMEOUT_MS`   | `60000`        | Keep-alive idle timeout.                                   |
| `SIMPANIZ_MAX_CONNS`         | `256`          | Bounded worker pool. Connections beyond this wait for a slot. |
| `SIMPANIZ_MASTER_KEY`        | *(empty)*      | Base64 32-byte master key. Required to accept `x-amz-server-side-encryption: AES256`; used to wrap per-object DEKs. |
| `SIMPANIZ_SCRUB_INTERVAL_S`  | `0`            | Bitrot scrubber interval in seconds. `0` disables. Re-verifies object MD5 in the background. |
| `SIMPANIZ_LIFECYCLE_INTERVAL_S` | `0`         | Lifecycle sweeper interval in seconds. `0` disables. Expires objects per `?lifecycle` rules. |
| `SIMPANIZ_TLS_CERT`          | *(empty)*      | Path to TLS certificate (PEM). Setting this enables in-process TLS 1.3 — `curl https://...` works with no reverse proxy. Requires `SIMPANIZ_TLS_KEY` too (setting only one refuses startup). Cert must be ECDSA P-256. |
| `SIMPANIZ_TLS_KEY`           | *(empty)*      | Path to TLS private key (PEM, PKCS#8 or SEC1 P-256).       |
| `SIMPANIZ_TLS_ACME`          | *(empty)*      | Domain name for zero-config ACME (Let's Encrypt) TLS — obtains and auto-renews an ECDSA P-256 certificate with no manual setup. Mutually exclusive with `SIMPANIZ_TLS_CERT`/`SIMPANIZ_TLS_KEY`. See "Zero-config TLS (ACME)" below. |
| `SIMPANIZ_ACME_DIRECTORY`    | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL. Point at Let's Encrypt's staging directory for testing (avoids production rate limits). |
| `SIMPANIZ_ACME_CONTACT`      | *(empty)*      | Optional ACME account contact, e.g. `mailto:ops@example.com`. |
| `SIMPANIZ_ACME_HTTP_PORT`    | `80`           | Port the HTTP-01 challenge listener binds on while proving domain control. |
| `SIMPANIZ_NOTIFY_WEBHOOK`    | *(empty)*      | Webhook URL for event notifications. When set, per-bucket `?notification` config (`PutBucketNotificationConfiguration`) triggers async best-effort HTTP POST of S3-event-shaped JSON on object create/delete. |
| `SIMPANIZ_NODE_ID`           | *(empty)*      | This node's id when running in cluster mode (e.g. `node-1`). Empty disables cluster mode. |
| `SIMPANIZ_PEERS`             | *(empty)*      | Comma list of `id@host:port` peers; must include this node. Required in cluster mode. |
| `SIMPANIZ_EC_K`              | `4`            | Reed-Solomon data shards.                                  |
| `SIMPANIZ_EC_M`              | `2`            | Reed-Solomon parity shards. Tolerates losing any `m` of `k+m` shards. |
| `SIMPANIZ_CLUSTER_SECRET`    | *(empty)*      | Shared secret used by inter-node shard transfers (≥ 16 chars). Required in cluster mode. |
| `SIMPANIZ_HEAL_INTERVAL_S`   | `0`            | Self-heal daemon interval in seconds (cluster mode only). `0` disables. Walks local meta files and repairs missing shards. |
| `SIMPANIZ_CLUSTER_TIMEOUT_MS`| `5000`         | Send/recv timeout (ms) on inter-node TCP connections. |
| `SIMPANIZ_REPL_TARGETS`      | *(empty)*      | Comma list of `src-bucket=>http://host:port[/dst-bucket]` mappings. Enables async cross-cluster replication. |
| `SIMPANIZ_REPL_AUTH`         | *(empty)*      | Optional value sent verbatim as `Authorization` header on replication PUTs. |
| `SIMPANIZ_PROBE_INTERVAL_MS` | `2000`         | Cluster mode: membership health-probe interval (ms). |
| `SIMPANIZ_PROBE_FAILS`       | `3`            | Cluster mode: consecutive probe failures before a node is marked `down`. |
| `SIMPANIZ_REBALANCE_INTERVAL_S` | `300`       | Cluster mode: shard-rebalance sweep interval (s). `0` disables the daemon. |
| `SIMPANIZ_JOIN`              | *(empty)*      | Cluster mode: `1`/`true` — announce this node to configured peers on boot via `POST /_simpaniz/join`. |
| `SIMPANIZ_TIER_DIR`          | *(empty)*      | Local cold-storage tiering target: a second on-disk root. Lifecycle `<Transition>` copies aged objects here and leaves a stub locally. |
| `SIMPANIZ_TIER_URL`          | *(empty)*      | Remote cold-storage tiering target: base URL of an S3-compatible endpoint. Requires `SIMPANIZ_TIER_BUCKET`/`SIMPANIZ_TIER_ACCESS_KEY`/`SIMPANIZ_TIER_SECRET_KEY`. Mutually exclusive with `SIMPANIZ_TIER_DIR`. |
| `SIMPANIZ_TIER_BUCKET`       | *(empty)*      | Bucket name on the remote tiering target. |
| `SIMPANIZ_TIER_ACCESS_KEY`   | *(empty)*      | Access key for SigV4-signing requests to the remote tiering target. |
| `SIMPANIZ_TIER_SECRET_KEY`   | *(empty)*      | Secret key for SigV4-signing requests to the remote tiering target. |
| `SIMPANIZ_TIER_REGION`       | `us-east-1`    | Region used to sign requests to the remote tiering target. |
| `SIMPANIZ_TIER_REHYDRATE`    | *(empty)*      | When `1`/`true`/`yes`, a GET on a tiered object writes it back to hot storage and deletes the cold copy (rehydration). |
| `SIMPANIZ_OIDC_JWKS_URL`     | *(empty)*      | Presence enables `AssumeRoleWithWebIdentity`. JWKS endpoint used to verify OIDC JWTs (ES256/RS256). |
| `SIMPANIZ_OIDC_ISSUER`       | *(empty)*      | Required OIDC `iss` claim when `SIMPANIZ_OIDC_JWKS_URL` is set. |
| `SIMPANIZ_OIDC_AUDIENCE`     | *(empty)*      | Optional OIDC `aud` claim to enforce. |
| `SIMPANIZ_OIDC_DEFAULT_POLICY` | *(empty)*    | Optional named policy file (under `.simpaniz-iam/policies/`) applied when the JWT carries no policy claim. |
| `SIMPANIZ_ADMIN_ENDPOINT`    | `http://127.0.0.1:9000` | Endpoint the `simpaniz admin` CLI targets. |
| `SIMPANIZ_METRICS_SAMPLE_S`  | `10`           | Background sampler period (seconds) for the in-process 24h metric history that powers the console's Metrics tab. `0` disables the sampler; `/_dashboard/api/*` still answers, `/summary` from live counters, `/series` with no points. |

### Zero-config TLS (ACME)

Set `SIMPANIZ_TLS_ACME=example.com` and Simpaniz obtains and auto-renews an
ECDSA P-256 certificate from Let's Encrypt with no manual `certbot`/reverse-proxy
setup — a differentiator MinIO doesn't have (MinIO expects TLS termination or
manual cert placement). Requirements: port 80 reachable from the internet for
the HTTP-01 challenge (or set `SIMPANIZ_ACME_HTTP_PORT` and forward it), and
DNS for the domain already pointing at this host.

On boot, Simpaniz runs the ACME v2 (RFC 8555) flow once synchronously — account
key + domain key + certificate are persisted under
`<DATA_DIR>/.simpaniz-acme/` — then starts the TLS listener from the issued
cert. A background daemon checks daily and re-issues whenever the certificate
is within 30 days of expiring, hot-swapping the new cert/key pair into the
running listener with no restart and no dropped connections; if a renewal
attempt fails, the server keeps serving the current certificate and retries
the next day.

`SIMPANIZ_TLS_ACME` is mutually exclusive with `SIMPANIZ_TLS_CERT`/`SIMPANIZ_TLS_KEY`
(manual cert/key). Point `SIMPANIZ_ACME_DIRECTORY` at Let's Encrypt's staging
directory while testing to avoid production rate limits.

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
| `/console/` | GET    | Embedded web console (single-page admin UI).       |
| `/_dashboard/api/summary` | GET | SigV4-authenticated JSON: uptime, totals, latency percentiles, mode, TLS, IAM users, tiering, cluster states. Powers the console's Metrics tab. |
| `/_dashboard/api/series`  | GET | SigV4-authenticated JSON time series (`?window=60..86400` seconds) from the in-process 24h metric history. |

### Web console

A minimal admin UI is baked into the binary at `/console/`. Open
`http://localhost:9000/console/` in a browser to:

- Sign in with your access/secret (or check **anonymous** if the server
  has no credentials configured).
- Create and delete buckets.
- Browse objects with prefix/folder navigation.
- Upload, download, and delete objects.

On **first launch** with no `SIMPANIZ_ACCESS_KEY` / `SIMPANIZ_SECRET_KEY`
in the environment, a random root credential is generated, persisted to
`<DATA_DIR>/.simpaniz-credentials`, and printed to the log so you can
sign in immediately. To run without auth (read-only public buckets,
dev sandboxes), set `SIMPANIZ_ANONYMOUS=1` instead.

The console is a vanilla HTML/JS bundle (no build step, zero deps) that
talks to the existing S3 API. SigV4 is computed in the browser via Web
Crypto, so every action is authenticated the same way as a `curl` or
`aws s3` call. Credentials are kept in `sessionStorage` and never sent
anywhere except as part of the S3 signature.

#### Metrics dashboard

The console's **Metrics** tab is a built-in, single-binary alternative to a
Prometheus + Grafana stack — no external scraper or dashboard service
required. It draws dependency-free canvas line charts (requests/errors per
second, latency p50/p95/p99, throughput, in-flight requests), summary cards,
and cluster node-state dots, over 15m/1h/6h/24h windows with a 10s
auto-refresh. Data comes from an in-process 24h ring buffer (sampled every
`SIMPANIZ_METRICS_SAMPLE_S` seconds, default 10; in-memory only, cleared on
restart) served by the SigV4-authenticated `/_dashboard/api/*` endpoints
above. The plain-text `/metrics` Prometheus endpoint is unaffected and still
available for external scraping.

## Admin CLI

`simpaniz admin` is the client half of the root-only `/_admin/` REST API,
shipped in the **same binary** as the server — no separate `mc`-style tool.
Requests are SigV4-signed against `SIMPANIZ_ADMIN_ENDPOINT` (default
`http://127.0.0.1:9000`) using `SIMPANIZ_ACCESS_KEY`/`SIMPANIZ_SECRET_KEY`.

```bash
export SIMPANIZ_ACCESS_KEY=... SIMPANIZ_SECRET_KEY=...

simpaniz admin info
simpaniz admin user add alice s3cr3t --policy ./read-only.json
simpaniz admin policy set read-only ./read-only.json
simpaniz admin cluster
simpaniz admin cluster decommission node-3
```

`cluster decommission <node-id>` (`POST /_admin/cluster/decommission?node=<id>`,
root-only) marks a node `draining`: it stays a read source while the
rebalance daemon migrates its shards to the remaining nodes, then it
auto-promotes to `removed` and drops out of the persisted peer overlay once
empty. Can be issued against any node in the cluster — the decision
gossips to the rest, including the target. `simpaniz admin cluster` (and
`GET /_admin/cluster`) reports each node's state, including `draining`/
`removed`.

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
    .simpaniz-tmp/                in-flight/orphaned upload temp files
    .simpaniz-tags/<key>.xml      object tag set XML
    .simpaniz-versions/           version snapshots and delete markers
    .simpaniz-lock/               object retention metadata
    .simpaniz-hold/               legal hold metadata
    .simpaniz-repl/queue.log      cross-cluster replication journal
    .simpaniz-index/              metadata index: WAL + sorted segment (single-node listing)
    <key>                       object data
    <prefix>/<key>              nested keys reflect on-disk hierarchy
  .simpaniz-peers.json           dynamically joined cluster peers (persisted across restarts)
```

## Known gaps toward MinIO-level

These are real engineering investments — they're documented as
current limits, not "coming soon":

- **ACLs, LDAP.** IAM/policy enforcement, in-process TLS 1.3, and STS
  (`AssumeRole` / `AssumeRoleWithWebIdentity` via OIDC) are done; per-object
  ACLs and LDAP are not. STS credentials are in-memory only — a restart
  invalidates them.
- **External KMS.** SSE-KMS uses a local keyring (master-key wrap), not a
  pluggable external KMS; no key rotation primitives.
- **Tiering backends.** Lifecycle `<Transition>` moves cold objects to a
  local dir (`SIMPANIZ_TIER_DIR`) or a remote S3-compatible endpoint
  (`SIMPANIZ_TIER_URL`); no native GCS/Azure backend. Rehydration on GET is
  opt-in via `SIMPANIZ_TIER_REHYDRATE` (default off — GET re-fetches from
  cold on every request).
- **Cluster maturity.** SWIM-lite membership (active health probing, gossip,
  dynamic join) and an HRW rebalance daemon now exist, but there's no Raft, no
  decommission, and limited cluster-mode support for advanced bucket
  features. EC is stripe-streamed (no more full-object buffers).
- **Replication maturity.** Cross-cluster replication is best-effort async.
  Event notifications support webhook only (no Kafka/NATS/AMQP/MQTT targets).
- **Large-bucket indexing.** Single-node listing is served from a per-bucket
  LSM-lite index (`.simpaniz-index/`, FS-walk fallback); cluster-mode listing
  still walks and sorts the filesystem in memory.

These are what turn an "S3-compatible server" into a "distributed
object store like MinIO" — they're not one-line polish items.

## Requirements

- Zig 0.15.2
- Docker (optional)

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — module layout, request lifecycle,
  on-disk format, concurrency model.
- [`SECURITY.md`](./SECURITY.md) — threat model, deployment guidance,
  resource limits.
- [`COMPATIBILITY.md`](./COMPATIBILITY.md) — full S3 operation matrix.
