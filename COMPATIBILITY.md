# Simpaniz — S3 API compatibility matrix

Status legend:

- ✅ — implemented
- ⚠️ — partial (see notes)
- ❌ — not implemented (deferred / out of scope)

## Service / bucket operations

| Operation                    | Status | Notes                                           |
| ---------------------------- | :----: | ----------------------------------------------- |
| `ListBuckets` (`GET /`)      |   ✅   |                                                 |
| `CreateBucket` (`PUT /b`)    |   ✅   | Names: 3–63 chars, lowercase, digits, hyphens.  |
| `DeleteBucket` (`DELETE /b`) |   ✅   | Returns `BucketNotEmpty` if any keys remain.    |
| `HeadBucket` (`HEAD /b`)     |   ✅   |                                                 |
| `GetBucketLocation`          |   ✅   | Returns the configured `SIMPANIZ_REGION`.         |
| `GetBucketCors` / `PutBucketCors` | ⚠️ | Stored as raw XML; `Origin`/preflight handled. |
| `GetBucketPolicy` / `PutBucketPolicy` / `DeleteBucketPolicy` | ⚠️ | Stored as raw JSON; not enforced on requests. |
| `GetBucketVersioning` / `PutBucketVersioning` | ⚠️ | `Enabled` / `Suspended` honoured. PUT snapshots the prior version under `.simpaniz-versions/`. `?versionId=` GET/HEAD/DELETE supported. `ListObjectVersions` (`GET ?versions`) returns versions and delete markers. Delete markers are written when versioning is enabled and `DELETE` arrives without `?versionId=`. `Suspended` semantics on overwrite still TODO. |
| `GetBucketLifecycle` / `PutBucketLifecycle` / `DeleteBucketLifecycle` | ⚠️ | XML stored verbatim. Background sweeper expires objects matching `<Prefix>` older than `<Days>` when `SIMPANIZ_LIFECYCLE_INTERVAL_S` > 0. Transitions, `<NoncurrentVersionExpiration>`, and tag filters are not implemented. |

## Object operations

| Operation                                  | Status | Notes                                                    |
| ------------------------------------------ | :----: | -------------------------------------------------------- |
| `PutObject`                                |   ✅   | Streamed; `Content-MD5` & `x-amz-content-sha256` checked. |
| `GetObject`                                |   ✅   | Zero-copy file streaming.                                 |
| `GetObject` with `Range`                   |   ✅   | `bytes=start-end` and `bytes=start-`. `206 Partial Content`. |
| `HeadObject`                               |   ✅   |                                                          |
| `DeleteObject`                             |   ✅   | Removes data, metadata, and now-empty parent dirs.        |
| `DeleteObjects` (`POST ?delete`)           |   ✅   |                                                          |
| `CopyObject`                               |   ✅   | `x-amz-copy-source` (path-style only).                    |
| Conditional `If-Match` / `If-None-Match`   |   ✅   | On `GET` and `HEAD`.                                      |
| Conditional `If-Modified-Since` / `Unmodified-Since` | ✅ |                                                  |
| `ListObjectsV2`                            |   ✅   | `prefix`, `delimiter`, `max-keys`, `continuation-token`, `start-after`, `CommonPrefixes`. |
| `ListObjects` (v1)                         |   ⚠️  | Routes to the same handler; `marker` ≈ `start-after`.     |
| Object tags (`PutObjectTagging` / `GetObjectTagging` / `DeleteObjectTagging`) | ✅ | Stored as XML next to object metadata. |
| Object Lock / Legal Hold                   |   ⚠️  | Per-object retention (`PutObjectRetention`/`GetObjectRetention`) and legal hold (`PutObjectLegalHold`/`GetObjectLegalHold`) implemented. `DELETE`/overwrite returns `403 AccessDenied` while protected. `GOVERNANCE` may be bypassed with `x-amz-bypass-governance-retention: true`. Bucket-level default retention not yet stored. |
| Bitrot scrubber                            |   ✅   | Background MD5 re-verification when `SIMPANIZ_SCRUB_INTERVAL_S` > 0. Surfaces failures via `simpaniz_bitrot_errors_total` and warn-level logs. |
| Object ACLs                                |   ❌   | All-or-nothing access via SigV4.                          |
| SSE-S3 (`x-amz-server-side-encryption: AES256`) | ⚠️ | AES-256-GCM, chunked (64 KiB), per-object DEK wrapped under `SIMPANIZ_MASTER_KEY`. Not yet supported on multipart, copy-source, default-bucket-encryption, or `Range` GET. |
| SSE-KMS / SSE-C                            |   ❌   | Not implemented.                                          |

## Multipart upload

| Operation                                  | Status | Notes                                                    |
| ------------------------------------------ | :----: | -------------------------------------------------------- |
| `CreateMultipartUpload` (`POST ?uploads`)  |   ✅   |                                                          |
| `UploadPart` (`PUT ?partNumber=&uploadId=`)|   ✅   | Streamed; per-part MD5 ETag.                              |
| `CompleteMultipartUpload`                  |   ✅   | Composite ETag = `md5(concat(part_md5_bytes))-N`.         |
| `AbortMultipartUpload`                     |   ✅   |                                                          |
| `ListParts`                                |   ✅   |                                                          |
| `ListMultipartUploads`                     |   ✅   | Bucket-level listing via `GET /b?uploads`.                |
| `UploadPartCopy`                           |   ✅   | Triggered by `x-amz-copy-source` on `UploadPart`. Range supported. |

## Authentication

| Mechanism                                  | Status | Notes                                                    |
| ------------------------------------------ | :----: | -------------------------------------------------------- |
| AWS Signature V4 — header form             |   ✅   |                                                          |
| AWS Signature V4 — presigned URL           |   ✅   |                                                          |
| AWS Signature V2                           |   ❌   | Deprecated by AWS; not implemented.                       |
| `STS:AssumeRole` etc.                      |   ❌   |                                                          |
| Anonymous mode                             |   ✅   | When no credentials configured.                           |

## Routing

| Mode                                       | Status | Notes                                                    |
| ------------------------------------------ | :----: | -------------------------------------------------------- |
| Path-style (`/bucket/key`)                 |   ✅   |                                                          |
| Virtual-host-style (`bucket.host/key`)     |   ✅   | Detected via `Host` header heuristic.                     |

## Operability

| Endpoint                                   | Status | Notes                                                    |
| ------------------------------------------ | :----: | -------------------------------------------------------- |
| `/healthz`                                 |   ✅   | Liveness — server is up.                                  |
| `/readyz`                                  |   ✅   | Readiness — data dir writable.                            |
| `/metrics`                                 |   ✅   | Prometheus text-exposition format.                        |
| Structured JSON access log                 |   ✅   | One line per request.                                     |
| `x-amz-request-id` header                  |   ✅   | Per-request 32-hex-char id.                               |

## Compatibility test matrix (manual)

The following clients have been used against Simpaniz:

- ✅ `curl` — all CRUD ops, multipart, range, conditional GETs.
- ⚠️ AWS CLI — works for object CRUD; multipart upload works with
  `--multipart-chunksize ≥ 5MB`. Some bucket-level admin ops (e.g.
  `s3api put-bucket-policy`) are not implemented and return 501.
- ⚠️ `mc` (MinIO client) — basic ops work; admin commands are
  MinIO-proprietary and not supported.
- ⚠️ `s3cmd` / `boto3` / `aws-sdk-go` — object ops work; advanced
  features (versioning, lifecycle, ACLs) return errors.


## Distribution / Erasure Coding

| Feature                                    | Status | Notes                                                    |
| ------------------------------------------ | :----: | -------------------------------------------------------- |
| Reed-Solomon erasure-coded primitives      |   ✅   | Pure Zig RS(k,m) over GF(256). Tolerates losing any `m` of `k+m` shards. |
| Rendezvous (HRW) shard placement           |   ✅   | Stable under add/remove of non-owner nodes.               |
| Distributed put/get/delete/heal orchestrator |   ✅ | Pluggable transport vtable.                              |
| Cluster config (`SIMPANIZ_NODE_ID`/`SIMPANIZ_PEERS`) | ✅ | Static peer list, EC params, shared cluster secret. |
| HTTP shard transport (inter-node)          |   ✅   | Hand-rolled HTTP/1.1 over `std.net`. Self-node short-circuits to local disk. Auth via `X-Simpaniz-Cluster-Auth` shared secret. Configurable send/recv timeout via `SIMPANIZ_CLUSTER_TIMEOUT_MS` (default 5000). Per-RPC counters surface as `simpaniz_cluster_*` Prometheus metrics. |
| Internal `/_simpaniz/{shards,meta,bucket}/...` endpoint | ✅ | Bypasses SigV4. Constant-time secret compare. |
| Distributed PUT / GET / HEAD / DELETE      |   ✅   | Cluster PUT streams directly into the encode buffer (no double-buffer). Cluster GET supports `Range`, `If-Match`, `If-None-Match`. Cluster CopyObject (`x-amz-copy-source`) reads source via the EC ring and re-puts into the destination. |
| Multipart upload in cluster mode           |   ✅   | `CreateMultipartUpload`/`UploadPart` stay local; `CompleteMultipartUpload` assembles locally, promotes the object into the EC ring, then drops the local copy. ETag retains MinIO/S3 `<md5>-<N>` format on the API response. |
| Self-healing background daemon             |   ✅   | `SIMPANIZ_HEAL_INTERVAL_S` (default 0). Walks local meta files, repairs missing shards via the orchestrator. Counter `simpaniz_heal_repaired_total`. |
| Bucket replication on `CreateBucket`/`DeleteBucket` | ✅ | Auto fans out to every peer over the internal endpoint. Tolerates up to `m` peer failures (matches shard write quorum). Idempotent. |
| Server-side replication (cross-cluster)    |   ⚠️  | Best-effort async replicator: enqueue on PUT, deliver via background worker over HTTP **or HTTPS** (scheme picked from target URL via `std.http.Client.fetch`). Configure with `SIMPANIZ_REPL_TARGETS="src=>http://peer:9000/dst,..."` or `https://...`. Optional `SIMPANIZ_REPL_AUTH` is sent verbatim as `Authorization`. Persistent on-disk journal at `<data_dir>/.simpaniz-repl/queue.log` survives restarts. Metrics: `simpaniz_repl_{queued,replicated,failed}_total` + `simpaniz_repl_pending`. |
| `/cluster/health` endpoint                 |   ✅   | JSON status: own node id and peer list. No active probing yet. |
| Membership (gossip / Raft)                 |   ❌   | Static peer list only — deferred. Quorum is implicit via `k+m` placement; tolerates up to `m` failed peers per write. |

### Cluster mode quickstart

3 nodes on one host (k=2, m=1 — tolerates any 1 node down):

```sh
# Same on all 3 — peers and secret are shared.
export SIMPANIZ_PEERS='n1@127.0.0.1:9001,n2@127.0.0.1:9002,n3@127.0.0.1:9003'
export SIMPANIZ_EC_K=2
export SIMPANIZ_EC_M=1
export SIMPANIZ_CLUSTER_SECRET=changeme
export SIMPANIZ_HEAL_INTERVAL_S=60

# Per-node: set NODE_ID + listen port + data dir.
SIMPANIZ_NODE_ID=n1 SIMPANIZ_PORT=9001 SIMPANIZ_DATA_DIR=/var/simpaniz/n1 ./simpaniz &
SIMPANIZ_NODE_ID=n2 SIMPANIZ_PORT=9002 SIMPANIZ_DATA_DIR=/var/simpaniz/n2 ./simpaniz &
SIMPANIZ_NODE_ID=n3 SIMPANIZ_PORT=9003 SIMPANIZ_DATA_DIR=/var/simpaniz/n3 ./simpaniz &

# Create the bucket on any one node — it auto-replicates to peers.
curl -X PUT http://127.0.0.1:9001/mybucket

# Now any single PUT to any node fans out across all 3.
curl -X PUT --data-binary @file.bin http://127.0.0.1:9001/mybucket/file.bin

# Multipart and Range work too:
aws --endpoint http://127.0.0.1:9001 s3 cp big.iso s3://mybucket/big.iso
curl -H 'Range: bytes=0-99' http://127.0.0.1:9002/mybucket/big.iso
```

### Cross-cluster replication (SSR)

Set `SIMPANIZ_REPL_TARGETS` to a comma-separated list of `src-bucket=>url`
mappings. The destination URL is `http://host:port[/dst-bucket]`; if
`dst-bucket` is omitted the source bucket name is reused.

```sh
# Replicate every PUT into bucket "logs" to a remote MinIO at example.com.
export SIMPANIZ_REPL_TARGETS='logs=>http://logs.example.com:9000/logs-mirror'
export SIMPANIZ_REPL_AUTH='Bearer eyJ…'   # optional; sent as Authorization
```

