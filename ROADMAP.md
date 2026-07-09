# Simpaniz Roadmap — Parity with MinIO and Beyond

Goal: full S3 + MinIO feature parity, then exceed on footprint, operability,
and a focused differentiator. This is an engineering roadmap, not marketing —
each item names the modules it touches and the acceptance bar.

Baseline (v0.1.1): 40 Zig source files, single ~3.4 MB binary, zero deps.
Strong S3 core, Reed-Solomon cluster, partial IAM/SSE/versioning/lifecycle.

Status legend: ✅ done · ⚠️ partial · ❌ missing

---

## Gap analysis vs MinIO

| Area | MinIO | Simpaniz now | Gap |
|---|---|---|---|
| IAM / policy | Multi-user, PBAC enforced, STS, groups | multi-user store + policy **enforced** (`iam.zig`) + STS (`sts.zig`) | groups |
| Identity | OIDC, LDAP, AssumeRole | AssumeRole + AssumeRoleWithWebIdentity (OIDC, ES256+RS256) (`sts.zig`) | LDAP |
| Encryption | SSE-S3/KMS/C complete, KES | SSE-S3/C/KMS(local keyring) complete: multipart, copy, range, default-bucket (`sse.zig`) | external KMS/KES |
| TLS | in-process | in-process TLS 1.3 (`tls_server.zig`) + ACME auto-cert (`acme.zig`, `SIMPANIZ_TLS_ACME`) | none — parity + differentiator |
| Cluster | erasure sets, rebalance, dist. locks | SWIM-lite membership (probe/gossip/join) + HRW rebalance daemon (`membership.zig`, `rebalance.zig`) + drain/auto-remove decommission | dist. locks |
| Listing | metadata layer | per-bucket LSM-lite index (`index.zig`); cluster-mode listing merges each node's index over an internal route (`cluster/list_index.zig`, `cluster/list_merge.zig`) | none — parity |
| Events | webhook/Kafka/NATS/AMQP/MQTT | webhook (`events.zig`) | Kafka/NATS/AMQP/MQTT targets |
| Replication | active-active, sync | async best-effort (`replication.zig`) | sync + bidirectional |
| Tiering | hot→cold (S3/GCS/Azure) | lifecycle `<Transition>` → local cold dir or remote S3-compatible target, transparent GET (`tiering.zig`) | native GCS/Azure backends |
| Admin | `mc admin`, admin API | admin REST + one-binary CLI, user/policy CRUD, cluster, config (`admin.zig`, `admin_cli.zig`) | none — parity |
| Versioning | full | ✅ suspended-null semantics, `?versionId=null`, IsLatest ordering, `x-amz-version-id` on PUT (`versioning.zig`) | none |
| Object Lock | full WORM | ✅ bucket-default retention applied on PUT (`object_lock_config.zig`, `handlers.applyDefaultRetention`) | none |

---

## Phase 1 — Enforcement: make it prod, not demo

These four block real multi-tenant use. Highest priority. **All four DONE**
(121 tests green, live smoke-tested).

### 1.1 IAM / policy enforcement ❌→✅ DONE
- **Files:** `iam.zig`, `server.zig`, `handlers.zig`.
- Multi-user credential store: `<DATA_DIR>/.simpaniz-iam/users.json`
  (`{"users":[{"access_key","secret_key","enabled","policy":{...}}]}`).
- Policy evaluation engine: AWS-style Effect/Action/Resource/Principal/Condition,
  explicit Deny wins, then Allow, default-deny for authenticated non-root users,
  anonymous default-allow unless denied. Root bypasses policy entirely.
- Wired into request path after SigV4 verify, before handler dispatch; health/
  metrics/console paths exempt.
- **Accept:** `aws s3api put-bucket-policy` deny rule actually blocks a request;
  second user with read-only policy gets `403` on PUT. Verified live: bucket
  policy Deny s3:PutObject → 403, GET still 200.

### 1.2 In-process TLS ❌→✅ DONE (ACME stretch ❌→✅ DONE)
- **New file:** `src/tls_server.zig`. Touch: `main.zig`, `server.zig`.
- Hand-rolled TLS 1.3 server (Zig std has client only), reusing
  `std.crypto.tls` wire types. TLS 1.3 only; AES-128/256-GCM +
  ChaCha20-Poly1305; x25519 key exchange only; ECDSA P-256 server certs
  (PKCS#8/SEC1); ALPN `http/1.1`. No client certs, resumption, or 0-RTT.
- Load `SIMPANIZ_TLS_CERT`/`SIMPANIZ_TLS_KEY` PEM (both required together).
- **Stretch (differentiator) shipped:** ACME/Let's-Encrypt auto-cert
  (`SIMPANIZ_TLS_ACME=domain`) — **new:** `src/acme.zig`. Hand-rolled ACME v2
  (RFC 8555) client: JWS (ES256), RFC 7638 JWK thumbprint, a minimal PKCS#10
  CSR DER writer, and an HTTP-01 challenge listener, all on top of
  `std.crypto`/`std.http.Client`/`std.json` (zero new deps). Account/domain
  keys and the issued cert persist under `<DATA_DIR>/.simpaniz-acme/`; issued
  synchronously on boot if missing or near-expiry, then a daily background
  daemon re-issues within 30 days of expiry and hot-swaps the new cert/key
  pair into the running TLS listener (mutex-guarded pointer swap in
  `acme.TlsHolder`, read once per accepted connection) with no restart and no
  dropped connections. Mutually exclusive with `SIMPANIZ_TLS_CERT`/`_KEY`.
- **Accept:** `curl https://localhost:9000/` works with no reverse proxy.
  Verified live over HTTPS with curl. ACME building blocks (base64url, JWS
  sign+verify, JWK thumbprint, CSR build+parse+signature-verify, X.509
  notAfter parsing, HTTP-01 responder) covered by an offline test suite (no
  live ACME network calls in tests).

### 1.3 SSE completeness ⚠️→✅ DONE
- **Files:** `storage/sse.zig`, `storage/multipart.zig`, `storage/objects.zig`,
  `storage/encryption_config.zig`, `handlers.zig`.
- Extended AES-256-GCM + DEK-wrap to: multipart parts (encrypted at complete,
  staged parts plaintext), copy-source (decrypt source / re-encrypt dest),
  default-bucket-encryption via `?encryption` subresource (Put/Get/Delete),
  **Range GET on encrypted objects** (per-chunk IV addressing), SSE-C
  (customer-provided keys, MD5-validated), SSE-KMS (local keyring, master-key
  wrap, alg `aws:kms` + key-id echoed).
- **Accept:** `aws s3 cp --sse aes256` round-trips a 100 MB multipart object;
  Range GET returns correct plaintext bytes.

### 1.4 Event notifications ❌→✅ DONE
- **New file:** `src/events.zig`, `storage/notification.zig`. **Touch:** `handlers.zig` (fire points).
- Bucket notification config (`PutBucketNotificationConfiguration` XML via
  `?notification` subresource), event types (`s3:ObjectCreated:*`,
  `s3:ObjectRemoved:*`) with prefix/suffix FilterRules.
- Target: webhook (`SIMPANIZ_NOTIFY_WEBHOOK`), async best-effort HTTP POST JSON
  on ObjectCreated:Put/Copy/CompleteMultipartUpload and
  ObjectRemoved:Delete/DeleteMarkerCreated. Queue-backed targets still deferred.
- **Accept:** PUT to a configured bucket POSTs an S3-event-shaped JSON to a sink.

---

## Phase 2 — Scale correctness

### 2.1 Metadata index layer ⚠️→✅ DONE
- **New:** `src/index.zig`. **Touch:** `storage/objects.zig`, `storage/buckets.zig`, `xml.zig` listers.
- Replaced in-mem FS walk+sort with per-bucket LSM-lite under
  `<bucket>/.simpaniz-index/` (WAL + sorted segment with sparse footer);
  listing served from index with FS-walk fallback + lazy bootstrap.
- **Cluster-mode listing ⚠️→✅ DONE:** `ListObjectsV2` in cluster mode
  previously walked only the local node's FS and never saw remote nodes'
  keys. Each node now maintains its own LSM-lite index over the cluster meta
  it stores locally; the listing node fetches every usable peer's index page
  over a new internal route (`GET /_simpaniz/list`, routed through the
  existing `Transport` vtable) and k-way merges the sorted streams, deduping
  replicated entries by newest mtime, through the same pagination/delimiter
  bookkeeping as single-node (`cluster/list_index.zig`, `cluster/list_merge.zig`).
  A peer fetch failing twice fails the whole request rather than returning a
  partial listing.
- Also fixed a pre-existing pagination data-loss bug: the continuation-token
  boundary key was silently dropped on every truncated page (both listers now
  zero-loss; token is inclusive, `start-after` exclusive).
- **Accept:** `ListObjectsV2` on a 1M-key bucket returns first page < 50 ms,
  flat memory. Benchmarked on 200k keys: first page 9–11 ms warm, prefix
  listing 14 ms, server RSS 6.5 MB.

### 2.2 Streaming erasure coding ⚠️→✅ DONE
- **Files:** `cluster/orchestrator.zig`, `cluster/transport.zig`, `cluster/disk_store.zig`, `cluster/internal_handler.zig`.
- Killed full-object encode/decode buffers. Stripe-streaming (default 1 MiB
  chunk/shard/stripe) replaces full-object EC buffers — cluster PUT/GET/heal
  memory now ~one stripe ((k+m)·chunk ≈ few MB) regardless of object size.
  Ranged shard reads; seq-validated idempotent chunk append; Range GET on
  cluster objects streams only overlapping stripes. Back-compatible with the
  old single-stripe shard layout.
- **Accept:** cluster PUT of 2 GB object holds < 1 stripe (~MBs) RAM, not 2 GB.

### 2.3 Cluster membership + health + rebalance ⚠️→✅ DONE
- **Files:** `cluster/membership.zig`, `cluster/rebalance.zig`.
- Active health probing (`SIMPANIZ_PROBE_INTERVAL_MS` default 2000,
  `SIMPANIZ_PROBE_FAILS` default 3), alive/suspect/down states, SWIM-lite
  gossip piggybacked on `/_simpaniz/ping`, dynamic node join (`SIMPANIZ_JOIN=1`
  + `POST /_simpaniz/join`, persisted to `.simpaniz-peers.json`), down-node
  fast-skip on reads.
- Shard rebalance daemon (`SIMPANIZ_REBALANCE_INTERVAL_S` default 300;
  membership-change-triggered sweeps) migrates shards to new HRW owners
  (copy+verify+delete). `/cluster/health` now includes per-node membership
  states.
- **Node decommission ❌→✅ DONE:** admin-driven drain + auto-remove flow. A
  node marked `draining` (`POST /_admin/cluster/decommission?node=<id>`,
  root-only, or `simpaniz admin cluster decommission <node-id>`) stays a read
  source while the rebalance daemon migrates its shards off to the remaining
  nodes (write placement excludes draining/removed nodes; reads are
  unaffected so in-flight reads still find not-yet-migrated shards). Once a
  draining node's own sweep reaches zero local shards and zero errors, it
  auto-promotes to `removed` and drops out of the persisted peer overlay;
  `draining`/`removed` are sticky and gossip-propagate with
  `removed > draining` precedence, so decommissioning can be issued against
  any node in the cluster.
- Limitations: joiner needs full peer list in its own env; migrated shards may
  leave orphaned local meta.
- **Accept:** add a 4th node to a 3-node cluster → shards redistribute without
  client errors; killing a node marks it down within probe interval;
  decommissioning a node drains its shards and it drops out of membership.

---

## Phase 3 — Feature parity completion

All six DONE (~175 tests green, live smoke-tested).

### 3.1 Versioning completeness ⚠️→✅ DONE
- `storage/versioning.zig`: suspended-versioning null-version semantics
  (overwrite-in-place of the null version, null delete markers),
  `?versionId=null` addressing, correct IsLatest/newest-first ordering (live
  object pinned), `x-amz-version-id` on PUT, noncurrent-since timestamps for
  lifecycle.

### 3.2 Lifecycle completeness ⚠️→✅ DONE
- `storage/lifecycle.zig`: `<NoncurrentVersionExpiration>` (expires
  noncurrent versions N days after becoming noncurrent), `<Filter>` tag
  filters (single `<Tag>`, incl. inside `<And>`), `<Transition>`
  (Days + StorageClass) driving tiering (links to 3.4); per-sub-block Days
  parsing fix.

### 3.3 Object Lock completeness ⚠️→✅ DONE
- `storage/object_lock_config.zig` + `handlers.applyDefaultRetention`:
  bucket-level default retention storage, applied to every PUT.

### 3.4 Tiering ❌→✅ DONE
- **New:** `src/tiering.zig`. Lifecycle `<Transition>` moves cold objects to
  `SIMPANIZ_TIER_DIR` (local cold dir) or a SigV4-signed remote
  S3-compatible target (`SIMPANIZ_TIER_URL`/`SIMPANIZ_TIER_BUCKET`/
  `SIMPANIZ_TIER_ACCESS_KEY`/`SIMPANIZ_TIER_SECRET_KEY`/`SIMPANIZ_TIER_REGION`);
  local file becomes a stub. GET transparently fetches from cold (spooled to
  a temp file). `x-amz-storage-class` header echoed. SSE composes — cold
  storage holds the same on-disk (encrypted) bytes.
- **Cold-GET rehydration ❌→✅ DONE:** `SIMPANIZ_TIER_REHYDRATE=1` writes a
  fetched cold object back to hot local storage (tmp + fsync + rename,
  mirroring the PUT path) and clears the metadata sidecar's tiered marker,
  then deletes the cold copy (local file, or a new SigV4-signed DELETE for a
  remote tier). Best-effort — any failure is logged and the GET still serves
  the already-fetched bytes; default off (preserves always-re-fetch
  behavior).
- **Accept:** object older than N days transitions; GET still returns it
  (pulled from cold); with rehydration on, a second GET is served hot without
  re-fetching from the tier.

### 3.5 STS / external identity ❌→✅ DONE
- **New:** `src/sts.zig`.
- `AssumeRole` (SigV4-signed, temp creds with optional session `Policy`,
  900–43200 s) and `AssumeRoleWithWebIdentity` (unsigned, OIDC JWT: ES256
  fully verified, RS256 verified via bigint modexp; JWKS fetched from
  `SIMPANIZ_OIDC_JWKS_URL`, issuer `SIMPANIZ_OIDC_ISSUER`, optional
  `SIMPANIZ_OIDC_AUDIENCE`, policy claim → named policy files under
  `.simpaniz-iam/policies/`, default `SIMPANIZ_OIDC_DEFAULT_POLICY`). Session
  tokens via `x-amz-security-token`; session policy intersects base
  permissions (gates root too). Query-param API only (no form body parsing).
  Creds in-memory — restart invalidates. LDAP optional/later.
- **Accept:** OIDC token → temp creds → scoped S3 access.

### 3.6 Admin API + CLI parity ⚠️→✅ DONE
- **New:** `src/admin.zig` (admin REST), `src/admin_cli.zig` +
  `src/s3_client.zig` (CLI client, same binary).
- Root-only REST under `/_admin/`: info, users CRUD, policies CRUD, cluster,
  sanitized config (never returns secrets). IAM users are now hot-editable
  (mutex + persisted `users.json`).
- **Differentiator:** ship server + client in **one binary**
  (`simpaniz admin …` subcommand, SigV4-signed via
  `SIMPANIZ_ADMIN_ENDPOINT`/`SIMPANIZ_ACCESS_KEY`/`SIMPANIZ_SECRET_KEY`) —
  MinIO needs a separate `mc`.

---

## Phase 4 — Exceed MinIO (the wedge)

Don't out-feature MinIO on its turf — win where it's heavy or weak.

1. **Footprint** — keep single static ~3.4 MB binary, zero runtime deps, vs
   MinIO ~100 MB. Lean into edge / IoT / embedded / air-gapped self-host.
   Guard rule: every new feature must justify any new dependency or stay stdlib.
   Still holding after the P4 dashboard bet — no new deps added (dashboard.js
   is vanilla canvas/JS, embedded like the rest of the console).
2. **Zero-config TLS ❌→✅ DONE** — ACME auto-cert (1.2 stretch, `src/acme.zig`,
   `SIMPANIZ_TLS_ACME`). MinIO needs manual cert setup or a reverse proxy;
   Simpaniz obtains and auto-renews a Let's Encrypt certificate with zero
   manual steps.
3. **One binary = server + client + admin** — no separate `mc`.
4. **Deep bet — CHOSEN: built-in single-binary metrics+UI dashboard ❌→✅ DONE.**
   Per the "pick ONE" rule, the other two candidates were **not built**:
   WASM/Lua on-PUT/on-GET transform filters, and native sync active-active
   replication w/ version-vector conflict resolution. Both remain open if a
   future deep bet is warranted.
   - **New:** `src/timeseries.zig` — in-process 24h metric history.
     Background sampler (`SIMPANIZ_METRICS_SAMPLE_S`, default 10s, `0`
     disables) snapshots `metrics.Registry` into an 8640-point ring;
     per-second rates and p50/p95/p99 latency derived server-side from
     histogram-bucket deltas (Prometheus-style interpolation). In-memory
     only — restart clears history.
   - **New:** `src/dashboard.zig` — SigV4-authenticated read-only API:
     `GET /_dashboard/api/summary` (uptime, totals, percentiles, mode, TLS,
     IAM users, tiering, cluster membership states) and
     `GET /_dashboard/api/series?window=60..86400`.
   - Console gained a **Metrics tab** (`src/ui_assets/dashboard.js`):
     dependency-free canvas line charts (requests/errors per s, latency
     percentiles, throughput, in-flight), summary cards, cluster node-state
     dots; 15m/1h/6h/24h windows, 10s auto-refresh; reuses the console's
     browser-side SigV4 signer.
   - **Accept:** open `/console/`, Metrics tab renders live charts with no
     Prometheus/Grafana running. Verified live.

---

## Sequencing & gates

```
P1.1 IAM ─┐
P1.2 TLS ─┼─→ "prod-usable" gate (multi-tenant + encrypted transport)
P1.3 SSE ─┤
P1.4 Evt ─┘
                P2.1 Index ──→ "scale" gate (1M keys, flat mem)
                P2.2 StreamEC ┤
                P2.3 Cluster ─┘
                            P3.x parity completion (parallelizable)
                                        P4 differentiator (pick one)
```

- **P1 is done** — IAM enforcement, in-process TLS, SSE completeness, and event
  notifications all shipped (121 tests green, live smoke-tested). "Production
  multi-tenant" claim now holds; ACME auto-cert (P4 stretch item) has since
  shipped too — see P4 below.
- **P2 is done** — metadata index layer, streaming EC, and cluster
  membership + rebalance all shipped (141 tests green, benchmarked).
- **P3 is done** — versioning suspended-null semantics, lifecycle
  completeness (NoncurrentVersionExpiration/tag filters/transitions),
  tiering, STS/OIDC identity, and admin API + CLI all shipped (~175 tests
  green, live smoke-tested).
- **P4 is done** — deep bet chosen and shipped: built-in single-binary
  metrics+UI dashboard (`timeseries.zig`, `dashboard.zig`, console Metrics
  tab). The other two candidate bets (WASM/Lua transform filters, sync
  active-active replication) were intentionally not built, per "pick ONE."
  Footprint/one-binary properties still hold. The ACME auto-cert stretch item
  (`src/acme.zig`) also shipped, closing out the last open item from 1.2.

## Anti-goals

- No feature-checklist race for its own sake — parity where it unblocks users,
  depth where it differentiates.
- Don't break the zero-dep / single-binary property without explicit payoff.
- Don't add Raft before gossip proves insufficient (YAGNI).

## Verification per phase

Build green (`zig build -Doptimize=ReleaseSafe`), plus client conformance:
extend the manual matrix in `COMPATIBILITY.md` to automated runs against
`aws s3api`, `boto3`, and `mc` for every newly-✅ row.
