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
| IAM / policy | Multi-user, PBAC enforced, STS, groups | multi-user store + policy **enforced** (`iam.zig`), explicit-deny-wins evaluation | STS, groups |
| Identity | OIDC, LDAP, AssumeRole | SigV4 only | external IdP |
| Encryption | SSE-S3/KMS/C complete, KES | SSE-S3/C/KMS(local keyring) complete: multipart, copy, range, default-bucket (`sse.zig`) | external KMS/KES |
| TLS | in-process | in-process TLS 1.3 (`tls_server.zig`) | ACME auto-cert (stretch) |
| Cluster | erasure sets, rebalance, dist. locks | SWIM-lite membership (probe/gossip/join) + HRW rebalance daemon (`membership.zig`, `rebalance.zig`) | dist. locks, decommission |
| Listing | metadata layer | per-bucket LSM-lite index (`index.zig`), FS-walk fallback | none (single-node only; cluster still FS-walk) |
| Events | webhook/Kafka/NATS/AMQP/MQTT | webhook (`events.zig`) | Kafka/NATS/AMQP/MQTT targets |
| Replication | active-active, sync | async best-effort (`replication.zig`) | sync + bidirectional |
| Tiering | hot→cold (S3/GCS/Azure) | none | lifecycle transitions |
| Admin | `mc admin`, admin API | console UI only (`ui.zig`) | admin API + CLI |
| Versioning | full | ⚠️ suspended-overwrite TODO | completeness |
| Object Lock | full WORM | ⚠️ no bucket-default retention | completeness |

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

### 1.2 In-process TLS ❌→✅ DONE (ACME stretch still open)
- **New file:** `src/tls_server.zig`. Touch: `main.zig`, `server.zig`.
- Hand-rolled TLS 1.3 server (Zig std has client only), reusing
  `std.crypto.tls` wire types. TLS 1.3 only; AES-128/256-GCM +
  ChaCha20-Poly1305; x25519 key exchange only; ECDSA P-256 server certs
  (PKCS#8/SEC1); ALPN `http/1.1`. No client certs, resumption, or 0-RTT.
- Load `SIMPANIZ_TLS_CERT`/`SIMPANIZ_TLS_KEY` PEM (both required together).
- **Stretch (differentiator, still open):** ACME/Let's-Encrypt auto-cert
  (`SIMPANIZ_TLS_ACME=domain`).
- **Accept:** `curl https://localhost:9000/` works with no reverse proxy.
  Verified live over HTTPS with curl.

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
  Single-node only — cluster listing still FS-walk.
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
- Limitations: joiner needs full peer list in its own env; no decommission;
  migrated shards may leave orphaned local meta.
- **Accept:** add a 4th node to a 3-node cluster → shards redistribute without
  client errors; killing a node marks it down within probe interval.

---

## Phase 3 — Feature parity completion

### 3.1 Versioning completeness ⚠️→✅
- `storage/versioning.zig`: suspended-versioning overwrite semantics (null
  version id), noncurrent version ordering for lifecycle.

### 3.2 Lifecycle completeness ⚠️→✅
- `storage/lifecycle.zig`: `<NoncurrentVersionExpiration>`, tag filters,
  **transitions** (links to 3.4 tiering).

### 3.3 Object Lock completeness ⚠️→✅
- `storage/object_lock_config.zig`: bucket-level default retention storage +
  application on PUT.

### 3.4 Tiering ❌→✅
- **New:** `src/tiering.zig`. Lifecycle `<Transition>` → move cold objects to a
  remote S3/local-cold target, leave a stub; transparent fetch on GET.
- **Accept:** object older than N days transitions; GET still returns it (pulled
  from cold).

### 3.5 STS / external identity ❌→✅
- **Files:** `auth.zig`, new `src/sts.zig`.
- `AssumeRole`, then OIDC (`AssumeRoleWithWebIdentity`). LDAP optional/later.
- **Accept:** OIDC token → temp creds → scoped S3 access.

### 3.6 Admin API + CLI parity ⚠️→✅
- **New:** `src/admin.zig` (admin REST), extend `ui.zig`.
- Admin endpoints: user/policy CRUD, cluster info, healing status, config.
- **Differentiator:** ship server + client in **one binary** (`simpaniz admin …`
  subcommand) — MinIO needs separate `mc`. Build-flag in `build.zig`.

---

## Phase 4 — Exceed MinIO (the wedge)

Don't out-feature MinIO on its turf — win where it's heavy or weak.

1. **Footprint** — keep single static ~3.4 MB binary, zero runtime deps, vs
   MinIO ~100 MB. Lean into edge / IoT / embedded / air-gapped self-host.
   Guard rule: every new feature must justify any new dependency or stay stdlib.
2. **Zero-config TLS** — ACME auto-cert (1.2 stretch). MinIO needs manual setup.
3. **One binary = server + client + admin** — no separate `mc`.
4. **Pick ONE deep bet (don't build all):**
   - WASM/Lua server-side object transform filters (on-PUT/on-GET hooks).
   - Native sync active-active replication w/ version-vector conflict
     resolution — MinIO's active-active is operationally fiddly.
   - Built-in single-binary metrics+UI dashboard beyond Prometheus scrape.

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
  multi-tenant" claim now holds; ACME auto-cert remains a P4 stretch item.
- **P2 is done** — metadata index layer, streaming EC, and cluster
  membership + rebalance all shipped (141 tests green, benchmarked).
- **P4:** commit to exactly one deep bet. Breadth here loses to MinIO; depth wins.

## Anti-goals

- No feature-checklist race for its own sake — parity where it unblocks users,
  depth where it differentiates.
- Don't break the zero-dep / single-binary property without explicit payoff.
- Don't add Raft before gossip proves insufficient (YAGNI).

## Verification per phase

Build green (`zig build -Doptimize=ReleaseSafe`), plus client conformance:
extend the manual matrix in `COMPATIBILITY.md` to automated runs against
`aws s3api`, `boto3`, and `mc` for every newly-✅ row.
