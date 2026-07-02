# Simpaniz — Security

## Threat model (current)

- **In scope** — request smuggling, path traversal, unauthorised access via
  forged signatures, unauthorised access via policy enforcement, request-size
  DoS, slowloris.
- **Out of scope / partial** — external key management (KMS), ACLs, LDAP,
  multi-tenant isolation beyond IAM policy, audit logging beyond access logs.

## Network exposure

Simpaniz can terminate TLS in-process (TLS 1.3 only, `tls_server.zig`): set
`SIMPANIZ_TLS_CERT` and `SIMPANIZ_TLS_KEY` (PEM) and `curl https://...` works
with no reverse proxy. Requirements: TLS 1.3 only (no 1.2 fallback), x25519
key exchange only, server certificate must be ECDSA P-256 (PKCS#8 or SEC1
key), no client certificates, no session resumption/0-RTT.

A reverse proxy (nginx, Caddy, traefik, AWS ALB) is still the right choice
when you need RSA certificates, TLS 1.2 client support, ACME auto-renewal
(not yet built in — roadmap stretch item), or LB/WAF fan-out. Example nginx
upstream:

```nginx
server {
    listen 443 ssl http2;
    server_name s3.example.com;
    ssl_certificate     /etc/letsencrypt/live/s3.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/s3.example.com/privkey.pem;
    client_max_body_size 5G;
    proxy_request_buffering off;
    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Authentication

Simpaniz implements AWS Signature V4 verification:

- **Header form** — `Authorization: AWS4-HMAC-SHA256 Credential=...,
  SignedHeaders=..., Signature=...`. The server reconstructs the
  canonical request from the raw URI, the sorted re-encoded query
  string, the listed signed headers, and the supplied
  `x-amz-content-sha256` (or `UNSIGNED-PAYLOAD`).
- **Presigned form** — query parameters `X-Amz-Algorithm`,
  `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`,
  `X-Amz-SignedHeaders`, `X-Amz-Signature` are all honoured.
- **Root credential** — one `(access key, secret key)` pair configured via env
  (`SIMPANIZ_ACCESS_KEY`, `SIMPANIZ_SECRET_KEY`) or auto-generated on first
  launch. Root always bypasses IAM policy (MinIO-style).
- **Multi-user IAM** — additional users are loaded from
  `<DATA_DIR>/.simpaniz-iam/users.json` (`{"users":[{"access_key",
  "secret_key","enabled","policy":{...}}]}`). Bucket policies (`PutBucketPolicy`)
  and each user's inline policy are **enforced on every request** after SigV4
  verification, before the handler runs: explicit `Deny` wins over `Allow`;
  authenticated non-root users default-deny absent a grant; statements with a
  `Condition` are skipped for `Allow` (can't safely assume it holds) but still
  applied for `Deny` (fail closed). `/healthz`, `/metrics`, `/console/` are
  exempt from policy checks.
- **Region binding** — `SIMPANIZ_REGION` is part of the signing context;
  signatures from a different region are rejected.
- **Anonymous mode** — when `SIMPANIZ_ACCESS_KEY` is unset, the server
  serves anonymous requests, default-allow unless a bucket policy denies.
  **Do not run anonymous mode on a network anyone else can reach.**

## STS

`sts.zig` issues temporary credentials via two operations:

- **`AssumeRole`** — SigV4-signed, root or an IAM user only. Optional
  session `Policy` narrows the resulting permissions further: it
  **intersects** with the caller's base policy (statements must satisfy
  both), so a session policy also gates the root principal — it cannot be
  used to escalate.
- **`AssumeRoleWithWebIdentity`** — unsigned (anyone can call it), so all
  trust is in JWT validation: signature (ES256 fully verified; RS256 via
  bigint modexp), `iss` matches `SIMPANIZ_OIDC_ISSUER`, `aud` matches
  `SIMPANIZ_OIDC_AUDIENCE` when configured, `exp` not passed. The token's
  policy claim (or `SIMPANIZ_OIDC_DEFAULT_POLICY`) selects a named policy
  file under `.simpaniz-iam/policies/` — this is the only permission
  surface for web-identity sessions.
- Temp credentials (`x-amz-security-token`) are held **in-memory only**;
  a server restart invalidates every outstanding session — there is no
  persisted revocation list to manage separately.
- Duration is clamped to AWS's 900–43200 s range regardless of what's
  requested.

## Admin API

`/_admin/*` (`admin.zig`) is **root-only** — any non-root caller, including
one with a broad IAM policy, gets `403`. Responses never include secret
keys: `user list` and `config` echo access keys and metadata only. Treat
`SIMPANIZ_ACCESS_KEY`/`SIMPANIZ_SECRET_KEY` used by the `simpaniz admin` CLI
with the same care as root credentials — anyone who has them can create,
delete, and repolicy every IAM user.

## Path traversal

All object and bucket names are validated:

- **Bucket names** — 3 to 63 chars, lowercase letters / digits /
  hyphens only, may not start or end with a hyphen, may not look
  like an IP address.
- **Object keys** — no `..` segments, no leading slash, no NUL
  bytes, max 1024 bytes UTF-8.

In addition to validation, the server scopes all filesystem
operations to the per-bucket `std.fs.Dir` handle, so a `../`
that somehow slipped through validation cannot escape the bucket.

## Resource limits

Configurable via env (defaults shown):

- `SIMPANIZ_MAX_BODY_BYTES` — `5368709120` (5 GiB). Single-request
  body cap; requests larger than this get `413`.
- `SIMPANIZ_MAX_HEADER_BYTES` — `16384`. Total request-header bytes.
- `SIMPANIZ_MAX_HEADERS` — `64`. Maximum number of header lines.
- `SIMPANIZ_READ_TIMEOUT_MS` — `30000`. Per-connection read timeout
  (slowloris guard).
- `SIMPANIZ_IDLE_TIMEOUT_MS` — `60000`. Keep-alive idle timeout.

Header parsing aborts immediately on:

- request line longer than `max_header_bytes` (`431`)
- more than `max_headers` headers (`431`)
- malformed request line or header (`400`)
- unsupported method (`405`)

## Storage durability

- **Atomic writes** — every PUT writes to `.simpaniz-tmp/upload-XXXX`,
  fsyncs the file, and renames into place. Crashes mid-write leave
  only orphaned tmp files; an automatic stale-temp reaper is still a
  durability/operations TODO.
- **No silent corruption** — if a `Content-MD5` or
  `x-amz-content-sha256` header is supplied, Simpaniz verifies the
  body digest and returns `400 BadDigest` on mismatch.

## What Simpaniz does NOT do (yet)

- **No external key management.** SSE-S3/SSE-C/SSE-KMS are complete for
  single-object PUT/GET, multipart, copy-source, Range GET, and default
  bucket encryption (`?encryption` subresource) — but SSE-KMS uses a local
  keyring (master-key wrap under `SIMPANIZ_MASTER_KEY`) rather than an
  external KMS, and there's no key rotation. SSE-C accepts customer-provided
  keys via request headers, MD5-validated, key never persisted. Use full-disk
  encryption (LUKS, BitLocker, EBS encryption) on the data volume for broader
  protection.
- **No audit log retention policy.** The JSON access log is written
  to stderr; route it to your log infra.
- **No rate limiting.** Use the reverse proxy.
- **No DDoS protection.** Use the reverse proxy / a CDN.
- **No secret rotation primitives.** Restart with the new credentials.

## Reporting

Security issues — please open a private security advisory on the
GitHub repo.
