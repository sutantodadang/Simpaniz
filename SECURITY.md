# Simpaniz — Security

## Threat model (current)

- **In scope** — request smuggling, path traversal, unauthorised access via
  forged signatures, request-size DoS, slowloris.
- **Out of scope (deferred)** — at-rest encryption, key management,
  fine-grained IAM, multi-tenant isolation, audit logging beyond
  access logs.

## Network exposure

Simpaniz does **not** terminate TLS. Run it behind a reverse proxy
(nginx, Caddy, traefik, AWS ALB) and bind it to `127.0.0.1` or a
private network interface. Example nginx upstream:

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
- **Single credential** — only one `(access key, secret key)` pair is
  configured via env (`SIMPANIZ_ACCESS_KEY`, `SIMPANIZ_SECRET_KEY`). Multi-user
  IAM is on the deferred list.
- **Region binding** — `SIMPANIZ_REGION` is part of the signing context;
  signatures from a different region are rejected.
- **Anonymous mode** — when `SIMPANIZ_ACCESS_KEY` is unset, the server
  serves anonymous requests. **Do not run anonymous mode on a
  network anyone else can reach.**

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
  only orphaned tmp files (cleaned on next bucket touch by the
  background reaper — TODO).
- **No silent corruption** — if a `Content-MD5` or
  `x-amz-content-sha256` header is supplied, Simpaniz verifies the
  body digest and returns `400 BadDigest` on mismatch.

## What Simpaniz does NOT do (yet)

- **No at-rest encryption.** Use full-disk encryption (LUKS, BitLocker,
  EBS encryption) on the data volume.
- **No audit log retention policy.** The JSON access log is written
  to stderr; route it to your log infra.
- **No rate limiting.** Use the reverse proxy.
- **No DDoS protection.** Use the reverse proxy / a CDN.
- **No secret rotation primitives.** Restart with the new credentials.

## Reporting

Security issues — please open a private security advisory on the
GitHub repo.
