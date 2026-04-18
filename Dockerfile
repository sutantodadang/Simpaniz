# syntax=docker/dockerfile:1.7

# ── Build stage ────────────────────────────────────────────────────────────────
FROM alpine:3.21 AS builder

ARG TARGETARCH
ARG ZIG_VERSION=0.15.2

# Alpine 3.21 only ships zig 0.13. Pull the official 0.15.2 tarball instead.
# Map Docker's TARGETARCH (amd64/arm64) to Zig's arch naming (x86_64/aarch64).
RUN apk add --no-cache curl xz tar ca-certificates && \
    case "${TARGETARCH}" in \
      amd64) ZARCH=x86_64 ;; \
      arm64) ZARCH=aarch64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZARCH}-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz && \
    mkdir -p /opt/zig && \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 && \
    rm /tmp/zig.tar.xz && \
    ln -s /opt/zig/zig /usr/local/bin/zig && \
    zig version

WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src/ src/

RUN zig build -Doptimize=ReleaseSafe

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache wget ca-certificates && \
    addgroup -S simpaniz && adduser -S simpaniz -G simpaniz

COPY --from=builder /src/zig-out/bin/simpaniz /usr/local/bin/simpaniz

RUN mkdir -p /data && chown simpaniz:simpaniz /data

USER simpaniz

ENV SIMPANIZ_HOST=0.0.0.0
ENV SIMPANIZ_PORT=9000
ENV SIMPANIZ_DATA_DIR=/data
ENV SIMPANIZ_REGION=us-east-1

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:9000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/simpaniz"]

