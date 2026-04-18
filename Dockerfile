# ── Build stage ────────────────────────────────────────────────────────────────
FROM alpine:3.21 AS builder

RUN apk add --no-cache zig=~0.15

WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src/ src/

RUN zig build -Doptimize=ReleaseSafe

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN addgroup -S simpaniz && adduser -S simpaniz -G simpaniz

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
