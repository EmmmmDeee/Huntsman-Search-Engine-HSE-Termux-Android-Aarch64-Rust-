# Current Huntsman Recon image for Railway and generic Linux container runtimes.
# This is the single canonical container definition for Huntsman Recon.
FROM rust:1.99-trixie AS builder
WORKDIR /build

ENV HUNTSMAN_HIBP_NO_EMBED=1

COPY Cargo.toml Cargo.lock build.rs capabilities.json benchmarks.json ./
COPY src ./src

RUN cargo build --release --locked --bin huntsman-recon

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --home-dir /data --shell /usr/sbin/nologin huntsman \
    && mkdir -p /data/.huntsman /data/var \
    && chown -R huntsman:huntsman /data

COPY --from=builder /build/target/release/huntsman-recon /usr/local/bin/huntsman-recon
COPY scripts/railway-entrypoint.sh /usr/local/bin/huntsman-entrypoint
RUN chmod 0755 /usr/local/bin/huntsman-recon /usr/local/bin/huntsman-entrypoint

ENV HOME=/data \
    HUNTSMAN_DATA_DIR=/data \
    HUNTSMAN_STARTUP_CHECK=1

WORKDIR /data
EXPOSE 8080
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8080}/api/health" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/huntsman-entrypoint"]
CMD ["serve"]
