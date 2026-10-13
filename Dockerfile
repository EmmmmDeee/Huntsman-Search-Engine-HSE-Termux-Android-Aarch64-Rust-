# Current Huntsman Recon image for Railway and generic Linux container runtimes.
# This is the single canonical container definition for Huntsman Recon.
# Base images are pinned by digest, so a moved tag cannot change the toolchain or OS under a build.
FROM rust:1.99-trixie@sha256:6ff07edce8775d0f64be7aba9197229407301bddf2054d62c27b541a6238a181 AS builder
WORKDIR /build

ARG HUNTSMAN_BUILD_SHA=unknown
ENV HUNTSMAN_HIBP_NO_EMBED=1 \
    HUNTSMAN_BUILD_SHA=${HUNTSMAN_BUILD_SHA}

COPY Cargo.toml Cargo.lock build.rs capabilities.json benchmarks.json HUNTSMAN_CANONICAL_TEAM_DIRECTIVE.md ./
COPY src ./src
# The root manifest declares xtask as a workspace member, so cargo reads its manifest and
# source while loading the workspace. This build does not compile xtask.
COPY xtask/Cargo.toml ./xtask/Cargo.toml
COPY xtask/src ./xtask/src
# huntsman-core is a workspace member, so cargo reads its manifest and source while loading the
# workspace. This image does not compile it.
COPY crates/huntsman-core/Cargo.toml ./crates/huntsman-core/Cargo.toml
COPY crates/huntsman-core/src ./crates/huntsman-core/src
COPY crates/huntsman-storage/Cargo.toml ./crates/huntsman-storage/Cargo.toml
COPY crates/huntsman-storage/src ./crates/huntsman-storage/src
COPY crates/huntsman-collectors/Cargo.toml ./crates/huntsman-collectors/Cargo.toml
COPY crates/huntsman-collectors/src ./crates/huntsman-collectors/src
COPY crates/huntsman-pipeline/Cargo.toml ./crates/huntsman-pipeline/Cargo.toml
COPY crates/huntsman-pipeline/src ./crates/huntsman-pipeline/src

RUN cargo build --release --locked --bin huntsman-recon

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS runtime

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
