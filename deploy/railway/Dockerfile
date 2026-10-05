# Railway deployment adapter for the preserved HSE v1.41 server.
#
# The canonical repository root is the reconstructed huntsman-recon crate and
# intentionally no longer contains the old `hse serve` application. Railway's
# production web service therefore builds the preserved, provenance-tracked
# monolith without mutating anything under legacy/.
FROM rust:1.98.0-bookworm AS builder
WORKDIR /build

# rusqlite uses its bundled SQLite build, which requires a C toolchain.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy every compile-time input that the server actually depends on. In
# particular, hse-core is a path dependency and wasm-ui/pkg is embedded with
# include_bytes!, so omitting either makes the Docker build deterministically
# incomplete.
COPY legacy/hse-monolith-v1.41.0/Cargo.toml legacy/hse-monolith-v1.41.0/Cargo.lock legacy/hse-monolith-v1.41.0/build.rs ./
COPY legacy/hse-monolith-v1.41.0/src ./src
COPY legacy/hse-monolith-v1.41.0/hse-core ./hse-core
COPY legacy/hse-monolith-v1.41.0/wasm-ui/pkg ./wasm-ui/pkg

# Railway supplies this build argument for Git-backed deploys. Keep a safe
# fallback so the build remains portable; the binary itself treats "unknown"
# as unverifiable rather than fabricating provenance.
ARG RAILWAY_GIT_COMMIT_SHA=unknown
RUN HSE_BUILD_SHA="${RAILWAY_GIT_COMMIT_SHA}" cargo build --release --locked --bin hse

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gosu \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --home-dir /data --uid 10001 hse
ENV HOME=/data

COPY --from=builder /build/target/release/hse /usr/local/bin/hse
COPY legacy/hse-monolith-v1.41.0/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

WORKDIR /data
EXPOSE 8080

# Keep the legacy volume-ownership reconciliation boundary intact before
# dropping privileges. Railway may override CMD, but must not bypass this.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/sh", "-c", "exec hse serve --bind 0.0.0.0:${PORT:-8080} --no-key-write"]
