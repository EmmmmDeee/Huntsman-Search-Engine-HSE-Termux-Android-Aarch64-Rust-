# Huntsman Search Engine — container image for PaaS deployment (Railway et al).
#
# This is a SECOND deployment target, not a replacement for Termux. `install.sh`
# remains the supported path for the on-device Android use case and is unaffected
# by anything here.
#
# Read `docs/RAILWAY.md` before deploying: a public bind exposes an OSINT store
# holding third-party personal data, and HSE_API_TOKEN is the control that keeps
# it from being world-readable.

# ── builder ──────────────────────────────────────────────────────────────────
# Pinned to the crate's declared MSRV so the image cannot silently drift ahead of
# what CI's MSRV job verifies.
FROM rust:1.88-bookworm AS builder

WORKDIR /build

# Dependency pre-build: copying the manifests alone lets Docker cache the whole
# dependency graph, so an edit to src/ does not re-download and re-compile ~400
# crates. The dummy main.rs is replaced by the real sources in the next layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked --bin hse 2>/dev/null || true \
    && rm -rf src

COPY . .

# `--locked` so the image is byte-reproducible against the committed lockfile:
# a Cargo.lock that would need updating fails the build instead of silently
# resolving to newer dependencies than CI tested.
RUN touch src/main.rs \
    && cargo build --release --locked --bin hse --bin hse-ai-daemon \
    && strip target/release/hse target/release/hse-ai-daemon

# ── runtime ──────────────────────────────────────────────────────────────────
# The binary links only libgcc_s/libm/libc — SQLite is statically bundled
# (rusqlite "bundled") and TLS is rustls, so there is no libssl or libsqlite3 to
# install. ca-certificates is required: OSINT modules make outbound HTTPS calls
# and rustls verifies against the system root store.
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root. The scan engine needs no privileges, and a compromised OSINT module
# parsing hostile third-party HTML should not be running as uid 0.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin huntsman

COPY --from=builder /build/target/release/hse           /usr/local/bin/hse
COPY --from=builder /build/target/release/hse-ai-daemon /usr/local/bin/hse-ai-daemon
COPY docker-entrypoint.sh                               /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

# HOME drives the state directory: HSE resolves its database to
# `$HOME/.huntsman/huntsman.db`. Pointing HOME at /data means mounting a volume
# there is the whole persistence story — without it the scan store is lost on
# every redeploy, since a container filesystem is ephemeral.
ENV HOME=/data \
    HSE_ENV_FILE=/data/.huntsman.env
RUN mkdir -p /data && chown -R huntsman:huntsman /data
VOLUME ["/data"]

USER huntsman
EXPOSE 8080

# The platform's own healthcheck should hit /api/v1/health, which is
# deliberately unauthenticated so a probe needs no credential.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8080}/api/v1/health" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
