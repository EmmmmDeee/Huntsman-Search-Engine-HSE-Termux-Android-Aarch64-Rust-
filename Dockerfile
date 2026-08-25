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

# build.rs derives the build SHA from `git rev-parse HEAD`, falling back to this
# variable "for builds from a source archive with no .git" — which is exactly
# what a Docker context is, since .dockerignore excludes .git to keep the
# context small. Without it `hse version` reports an unknown revision, so pass
# it from CI/Railway:  --build-arg HSE_BUILD_SHA=$RAILWAY_GIT_COMMIT_SHA
ARG HSE_BUILD_SHA=""
ENV HSE_BUILD_SHA=$HSE_BUILD_SHA

WORKDIR /build

# Dependency pre-build: compile the third-party graph in its own layer so an
# edit under src/ does not re-download and re-compile ~400 crates on every
# deploy.
#
# The stub tree below is not decoration — it is the minimum Cargo needs to PARSE
# this manifest. Cargo validates every declared target at parse time, so a stub
# is required for the lib, all three [[bin]]s, both [[bench]]s AND build.rs.
# Verified: with only `src/main.rs`, `cargo metadata` fails with
#   "can't find `correlation_pass` bench at `benches/correlation_pass.rs`"
# which an earlier `|| true` here swallowed — leaving the layer a silent no-op
# that cached nothing while appearing to work. No `|| true`: if this layer
# cannot do its job, the build must say so.
#
# Building the stub *lib* is what populates the cache: Cargo compiles every
# crate in [dependencies] for the target being built, whether or not the source
# references it.
COPY Cargo.toml Cargo.lock build.rs ./
RUN mkdir -p src/bin/hse_ai_daemon src/bin/dep_cooldown benches \
    && echo 'fn main() {}' > src/main.rs \
    && : > src/lib.rs \
    && echo 'fn main() {}' > src/bin/hse_ai_daemon/main.rs \
    && echo 'fn main() {}' > src/bin/dep_cooldown/main.rs \
    && echo 'fn main() {}' > benches/scan_throughput.rs \
    && echo 'fn main() {}' > benches/correlation_pass.rs \
    && cargo build --release --locked --lib \
    && rm -rf src benches build.rs

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

# NOTE: deliberately NOT `USER huntsman`. A platform volume mounted at /data
# arrives owned by root, and a container that has already dropped privileges
# cannot chown it — the server would start and then fail to create its
# database. The entrypoint therefore starts as root, takes ownership of /data
# only if it is not already correct, and drops to uid 10001 via setpriv before
# exec'ing the server. Verified: with a root-owned volume and a pre-dropped
# uid, `touch /data/probe` fails with EACCES.
EXPOSE 8080

# The platform's own healthcheck should hit /api/v1/health, which is
# deliberately unauthenticated so a probe needs no credential.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8080}/api/v1/health" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
