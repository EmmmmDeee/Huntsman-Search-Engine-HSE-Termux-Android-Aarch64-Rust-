# Railway / generic-Linux container image for the HSE server (`hse serve`).
#
# Termux aarch64 is NOT built or run through this image — it has its own
# no-root install path (see install.sh, scripts/setup-dev.sh). This Dockerfile
# exists solely for the "generic Linux" and "Railway" targets.
#
# Toolchain pinned to match rust-toolchain.toml exactly, so a container build
# can never silently diverge from what CI/local dev compile against.
FROM rust:1.97.1-bookworm AS builder
WORKDIR /build

# rusqlite is built with the `bundled` feature (compiles SQLite from C source
# via the `cc` crate) — no system libsqlite, but a C toolchain is required.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY benches ./benches

# --locked: the image must build from exactly the committed Cargo.lock, never
# a silently re-resolved one. --bin hse: skip the AI-daemon and dep-cooldown
# dev-tooling binaries, which have no place in a production server image.
RUN cargo build --release --locked --bin hse

FROM debian:bookworm-slim AS runtime

# ca-certificates: required for the rustls-backed HTTPS client to validate
# any TLS connection. curl: several OSINT modules shell out to it as a
# SSRF-hardened fallback fetch path (see src/util/curl/, src/util/egress/) —
# without it those code paths degrade, they don't crash, but a production
# image should carry it so those fallbacks actually work. gosu: lets the
# entrypoint start as root (needed to fix up volume ownership below) and
# then drop to the unprivileged user for the actual server process.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Non-root: HSE persists its state (SQLite store, key pool, event log) under
# $HOME/.huntsman. Pointing HOME at a dedicated, owned directory keeps that
# entirely inside one path a Railway volume (or any bind mount) can target
# for persistence across restarts/redeploys.
RUN useradd --create-home --home-dir /data --uid 10001 hse
ENV HOME=/data
COPY --from=builder /build/target/release/hse /usr/local/bin/hse
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Deliberately stays root here — see docker-entrypoint.sh. A bind-mounted or
# Railway-Volume-backed /data carries the HOST side's ownership, not this
# layer's `useradd --create-home` chown, so the entrypoint reconciles it
# before dropping to `hse` and exec'ing the real command. Verified: without
# this, mounting any external volume at /data crash-loops on "unable to open
# database file" on first boot.
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["docker-entrypoint.sh"]

# Railway (and most PaaS hosts) inject $PORT at runtime and expect the
# process to bind it on 0.0.0.0 — `hse serve`'s own default is
# 127.0.0.1:8080 (loopback-only, deliberately, for the bare-metal/Termux
# case), so the container's own entrypoint is the platform adapter that
# translates $PORT into that flag rather than changing the loopback-first
# default in core code. `--no-key-write` is redundant with the endpoint's
# unconditional loopback-peer check on a 0.0.0.0 bind (see src/cli/serve),
# but it is a free extra layer of defense-in-depth for a public deployment.
CMD ["/bin/sh", "-c", "exec hse serve --bind 0.0.0.0:${PORT:-8080} --no-key-write"]
