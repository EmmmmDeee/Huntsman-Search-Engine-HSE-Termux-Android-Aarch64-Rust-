#!/usr/bin/env bash
# Container entrypoint for PaaS deployment (Railway, Fly, Render, plain Docker).
#
# Two jobs the Dockerfile cannot do on its own, because both depend on values
# that only exist at RUN time:
#
#   1. $PORT is injected by the platform per-deploy and is not known when the
#      image is built, so the bind address has to be composed here.
#   2. Refusing to start unauthenticated on a public bind — see below. This is
#      a startup precondition, not a warning, because a warning in a deploy log
#      nobody reads is indistinguishable from no control at all.
set -euo pipefail

# ── Privilege drop ───────────────────────────────────────────────────────────
# Runs as root only long enough to make the mounted volume writable, then
# re-executes itself as an unprivileged user. Without this, a root-owned volume
# (which is how platforms mount them) is unwritable by the runtime user and the
# server dies trying to create its database.
HSE_UID=10001
HSE_GID=10001
if [ "$(id -u)" = "0" ]; then
    mkdir -p /data
    # Only chown when ownership is actually wrong: a recursive chown of a large
    # volume on every boot is slow and pointless once it is correct.
    if [ "$(stat -c %u /data 2>/dev/null || echo 0)" != "$HSE_UID" ]; then
        chown -R "$HSE_UID:$HSE_GID" /data 2>/dev/null \
            || echo "hse: could not chown /data — the server may fail to write." >&2
    fi
    # setpriv ships with util-linux, which is present in debian-slim (verified).
    # The re-exec lands in this same script with a non-zero uid, so this branch
    # runs exactly once.
    exec setpriv --reuid="$HSE_UID" --regid="$HSE_GID" --init-groups "$0" "$@"
fi

PORT="${PORT:-8080}"

# HSE reads its bind from HSE_BIND (documented flag: "Localhost-only by default
# — change at your own risk"). A container that binds loopback is unreachable
# from the platform's router, so 0.0.0.0 is required here — this is the
# supported non-loopback path. Note what does and does NOT carry over: CORS is
# bound to the origin derived from this bind, but the Host-header allowlist is
# deliberately skipped for a non-loopback bind (see routes/mod.rs), so it is
# NOT protecting this deployment. HSE_API_TOKEN is the control here.
export HSE_BIND="${HSE_BIND:-0.0.0.0:${PORT}}"

is_public_bind() {
    case "${HSE_BIND}" in
        127.0.0.1:*|localhost:*|\[::1\]:*) return 1 ;;
        *) return 0 ;;
    esac
}

# Fail closed. HSE's HTTP API has no authentication of its own: on a public URL
# every scan route, and the entire stored graph of third-party personal data, is
# readable by anyone who finds the hostname. HSE_API_TOKEN enables the bearer
# check in front of every route except /api/v1/health.
#
# HSE_ALLOW_PUBLIC_NO_AUTH=1 is a deliberate, explicit override for someone who
# genuinely wants an open instance (a throwaway demo with an empty database).
# It is not the default, and it is not silent.
if is_public_bind && [ -z "${HSE_API_TOKEN:-}" ] && [ "${HSE_ALLOW_PUBLIC_NO_AUTH:-0}" != "1" ]; then
    cat >&2 <<'REFUSAL'
hse: refusing to start.

  Bind is public but HSE_API_TOKEN is unset, which would publish an
  unauthenticated OSINT database — including any personal data about third
  parties that previous scans collected — to anyone who finds this URL.

  Fix (pick one):
    - Set HSE_API_TOKEN to a long random secret (recommended):
          openssl rand -hex 32
      Then send it as:  Authorization: Bearer <token>
    - Or bind loopback only:            HSE_BIND=127.0.0.1:8080
    - Or, if you really want an open instance and understand the consequence:
          HSE_ALLOW_PUBLIC_NO_AUTH=1

  /api/v1/health stays open either way so platform health checks work.
REFUSAL
    exit 1
fi

# The state directory lives on the mounted volume (HOME=/data). Without a
# volume this still works, but the scan store is discarded on every redeploy —
# warn once, since silent data loss is worse than a slow start.
mkdir -p "${HOME}/.huntsman"
if ! mountpoint -q /data 2>/dev/null && [ "${HSE_QUIET_VOLUME_WARNING:-0}" != "1" ]; then
    echo "hse: /data is not a mounted volume — the scan database will NOT survive a redeploy." >&2
    echo "hse: attach a persistent volume at /data to keep scan history." >&2
fi

case "${1:-serve}" in
    serve)
        exec hse serve --bind "${HSE_BIND}"
        ;;
    ai-daemon)
        # The background poller that analyses newly-completed scans. Runs as its
        # own service pointing at the same volume.
        exec hse-ai-daemon
        ;;
    *)
        exec hse "$@"
        ;;
esac
