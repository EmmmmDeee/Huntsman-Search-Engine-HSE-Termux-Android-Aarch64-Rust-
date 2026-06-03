#!/usr/bin/env bash
# SessionStart hook for Claude Code on the web.
#
# Installs the Rust build toolchain + system build dependencies and warms the
# crate cache so `cargo fmt`/`clippy`/`test` work immediately in a web session.
# Idempotent, non-interactive, and scoped to the remote (web) environment so it
# never touches a developer's local checkout.
#
# Project: Huntsman Search Engine — pure-Rust, edition 2024, MSRV 1.88.
# TLS is rustls and SQLite is bundled (rusqlite), so NO system openssl/sqlite
# is required — only a C compiler (for the bundled SQLite + ring/aws-lc).
set -uo pipefail

log() { printf '[session-start] %s\n' "$*" >&2; }

# Web-only: do nothing on a local machine (the repo's own install.sh / manual
# build instructions cover local dev).
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Run a command as root when possible (the web container may already be root).
as_root() {
  if [ "$(id -u)" = "0" ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  fi
}

# ── 1. System build dependencies (best-effort, only if missing) ──────────────
missing=""
for bin in cc clang pkg-config perl make git curl; do
  command -v "$bin" >/dev/null 2>&1 || missing="$missing $bin"
done
if [ -n "$missing" ] && command -v apt-get >/dev/null 2>&1; then
  log "installing system deps:$missing"
  export DEBIAN_FRONTEND=noninteractive
  as_root apt-get update -y -q || true
  as_root apt-get install -y -q --no-install-recommends \
    build-essential clang llvm pkg-config perl make git curl ca-certificates || true
fi

# ── 2. Rust toolchain (rustup, stable ≥ MSRV 1.88) ───────────────────────────
if ! command -v rustup >/dev/null 2>&1; then
  log "installing rustup + stable toolchain"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
fi
# Make cargo available for the rest of this script and persist it for the
# session's agent loop.
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  printf 'export PATH="%s/.cargo/bin:$PATH"\n' "$HOME" >> "$CLAUDE_ENV_FILE"
fi

# Ensure a stable toolchain with the components the checks need (mirrors CI:
# dtolnay/rust-toolchain@stable + components rustfmt, clippy). The repo pins no
# toolchain; edition 2024 + MSRV 1.88 are both satisfied by current stable.
if command -v rustup >/dev/null 2>&1; then
  rustup toolchain install stable --profile minimal --no-self-update >/dev/null 2>&1 || true
  rustup default stable >/dev/null 2>&1 || true
  rustup component add rustfmt clippy >/dev/null 2>&1 || true
fi

# ── 3. Warm the dependency cache ─────────────────────────────────────────────
# Downloaded crates persist in the cached container, so the first clippy/test in
# a session doesn't re-download the whole dependency graph.
if command -v cargo >/dev/null 2>&1 && [ -f Cargo.lock ]; then
  log "fetching crate dependencies"
  cargo fetch --locked >/dev/null 2>&1 || cargo fetch >/dev/null 2>&1 || true
fi

log "ready: $(rustc --version 2>/dev/null || echo 'rustc unavailable')"
exit 0
