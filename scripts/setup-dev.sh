#!/usr/bin/env bash
# Developer environment setup for Huntsman Search Engine.
#
# Installs the Rust toolchain + system build dependencies and configures your
# environment so you can build, test, and lint HSE from source. Idempotent and
# non-interactive — safe to re-run.
#
# Scope vs. the other scripts in this repo:
#   * THIS script (scripts/setup-dev.sh) — set up a DEVELOPER environment
#     (toolchain + rustfmt/clippy + deps + key file), without installing the
#     binary. Run it on your own machine.
#   * install.sh — END-USER installer (the curl|bash one-liner): installs deps,
#     builds, and installs the `hse` binary to your PATH.
#   * .claude/hooks/session-start.sh — Claude Code on the web: calls this script
#     with --deps-only to provision the session container.
#
# Usage:
#   scripts/setup-dev.sh              # install deps + configure env + verify
#   scripts/setup-dev.sh --deps-only  # install deps/toolchain only (skip verify)
#
# TLS is rustls and SQLite is bundled (rusqlite), so NO system openssl/sqlite is
# required — only a C compiler (for the bundled SQLite + the ring/aws-lc TLS).
set -uo pipefail

DEPS_ONLY=0
[ "${1:-}" = "--deps-only" ] && DEPS_ONLY=1

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }

# Run a privileged command as root when needed (no-op prefix if already root).
as_root() {
  if [ "$(id -u)" = "0" ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else "$@"
  fi
}

# Only invoke the package manager if something we need is actually missing.
deps_present() {
  command -v cc >/dev/null 2>&1 &&
    command -v pkg-config >/dev/null 2>&1 &&
    command -v git >/dev/null 2>&1 &&
    command -v make >/dev/null 2>&1 &&
    command -v perl >/dev/null 2>&1
}

install_system_deps() {
  if deps_present; then
    log "system build dependencies already present"
    return 0
  fi
  if [ -n "${TERMUX_VERSION:-}" ] && command -v pkg >/dev/null 2>&1; then
    log "Termux detected — installing build deps via pkg"
    pkg install -y rust git clang make pkg-config openssl-tool binutils || true
  elif command -v apt-get >/dev/null 2>&1; then
    log "Debian/Ubuntu detected — installing build deps via apt"
    export DEBIAN_FRONTEND=noninteractive
    as_root apt-get update -y -q || true
    as_root apt-get install -y -q --no-install-recommends \
      build-essential clang llvm pkg-config perl make git curl ca-certificates || true
  elif command -v brew >/dev/null 2>&1; then
    log "macOS detected — ensuring Xcode CLT + Homebrew deps"
    xcode-select --install 2>/dev/null || true
    brew install pkg-config llvm || true
  else
    warn "no known package manager (pkg/apt/brew) found — please ensure a C compiler, pkg-config, git, make, perl and curl are installed"
  fi
}

ensure_rust() {
  # Termux installs rust via pkg above (a system package with no rustup
  # underneath — it ignores the pin below and tracks whatever version
  # Termux's package repo ships); elsewhere bootstrap rustup if cargo is
  # absent. rust-toolchain.toml (repo root) pins the exact rustup toolchain
  # (currently 1.97.1, components rustfmt+clippy, target aarch64-linux-android)
  # so a plain `--default-toolchain stable` bootstrap here still ends up
  # running the pinned version inside this repo — rustup auto-installs and
  # switches to a rust-toolchain.toml's pin the first time cargo/rustc runs in
  # a directory that has one, with no extra step needed here.
  if ! command -v cargo >/dev/null 2>&1; then
    if [ -z "${TERMUX_VERSION:-}" ]; then
      log "installing Rust via rustup (stable; the repo's rust-toolchain.toml pin takes over inside it)"
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
        sh -s -- -y --profile minimal --default-toolchain stable
    fi
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
  fi
  # rustfmt + clippy are needed for the `fmt`/`clippy` gates (rustup toolchains).
  # Run from the repo root (see caller), so this targets the pinned toolchain
  # rust-toolchain.toml selects, not whatever `rustup default` is.
  if command -v rustup >/dev/null 2>&1; then
    rustup component add rustfmt clippy >/dev/null 2>&1 || true
  fi
  if command -v rustc >/dev/null 2>&1; then
    log "toolchain: $(rustc --version)"
  else
    warn "rustc not on PATH — open a new shell, or run: . \"\$HOME/.cargo/env\""
  fi
}

configure_env() {
  # The API-key file modules read at runtime (chmod 0600; never committed).
  # HSE ships with embedded keys, so an empty file is fine to start; run
  # `hse provision` (or `cargo run -- provision`) to write the full template.
  local envf="$HOME/.huntsman.env"
  if [ -f "$envf" ]; then
    log "$envf already present — leaving it untouched"
    return 0
  fi
  log "creating $envf (chmod 0600)"
  ( umask 077
    cat > "$envf" <<'ENVEOF'
# Huntsman Search Engine — API keys. All keys MUST be prefixed HUNTSMAN_.
# chmod 0600 — never commit. The v0.2+ free modules need no keys at all.
# Run `hse provision` (or `cargo run -- provision`) for the full key template,
# or `hse serve` -> Settings to paste/save keys from the browser.
ENVEOF
  )
  chmod 0600 "$envf" 2>/dev/null || true
}

verify() {
  if ! command -v cargo >/dev/null 2>&1; then
    warn "cargo unavailable — skipping verification"
    return 0
  fi
  log "format check  (cargo fmt --all -- --check)"
  cargo fmt --all -- --check || warn "formatting issues — run: cargo fmt --all"
  log "lint          (cargo clippy --all-targets --locked -- -D warnings)"
  cargo clippy --all-targets --locked -- -D warnings || warn "clippy reported issues"
  log "build         (cargo build --locked)"
  if ! cargo build --locked; then
    warn "build failed"
    return 1
  fi
  log "dev environment ready. Next:  cargo test --all --locked   |   cargo run -- doctor"
}

main() {
  local script_dir
  script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
  cd "$script_dir/.." || exit 1
  log "Huntsman Search Engine — developer setup ($(uname -s) $(uname -m))"
  install_system_deps
  ensure_rust
  configure_env
  if [ "$DEPS_ONLY" = "1" ]; then
    log "--deps-only: skipping verification"
    exit 0
  fi
  verify
}

main "$@"
