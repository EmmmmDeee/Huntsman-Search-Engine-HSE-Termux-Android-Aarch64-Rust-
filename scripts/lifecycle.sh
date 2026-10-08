#!/usr/bin/env bash
# One command for the canonical crate: build, test, run, sync.
# Termux aarch64, no root, no ports below 1024.
# Usage: bash scripts/lifecycle.sh [build|test|run|sync|all]
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STATE_DIR="${HUNTSMAN_HOME:-$HOME/.huntsman}"
LOG="$STATE_DIR/lifecycle.log"
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR" || true

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"
}

die() {
  log "error: $*"
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cmd="${1:-all}"

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

build() {
  need cargo
  log "build start rustc=$(rustc --version 2>/dev/null || echo missing)"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/huntsman-recon-target}"
  cargo build --locked --bin huntsman-recon
  log "build ok target=$CARGO_TARGET_DIR"
}

test_cmd() {
  need cargo
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/huntsman-recon-target}"
  log "test start"
  if ! cargo test --locked --bin huntsman-recon --lib -- --test-threads=1; then
    die "tests failed or the compiler was killed (often low memory on a phone; retry after freeing RAM)"
  fi
  log "test ok"
}

run_cmd() {
  need cargo
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/huntsman-recon-target}"
  bin="$CARGO_TARGET_DIR/debug/huntsman-recon"
  if [[ ! -x "$bin" ]]; then
    build
  fi
  log "run check"
  "$bin" check
  log "run ok"
}

sync_cmd() {
  need git
  if [[ ! -d .git ]]; then
    die "not a git checkout; clone the canonical repo before sync"
  fi
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$branch" == "main" ]] || die "sync refuses non-main branch: $branch"
  if [[ -n "$(git status --porcelain)" ]]; then
    if [[ "${HUNTSMAN_SYNC_COMMIT:-}" != "1" ]]; then
      die "dirty tree; set HUNTSMAN_SYNC_COMMIT=1 to commit, or commit yourself"
    fi
    git add -A
    git commit -m "${HUNTSMAN_SYNC_MESSAGE:-lifecycle: operator sync}"
    log "committed"
  else
    log "clean tree"
  fi
  if git remote get-url origin >/dev/null 2>&1; then
    if ! git push origin main; then
      die "push failed; credentials or network. Local state is in $LOG"
    fi
    log "pushed $(git rev-parse --short HEAD)"
  else
    die "no origin remote"
  fi
}

case "$cmd" in
  build) build ;;
  test) test_cmd ;;
  run) run_cmd ;;
  sync) sync_cmd ;;
  all)
    build
    run_cmd
    if [[ "${HUNTSMAN_SYNC:-}" == "1" ]]; then
      sync_cmd
    else
      log "sync skipped (set HUNTSMAN_SYNC=1 to push)"
    fi
    ;;
  *)
    die "usage: bash scripts/lifecycle.sh [build|test|run|sync|all]"
    ;;
esac
