#!/usr/bin/env bash
# Canonical lifecycle. No opt-in flags.
#   bash scripts/lifecycle.sh
# builds the locked binary, runs check, records state, commits non-secret
# changes, and pushes main. Termux aarch64, no root, no ports below 1024.
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STATE_DIR="${HUNTSMAN_HOME:-$HOME/.huntsman}"
LOG="$STATE_DIR/lifecycle.log"
STATE="$STATE_DIR/lifecycle-state"
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR" || true

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"
}

die() {
  log "error: $*"
  printf 'error: %s\n' "$*" >&2
  printf 'state=%s\nlog=%s\n' "$STATE" "$LOG" >&2
  exit 1
}

write_state() {
  umask 077
  cat > "$STATE" <<EOF
updated=$(date -u +%Y-%m-%dT%H:%M:%SZ)
revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)
phase=$1
status=$2
detail=$3
EOF
  chmod 0600 "$STATE" || true
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/huntsman-recon-target}"
BIN="$CARGO_TARGET_DIR/debug/huntsman-recon"

build() {
  need cargo
  log "build start rustc=$(rustc --version 2>/dev/null || echo missing)"
  write_state build running "cargo build --locked --bin huntsman-recon"
  cargo build --locked --bin huntsman-recon
  log "build ok"
  write_state build ok "$BIN"
}

check_cmd() {
  [[ -x "$BIN" ]] || build
  log "check start"
  write_state check running "$BIN check"
  "$BIN" check
  log "check ok"
  write_state check ok "huntsman-recon check"
}

test_cmd() {
  need cargo
  log "test start"
  write_state test running "cargo test --locked --lib --test-threads=1"
  set +e
  cargo test --locked --lib -- --test-threads=1
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    log "test ok"
    write_state test ok "lib tests"
    return 0
  fi
  if [[ "$status" -eq 137 ]]; then
    log "test killed (memory). build and check still gate sync"
    write_state test degraded "SIGKILL; retry when memory is free"
    return 0
  fi
  write_state test failed "exit $status"
  die "tests failed with exit $status"
}

secret_path() {
  case "$1" in
    *.env|*.env.*|*.pem|*.key|*id_rsa*|*id_ed25519*|*/keys/*|*credentials*|*secret*)
      return 0
      ;;
  esac
  return 1
}

sync_cmd() {
  need git
  [[ -d .git ]] || die "not a git checkout; clone the canonical repo before sync"
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$branch" == "main" ]] || die "sync refuses non-main branch: $branch"
  write_state sync running "$branch"
  mapfile -t dirty < <(git status --porcelain)
  if [[ ${#dirty[@]} -gt 0 ]]; then
    for line in "${dirty[@]}"; do
      path="${line:3}"
      if secret_path "$path"; then
        write_state sync refused "$path"
        die "refusing to commit secret-looking path: $path"
      fi
    done
    git add -A
    git commit -m "lifecycle: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    log "committed $(git rev-parse --short HEAD)"
  else
    log "clean tree"
  fi
  git remote get-url origin >/dev/null 2>&1 || die "no origin remote"
  if ! git push origin main; then
    write_state sync failed "git push origin main"
    die "push failed; credentials or network. Local commit is kept. See $LOG"
  fi
  log "pushed $(git rev-parse --short HEAD)"
  write_state sync ok "$(git rev-parse HEAD)"
}

cmd="${1:-all}"
case "$cmd" in
  build) build ;;
  test) test_cmd ;;
  run) check_cmd ;;
  sync) sync_cmd ;;
  all)
    build
    check_cmd
    test_cmd
    sync_cmd
    printf 'lifecycle ok revision=%s\n' "$(git rev-parse --short HEAD)"
    printf 'state=%s\n' "$STATE"
    ;;
  *)
    die "usage: bash scripts/lifecycle.sh [all|build|test|run|sync]"
    ;;
esac
