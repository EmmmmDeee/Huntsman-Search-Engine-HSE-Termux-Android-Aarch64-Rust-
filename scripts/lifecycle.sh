#!/usr/bin/env bash
# Canonical lifecycle. No opt-in flags.
#   bash scripts/lifecycle.sh
# builds the locked binary, runs check, records state, commits non-secret
# changes, and pushes main. Direct sync must pass the same checks as all.
# Termux aarch64, no root, no ports below 1024.
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
# Ephemeral only: a previous process or persisted state cannot authorise a push.
SYNC_VERIFIED=0
SYNC_BASE_HEAD=""
SYNC_EXPECTED_TREE=""

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
    log "test interrupted (exit 137); refusing to sync unverified changes"
    write_state test failed "exit 137; tests incomplete (SIGKILL or out of memory)"
    die "tests interrupted (exit 137); refusing sync"
  fi
  write_state test failed "exit $status"
  die "tests failed with exit $status"
}

secret_path() {
  case "$1" in
    *.env|*.env.*|*.pem|*.key|*id_rsa*|*id_ed25519*|keys/*|*/keys/*|*credentials*|*secret*)
      return 0
      ;;
  esac
  return 1
}


# Enumerate candidate paths before hashing or staging them. Repeat this after
# tests so that a newly created secret-looking path is also refused.
scan_changed_paths() {
  # Every path that `git add -A` and `git commit` would take, one entry per file and unquoted:
  # untracked files (not the directory that holds them), tracked changes, and what is staged.
  # `git status --porcelain` lists an untracked directory as one entry and quotes a name with a
  # space or a non-ASCII character, so a secret inside a directory or behind a quote got past
  # secret_path. A listing that fails stops the sync.
  listing="$(mktemp "$STATE_DIR/changed-paths.XXXXXX")"
  {
    git ls-files -z --others --exclude-standard &&
      git ls-files -z --modified --deleted &&
      git diff -z --cached --name-only
  } > "$listing" || {
    rm -f "$listing"
    die "could not list the changed paths"
  }
  mapfile -d '' -t dirty < "$listing"
  rm -f "$listing"
  if [[ ${#dirty[@]} -gt 0 ]]; then
    for path in "${dirty[@]}"; do
      if secret_path "$path"; then
        write_state sync refused "$path"
        die "refusing to commit secret-looking path: $path"
      fi
    done
  fi
}

# Hash exactly the Git tree that 'git add -A' would stage, without changing the
# operator's actual index. Git trees cover contents, modes, paths, and deletions.
# Only ephemeral index files are used; state and global Git configuration survive.
candidate_tree() (
  local tmp
  tmp="$(mktemp -d "$STATE_DIR/lifecycle-index.XXXXXX")" || exit 1
  trap 'rm -rf "$tmp"' EXIT
  export GIT_INDEX_FILE="$tmp/index"
  git read-tree HEAD || exit 1
  git add -A || exit 1
  git write-tree
)

prepare_sync() {
  need git
  [[ -d .git ]] || die "not a git checkout; clone the canonical repo before sync"
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$branch" == "main" ]] || die "sync refuses non-main branch: $branch"
  scan_changed_paths
  SYNC_BASE_HEAD="$(git rev-parse HEAD)" || die "could not read local HEAD"
  SYNC_EXPECTED_TREE="$(candidate_tree)" || die "could not fingerprint the candidate tree"
  log "verification candidate head=$SYNC_BASE_HEAD tree=$SYNC_EXPECTED_TREE"
}

sync_cmd() {
  # 'all' captures the candidate before build/tests; direct 'sync' captures it here.
  [[ -n "$SYNC_EXPECTED_TREE" ]] || prepare_sync
  if [[ "$SYNC_VERIFIED" != "1" ]]; then
    log "sync verification: running build, check, and lib tests"
    build
    check_cmd
    test_cmd
    SYNC_VERIFIED=1
  fi

  # A successful test authorises only the *same* source tree. Neither a changing
  # worktree nor a concurrent checkout/commit may be silently published.
  [[ "$(git rev-parse HEAD)" == "$SYNC_BASE_HEAD" ]] ||
    die "HEAD changed during verification; refusing sync"
  scan_changed_paths
  local current_tree
  current_tree="$(candidate_tree)" || die "could not recheck the candidate tree"
  [[ "$current_tree" == "$SYNC_EXPECTED_TREE" ]] ||
    die "worktree changed during verification; refusing sync"

  write_state sync running "$branch"
  if [[ ${#dirty[@]} -gt 0 ]]; then
    git add -A
    # Close the race between the second snapshot and the real index write.
    [[ "$(git write-tree)" == "$SYNC_EXPECTED_TREE" ]] ||
      die "staged tree differs from verified tree; refusing commit and push"
    git commit -m "lifecycle: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # A pre-commit or commit-msg hook may change what the commit actually holds.
    [[ "$(git rev-parse 'HEAD^{tree}')" == "$SYNC_EXPECTED_TREE" ]] ||
      die "committed tree differs from verified tree; refusing push"
    log "committed $(git rev-parse --short HEAD)"
  else
    [[ "$(git rev-parse 'HEAD^{tree}')" == "$SYNC_EXPECTED_TREE" ]] ||
      die "clean tree differs from verified tree; refusing push"
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
    prepare_sync
    build
    check_cmd
    test_cmd
    SYNC_VERIFIED=1
    sync_cmd
    printf 'lifecycle ok revision=%s\n' "$(git rev-parse --short HEAD)"
    printf 'state=%s\n' "$STATE"
    ;;
  *)
    die "usage: bash scripts/lifecycle.sh [all|build|test|run|sync]"
    ;;
esac
