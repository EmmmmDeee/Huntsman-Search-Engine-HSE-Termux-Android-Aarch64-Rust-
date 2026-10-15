#!/data/data/com.termux/files/usr/bin/bash
# hse-baseline.sh
#
# Bounded, read-only baseline for the HSE upgrade pass, run on Termux.
#   toolchain -> source -> branch -> checks -> summary
#
# It never pushes, merges, commits, installs the app, or deploys. Every run
# leaves $WORK/reports/<stamp>/SUMMARY.txt, including runs that abort early.
#
# Environment overrides:
#   REPO_URL      repository to clone               (default: the HSE repo)
#   WORK          working root                       (default: $HOME/hse-upgrade)
#   REF           commit-ish to baseline             (default: origin/main)
#   JOBS          parallel cargo jobs                (default: 2; use 1 on low memory)
#   SKIP_TESTS=1  run the checks but not the tests
#   RUN_RELEASE=1 also run the release build (memory-heavy)
#
# Examples:
#   bash hse-baseline.sh
#   SKIP_TESTS=1 bash hse-baseline.sh
#   JOBS=1 RUN_RELEASE=1 bash hse-baseline.sh
#   REF=<sha-or-branch> bash hse-baseline.sh

set -u

# --- configuration ---------------------------------------------------------
REPO_URL="${REPO_URL:-https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git}"
WORK="${WORK:-$HOME/hse-upgrade}"
REF="${REF:-origin/main}"
JOBS="${JOBS:-2}"

REPO_DIR="$WORK/src"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
REPORT_DIR="$WORK/reports/$STAMP"
RESULTS="$REPORT_DIR/results.tsv"
GITLOG="$REPORT_DIR/git.log"
BRANCH="hse-upgrade/baseline-$STAMP"
LOCK="$WORK/.baseline.lock"

# --- run state -------------------------------------------------------------
FAILS=0
HAVE_LOCK=0
ABORT_REASON=""
MAIN_SHA=""
INSTALLED="unknown"

# --- helpers ---------------------------------------------------------------
log()        { printf '%s\n' "$*" | tee -a "$REPORT_DIR/run.log"; }
need()       { command -v "$1" >/dev/null 2>&1; }
tree_clean() { [ -z "$(git -C "$REPO_DIR" status --porcelain)" ]; }

# abort REASON...: stop the run. The EXIT trap writes the summary and releases the lock.
abort() {
  ABORT_REASON="$*"
  log "ABORT: $ABORT_REASON"
  exit 1
}

# record STATUS NAME TIME EXIT LOG: append one row to the results table.
record() {
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$RESULTS"
  if [ "$1" = FAIL ]; then FAILS=$((FAILS + 1)); fi
}

# table: print the results as an aligned table.
table() {
  local st nm tm rc lg   # local, or the read loop overwrites the caller's variables
  printf '%-6s %-24s %-8s %-5s %s\n' RESULT STEP TIME EXIT LOG
  while IFS=$'\t' read -r st nm tm rc lg; do
    printf '%-6s %-24s %-8s %-5s %s\n' "$st" "$nm" "$tm" "$rc" "$lg"
  done < "$RESULTS"
}

# write_summary HEADLINE [REASON]: write SUMMARY.txt and print it.
write_summary() {
  {
    echo "$1"
    if [ -n "${2:-}" ]; then echo "reason:    $2"; fi
    echo "commit:    ${MAIN_SHA:-not resolved}${MAIN_SHA:+ ($REF)}"
    echo "installed: $INSTALLED"
    echo
    table
    echo
    if [ -n "${2:-}" ]; then
      echo "failures recorded before the stop: $FAILS (incomplete run, not a baseline)"
    else
      echo "failures: $FAILS"
    fi
    echo "log: $REPORT_DIR/run.log"
    echo "nothing was pushed, merged, installed, or deployed"
  } > "$REPORT_DIR/SUMMARY.txt"
  cat "$REPORT_DIR/SUMMARY.txt"
}

# finish runs on every exit. It guarantees a summary and releases the lock.
finish() {
  local rc=$?
  if [ ! -s "$REPORT_DIR/SUMMARY.txt" ]; then
    write_summary "HSE baseline $STAMP did not finish (exit $rc)" "${ABORT_REASON:-unexpected exit; see run.log}"
  fi
  if [ "$HAVE_LOCK" = 1 ]; then rm -rf "$LOCK" 2>/dev/null; fi
  exit "$rc"
}

# step NAME COMMAND...: run a check, keep its output in a log file, record the result.
step() {
  local name="$1"; shift
  local file="$REPORT_DIR/$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_').log"
  local start rc status
  start=$(date +%s)
  log "==> $name"
  "$@" >"$file" 2>&1
  rc=$?
  status=PASS
  if [ "$rc" -ne 0 ]; then status=FAIL; fi
  record "$status" "$name" "$(( $(date +%s) - start ))s" "$rc" "$(basename "$file")"
  log "    $status (exit $rc), output in $file"
}

# skip NAME REASON: a step that was intentionally not run.
skip() {
  record SKIP "$1" - - "$2"
  log "==> SKIP $1 ($2)"
}

# missing NAME TOOL: a required tool is absent, so the check fails without running.
missing() {
  record FAIL "$1" - - "$2 not installed"
  log "==> $1: FAIL ($2 not installed)"
}

# run_git MESSAGE GIT-ARGS...: run git with output in GITLOG. On failure, show the tail and abort.
run_git() {
  local msg="$1"; shift
  if ! git "$@" >"$GITLOG" 2>&1; then
    tail -n 5 "$GITLOG" | sed 's/^/  git: /' | tee -a "$REPORT_DIR/run.log"
    abort "$msg"
  fi
}

# ensure COMMAND PACKAGE: install PACKAGE if COMMAND is missing, then re-check.
ensure() {
  need "$1" && return 0
  log "Installing $2 (pkg install $2)..."
  pkg install -y "$2" >>"$REPORT_DIR/pkg.log" 2>&1 \
    || abort "pkg install $2 failed (see $REPORT_DIR/pkg.log). Try 'pkg update', then rerun"
  need "$1" || abort "$2 installed, but '$1' is still not on PATH"
}

# --- phases ----------------------------------------------------------------
acquire_lock() {
  # One run per WORK directory: a concurrent run would corrupt the shared clone. The lock is a
  # directory holding the owner's PID. A hard-killed run (Termux closed, OOM, logout) cannot run
  # its EXIT trap and so leaves the lock behind; rather than wedge every later run forever, a lock
  # whose owner is no longer running is reclaimed.
  if ! mkdir "$LOCK" 2>/dev/null; then
    local owner
    owner="$(cat "$LOCK/pid" 2>/dev/null || true)"
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
      abort "another run (pid $owner) is using $WORK"
    fi
    log "Reclaiming a stale lock at $LOCK (owner ${owner:-unknown} is not running)"
    rm -rf "$LOCK"
    mkdir "$LOCK" 2>/dev/null || abort "could not take the lock at $LOCK"
  fi
  HAVE_LOCK=1
  echo "$$" > "$LOCK/pid"
}

phase_toolchain() {
  ensure git git
  ensure cargo rust
  {
    echo "date:      $STAMP"
    echo "arch:      $(uname -m)"
    echo "git:       $(git --version)"
    echo "cargo:     $(cargo --version 2>&1)"
    echo "rustc:     $(rustc --version 2>&1)"
    echo "clippy:    $(cargo clippy --version 2>&1 || echo missing)"
    echo "fmt:       $(cargo fmt --version 2>&1 || echo missing)"
    echo "jobs:      $JOBS"
    echo "disk:"; df -h "$HOME" 2>/dev/null
    echo "memory:"; grep -E 'MemTotal|MemAvailable' /proc/meminfo 2>/dev/null
  } > "$REPORT_DIR/environment.txt"
  INSTALLED="$(head -n 1 "$HOME/.huntsman/installed-revision" 2>/dev/null || echo unknown)"
  echo "installed provenance: $INSTALLED" >> "$REPORT_DIR/environment.txt"
}

phase_source() {
  mkdir -p "$WORK" || abort "cannot create $WORK"
  if [ ! -d "$REPO_DIR/.git" ]; then
    log "Cloning $REPO_URL"
    run_git "clone failed. If the repo is private, sign in to GitHub first (gh auth login), or set REPO_URL" \
      clone "$REPO_URL" "$REPO_DIR"
  else
    local origin
    origin="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || echo none)"
    [ "$origin" = "$REPO_URL" ] \
      || abort "existing clone at $REPO_DIR has origin '$origin', expected '$REPO_URL'. Use a different WORK"
    log "Refreshing existing clone at $REPO_DIR"
    run_git "fetch failed (see $GITLOG)" -C "$REPO_DIR" fetch --prune origin
  fi
  if ! tree_clean; then
    git -C "$REPO_DIR" status --short | head -n 10 | sed 's/^/  /' | tee -a "$REPORT_DIR/run.log"
    abort "working tree at $REPO_DIR has uncommitted or untracked changes. Move them aside, or use a different WORK"
  fi
}

phase_branch() {
  MAIN_SHA="$(git -C "$REPO_DIR" rev-parse --verify --quiet "$REF^{commit}" || true)"
  [ -n "$MAIN_SHA" ] || abort "cannot resolve REF=$REF in $REPO_DIR"
  git -C "$REPO_DIR" switch -c "$BRANCH" "$MAIN_SHA" >>"$REPORT_DIR/run.log" 2>&1 \
    || abort "could not create local branch $BRANCH"
  {
    echo "ref:       $REF"
    echo "commit:    $MAIN_SHA"
    echo "subject:   $(git -C "$REPO_DIR" log -1 --format=%s "$MAIN_SHA")"
    echo "branch:    $BRANCH (local only)"
    echo "installed: $INSTALLED"
  } > "$REPORT_DIR/baseline.txt"
  cat "$REPORT_DIR/baseline.txt"
}

phase_checks() {
  # Every cargo command uses --workspace, so no member crate is skipped.
  cd "$REPO_DIR" || abort "cannot enter $REPO_DIR"
  export CARGO_BUILD_JOBS="$JOBS"

  if cargo fmt --version >/dev/null 2>&1; then
    step "fmt check" cargo fmt --all -- --check
  else
    missing "fmt check" "rustfmt"
  fi
  step "cargo check" cargo check --workspace --all-targets --locked
  if cargo clippy --version >/dev/null 2>&1; then
    step "clippy" cargo clippy --workspace --all-targets --locked -- -D warnings
  else
    missing "clippy" "clippy"
  fi
  if [ "${SKIP_TESTS:-0}" = 1 ]; then
    skip "tests" "SKIP_TESTS=1"
  else
    step "tests" cargo test --workspace --locked
  fi
  if [ "${RUN_RELEASE:-0}" = 1 ]; then
    step "release build" cargo build --workspace --release --locked
  else
    skip "release build" "RUN_RELEASE not set (memory-heavy)"
  fi
  step "tree clean after build" tree_clean
}

phase_summary() {
  write_summary "HSE baseline $STAMP"
  log "Branch $BRANCH exists locally only. Report: $REPORT_DIR"
}

main() {
  mkdir -p "$REPORT_DIR" || exit 1
  : > "$RESULTS"
  trap finish EXIT
  acquire_lock
  log "HSE baseline $STAMP"
  log "Report: $REPORT_DIR"
  phase_toolchain
  phase_source
  phase_branch
  phase_checks
  phase_summary
  [ "$FAILS" -eq 0 ]
}

main "$@"
