#!/data/data/com.termux/files/usr/bin/bash
# Offline from GitHub Actions; source acquisition still requires public GitHub HTTPS.
# Usage: bash huntsman-termux-pr-verify.sh PR_NUMBER EXACT_40_CHARACTER_COMMIT_SHA
# This script never modifies main, merges a PR, installs a binary, or claims CI passed.
set -Eeuo pipefail
umask 077

fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
if (( $# != 2 )); then
  fail 'usage: bash huntsman-termux-pr-verify.sh PR_NUMBER EXACT_SHA'
fi
PR="$1"
EXPECTED="$2"
[[ "$PR" =~ ^[1-9][0-9]*$ ]] || fail 'PR_NUMBER must be a positive decimal integer'
[[ "$EXPECTED" =~ ^[0-9a-f]{40}$ ]] || fail 'EXACT_SHA must be a 40-character lowercase hexadecimal commit'
[[ "$(id -u)" != 0 ]] || fail 'root is not supported'
[[ "$(uname -m)" == aarch64 ]] || fail 'requires a physical Android AArch64 Termux shell'
[[ "${PREFIX:-}" == /data/data/com.termux/files/usr* ]] || fail 'requires standard Termux PREFIX'
for cmd in git cargo rustc jq mktemp sha256sum chmod date rm mkdir mv rmdir; do
  command -v "$cmd" >/dev/null 2>&1 || fail "missing tool: $cmd"
done

REPO='https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git'
BASE="${HUNTSMAN_HOME:-$HOME/.huntsman}"
[[ ! -L "$BASE" ]] || fail 'refusing symlink HUNTSMAN_HOME'
ROOT="$BASE/local-pr-gates"
[[ "$ROOT" = /* ]] || fail 'HUNTSMAN_HOME must be an absolute path'
[[ ! -L "$ROOT" ]] || fail 'refusing symlink output directory'
mkdir -p "$ROOT"
chmod 700 "$ROOT" || fail 'cannot protect output directory'
SESSION="$(mktemp -d "$ROOT/pr${PR}.XXXXXX")" || fail 'cannot create run directory'
chmod 700 "$SESSION"
SOURCE="$SESSION/source"
TARGET="$ROOT/cache-$EXPECTED"
LOCK="$ROOT/.lock-$EXPECTED"
STATUS=failed
PHASE=initialised
OBSERVED=''
CURRENT=''
GATE_RC=-1
DEVICE_RC=-1
HEAD_VERIFIED=false
LOCK_OWNED=false

finish() {
  local rc="$1" log_sha=''
  trap - EXIT
  set +e
  if [[ -f "$SESSION/gate.log" ]]; then
    log_sha="$(sha256sum "$SESSION/gate.log")"
    log_sha="${log_sha%% *}"
  fi
  jq -n --arg status "$STATUS" --arg phase "$PHASE" \
    --arg expected "$EXPECTED" --arg observed "$OBSERVED" --arg current "$CURRENT" \
    --arg log_sha "$log_sha" --arg utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson pr "$PR" --argjson exit_code "$rc" \
    --argjson gate_exit "$GATE_RC" --argjson device_exit "$DEVICE_RC" \
    --argjson head_verified "$HEAD_VERIFIED" \
    '{schema_version:1, status:$status, phase:$phase, timestamp_utc:$utc,
      pr:$pr, expected_sha:$expected, checked_out_sha:$observed, current_remote_sha:$current,
      current_head_verified:$head_verified, gate_exit:$gate_exit,
      physical_termux_acceptance_exit:$device_exit, command_exit:$exit_code,
      gate_log_sha256:$log_sha,
      limits:"LOCAL HANDSET EVIDENCE ONLY; not GitHub Actions checks, branch-protection approval or deployment"}' \
      > "$SESSION/report.json.tmp" && mv "$SESSION/report.json.tmp" "$SESSION/report.json"
  chmod 600 "$SESSION"/*.log "$SESSION"/*.json 2>/dev/null || true
  if [[ "$LOCK_OWNED" == true ]]; then rmdir "$LOCK" 2>/dev/null || true; fi
  if [[ -d "$SOURCE" ]]; then rm -rf -- "$SOURCE"; fi
  printf 'RESULT  %s (phase=%s, exit=%s)\nREPORT  %s\n' "$STATUS" "$PHASE" "$rc" "$SESSION/report.json" >&2
}
trap 'finish $?' EXIT

# Prevent concurrent builds from sharing the same Cargo target directory. A stale lock
# after abrupt termination requires human inspection; never delete someone else's lock.
mkdir "$LOCK" 2>/dev/null || fail "another verification owns cache lock: $LOCK"
LOCK_OWNED=true
PHASE=fetch
export GIT_TERMINAL_PROMPT=0
mkdir "$SOURCE"
git -C "$SOURCE" init -q
git -C "$SOURCE" fetch -q --no-tags --depth=1 "$REPO" "refs/pull/$PR/head" \
  > "$SESSION/fetch.log" 2>&1 || fail 'failed to fetch public PR head; inspect fetch.log'
OBSERVED="$(git -C "$SOURCE" rev-parse --verify FETCH_HEAD^{commit})" || fail 'invalid fetched commit'
[[ "$OBSERVED" == "$EXPECTED" ]] || fail "PR head changed: expected $EXPECTED, got $OBSERVED"
git -C "$SOURCE" -c advice.detachedHead=false checkout -q --detach "$OBSERVED" || fail 'checkout failed'
[[ "$(git -C "$SOURCE" rev-parse HEAD)" == "$EXPECTED" ]] || fail 'checkout SHA mismatch'

# The existing xtask runs shell syntax, rustfmt, strict clippy, full locked Rust tests,
# the actual CLI self-check and tracked/untracked tree-integrity verification.
PHASE=rust_gate
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_BUILD_DIR="$TARGET"
set +e
(cd "$SOURCE" && cargo run --locked -p xtask -- gate full) > "$SESSION/gate.log" 2>&1
GATE_RC=$?
set -e
[[ "$GATE_RC" == 0 ]] || fail "Rust gate exited $GATE_RC; inspect gate.log"

PHASE=binary_identity
BIN="$TARGET/debug/huntsman-recon"
[[ -f "$BIN" && -x "$BIN" ]] || fail 'verified binary not present after cargo gate'
BUILD_SHA="$("$BIN" build-sha 2> "$SESSION/build-sha.log")" || fail 'binary build-sha failed'
[[ "$BUILD_SHA" == "$EXPECTED" ]] || fail "binary identifies different commit: $BUILD_SHA"

# This is real device validation of the candidate binary, not the installed version.
PHASE=physical_acceptance
set +e
HSE_BIN="$BIN" HUNTSMAN_HOME="$SESSION/acceptance" \
  bash "$SOURCE/scripts/termux-runtime-acceptance.sh" \
  > "$SESSION/physical-acceptance.log" 2>&1
DEVICE_RC=$?
set -e
[[ "$DEVICE_RC" == 0 ]] || fail "physical Termux acceptance exited $DEVICE_RC"

# A post-test read must still show the same PR head: no stale-head PASS.
PHASE=postflight_head
REMOTE="$(git ls-remote "$REPO" "refs/pull/$PR/head" 2> "$SESSION/postflight.log")" ||
  fail 'remote PR head could not be rechecked'
CURRENT="${REMOTE%%[[:space:]]*}"
[[ "$CURRENT" == "$EXPECTED" ]] || fail "PR advanced while testing; now $CURRENT"
HEAD_VERIFIED=true
STATUS=passed_local_only
PHASE=complete
printf 'PASS  exact-commit Rust gate + physical Termux acceptance, locally; GitHub Actions remains unverified\n'
