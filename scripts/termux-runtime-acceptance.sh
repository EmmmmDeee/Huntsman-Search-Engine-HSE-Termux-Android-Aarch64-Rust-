#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Huntsman real-device Termux acceptance harness.
# Run after installing/upgrading hse. This verifies runtime facts that cross-build CI cannot prove.

HSE_BIN="${HSE_BIN:-$(command -v hse || true)}"
STATE_DIR="${HUNTSMAN_HOME:-$HOME/.huntsman}"
REPORT="${HSE_ACCEPTANCE_REPORT:-$STATE_DIR/termux-acceptance.txt}"
TIMEOUT_SECS="${HSE_ACCEPTANCE_TIMEOUT:-20}"

mkdir -p "$STATE_DIR"
: > "$REPORT"

pass() { printf 'PASS  %s\n' "$*" | tee -a "$REPORT"; }
fail() { printf 'FAIL  %s\n' "$*" | tee -a "$REPORT" >&2; exit 1; }
note() { printf 'INFO  %s\n' "$*" | tee -a "$REPORT"; }

note "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "uname=$(uname -a)"
note "prefix=${PREFIX:-unknown}"

[ -n "$HSE_BIN" ] || fail 'hse binary not found in PATH'
[ -x "$HSE_BIN" ] || fail "hse is not executable: $HSE_BIN"
pass "binary executable: $HSE_BIN"

case "$(uname -m)" in
  aarch64|arm64) pass 'runtime architecture is ARM64' ;;
  *) fail "unexpected runtime architecture: $(uname -m)" ;;
esac

case "${PREFIX:-}" in
  /data/data/com.termux/files/usr*) pass 'Termux PREFIX detected' ;;
  *) fail "not running in a standard Termux PREFIX: ${PREFIX:-unset}" ;;
esac

if timeout "$TIMEOUT_SECS" "$HSE_BIN" --version >>"$REPORT" 2>&1; then
  pass 'hse --version executes'
else
  fail 'hse --version failed or timed out'
fi

if timeout "$TIMEOUT_SECS" "$HSE_BIN" --help >>"$REPORT" 2>&1; then
  pass 'hse --help executes'
else
  fail 'hse --help failed or timed out'
fi

# The runtime must be able to create and persist its state directory.
probe="$STATE_DIR/.acceptance-write-$$"
printf '%s\n' 'huntsman-runtime-acceptance' > "$probe" || fail 'state directory is not writable'
grep -qx 'huntsman-runtime-acceptance' "$probe" || fail 'state persistence probe mismatch'
rm -f "$probe"
pass "state directory writable: $STATE_DIR"

# Runtime secret invariant: a configured HIBP key must not be required merely to start CLI metadata paths.
# Never print the value. A missing key is valid for this acceptance test.
if [ -n "${HIBP_API_KEY:-}" ]; then
  pass 'HIBP_API_KEY is available at runtime (value intentionally not recorded)'
else
  note 'HIBP_API_KEY is not set; runtime metadata paths still executed without it'
fi

# Optional self-test: execute only if this build advertises one. This avoids inventing a CLI contract.
help="$($HSE_BIN --help 2>&1 || true)"
if printf '%s\n' "$help" | grep -Eq '(^|[[:space:]])(self-test|selftest)([[:space:]]|$)'; then
  cmd=self-test
  printf '%s\n' "$help" | grep -Eq '(^|[[:space:]])selftest([[:space:]]|$)' && cmd=selftest
  if timeout 180 "$HSE_BIN" "$cmd" >>"$REPORT" 2>&1; then
    pass "hse $cmd executes"
  else
    fail "hse $cmd failed"
  fi
else
  note 'no self-test command advertised; skipped rather than assuming unsupported CLI'
fi

pass 'TERMUX_RUNTIME_ACCEPTANCE'
note "report=$REPORT"
