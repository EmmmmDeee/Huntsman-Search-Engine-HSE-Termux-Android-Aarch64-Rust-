#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'

# Huntsman real-device Termux acceptance harness.
# Canonical invocation (does not depend on the Git executable bit):
#   bash scripts/termux-runtime-acceptance.sh
#
# Verifies runtime facts that cross-build CI cannot prove. The harness is
# fail-closed, bounded by timeouts, and cleans up every server process it starts.

HSE_BIN="${HSE_BIN:-$(command -v hse || true)}"
STATE_DIR="${HUNTSMAN_HOME:-$HOME/.huntsman}"
REPORT="${HSE_ACCEPTANCE_REPORT:-$STATE_DIR/termux-acceptance.txt}"
TIMEOUT_SECS="${HSE_ACCEPTANCE_TIMEOUT:-20}"
SERVER_TIMEOUT_SECS="${HSE_ACCEPTANCE_SERVER_TIMEOUT:-30}"
HEALTH_URL="${HSE_ACCEPTANCE_HEALTH_URL:-http://127.0.0.1:8080/api/v1/health}"
SERVER_LOG="${HSE_ACCEPTANCE_SERVER_LOG:-$STATE_DIR/termux-acceptance-server.log}"
SERVER_PID=""

mkdir -p "$STATE_DIR"
: > "$REPORT"
: > "$SERVER_LOG"

pass() { printf 'PASS  %s\n' "$*" | tee -a "$REPORT"; }
fail() { printf 'FAIL  %s\n' "$*" | tee -a "$REPORT" >&2; exit 1; }
note() { printf 'INFO  %s\n' "$*" | tee -a "$REPORT"; }

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM HUP

wait_for_health() {
  deadline=$(( $(date +%s) + SERVER_TIMEOUT_SECS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      note 'server exited before health became ready'
      tail -n 40 "$SERVER_LOG" >>"$REPORT" 2>/dev/null || true
      return 1
    fi
    if curl --fail --silent --show-error --max-time 2 "$HEALTH_URL" >>"$REPORT" 2>&1; then
      printf '\n' >>"$REPORT"
      return 0
    fi
    sleep 1
  done
  note "health endpoint did not become ready within ${SERVER_TIMEOUT_SECS}s"
  tail -n 40 "$SERVER_LOG" >>"$REPORT" 2>/dev/null || true
  return 1
}

stop_server() {
  [ -n "$SERVER_PID" ] || return 0
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    deadline=$(( $(date +%s) + 10 ))
    while kill -0 "$SERVER_PID" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do
      sleep 1
    done
    if kill -0 "$SERVER_PID" 2>/dev/null; then
      kill -KILL "$SERVER_PID" 2>/dev/null || true
    fi
  fi
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

start_and_verify_server() {
  : > "$SERVER_LOG"
  "$HSE_BIN" serve >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  wait_for_health || return 1
  pass "server health responds: $HEALTH_URL"
  stop_server
  pass 'server stops cleanly under harness control'
}

note "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "uname=$(uname -a)"
note "prefix=${PREFIX:-unknown}"

[ -n "$HSE_BIN" ] || fail 'hse binary not found in PATH'
[ -x "$HSE_BIN" ] || fail "hse is not executable: $HSE_BIN"
pass "binary executable: $HSE_BIN"

for cmd in timeout curl date grep tail; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required Termux command not found: $cmd"
done
pass 'required runtime commands available'

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

# Runtime secret invariant: a configured HIBP key must not be required merely
# to start CLI metadata paths. Never print the value.
if [ -n "${HIBP_API_KEY:-}" ]; then
  pass 'HIBP_API_KEY is available at runtime (value intentionally not recorded)'
else
  note 'HIBP_API_KEY is not set; runtime metadata paths still executed without it'
fi

# Optional self-test: execute only if this build advertises one. This avoids
# inventing a CLI contract.
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

# Application-runtime acceptance. The repository contract defines `hse serve`
# as loopback-only by default and exposes the dependency-free liveness endpoint
# at /api/v1/health. Exercise start -> readiness -> stop -> restart -> readiness.
if start_and_verify_server; then
  pass 'server lifecycle pass=1'
else
  fail 'server failed initial lifecycle/readiness acceptance'
fi

if start_and_verify_server; then
  pass 'server lifecycle pass=2 (restart)'
else
  fail 'server failed restart lifecycle/readiness acceptance'
fi

pass 'TERMUX_RUNTIME_ACCEPTANCE'
note "report=$REPORT"
note "server_log=$SERVER_LOG"
