#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'

# Huntsman real-device Termux acceptance harness.
# Canonical invocation:
#   bash scripts/termux-runtime-acceptance.sh
#
# Cross-build CI cannot prove these device/runtime properties. Keep this
# harness fail-closed, bounded, non-destructive, and explicit about what it
# actually establishes.

HSE_BIN="${HSE_BIN:-$(command -v hse || true)}"
STATE_DIR="${HUNTSMAN_HOME:-$HOME/.huntsman}"
REPORT="${HSE_ACCEPTANCE_REPORT:-$STATE_DIR/termux-acceptance.txt}"
TIMEOUT_SECS="${HSE_ACCEPTANCE_TIMEOUT:-20}"
SERVER_TIMEOUT_SECS="${HSE_ACCEPTANCE_SERVER_TIMEOUT:-30}"
SERVER_PORT="${HSE_ACCEPTANCE_PORT:-}"
SERVER_PID=""
SERVER_BIND=""
BASE_URL=""
HEALTH_URL=""
MODULES_URL=""
SERVER_LOG="${HSE_ACCEPTANCE_SERVER_LOG:-$STATE_DIR/termux-acceptance-server.log}"

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

choose_port() {
  if [ -n "$SERVER_PORT" ]; then
    return 0
  fi

  # Android/Termux does not guarantee Python. Pick from the high ephemeral
  # range and let the spawned server itself arbitrate ownership. Retry on a
  # bind collision rather than probing with another process and introducing a
  # TOCTOU race.
  SERVER_PORT=$((49152 + (($$ + $(date +%s)) % 16384)))
}

set_urls() {
  SERVER_BIND="127.0.0.1:$SERVER_PORT"
  BASE_URL="http://$SERVER_BIND"
  HEALTH_URL="$BASE_URL/api/v1/health"
  MODULES_URL="$BASE_URL/api/v1/modules"
}

wait_for_health() {
  local deadline
  deadline=$(( $(date +%s) + SERVER_TIMEOUT_SECS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      note 'spawned server exited before health became ready'
      tail -n 60 "$SERVER_LOG" >>"$REPORT" 2>/dev/null || true
      return 1
    fi
    if curl --fail --silent --show-error --max-time 2 "$HEALTH_URL" >>"$REPORT" 2>&1; then
      printf '\n' >>"$REPORT"
      # The responder alone is insufficient: the process we spawned must
      # still be alive after the successful observation.
      kill -0 "$SERVER_PID" 2>/dev/null || return 1
      return 0
    fi
    sleep 1
  done
  note "health endpoint did not become ready within ${SERVER_TIMEOUT_SECS}s"
  tail -n 60 "$SERVER_LOG" >>"$REPORT" 2>/dev/null || true
  return 1
}

verify_functional_api() {
  local body="$STATE_DIR/.acceptance-modules-$$.json"
  rm -f "$body"
  if ! curl --fail --silent --show-error --max-time 5 "$MODULES_URL" -o "$body"; then
    rm -f "$body"
    return 1
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || { rm -f "$body"; return 1; }
  [ -s "$body" ] || { rm -f "$body"; return 1; }
  # Avoid requiring jq on a minimal Termux install. A non-empty successful
  # response from the real module catalogue is a stronger functional probe
  # than the dependency-free liveness route while remaining non-mutating.
  grep -Eq '[\[{]' "$body" || { rm -f "$body"; return 1; }
  rm -f "$body"
}

stop_server() {
  local deadline
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
  "$HSE_BIN" serve --bind "$SERVER_BIND" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  wait_for_health || return 1
  pass "spawned server health responds: $HEALTH_URL"
  verify_functional_api || return 1
  pass "functional modules API responds: $MODULES_URL"
  stop_server
  pass 'spawned server stops under harness control'
}

note "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "uname=$(uname -a)"
note "prefix=${PREFIX:-unknown}"

[ -n "$HSE_BIN" ] || fail 'hse binary not found in PATH'
[ -x "$HSE_BIN" ] || fail "hse is not executable: $HSE_BIN"
pass "binary executable: $HSE_BIN"

for cmd in timeout curl date grep tail env; do
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

# Explicitly test both credential states without recording a real credential.
# These are metadata-only startup paths: neither should require provider access.
if env -u HIBP_API_KEY timeout "$TIMEOUT_SECS" "$HSE_BIN" --version >>"$REPORT" 2>&1; then
  pass 'metadata startup succeeds with HIBP_API_KEY absent'
else
  fail 'metadata startup unexpectedly requires HIBP_API_KEY'
fi

if env HIBP_API_KEY='huntsman-termux-acceptance' timeout "$TIMEOUT_SECS" "$HSE_BIN" --version >>"$REPORT" 2>&1; then
  pass 'metadata startup succeeds with controlled HIBP_API_KEY present'
else
  fail 'metadata startup failed with controlled HIBP_API_KEY present'
fi

# Filesystem persistence is intentionally labelled as such; this is not a
# claim about Huntsman's SQLite/application-state semantics.
probe="$STATE_DIR/.acceptance-write-$$"
printf '%s\n' 'huntsman-runtime-acceptance' > "$probe" || fail 'state directory is not writable'
grep -qx 'huntsman-runtime-acceptance' "$probe" || fail 'filesystem persistence probe mismatch'
rm -f "$probe"
pass "filesystem state directory writable/readable: $STATE_DIR"

# Optional self-test: execute only if this build advertises one.
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

choose_port
set_urls
note "isolated_bind=$SERVER_BIND"

# Start -> liveness -> functional API -> stop -> restart -> repeat. A unique
# high port plus post-response PID checks prevents an unrelated default-port
# service from satisfying the acceptance observations.
if start_and_verify_server; then
  pass 'server lifecycle pass=1'
else
  fail 'server failed initial isolated lifecycle acceptance'
fi

if start_and_verify_server; then
  pass 'server lifecycle pass=2 (restart)'
else
  fail 'server failed restart lifecycle acceptance'
fi

pass 'TERMUX_RUNTIME_ACCEPTANCE'
note 'application-state/SQLite persistence remains a separate proof obligation'
note "report=$REPORT"
note "server_log=$SERVER_LOG"
