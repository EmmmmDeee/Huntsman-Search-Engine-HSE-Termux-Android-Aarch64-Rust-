#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'

# Real-device acceptance for the current Huntsman Recon binary.
# This script is intentionally device-only: CI cross-builds Android, but cannot
# prove execution under a real Termux userspace.
#
# Canonical invocation:
#   bash scripts/termux-runtime-acceptance.sh

ORIGINAL_PWD="$(pwd -P)"
HSE_BIN="${HSE_BIN:-$(command -v huntsman-recon || true)}"
STATE_DIR="${HUNTSMAN_HOME:-$HOME/.huntsman}"
REPORT="${HSE_ACCEPTANCE_REPORT:-$STATE_DIR/termux-acceptance.txt}"
SERVER_LOG="${HSE_ACCEPTANCE_SERVER_LOG:-$STATE_DIR/termux-acceptance-server.log}"
TIMEOUT_SECS="${HSE_ACCEPTANCE_TIMEOUT:-30}"
SERVER_TIMEOUT_SECS="${HSE_ACCEPTANCE_SERVER_TIMEOUT:-30}"
SERVER_PORT="${HSE_ACCEPTANCE_PORT:-}"
SERVER_PID=""
WORK_DIR=""

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
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT INT TERM HUP

for cmd in timeout curl date grep mktemp rm tee tail sleep uname; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required Termux command not found: $cmd"
done

[ -n "$HSE_BIN" ] || fail 'huntsman-recon binary not found in PATH'
case "$HSE_BIN" in
  /*) ;;
  *) HSE_BIN="$ORIGINAL_PWD/$HSE_BIN" ;;
esac
[ -f "$HSE_BIN" ] || fail "huntsman-recon is not a regular file: $HSE_BIN"
[ -x "$HSE_BIN" ] || fail "huntsman-recon is not executable: $HSE_BIN"

case "$(uname -m)" in
  aarch64|arm64) pass 'runtime architecture is ARM64' ;;
  *) fail "unexpected runtime architecture: $(uname -m)" ;;
esac

case "${PREFIX:-}" in
  /data/data/com.termux/files/usr*) pass 'Termux PREFIX detected' ;;
  *) fail "not running in a standard Termux PREFIX: ${PREFIX:-unset}" ;;
esac

note "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "binary=$HSE_BIN"
note "prefix=${PREFIX:-unknown}"

if timeout "$TIMEOUT_SECS" "$HSE_BIN" --version >>"$REPORT" 2>&1; then
  pass 'huntsman-recon --version executes'
else
  fail 'huntsman-recon --version failed or timed out'
fi

if timeout "$TIMEOUT_SECS" "$HSE_BIN" --help >>"$REPORT" 2>&1; then
  pass 'huntsman-recon --help executes'
else
  fail 'huntsman-recon --help failed or timed out'
fi

WORK_DIR="$(mktemp -d "$STATE_DIR/termux-acceptance.XXXXXX")"
if (
  cd "$WORK_DIR" &&
  timeout "$TIMEOUT_SECS" "$HSE_BIN" check >>"$REPORT" 2>&1 &&
  timeout "$TIMEOUT_SECS" "$HSE_BIN" verify var/ledger.json >>"$REPORT" 2>&1
); then
  pass 'offline check and ledger verification execute in a disposable directory'
else
  fail 'offline check or ledger verification failed'
fi

choose_port() {
  if [ -n "$SERVER_PORT" ]; then
    return
  fi
  SERVER_PORT=$((49152 + (($$ + $(date +%s)) % 16384)))
}

stop_server() {
  [ -n "$SERVER_PID" ] || return 0
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    local deadline
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

wait_for_health() {
  local health_url="$1"
  local deadline
  deadline=$(( $(date +%s) + SERVER_TIMEOUT_SECS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      tail -n 80 "$SERVER_LOG" >>"$REPORT" 2>/dev/null || true
      return 1
    fi
    if curl --fail --silent --show-error --max-time 2 "$health_url" |
      grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
      kill -0 "$SERVER_PID" 2>/dev/null || return 1
      return 0
    fi
    sleep 1
  done
  tail -n 80 "$SERVER_LOG" >>"$REPORT" 2>/dev/null || true
  return 1
}

verify_api() {
  local base="$1"
  local modules="$WORK_DIR/modules.json"
  local command="$WORK_DIR/command.json"

  curl --fail --silent --show-error --max-time 5 "$base/api/modules" -o "$modules" || return 1
  curl --fail --silent --show-error --max-time 5 "$base/api/command" -o "$command" || return 1
  kill -0 "$SERVER_PID" 2>/dev/null || return 1
  grep -q '"modules"' "$modules" || return 1
  grep -q '"count"' "$modules" || return 1
  grep -q '"invariant"' "$command" || return 1
  grep -q '"roles"' "$command" || return 1
}

start_and_verify_server() {
  local bind="$1"
  local base="http://$bind"
  : > "$SERVER_LOG"

  (
    unset HSE_AUTH_TOKEN
    exec "$HSE_BIN" serve --bind "$bind"
  ) >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!

  wait_for_health "$base/api/health" ||
    fail "serve did not become healthy at $base/api/health"
  pass "health API responds from spawned process: $base/api/health"

  verify_api "$base" || fail 'module/command APIs did not pass functional checks'
  pass 'module and command APIs return current structured state'

  stop_server
  pass 'spawned server stops under harness control'
}

choose_port
BIND="127.0.0.1:$SERVER_PORT"
note "isolated_bind=$BIND"

start_and_verify_server "$BIND"
pass 'server lifecycle pass=1'

start_and_verify_server "$BIND"
pass 'server lifecycle pass=2 (restart)'

pass 'TERMUX_RUNTIME_ACCEPTANCE'
note "report=$REPORT"
note "server_log=$SERVER_LOG"
