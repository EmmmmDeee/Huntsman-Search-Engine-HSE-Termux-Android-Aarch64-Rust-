#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'

# Real-device acceptance for the current Huntsman Recon binary.
# A pass is a handset pass only on a device: CI cross-builds Android, but cannot
# prove execution under a real Termux userspace.
#
# Canonical invocation, on the handset (no checkout needed):
#   curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/scripts/termux-runtime-acceptance.sh -o "$TMPDIR/termux-runtime-acceptance.sh"
#   bash "$TMPDIR/termux-runtime-acceptance.sh"
#
# HSE_ACCEPTANCE_HOST=1 runs every check except the two device ones on a build
# host, as CI does against each build so this harness cannot drift from the
# binary. Such a run ends HOST_RUNTIME_ACCEPTANCE, never
# TERMUX_RUNTIME_ACCEPTANCE: it is not a handset pass.

ORIGINAL_PWD="$(pwd -P)"

anchor_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$ORIGINAL_PWD" "$1" ;;
  esac
}

HSE_BIN="${HSE_BIN:-$(command -v huntsman-recon || true)}"
STATE_DIR="$(anchor_path "${HUNTSMAN_HOME:-$HOME/.huntsman}")"
REPORT="$(anchor_path "${HSE_ACCEPTANCE_REPORT:-$STATE_DIR/termux-acceptance.txt}")"
SERVER_LOG="$(anchor_path "${HSE_ACCEPTANCE_SERVER_LOG:-$STATE_DIR/termux-acceptance-server.log}")"
TIMEOUT_SECS="${HSE_ACCEPTANCE_TIMEOUT:-30}"
SERVER_TIMEOUT_SECS="${HSE_ACCEPTANCE_SERVER_TIMEOUT:-30}"
SERVER_PORT="${HSE_ACCEPTANCE_PORT:-}"
HOST_RUN="${HSE_ACCEPTANCE_HOST:-}"
SERVER_PID=""
WORK_DIR=""
PERSISTED_SCAN=""

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

case "$TIMEOUT_SECS" in
  ''|*[!0-9]*) fail "invalid HSE_ACCEPTANCE_TIMEOUT: $TIMEOUT_SECS" ;;
esac
[ "$TIMEOUT_SECS" -gt 0 ] || fail 'HSE_ACCEPTANCE_TIMEOUT must be positive'

case "$SERVER_TIMEOUT_SECS" in
  ''|*[!0-9]*) fail "invalid HSE_ACCEPTANCE_SERVER_TIMEOUT: $SERVER_TIMEOUT_SECS" ;;
esac
[ "$SERVER_TIMEOUT_SECS" -gt 0 ] || fail 'HSE_ACCEPTANCE_SERVER_TIMEOUT must be positive'

if [ -n "$SERVER_PORT" ]; then
  case "$SERVER_PORT" in
    *[!0-9]*) fail "invalid HSE_ACCEPTANCE_PORT: $SERVER_PORT" ;;
  esac
  [ "$SERVER_PORT" -ge 1 ] && [ "$SERVER_PORT" -le 65535 ] ||
    fail 'HSE_ACCEPTANCE_PORT must be in 1..65535'
fi

case "$HOST_RUN" in
  '') ;;
  1) note "host run on $(uname -m) with PREFIX=${PREFIX:-unset}: the two device checks are skipped and this is not a handset pass" ;;
  *) fail "HSE_ACCEPTANCE_HOST must be 1 or unset, got '$HOST_RUN'" ;;
esac

if [ "$HOST_RUN" != 1 ]; then
  case "$(uname -m)" in
    aarch64|arm64) pass 'runtime architecture is ARM64' ;;
    *) fail "unexpected runtime architecture: $(uname -m)" ;;
  esac

  case "${PREFIX:-}" in
    /data/data/com.termux/files/usr*) pass 'Termux PREFIX detected' ;;
    *) fail "not running in a standard Termux PREFIX: ${PREFIX:-unset}" ;;
  esac
fi

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
    health_body=""
    if health_body="$(curl --fail --silent --show-error --max-time 2 "$health_url")" \
      && grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' <<<"$health_body"; then
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

  if [ -n "$PERSISTED_SCAN" ]; then
    local persisted="$WORK_DIR/persisted-scan.json"
    curl --fail --silent --show-error --max-time 5 -H 'X-Huntsman-Lookup: 1' \
      "$base/api/scans/$PERSISTED_SCAN" -o "$persisted" || return 1
    grep -Fq "\"id\":\"$PERSISTED_SCAN\"" "$persisted" || return 1
    grep -Fq '"status":"FINISHED"' "$persisted" || return 1
    pass 'saved scan survives server restart'
  fi
  curl --fail --silent --show-error --max-time 5 "$base/api/modules" -o "$modules" || return 1
  curl --fail --silent --show-error --max-time 5 "$base/api/command" -o "$command" || return 1
  kill -0 "$SERVER_PID" 2>/dev/null || return 1
  grep -q '"modules"' "$modules" || return 1
  grep -q '"count"' "$modules" || return 1
  grep -q '"invariant"' "$command" || return 1
  grep -q '"roles"' "$command" || return 1
  # The Web UI lookup path, offline: a phone lookup makes no request, so this proves the
  # handler, its worker thread and the JSON report on the handset without network or keys.
  local lookup="$WORK_DIR/lookup.json"
  curl --fail --silent --show-error --max-time 10 -H 'X-Huntsman-Lookup: 1' \
    "$base/api/lookup?kind=phone&q=%2B61412345678" -o "$lookup" || return 1
  grep -q '"route":"phone"' "$lookup" || return 1
  grep -q '"value":"+61412345678"' "$lookup" || return 1
  # It was kept as a saved scan that the scan API reads back, finished.
  local scan
  scan="$(sed -n 's/.*"scan":"\([0-9a-f]*\)".*/\1/p' "$lookup")"
  [ -n "$scan" ] || return 1
  curl --fail --silent --show-error --max-time 5 -H 'X-Huntsman-Lookup: 1' \
    "$base/api/scans/$scan" -o "$WORK_DIR/lookup-scan.json" || return 1
  grep -q '"status":"FINISHED"' "$WORK_DIR/lookup-scan.json" || return 1
  # Without the header the lookup must be refused, so a page on another site cannot run one.
  [ "$(curl --silent --max-time 5 -o /dev/null -w '%{http_code}' "$base/api/lookup?kind=phone&q=%2B61412345678")" = 403 ] || return 1
  if [ -z "$PERSISTED_SCAN" ]; then PERSISTED_SCAN="$scan"; fi
  return 0
}

# The page the phone's browser opens. It must arrive whole with the policy that lets its own
# inline script run, and that script must call the endpoints this harness proves, so a page
# that no longer loads or no longer reaches the server cannot pass.
# The web UI as the phone's browser sees it, through the same probe `doctor` runs: the page
# loads under its policy with its script's hash, calls its APIs, and the offline analysis
# answers. `doctor serve` exits 0 only when all of that holds.
verify_web_ui() {
  local bind="$1"
  "$HSE_BIN" doctor serve --bind "$bind" >"$WORK_DIR/doctor-serve.txt" 2>&1 || {
    cat "$WORK_DIR/doctor-serve.txt" >&2
    return 1
  }
  kill -0 "$SERVER_PID" 2>/dev/null || return 1
  grep -qx "serve=healthy .*" "$WORK_DIR/doctor-serve.txt"
}

# A browser opens speculative connections and sends nothing on them. A server that serves one
# connection at a time makes the next request wait for each of them, so the web UI stalls for
# seconds. Hold two such connections open and ask for the health page with a short limit.
verify_idle_connections() {
  local bind="$1" host port rc=0
  host="${bind%:*}"
  port="${bind##*:}"
  if ! ( exec 7<>"/dev/tcp/$host/$port" ) 2>/dev/null; then
    note 'cannot establish Bash /dev/tcp probe connection; idle-connection acceptance cannot be verified'
    return 1
  fi
  { exec 8<>"/dev/tcp/$host/$port" 9<>"/dev/tcp/$host/$port"; } 2>/dev/null || return 1
  curl --fail --silent --show-error --max-time 3 "http://$bind/api/health" -o /dev/null || rc=1
  exec 8>&- 8<&- 9>&- 9<&-
  return "$rc"
}

start_and_verify_server() {
  local bind="$1"
  local base="http://$bind"
  : > "$SERVER_LOG"

  # The lookup it runs is kept as a saved scan; that scan goes in the disposable directory, not
  # among the operator's own scans.
  (
    unset HSE_AUTH_TOKEN
    export HUNTSMAN_HOME="$WORK_DIR/home"
    exec "$HSE_BIN" serve --bind "$bind"
  ) >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!

  wait_for_health "$base/api/health" ||
    fail "serve did not become healthy at $base/api/health"
  pass "health API responds from spawned process: $base/api/health"

  verify_api "$base" || fail 'module/command APIs did not pass functional checks'
  pass 'module and command APIs return current structured state'

  verify_web_ui "$bind" || fail 'the web UI page or its offline analysis did not load'
  pass 'web UI page loads under its policy and its offline analysis answers'

  verify_idle_connections "$bind" ||
    fail 'idle-connection probe failed, was unavailable, or requests stalled'
  pass 'idle connections do not delay a request'

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

if [ "$HOST_RUN" = 1 ]; then
  pass 'HOST_RUNTIME_ACCEPTANCE (not a handset pass)'
else
  pass 'TERMUX_RUNTIME_ACCEPTANCE'
fi
note "report=$REPORT"
note "server_log=$SERVER_LOG"
