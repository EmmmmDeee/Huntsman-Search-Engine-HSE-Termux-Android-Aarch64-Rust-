#!/usr/bin/env bash
set -euo pipefail

harness="scripts/termux-runtime-acceptance.sh"
fail=0

require() {
  local description=$1 pattern=$2
  if ! grep -Eq -- "$pattern" "$harness"; then
    printf 'FAIL  %s\n' "$description" >&2
    fail=1
  else
    printf 'PASS  %s\n' "$description"
  fi
}

require 'uses an isolated loopback bind address' '127\.0\.0\.1:\$SERVER_PORT'
require 'passes the isolated bind to hse serve' 'serve --bind "\$SERVER_BIND"'
require 'checks a functional modules endpoint' '/api/v1/modules'
require 'runs metadata startup with HIBP explicitly absent' 'env -u HIBP_API_KEY'
require 'runs metadata startup with a controlled HIBP value' 'HIBP_API_KEY=.*acceptance'
require 'verifies the spawned server remains alive after HTTP probes' 'kill -0 "\$SERVER_PID"'
require 'checks restart lifecycle' 'server lifecycle pass=2 \(restart\)'

exit "$fail"
