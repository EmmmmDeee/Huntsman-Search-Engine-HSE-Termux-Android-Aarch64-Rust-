#!/usr/bin/env bash
# Operator-run verification for the Telegram public-index fallback.
# Without --live, all tests are offline and no network provider is contacted.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

bash -n "$script_dir/telegram-public-discovery.sh" "$script_dir/test-telegram-public-discovery.sh"
bash "$script_dir/test-telegram-public-discovery.sh"
printf 'offline_checks=passed os=%s architecture=%s\n' "$(uname -s)" "$(uname -m)"

if [[ $# -eq 0 ]]; then
  printf 'live_probe=not_requested\n'
  exit 0
fi
if [[ $1 != --live || $# -lt 2 ]]; then
  printf 'Usage: %s [--live QUERY...]\n' "$0" >&2
  exit 64
fi
shift
bin=${HUNTSMAN_BIN:-huntsman-recon}
if ! command -v "$bin" >/dev/null 2>&1; then
  printf 'live_probe=unavailable reason=missing_huntsman_binary\n' >&2
  exit 69
fi
printf 'live_probe=enabled binary_commit=%s\n' "$("$bin" build-sha)"
bash "$script_dir/telegram-public-discovery.sh" "$@"
