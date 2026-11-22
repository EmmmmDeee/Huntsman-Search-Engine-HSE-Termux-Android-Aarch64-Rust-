#!/usr/bin/env bash
# Operator-run verification for the Telegram public-index fallback.
# Without --live, all tests are offline and no network provider is contacted.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

bash -n "$script_dir/telegram-public-discovery.sh" "$script_dir/test-telegram-public-discovery.sh" "$script_dir/telegram-termux-acceptance.sh"
bash "$script_dir/test-telegram-public-discovery.sh"
printf 'offline_checks=passed os=%s architecture=%s\n' "$(uname -s)" "$(uname -m)"

if [[ $# -eq 0 ]]; then
  printf 'native_rust_tests=not_requested live_probe=not_requested\n'
  exit 0
fi
case "$1" in
  --native-check|--native-live)
    mode=$1
    shift
    if [[ $mode == --native-check && $# -ne 0 ]] ||
       [[ $mode == --native-live && $# -eq 0 ]]; then
      printf 'Usage: %s [--native-check | --native-live QUERY... | --live QUERY...]\n' "$0" >&2
      exit 64
    fi
    if ! command -v cargo >/dev/null 2>&1; then
      printf 'native_rust_tests=unavailable reason=missing_cargo\n' >&2
      exit 69
    fi
    repo_root=$(cd -- "$script_dir/.." && pwd)
    if [[ ! -f "$repo_root/Cargo.toml" ]]; then
      printf 'native_rust_tests=unavailable reason=missing_repo_manifest\n' >&2
      exit 69
    fi
    cargo test --locked --manifest-path "$repo_root/Cargo.toml" telegram_index
    printf 'native_rust_tests=passed\n'
    if [[ $mode == --native-live ]]; then
      printf 'native_live_probe=enabled\n'
      cargo run --locked --manifest-path "$repo_root/Cargo.toml" -- public-osint telegram "$*"
    else
      printf 'native_live_probe=not_requested\n'
    fi
    exit 0
    ;;
  --live)
    [[ $# -ge 2 ]] || { printf 'Usage: %s --live QUERY...\n' "$0" >&2; exit 64; }
    shift
    ;;
  *)
    printf 'Usage: %s [--native-check | --native-live QUERY... | --live QUERY...]\n' "$0" >&2
    exit 64
    ;;
esac
bin=${HUNTSMAN_BIN:-huntsman-recon}
if ! command -v "$bin" >/dev/null 2>&1; then
  printf 'live_probe=unavailable reason=missing_huntsman_binary\n' >&2
  exit 69
fi
printf 'live_probe=enabled binary_commit=%s\n' "$("$bin" build-sha)"
bash "$script_dir/telegram-public-discovery.sh" "$@"
