#!/usr/bin/env bash
set -euo pipefail

prefix="${PREFIX:-/data/data/com.termux/files/usr}"
bin="${HUNTSMAN_BIN:-$prefix/bin/huntsman-recon}"

case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "termux-acceptance: requires Android ARM64/aarch64" >&2; exit 1 ;;
esac

case "$prefix" in
  /data/data/com.termux/files/usr*) ;;
  *) echo "termux-acceptance: non-Termux PREFIX: $prefix" >&2; exit 1 ;;
esac

command -v timeout >/dev/null 2>&1 || {
  echo "termux-acceptance: coreutils timeout is required" >&2
  exit 1
}
[[ -x "$bin" ]] || {
  echo "termux-acceptance: executable not found: $bin" >&2
  exit 1
}

tmp="$(mktemp -d "${TMPDIR:-$prefix/tmp}/huntsman-device-accept.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

(
  cd "$tmp"
  timeout 30 "$bin" check
  test -f var/ledger.json
  timeout 30 "$bin" verify var/ledger.json
  timeout 10 "$bin" --help >/dev/null
)

printf 'termux-acceptance: PASS\n'
printf 'binary=%s\n' "$bin"
printf 'arch=%s\n' "$(uname -m)"
printf 'prefix=%s\n' "$prefix"
