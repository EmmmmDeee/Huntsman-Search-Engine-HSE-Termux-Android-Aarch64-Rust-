#!/usr/bin/env bash
# Exercise the real installer with local release fixtures and no network.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
installer="$root/.github/scripts/install-termux.sh"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
mkdir -p "$temp/fake-bin"
cat > "$temp/fake-bin/uname" <<'SH'
#!/bin/sh
printf '%s\n' aarch64
SH
cat > "$temp/fake-bin/curl" <<'SH'
#!/bin/sh
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then shift; out="$1"; fi
  url="$1"
  shift
done
case "$url" in
  *.sha256) cp "$FIXTURE_DIR/asset.sha256" "$out" ;;
  *) cp "$FIXTURE_DIR/asset" "$out" ;;
esac
SH
chmod +x "$temp/fake-bin/"*
export PATH="$temp/fake-bin:$PATH"

run_case() (
  name="$1"
  expected="$2"
  export FIXTURE_DIR="$temp/$name"
  export PREFIX="$FIXTURE_DIR/prefix"
  export FAIL_CHECK="${3:-0}" FAIL_VERIFY="${4:-0}"
  export CALL_LOG="$FIXTURE_DIR/calls"
  mkdir -p "$PREFIX/bin" "$PREFIX/tmp" "$FIXTURE_DIR/work"
  printf 'old-recon\n' > "$PREFIX/bin/huntsman-recon"
  printf 'old-hse\n' > "$PREFIX/bin/hse"
  cat > "$FIXTURE_DIR/asset" <<'SH'
#!/bin/sh
printf '%s %s\n' "$1" "$PWD" >> "$CALL_LOG"
case "$1" in
  check)
    mkdir -p var
    printf 'fixture-ledger\n' > var/ledger.json
    [ "$FAIL_CHECK" = 0 ] || exit 9
    ;;
  verify)
    [ "$FAIL_VERIFY" = 0 ] || exit 9
    [ "$2" = var/ledger.json ] && [ -f "$2" ] || exit 9
    ;;
  *) exit 64 ;;
esac
SH
  cp "$FIXTURE_DIR/asset" "$FIXTURE_DIR/huntsman-recon-aarch64-linux-android"
  (cd "$FIXTURE_DIR" && sha256sum huntsman-recon-aarch64-linux-android > asset.sha256)
  if [ "$name" = bad-checksum ]; then
    printf 'corruption\n' >> "$FIXTURE_DIR/asset"
  fi
  status=0
  (cd "$FIXTURE_DIR/work" && HUNTSMAN_CHANNEL=recon HUNTSMAN_RELEASE_TAG=main-abcdef0 bash "$installer") > "$FIXTURE_DIR/output" 2>&1 || status=$?
  if [ "$expected" = success ]; then
    [ "$status" = 0 ] || { cat "$FIXTURE_DIR/output"; exit 1; }
    cmp "$FIXTURE_DIR/asset" "$PREFIX/bin/huntsman-recon"
    [ -f "$CALL_LOG" ] || { echo 'FAIL: binary installed without runtime acceptance'; exit 1; }
    grep -q '^check ' "$CALL_LOG"
    grep -q '^verify ' "$CALL_LOG"
    [ ! -e "$FIXTURE_DIR/work/var" ]
  else
    [ "$status" != 0 ] || { echo "FAIL: $name installed a rejected binary"; exit 1; }
    [ "$(cat "$PREFIX/bin/huntsman-recon")" = old-recon ]
  fi
  [ "$(cat "$PREFIX/bin/hse")" = old-hse ]
  [ -z "$(find "$PREFIX/bin" -name '.huntsman-recon.install.*' -print)" ]
  echo "PASS: $name"
)

run_case accepted success
run_case failed-check failure 1
run_case failed-ledger failure 0 1
run_case bad-checksum failure
