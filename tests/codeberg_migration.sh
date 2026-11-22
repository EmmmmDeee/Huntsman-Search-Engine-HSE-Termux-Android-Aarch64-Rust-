#!/usr/bin/env bash
# Offline, no-network regression for the zero-force Codeberg migration.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hse-codeberg-test.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT

mkdir "$tmp/source"
git -C "$tmp/source" init -q -b main
git -C "$tmp/source" config user.name 'Huntsman fixture'
git -C "$tmp/source" config user.email 'fixture@example.invalid'
printf 'fixture\n' > "$tmp/source/README.md"
git -C "$tmp/source" add README.md
git -C "$tmp/source" commit -qm 'create baseline'
git -C "$tmp/source" branch review/test
git -C "$tmp/source" tag -a baseline -m 'test tag'
git init -q --bare "$tmp/destination.git"

export HUNTSMAN_MIGRATION_SOURCE="$tmp/source"
export HUNTSMAN_MIGRATION_TEST_MODE=1
export HUNTSMAN_MIGRATION_TEST_DESTINATION="$tmp/destination.git"
script="$root/scripts/codeberg-migrate.sh"
bash -n "$script"
bash "$script" plan fixture/huntsman > "$tmp/plan.txt"
bash "$script" push fixture/huntsman > "$tmp/push.txt" 2>&1
bash "$script" verify fixture/huntsman > "$tmp/verify.txt"
grep -q 'VERIFIED:' "$tmp/push.txt"
grep -q 'VERIFIED:' "$tmp/verify.txt"
if bash "$script" push fixture/huntsman > "$tmp/repeat.txt" 2>&1; then
  printf 'repeat push into nonempty destination unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'Destination is not empty' "$tmp/repeat.txt"
if bash "$script" plan '../invalid/path' > "$tmp/invalid.txt" 2>&1; then
  printf 'invalid namespace unexpectedly accepted\n' >&2
  exit 1
fi
printf 'Codeberg migration offline fixture: PASS\n'
