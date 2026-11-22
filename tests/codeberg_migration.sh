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
# A real forge must set its default branch to main; the default of a local
# bare fixture is often master even though the only pushed branch is main.
git --git-dir="$tmp/destination.git" symbolic-ref HEAD refs/heads/main

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
# Matching branch and tag SHA values are not enough if the destination still
# advertises a missing/stale default branch; verify must refuse this case.
git --git-dir="$tmp/destination.git" symbolic-ref HEAD refs/heads/master
if bash "$script" verify fixture/huntsman > "$tmp/wrong-head.txt" 2>&1; then
  printf 'verify accepted destination with invalid default HEAD\n' >&2
  exit 1
fi
grep -q 'default HEAD is not canonical main' "$tmp/wrong-head.txt"
git --git-dir="$tmp/destination.git" symbolic-ref HEAD refs/heads/main
bash "$script" verify fixture/huntsman > "$tmp/head-recovered.txt"
grep -q 'VERIFIED:' "$tmp/head-recovered.txt"
if bash "$script" push fixture/huntsman > "$tmp/repeat.txt" 2>&1; then
  printf 'repeat push into nonempty destination unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'Destination is not empty' "$tmp/repeat.txt"
# An idempotent resume makes no changes when every ref already matches.
bash "$script" resume fixture/huntsman > "$tmp/resume-clean.txt"
# Simulate interruption after main and the annotated tag were pushed: a branch
# is absent while all other refs still match. Resume must restore exactly it.
git -C "$tmp/destination.git" update-ref -d refs/heads/review/test
if bash "$script" verify fixture/huntsman > "$tmp/partial.txt" 2>&1; then
  printf 'verify unexpectedly accepted a partially copied repository\n' >&2
  exit 1
fi
bash "$script" resume fixture/huntsman > "$tmp/resume-partial.txt" 2>&1
bash "$script" verify fixture/huntsman > "$tmp/verified-after-resume.txt"
# An extra branch cannot be silently accepted or deleted.
main_sha=$(git --git-dir="$tmp/destination.git" rev-parse refs/heads/main)
git --git-dir="$tmp/destination.git" update-ref refs/heads/foreign-branch "$main_sha"
if bash "$script" resume fixture/huntsman > "$tmp/foreign.txt" 2>&1; then
  printf 'resume unexpectedly accepted a foreign remote branch\n' >&2
  exit 1
fi
grep -q 'Unexpected remote ref' "$tmp/foreign.txt"
[[ $(git --git-dir="$tmp/destination.git" rev-parse refs/heads/foreign-branch) == "$main_sha" ]]
git --git-dir="$tmp/destination.git" update-ref -d refs/heads/foreign-branch
# Source main advances: the destination's existing main must never be updated
# by resume, even when the update would be a normal fast-forward.
printf 'advance\n' >> "$tmp/source/README.md"
git -C "$tmp/source" add README.md
git -C "$tmp/source" commit -qm 'source advance'
if bash "$script" resume fixture/huntsman > "$tmp/diverged.txt" 2>&1; then
  printf 'resume unexpectedly rewrote an existing branch\n' >&2
  exit 1
fi
grep -q 'Divergent remote ref' "$tmp/diverged.txt"
# A pinned-main mismatch must prevent a first push into an empty destination.
git init -q --bare "$tmp/empty.git"
export HUNTSMAN_MIGRATION_TEST_DESTINATION="$tmp/empty.git"
export HUNTSMAN_MIGRATION_EXPECT_MAIN=0000000000000000000000000000000000000000
if bash "$script" push fixture/huntsman > "$tmp/stale.txt" 2>&1; then
  printf 'pinned-main mismatch unexpectedly allowed push\n' >&2
  exit 1
fi
grep -q 'Source main differs' "$tmp/stale.txt"
[[ -z $(git --git-dir="$tmp/empty.git" for-each-ref) ]] || exit 1
unset HUNTSMAN_MIGRATION_EXPECT_MAIN
if bash "$script" plan '../invalid/path' > "$tmp/invalid.txt" 2>&1; then
  printf 'invalid namespace unexpectedly accepted\n' >&2
  exit 1
fi
printf 'Codeberg migration offline fixture: PASS (fresh, resume, partial, foreign ref, divergence, pinned SHA)\n'
