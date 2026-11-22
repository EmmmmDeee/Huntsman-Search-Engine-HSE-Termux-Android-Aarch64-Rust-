#!/usr/bin/env bash
# Offline regression tests: temporary bare repositories, no network or credentials.
set -Eeuo pipefail
umask 077
root="$(cd "$(dirname "$0")/.." && pwd)"
audit="$root/scripts/codeberg-migration-audit.sh"
bash -n "$audit"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/hse-codeberg-test.XXXXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT

git init -q --bare "$tmp/source.git"
git init -q -b main "$tmp/work"
git -C "$tmp/work" config user.name 'Offline Fixture'
git -C "$tmp/work" config user.email 'fixture@example.invalid'
printf 'initial\n' > "$tmp/work/test.txt"
git -C "$tmp/work" add test.txt
git -C "$tmp/work" commit -qm 'initial'
git -C "$tmp/work" remote add origin "$tmp/source.git"
git -C "$tmp/work" push -q origin main
git clone -q --mirror "$tmp/source.git" "$tmp/dest.git"

run_audit() {
  HUNTSMAN_SOURCE_REMOTE="$tmp/source.git" HUNTSMAN_DEST_REMOTE="$tmp/dest.git" \
    bash "$audit" > "$tmp/actual.out" 2> "$tmp/actual.err"
}
expect_pass() {
  if ! run_audit; then
    cat "$tmp/actual.err" >&2
    printf 'FAIL: expected parity success: %s\n' "$1" >&2
    exit 1
  fi
  grep -q '^PASS:' "$tmp/actual.out"
  printf 'PASS: %s\n' "$1"
}
expect_fail() {
  if run_audit; then
    printf 'FAIL: expected audit refusal: %s\n' "$1" >&2
    exit 1
  fi
  grep -q '^FAIL:' "$tmp/actual.err"
  printf 'PASS: %s\n' "$1"
}

expect_pass 'identical branches'
printf 'second\n' >> "$tmp/work/test.txt"
git -C "$tmp/work" commit -qam 'second'
git -C "$tmp/work" push -q origin main
expect_fail 'divergent main rejected'
git -C "$tmp/work" push -q "$tmp/dest.git" main
expect_pass 'matched main accepted'
git -C "$tmp/work" tag -a -m 'test tag' acceptance-tag
git -C "$tmp/work" push -q origin acceptance-tag
expect_fail 'missing annotated tag rejected'
git -C "$tmp/work" push -q "$tmp/dest.git" acceptance-tag
expect_pass 'matched annotated tag accepted'
git -C "$tmp/work" push -q "$tmp/dest.git" HEAD:refs/heads/destination-only
expect_fail 'unexpected destination branch rejected'
if HUNTSMAN_SOURCE_REMOTE="$tmp/source.git" HUNTSMAN_DEST_REMOTE="$tmp/source.git" \
   bash "$audit" > "$tmp/same.out" 2> "$tmp/same.err"; then
  printf 'FAIL: same-source-and-destination accepted\n' >&2
  exit 1
fi
grep -q '^FAIL:' "$tmp/same.err"
printf 'PASS: self-comparison rejected\n'
if HUNTSMAN_SOURCE_REMOTE="$tmp/missing.git" HUNTSMAN_DEST_REMOTE="$tmp/dest.git" \
   bash "$audit" > "$tmp/missing.out" 2> "$tmp/missing.err"; then
  printf 'FAIL: missing source accepted\n' >&2
  exit 1
fi
grep -q '^FAIL:' "$tmp/missing.err"
printf 'PASS: inaccessible source rejected\n'
