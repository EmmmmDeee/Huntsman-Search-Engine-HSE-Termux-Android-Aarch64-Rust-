#!/usr/bin/env bash
# Reproducible evidence capture for HSE refactors. Does not edit tracked files.
# Usage: bash scripts/refactor-baseline.sh [OUTPUT_DIRECTORY]
set -uo pipefail
umask 077

for executable in git cargo rustc; do
  if ! command -v "$executable" >/dev/null 2>&1; then
    printf 'error: required executable missing: %s\n' "$executable" >&2
    exit 2
  fi
done

root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo 'error: not inside a Git checkout' >&2
  exit 2
}
cd "$root" || exit 2

if [ "$#" -gt 1 ]; then
  echo 'usage: refactor-baseline.sh [OUTPUT_DIRECTORY]' >&2
  exit 2
fi

if [ "$#" -eq 1 ]; then
  mkdir -p "$1" || exit 2
  out="$(cd "$1" && pwd -P)" || exit 2
else
  out="$(mktemp -d "${TMPDIR:-/tmp}/huntsman-refactor.XXXXXXXX")" || exit 2
fi

git rev-parse HEAD > "$out/revision.txt"
git branch --show-current > "$out/branch.txt"
git status --porcelain=v1 > "$out/working-tree-before.txt"
git ls-files > "$out/tracked-files.txt"
git log -n 30 --date=iso-strict --format='%H %ad %s' > "$out/recent-commits.txt"
rustc --version --verbose > "$out/rustc-version.txt" 2>&1
cargo --version > "$out/cargo-version.txt" 2>&1

printf 'check\tresult\n' > "$out/checks.tsv"
failures=0
run_check() {
  local name="$1"
  shift
  printf '==> %s\n' "$name"
  if "$@" > "$out/$name.stdout" 2> "$out/$name.stderr"; then
    printf '%s\tPASS\n' "$name" >> "$out/checks.tsv"
  else
    local status=$?
    printf '%s\tFAIL(%s)\n' "$name" "$status" >> "$out/checks.tsv"
    failures=$((failures + 1))
  fi
}

run_check diff-whitespace git diff --check
run_check metadata cargo metadata --locked --no-deps --format-version 1
run_check fmt cargo fmt --all -- --check
run_check test cargo test --workspace --locked
run_check clippy cargo clippy --workspace --all-targets --locked -- -D warnings
run_check release cargo build --workspace --release --locked
run_check xtask-gate cargo run --locked -p xtask -- gate full

git status --porcelain=v1 > "$out/working-tree-after.txt"
if cmp -s "$out/working-tree-before.txt" "$out/working-tree-after.txt"; then
  printf 'working-tree-integrity\tPASS\n' >> "$out/checks.tsv"
else
  printf 'working-tree-integrity\tFAIL\n' >> "$out/checks.tsv"
  echo 'error: working tree changed during verification' >&2
  failures=$((failures + 1))
fi

cat "$out/checks.tsv"
printf 'Evidence directory: %s\n' "$out"
if [ "$failures" -ne 0 ]; then
  printf '%s\n' 'Acceptance failed; review captured stderr/stdout before merging.' >&2
  exit 1
fi
echo 'Local checks passed; Android, browser and Railway CI gates remain required.'
