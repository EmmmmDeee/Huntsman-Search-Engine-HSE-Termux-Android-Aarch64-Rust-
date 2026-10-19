#!/usr/bin/env bash
# Reproducible, non-destructive baseline for full-file refactoring.
# Usage: bash scripts/refactor-baseline.sh [OUTPUT_DIRECTORY]
set -uo pipefail
umask 077

if ! command -v git >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
  echo "error: git and cargo are required" >&2
  exit 2
fi
root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "error: run within a git checkout" >&2
  exit 2
}
cd "$root" || exit 2
out="${1:-$root/refactor-evidence}"
mkdir -p "$out" || exit 2
out="$(cd "$out" && pwd -P)" || exit 2

git rev-parse HEAD > "$out/revision.txt"
git status --porcelain=v1 > "$out/working-tree-before.txt"
git ls-files > "$out/tracked-files.txt"
git log -n 30 --date=iso-strict --format='%H %ad %s' > "$out/recent-commits.txt"
cargo metadata --no-deps --format-version 1 > "$out/cargo-metadata.json" 2> "$out/cargo-metadata.stderr"
printf 'test\tresult\n' > "$out/checks.tsv"
failures=0
run_check() {
  local name="$1"
  shift
  echo "==> $name"
  if "$@" > "$out/$name.stdout" 2> "$out/$name.stderr"; then
    printf '%s\tPASS\n' "$name" >> "$out/checks.tsv"
  else
    local status=$?
    printf '%s\tFAIL(%s)\n' "$name" "$status" >> "$out/checks.tsv"
    failures=$((failures + 1))
  fi
}
run_check fmt cargo fmt --all -- --check
run_check test cargo test --workspace --locked
run_check clippy cargo clippy --workspace --all-targets --locked -- -D warnings
run_check release cargo build --workspace --release --locked
run_check xtask-gate cargo run --locked -p xtask -- gate full
git status --porcelain=v1 > "$out/working-tree-after.txt"
if ! cmp -s "$out/working-tree-before.txt" "$out/working-tree-after.txt"; then
  printf '%s\n' 'WARNING: working-tree state changed during baseline run' >&2
  failures=$((failures + 1))
fi
cat "$out/checks.tsv"
echo "Evidence directory: $out"
if [ "$failures" -ne 0 ]; then
  echo "$failures checks or integrity conditions failed; do not claim acceptance." >&2
  exit 1
fi
echo "Local baseline checks passed; platform and deployment gates must still run in CI."
