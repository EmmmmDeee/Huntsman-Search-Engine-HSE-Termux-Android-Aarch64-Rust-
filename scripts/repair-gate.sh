#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: bash scripts/repair-gate.sh [fast|msrv|full]

Use after any error, bug, broken file, malfunctioning code path, failed refactor,
or suspicious repository change.

fast  - syntax/format + focused repository self-check
msrv  - full test suite + repository self-check (for Rust 1.87)
full  - format + strict clippy + full tests + repository self-check
EOF
}

mode="${1:-full}"
case "$mode" in
  fast|msrv|full) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 64 ;;
esac

root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail() {
  printf 'repair-gate: FAIL: %s\n' "$*" >&2
  exit 1
}

run() {
  printf 'repair-gate: RUN:'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

# File/shell contract checks first: fail cheaply before compilation.
run bash -n scripts/repair-gate.sh
run bash -n scripts/railway-live-acceptance.sh
run sh -n scripts/railway-entrypoint.sh

if [[ "$mode" == "fast" || "$mode" == "full" ]]; then
  run cargo fmt --check
fi

if [[ "$mode" == "full" ]]; then
  run cargo clippy --all-targets --locked -- -D warnings
fi

if [[ "$mode" == "msrv" || "$mode" == "full" ]]; then
  run cargo test --locked
else
  run cargo test --locked --test directive_lock
  run cargo test --locked --test deployment_targets
fi

before="$(git status --porcelain -- var/ || true)"
run cargo run --locked -- check
after="$(git status --porcelain -- var/ || true)"
[[ "$before" == "$after" ]] || fail "repository self-check changed committed var/ artifacts"

run git diff --exit-code -- var/

printf 'repair-gate: PASS mode=%s\n' "$mode"
