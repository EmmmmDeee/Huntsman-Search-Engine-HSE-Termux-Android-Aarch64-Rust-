#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: bash scripts/repair-gate.sh [fast|msrv|full]

Use after any error, bug, broken file, malfunctioning code path, failed refactor,
or suspicious repository change.

fast  - syntax/format + focused repository self-check
msrv  - full Rust test suite + repository self-check (for Rust 1.87)
full  - host acceptance: format + strict clippy + full tests + self-check

A full host pass is necessary but not sufficient for platform-specific changes.
Railway/container and Android/Termux changes require their platform gates too.
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

timeout_seconds="${REPAIR_GATE_TIMEOUT_SECONDS:-3600}"
case "$timeout_seconds" in
  ''|*[!0-9]*) printf 'repair-gate: invalid REPAIR_GATE_TIMEOUT_SECONDS=%q\n' "$timeout_seconds" >&2; exit 64 ;;
esac
if [[ "$timeout_seconds" -lt 1 ]]; then
  printf 'repair-gate: REPAIR_GATE_TIMEOUT_SECONDS must be >= 1\n' >&2
  exit 64
fi

fail() {
  printf 'repair-gate: FAIL: %s\n' "$*" >&2
  exit 1
}

run() {
  printf 'repair-gate: RUN:'
  printf ' %q' "$@"
  printf '\n'
  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=10s "${timeout_seconds}s" "$@"
  else
    "$@"
  fi
}

# Preserve the operator's pre-existing work while detecting any new mutation
# caused by verification itself. Ignored build products do not enter this set.
before_status="$(git status --porcelain=v1 --untracked-files=all)"

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
  run cargo test --locked --test repair_contract
fi

run cargo run --locked -- check

after_status="$(git status --porcelain=v1 --untracked-files=all)"
if [[ "$before_status" != "$after_status" ]]; then
  printf 'repair-gate: repository state changed during verification\n' >&2
  printf '%s\n' '--- before ---' "$before_status" '--- after ---' "$after_status" >&2
  fail "verification must not mutate tracked or untracked repository state"
fi

printf 'repair-gate: PASS mode=%s timeout=%ss\n' "$mode" "$timeout_seconds"
