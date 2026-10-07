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

for required_tool in timeout sha256sum sort; do
  command -v "$required_tool" >/dev/null 2>&1 \
    || fail "required verification tool is missing: $required_tool"
done

repo_fingerprint() {
  {
    git diff --binary --no-ext-diff HEAD --
    while IFS= read -r -d '' path; do
      printf '\0untracked\0%s\0' "$path"
      if [[ -L "$path" ]]; then
        readlink -- "$path"
      else
        sha256sum -- "$path"
      fi
    done < <(git ls-files --others --exclude-standard -z | sort -z)
  } | sha256sum | awk '{print $1}'
}

run() {
  printf 'repair-gate: RUN:'
  printf ' %q' "$@"
  printf '\n'
  timeout --signal=TERM --kill-after=10s "${timeout_seconds}s" "$@"
}

# Preserve the operator's pre-existing work while detecting any content change
# caused by verification itself. Ignored build products do not enter this hash.
before_fingerprint="$(repo_fingerprint)"

# File/shell contract checks first: fail cheaply before compilation.
run bash -n scripts/repair-gate.sh
run bash -n scripts/cleanup-unverified-prereleases.sh
run bash -n scripts/railway-iac-plan.sh
run bash -n scripts/railway-live-acceptance.sh
run bash -n scripts/validate-railway-iac.sh
run bash -n scripts/termux-runtime-acceptance.sh
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
  run cargo test --locked --test functional_code_contract
  run cargo test --locked --test directive_lock
  run cargo test --locked --test deployment_targets
  run cargo test --locked --test repair_contract
fi

run cargo run --locked -- check

after_fingerprint="$(repo_fingerprint)"
if [[ "$before_fingerprint" != "$after_fingerprint" ]]; then
  git status --short --untracked-files=all >&2 || true
  fail "verification mutated tracked or untracked repository content"
fi

printf 'repair-gate: PASS mode=%s timeout=%ss\n' "$mode" "$timeout_seconds"
