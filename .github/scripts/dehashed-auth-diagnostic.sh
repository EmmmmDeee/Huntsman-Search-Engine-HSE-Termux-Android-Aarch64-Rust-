#!/usr/bin/env bash
# Read-only, credit-free HUNTSMAN DeHashed probe. A valid response is NOT
# independent proof that the key was authenticated or that paid search works.
set -euo pipefail
set +x
umask 077

binary="${1:-./target/debug/huntsman-recon}"
if [[ -z "${HUNTSMAN_DEHASHED_KEY:-}" ]]; then
  printf 'dehashed_probe=not_configured\n'
  exit 2
fi
if [[ ! -x "$binary" ]]; then
  printf 'dehashed_probe=binary_unavailable\n'
  exit 3
fi

# Avoid probing any unrelated configured provider; never log raw command output.
probe_home="$(mktemp -d)"
trap 'rm -rf "$probe_home"' EXIT
# credential-status --probe examines every configured provider. A temporary
# HOME alone does not remove ambient process credentials, so drop unrelated
# provider slots *inside the subshell* before invoking the production binary.
# Keep the selected key in the environment rather than an argv assignment.
if ! report="$(
  while IFS= read -r slot; do
    case "$slot" in
      HUNTSMAN_DEHASHED_KEY) ;;
      HUNTSMAN_*|HSE_*|HIBP_API_KEY) unset "$slot" ;;
    esac
  done < <(compgen -e)
  HOME="$probe_home" "$binary" credential-status --probe 2>/dev/null
)"; then
  printf 'dehashed_probe=execution_failed\n'
  exit 4
fi

# Exactly one DeHashed row is necessary. No pipelines with an early-exiting
# reader under pipefail, and no line or value from upstream is printed.
line="$(awk -F '\t' '
  $1 == "provider=DeHashed" { count++; candidate=$0 }
  END { if (count == 1) print candidate }
' <<< "$report")"
if [[ -z "$line" ]]; then
  printf 'dehashed_probe=missing_or_duplicate_provider\n'
  exit 5
fi

state=""
probe=""
slot=""
state_seen=0
probe_seen=0
slot_seen=0
IFS=$'\t' read -r -a fields <<< "$line"
for field in "${fields[@]}"; do
  case "$field" in
    state=*)
      (( state_seen += 1 ))
      state="${field#state=}"
      ;;
    probe=*)
      (( probe_seen += 1 ))
      probe="${field#probe=}"
      ;;
    HUNTSMAN_DEHASHED_KEY=*)
      (( slot_seen += 1 ))
      slot="${field#HUNTSMAN_DEHASHED_KEY=}"
      ;;
  esac
done
if [[ "$state_seen" != 1 || "$probe_seen" != 1 || "$slot_seen" != 1 ]]; then
  printf 'dehashed_probe=malformed_status\n'
  exit 9
fi
# The production status writer emits the slot beside state and verdict.
# Contradictory or unknown values are malformed, never evidence of a valid key.
case "$state:$slot" in
  incomplete:unset)
    printf 'dehashed_probe=not_configured\n'
    exit 2
    ;;
  configured:set) ;;
  *)
    printf 'dehashed_probe=malformed_status\n'
    exit 9
    ;;
esac
case "$probe" in
  valid)
    printf 'dehashed_probe=valid_response\n'
    ;;
  rejected)
    printf 'dehashed_probe=rejected\n'
    exit 6
    ;;
  rate_limited)
    printf 'dehashed_probe=rate_limited\n'
    exit 7
    ;;
  indeterminate|unavailable|unsupported|not_configured)
    printf 'dehashed_probe=inconclusive\n'
    exit 8
    ;;
  *)
    printf 'dehashed_probe=unexpected_verdict\n'
    exit 9
    ;;
esac
