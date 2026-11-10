#!/usr/bin/env bash
# Credit-free DeHashed key diagnostic, using HUNTSMAN's production credential probe.
# Never print the key, arbitrary provider output, or error response bodies.
set -euo pipefail

binary="${1:-./target/debug/huntsman-recon}"
if [[ -z "${HUNTSMAN_DEHASHED_KEY:-}" ]]; then
  printf 'dehashed_auth=not_configured\n'
  exit 2
fi
if [[ ! -x "$binary" ]]; then
  printf 'dehashed_auth=binary_unavailable\n'
  exit 3
fi

# A clean HOME prevents a runner's other saved provider credentials being probed.
probe_home="$(mktemp -d)"
trap 'rm -rf "$probe_home"' EXIT
if ! report="$(HOME="$probe_home" "$binary" credential-status --probe 2>/dev/null)"; then
  printf 'dehashed_auth=probe_execution_failed\n'
  exit 4
fi

# HUNTSMAN emits tab-delimited status fields. Consume just DeHashed's status
# and discard all other provider output; never echo raw output to CI logs.
line="$(printf '%s\n' "$report" | awk -F '\t' '$1 == "provider=DeHashed" { print; exit }')"
if [[ -z "$line" ]]; then
  printf 'dehashed_auth=provider_not_reported\n'
  exit 5
fi
state=""
probe=""
IFS=$'\t' read -r -a fields <<< "$line"
for field in "${fields[@]}"; do
  case "$field" in
    state=*) state="${field#state=}" ;;
    probe=*) probe="${field#probe=}" ;;
  esac
done
if [[ "$state" != configured ]]; then
  printf 'dehashed_auth=not_configured\n'
  exit 2
fi
case "$probe" in
  valid)
    printf 'dehashed_auth=accepted\n'
    ;;
  rejected)
    printf 'dehashed_auth=rejected\n'
    exit 6
    ;;
  rate_limited)
    printf 'dehashed_auth=rate_limited\n'
    exit 7
    ;;
  indeterminate|unavailable|unsupported|not_configured)
    printf 'dehashed_auth=inconclusive\n'
    exit 8
    ;;
  *)
    printf 'dehashed_auth=unexpected_probe_result\n'
    exit 9
    ;;
esac
