#!/usr/bin/env bash
# ONE real DeHashed v2 credit-spending search against a public organisation domain.
# This is a manual acceptance tool, NEVER run by automatic CI.
# No record content, lookup identifiers beyond the fixed domain, or provider errors
# are emitted; the search output is filtered in-memory by awk.
set -euo pipefail
set +x

if [[ "${1:-}" != --allow-one-paid-search || $# -gt 2 ]]; then
  printf 'dehashed_live=opt_in_required\n'
  exit 64
fi
binary="${2:-./target/debug/huntsman-recon}"
if [[ ! -x "$binary" ]]; then
  printf 'dehashed_live=binary_unavailable\n'
  exit 3
fi

# A purpose-declared exact-match query for one real company domain, bounded to
# one page of one record. It costs up to one DeHashed search credit.
# The collector is the genuine HUNTSMAN executable, not a direct curl substitute.
# stdout is inspected without saving or emitting any breach records.
code=0
summary="$(
  "$binary" dehashed search \
    --domain telstra.com.au \
    --purpose security-research \
    --size 1 --page 1 2>/dev/null |
  awk '
    /^entry=/ { in_entry=1 }
    !in_entry && $0 == "source=DeHashed" { source++ }
    !in_entry && $0 == "purpose=security-research" { purpose++ }
    !in_entry && $0 == "query=domain:telstra.com.au" { query++ }
    !in_entry && $0 == "page=1" { page++ }
    !in_entry && /^results=[0-9]+$/ {
      results++
      count=substr($0,9)
      if (count !~ /^[0-9]+$/ || count > 1) invalid=1
    }
    END {
      if (source == 1 && purpose == 1 && query == 1 &&
          page == 1 && results == 1 && !invalid) {
        printf "results=%d", count
      } else {
        exit 91
      }
    }
  '
)" || code=$?

# pipefail detects an API/CLI error even if the first lines resemble success.
if [[ "$code" -ne 0 ]]; then
  case "$code" in
    66) printf 'dehashed_live=missing_key\n' ;;
    77) printf 'dehashed_live=auth_or_entitlement_denied\n' ;;
    69) printf 'dehashed_live=upstream_unavailable\n' ;;
    64|65) printf 'dehashed_live=invalid_request\n' ;;
    *) printf 'dehashed_live=failed\n' ;;
  esac
  exit 1
fi
if [[ "$summary" == "results=0" ]]; then
  printf 'dehashed_live=api_success_no_records domain=telstra.com.au\n'
else
  printf 'dehashed_live=api_success_with_record domain=telstra.com.au %s\n' "$summary"
fi
