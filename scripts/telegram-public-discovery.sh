#!/usr/bin/env bash
# Public-index Telegram discovery, routed through Huntsman's guarded Rust web search.
# Indexed URLs are unverified leads, not proof of channel existence or ownership.
set -uo pipefail
export LC_ALL=C
umask 077

usage() {
  printf 'Usage: %s [--expanded] [--output NEW_DIRECTORY] QUERY...\n' "$0" >&2
  exit 64
}

expanded=0
output=''
while (($#)); do
  case "$1" in
    --expanded) ((expanded == 0)) || usage; expanded=1; shift ;;
    --output) [[ $# -ge 2 && -n $2 && -z $output ]] || usage; output=$2; shift 2 ;;
    --) shift; break ;;
    --*) usage ;;
    *) break ;;
  esac
done
[[ $# -ge 1 ]] || usage
query="$*"
# The longest site prefix is 34 bytes: 120 + 1 + 34 <= Huntsman's 160-byte limit.
if (( ${#query} > 120 )) || [[ -z ${query//[[:space:]]/} ]] ||
   [[ $query =~ [[:cntrl:]] ]] || [[ $query == *\\* ]]; then
  printf 'Invalid query: 1-120 UTF-8 bytes without control characters or backslashes.\n' >&2
  exit 64
fi

# Validate before creating a directory or invoking the network.
validate_budget() {
  local raw=$1 maximum=$2 label=$3
  if [[ ! $raw =~ ^[0-9]{1,3}$ ]] || (( 10#$raw < 1 || 10#$raw > maximum )); then
    printf '%s must be an integer in 1..%d seconds.\n' "$label" "$maximum" >&2
    return 1
  fi
  printf '%d' "$((10#$raw))"
}
timeout_secs=$(validate_budget "${HUNTSMAN_TELEGRAM_TIMEOUT_SECS:-65}" 120 HUNTSMAN_TELEGRAM_TIMEOUT_SECS) || exit 64
total_secs=$(validate_budget "${HUNTSMAN_TELEGRAM_TOTAL_TIMEOUT_SECS:-240}" 600 HUNTSMAN_TELEGRAM_TOTAL_TIMEOUT_SECS) || exit 64

bin=${HUNTSMAN_BIN:-huntsman-recon}
for tool in "$bin" timeout sha256sum wc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Required tool is not available: %s\n' "$tool" >&2
    exit 69
  fi
done

if [[ -z $output ]]; then
  output="$PWD/telegram-discovery-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
if ! mkdir -m 700 -- "$output"; then
  printf 'Cannot create a new private output directory: %s\n' "$output" >&2
  exit 73
fi

labels=(telegram_public_channels telegram_public_links tgstat_index telemetr_index)
filters=('site:t.me/s' 'site:t.me' 'site:tgstat.com' 'site:telemetr.io')
if ((expanded)); then
  labels+=(telegraph_articles telegramchannels_directory telegram_directory_alt telegram_search_directory)
  filters+=('site:telegra.ph' 'site:telegramchannels.me' 'site:search-t.me' 'site:tgramsearch.com')
fi

manifest="$output/manifest.tsv"
if ! printf 'provider\texit_code\tquery\tresult_file\tstate\tbytes\tsha256\telapsed_secs\n' > "$manifest"; then
  printf 'Cannot write manifest.\n' >&2
  exit 74
fi

SECONDS=0
answered=0
failures=0
for ((i=0; i<${#labels[@]}; i++)); do
  label=${labels[i]}
  search="${filters[i]} $query"
  result="$output/$label.json"
  error="$output/$label.stderr"
  started=$SECONDS
  remaining=$((total_secs - SECONDS))
  if ((remaining <= 0)); then
    : > "$result"
    printf 'Not run: total scan budget exhausted.\n' > "$error"
    status=75
    state=not_run_budget_exhausted
  else
    cap=$timeout_secs
    if ((remaining < cap)); then cap=$remaining; fi
    if timeout -k 3s "${cap}s" "$bin" public-osint web "$search" > "$result" 2> "$error"; then
      status=0
      state=answered_unverified
      if [[ ! -s $result ]]; then
        status=65
        state=empty_report
        printf 'Source returned exit 0 without a report.\n' >> "$error"
      fi
    else
      status=$?
      state=failed_or_unanswered
      if ((status == 124)); then state=timed_out; fi
    fi
  fi
  bytes=$(wc -c < "$result") || exit 74
  checksum=$(sha256sum -- "$result") || exit 74
  checksum=${checksum%% *}
  elapsed=$((SECONDS - started))
  if ((status == 0)); then
    answered=$((answered + 1))
  else
    failures=$((failures + 1))
  fi
  if ! printf '%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\n' \
      "$label" "$status" "$search" "$label.json" "$state" "$bytes" "$checksum" "$elapsed" >> "$manifest"; then
    printf 'Manifest write failure: case is incomplete.\n' >&2
    exit 74
  fi
done

printf 'reports=%s searches=%d answered_searches=%d unsuccessful_or_skipped=%d status=unverified_public_index_leads\n' \
  "$output" "${#labels[@]}" "$answered" "$failures"
if ((answered == 0)); then
  printf 'No source cohort answered; review manifest and stderr.\n' >&2
  exit 69
fi
