#!/usr/bin/env bash
# Huntsman Telegram public discovery: search-engine indexed *public* URLs only.
# No Telegram login, Bot API, private group enumeration, or Telegram scraping.
set -uo pipefail
# Rust validates UTF-8 byte length, not Unicode scalar count.
export LC_ALL=C
umask 077

usage() {
  printf 'Usage: %s [--output NEW_DIRECTORY] QUERY...\n' "$0" >&2
  printf 'Uses huntsman-recon public-osint web; indexes are unverified leads.\n' >&2
  exit 64
}

output=''
if [[ ${1-} == '--output' ]]; then
  [[ $# -ge 3 && -n $2 ]] || usage
  output=$2
  shift 2
fi
[[ $# -ge 1 ]] || usage
query="$*"
# The longest site prefix is 19 bytes; 120 + 1 + 19 <= Huntsman's 160-byte limit.
if (( ${#query} > 120 )) || [[ -z ${query//[[:space:]]/} ]] ||
   [[ $query =~ [[:cntrl:]] ]] || [[ $query == *\"* ]] || [[ $query == *\\* ]]; then
  printf 'Invalid query: use 1-120 UTF-8 bytes without controls, quotes or backslashes.\n' >&2
  exit 64
fi

bin=${HUNTSMAN_BIN:-huntsman-recon}
if ! command -v "$bin" >/dev/null 2>&1; then
  printf 'Unavailable: huntsman-recon executable not found (%s).\n' "$bin" >&2
  exit 69
fi
if ! command -v timeout >/dev/null 2>&1; then
  printf 'Unavailable: coreutils timeout is required for bounded network execution.\n' >&2
  exit 69
fi
# User-overridable bound for each engine cohort; prevent accidental unlimited scans.
timeout_secs=${HUNTSMAN_TELEGRAM_TIMEOUT_SECS:-65}
if [[ ! $timeout_secs =~ ^[0-9]+$ ]] ||
   (( ${#timeout_secs} > 3 )) || (( 10#$timeout_secs < 1 || 10#$timeout_secs > 120 )); then
  printf 'HUNTSMAN_TELEGRAM_TIMEOUT_SECS must be an integer from 1 to 120.\n' >&2
  exit 64
fi
timeout_secs=$((10#$timeout_secs))

if [[ -z $output ]]; then
  output="$PWD/telegram-discovery-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
if ! mkdir -m 700 -- "$output"; then
  printf 'Cannot create new private output directory: %s\n' "$output" >&2
  exit 73
fi

# Keep each raw result intact. A search index cannot establish channel ownership or identity.
labels=(telegram_public_channels telegram_public_links tgstat_index telemetr_index)
filters=('site:t.me/s' 'site:t.me' 'site:tgstat.com' 'site:telemetr.io')
if ! printf 'provider\texit_code\tquery\tresult_file\n' > "$output/manifest.tsv"; then
  printf 'Could not write manifest.\n' >&2
  exit 74
fi
answered=0
for ((i=0; i<${#labels[@]}; i++)); do
  label=${labels[i]}
  search="${filters[i]} $query"
  result="$output/$label.json"
  if timeout -k 3s "${timeout_secs}s" "$bin" public-osint web "$search" > "$result" 2> "$output/$label.stderr"; then
    status=0
    # A zero exit with an empty body is not a usable source report.
    if [[ ! -s $result ]]; then
      status=65
      printf 'Source returned exit 0 without a report.\n' >> "$output/$label.stderr"
    fi
  else
    status=$?
  fi
  if (( status == 0 )); then
    answered=$((answered+1))
  fi
  if ! printf '%s\t%d\t%s\t%s\n' "$label" "$status" "$search" "$label.json" >> "$output/manifest.tsv"; then
    printf 'Manifest write failed; output is incomplete.\n' >&2
    exit 74
  fi
done

printf 'reports=%s searches=%d successful_searches=%d status=%s\n' \
  "$output" "${#labels[@]}" "$answered" 'unverified_public_index_leads'
if (( answered == 0 )); then
  printf 'No index search returned a nonempty report. Inspect outcomes and stderr.\n' >&2
  exit 69
fi
