#!/usr/bin/env bash
# Huntsman Telegram public discovery: search-engine indexed *public* URLs only.
# No Telegram login, Bot API, private group enumeration, or Telegram scraping.
set -u
# Rust validates UTF-8 byte length, not Unicode scalar count.
export LC_ALL=C
umask 077

usage() {
  printf 'Usage: %s [--output NEW_DIRECTORY] QUERY...\n' "$0" >&2
  printf 'Queries the canonical huntsman-recon public-osint web command.\n' >&2
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
if (( ${#query} > 120 )) || [[ -z ${query//[[:space:]]/} ]] ||
   [[ $query =~ [[:cntrl:]] ]] || [[ $query == *\"* ]] || [[ $query == *\\* ]]; then
  printf 'Invalid query: use 1-120 characters without control characters, quotes or backslashes.\n' >&2
  exit 64
fi

bin=${HUNTSMAN_BIN:-huntsman-recon}
if ! command -v "$bin" >/dev/null 2>&1; then
  printf 'Unavailable: huntsman-recon executable not found (%s).\n' "$bin" >&2
  exit 69
fi

if [[ -z $output ]]; then
  output="$PWD/telegram-discovery-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
if ! mkdir -m 700 -- "$output"; then
  printf 'Cannot create new private output directory: %s\n' "$output" >&2
  exit 73
fi

# Separately audit directory/index hits; a result is a lead, never independent proof.
# Every pass invokes Huntsman's existing 3-engine, guarded, keyless search path.
labels=(telegram_public_channels telegram_public_links tgstat_index telemetr_index)
filters=('site:t.me/s' 'site:t.me' 'site:tgstat.com' 'site:telemetr.io')
printf 'provider\texit_code\tquery\tresult_file\n' > "$output/manifest.tsv"
answered=0
for ((i=0; i<${#labels[@]}; i++)); do
  label=${labels[i]}
  search="${filters[i]} $query"
  result="$output/$label.json"
  if "$bin" public-osint web "$search" > "$result" 2> "$output/$label.stderr"; then
    status=0
    answered=$((answered+1))
  else
    status=$?
  fi
  printf '%s\t%d\t%s\t%s\n' "$label" "$status" "$search" "$label.json" >> "$output/manifest.tsv"
done

printf 'reports=%s searches=%d successful_searches=%d status=%s\n' \
  "$output" "${#labels[@]}" "$answered" 'unverified_public_index_leads'
if (( answered == 0 )); then
  printf 'No engine cohort answered successfully; examine *.stderr and outcomes in *.json.\n' >&2
  exit 69
fi
