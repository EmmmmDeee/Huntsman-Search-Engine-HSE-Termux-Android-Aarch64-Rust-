#!/usr/bin/env bash
# Live smoke of the keyless username/people collectors against their real public hosts.
# Usage: live-collector-smoke.sh BINARY OUTDIR
# Read-only: every probe is a keyless public lookup of a long-standing public account or record.
# It never reads a key file or a secret; HIBP_API_KEY and every HUNTSMAN_* override are unset.
# Writes OUTDIR/<probe>.out (stdout+stderr), OUTDIR/<probe>.exit and OUTDIR/verdict.tsv:
#   module  probe  verdict(PASS|FAIL)  evidence
# Exit status: 0 when every expected module is PASS, 1 otherwise.
set -uo pipefail
bin="${1:?binary}"
out="${2:?output directory}"
mkdir -p "$out"
unset HIBP_API_KEY
while IFS='=' read -r name _; do
  case "$name" in HUNTSMAN_*) unset "$name" ;; esac
done < <(env)

# probe-id|command line|module|regex the output must match for PASS
probes=(
  "user-dtolnay|username dtolnay|github_user|^github_user	success	"
  "user-dtolnay|username dtolnay|crates_io|^crates_io	success	"
  "user-pg|username pg|hacker_news|^hacker_news	success	"
  "user-jcs|username jcs|lobsters|^lobsters	success	"
  "user-torvalds|username torvalds|docker_hub_user|^docker_hub_user	success	"
  "wikidata-q42|wikidata Q42|wikidata|Q42"
  "asn-13335|asn 13335|peeringdb|[Pp]eering[Dd][Bb]"
)

printf 'module\tprobe\tverdict\tevidence\n' > "$out/verdict.tsv"
failed=0
for row in "${probes[@]}"; do
  IFS='|' read -r id cmd module pattern <<< "$row"
  if [ ! -e "$out/$id.exit" ]; then
    # shellcheck disable=SC2086 # the probe's words are its arguments
    timeout 180 "$bin" $cmd > "$out/$id.out" 2>&1
    echo "$?" > "$out/$id.exit"
  fi
  code="$(cat "$out/$id.exit")"
  line="$(grep -m1 -E "$pattern" "$out/$id.out" | cut -c1-160)"
  if [ -n "$line" ]; then
    verdict=PASS
  else
    verdict=FAIL
    failed=1
    line="$(grep -m1 -E "^$module	" "$out/$id.out" | cut -c1-160)"
    [ -n "$line" ] || line="$(head -c 160 "$out/$id.out" | tr '\n\t' '  ')"
  fi
  printf '%s\t%s\t%s\texit=%s %s\n' "$module" "$id" "$verdict" "$code" "$line" >> "$out/verdict.tsv"
done
cat "$out/verdict.tsv"
exit "$failed"
