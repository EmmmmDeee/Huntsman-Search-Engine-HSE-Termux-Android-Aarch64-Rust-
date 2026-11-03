#!/usr/bin/env bash
# Read-only, independent live source receipts from the genuine Huntsman binary.
# All calls are bounded and failures cannot suppress subsequent canaries.
set -Eeuo pipefail
umask 077

out="${RUNNER_TEMP:?RUNNER_TEMP required}/huntsman-live"
mkdir -p "$out"
unset GITHUB_TOKEN GH_TOKEN HIBP_API_KEY
while IFS='=' read -r key _; do
  case "$key" in HUNTSMAN_*|HSE_*|*_KEY|*_TOKEN|*_SECRET) unset "$key" ;; esac
done < <(env)

bin="./target/release/huntsman-recon"
[ -x "$bin" ] || { echo "::error::Built Huntsman binary missing"; exit 1; }
printf 'probe\tmodule\texit\tverdict\tobserved\n' > "$out/verdict.tsv"

collect() {
  local name="$1" limit="$2" code=0
  shift 2
  # A timeout/403/offline source is a FAIL row, not a shell-wide abort.
  if timeout --signal=TERM --kill-after=3s "$limit" "$bin" "$@" > "$out/$name.out" 2>&1; then
    code=0
  else
    code=$?
  fi
  printf '%s\n' "$code" > "$out/$name.exit"
}
verdict() {
  local name="$1" module="$2" code line status=FAIL
  code="$(cat "$out/$name.exit")"
  line="$(awk -F '\t' -v m="$module" '$1==m && ($2=="success" || $2=="valid_zero") {print;exit}' "$out/$name.out" | cut -c1-160)"
  if [ "$code" = 0 ] && [ -n "$line" ]; then status=PASS; fi
  [ -n "$line" ] || line="$(awk -F '\t' -v m="$module" '$1==m {print;exit}' "$out/$name.out" | cut -c1-160)"
  [ -n "$line" ] || line="no accepted provider row"
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$module" "$code" "$status" "$line" >> "$out/verdict.tsv"
  printf '%s: %s exit=%s %s\n' "$module" "$status" "$code" "$line"
}

collect wikidata_q42 60 wikidata Q42
verdict wikidata_q42 wikidata
# One lookup tests two independent public adapters; never repeat identical requests.
collect username_dtolnay 60 username dtolnay
verdict username_dtolnay github_user
verdict username_dtolnay crates_io
collect peeringdb_13335 60 asn 13335
verdict peeringdb_13335 peeringdb

# Use the actual dedicated DNS command, not the exhaustive multi-provider
# 'domain' scan. A DNS success requires a positive answer, not merely exit 0.
collect domain_example 45 recon dns example.com
dns_code="$(cat "$out/domain_example.exit")"
dns_status=FAIL
if [ "$dns_code" = 0 ] && grep -qx 'domain=example.com' "$out/domain_example.out" \
    && grep -Eq '^answers=[1-9][0-9]* failed=[0-9]+$' "$out/domain_example.out"; then
  dns_status=PASS
fi
printf 'domain_example\tdns\t%s\t%s\t%s\n' "$dns_code" "$dns_status" \
  "$(grep '^answers=' "$out/domain_example.out" | tail -n 1 || true)" >> "$out/verdict.tsv"
printf 'dns: %s exit=%s\n' "$dns_status" "$dns_code"

# Supplementary public search and people-source sweeps are diagnostic,
# not automatically marked PASS just because the process exits successfully.
collect query_huntsman 30 query huntsman spider
collect people_douglas 30 people Douglas Adams
printf 'search_engines exit=%s\n' "$(cat "$out/query_huntsman.exit")"
grep '^engine=' "$out/query_huntsman.out" | head -n 20 || true
printf 'people_sources exit=%s\n' "$(cat "$out/people_douglas.exit")"
grep -E '^(asic_persons|asic_director|wikidata|acnc|sec_edgar|seeknow)' "$out/people_douglas.out" | head -n 20 || true

{
  printf 'binary_commit=%s\n' "${GITHUB_SHA:-unknown}"
  printf '### Public live provider receipts (actual Rust binary)\n'
  printf '%s\n' '```'
  cat "$out/verdict.tsv"
  printf '%s\n' '```'
} >> "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY required}"
for f in "$out"/*.out; do
  echo "::group::$(basename "$f") (first 60 lines)"
  head -n 60 "$f" | cut -c1-240
  echo '::endgroup::'
done
passed="$(awk -F '\t' 'NR>1 && $4=="PASS" {n++} END {print n+0}' "$out/verdict.tsv")"
failed="$(awk -F '\t' 'NR>1 && $4=="FAIL" {n++} END {print n+0}' "$out/verdict.tsv")"
timed_out="$(awk -F '\t' 'NR>1 && $3=="124" {n++} END {print n+0}' "$out/verdict.tsv")"
printf 'accepted_canaries=%s failed_canaries=%s timed_out_canaries=%s\n' "$passed" "$failed" "$timed_out" | tee -a "$GITHUB_STEP_SUMMARY"
if [ "$passed" -eq 0 ]; then
  echo '::error::No provider returned an accepted public live outcome'
  exit 1
fi
