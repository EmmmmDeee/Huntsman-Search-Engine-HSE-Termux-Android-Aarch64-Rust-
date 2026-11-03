#!/data/data/com.termux/files/usr/bin/bash
# Hybrid OSINT receipt: exact body bytes + searchable leads + offline extraction.
# Source acquisition uses the rootless, public-only Huntsman Rust fetch transport.
set -Eeuo pipefail
umask 077

fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 2 ] || fail 'usage: termux-hybrid-evidence.sh PUBLIC_HTTPS_URL "PUBLIC_SEARCH_QUERY"'
URL="$1"
QUERY="$2"
case "$URL" in https://*) ;; *) fail 'only public HTTPS source URLs are accepted' ;; esac
case "$URL" in *$'\n'*|*$'\r'*|*'#'*) fail 'URL contains a fragment or control character' ;; esac
HOST="${URL#https://}"
HOST="${HOST%%/*}"
HOST="${HOST%%\?*}"
case "$HOST" in ''|*@*|*:*:*|localhost|127.*|10.*|192.168.*|169.254.*) fail 'URL authority is invalid or local' ;; esac
[ "${#URL}" -le 2048 ] || fail 'source URL too long'
[ -n "$QUERY" ] && [ "${#QUERY}" -le 512 ] || fail 'search query must be 1..512 bytes'
case "$QUERY" in *$'\n'*|*$'\r'* ) fail 'search query contains a newline' ;; esac
for command in jq timeout sha256sum wc date mktemp mv rm chmod; do
  command -v "$command" >/dev/null 2>&1 || fail "missing tool: $command"
done
BIN="${HSE_BIN:-$(command -v huntsman-recon || true)}"
[ -n "$BIN" ] && [ -f "$BIN" ] && [ -x "$BIN" ] || fail 'huntsman-recon binary missing'
SHA="$("$BIN" build-sha)" || fail 'binary build SHA unavailable'
[ "${#SHA}" -eq 40 ] || fail 'invalid build SHA'
BASE="${HUNTSMAN_HOME:-$HOME/.huntsman}/hybrid"
[ ! -L "$BASE" ] || fail 'refusing symlink casebook directory'
mkdir -p "$BASE"
chmod 700 "$BASE" || fail 'cannot protect casebook'
STAGE="$(mktemp -d "$BASE/.capture.XXXXXX")"
trap '[ -z "${STAGE:-}" ] || rm -rf "$STAGE"' EXIT
chmod 700 "$STAGE"
RAW="$STAGE/source-body.bin"
SEARCH="$STAGE/search-discovery.json"
EXTRACT="$STAGE/extracted-candidates.txt"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# stdout contains only the complete 2xx response body (not headers or messages).
timeout 90 "$BIN" fetch "$URL" --raw-body > "$RAW" ||
  fail 'raw source fetch failed: no complete source body admitted'
BYTES="$(wc -c < "$RAW" | tr -d '[:space:]')"
[ "$BYTES" -gt 0 ] && [ "$BYTES" -le 1048576 ] ||
  fail 'source body is empty or larger than the 1 MiB hybrid admission budget'
RAW_SHA="$(sha256sum "$RAW")"; RAW_SHA="${RAW_SHA%% *}"
QUERY_RC=0
timeout 180 "$BIN" query --adaptive "$QUERY" > "$SEARCH" || QUERY_RC=$?
[ "$(wc -c < "$SEARCH")" -le 1048576 ] || fail 'search report exceeds 1 MiB'
# Extraction is an offline, derived candidate list; its text is never primary evidence.
EXTRACT_RC=0
timeout 30 "$BIN" investigate --file "$RAW" > "$EXTRACT" || EXTRACT_RC=$?
[ "$(wc -c < "$EXTRACT")" -le 1048576 ] || fail 'extraction report exceeds 1 MiB'
JSON_OK=0
if jq -e '(.hits | type=="array") and (.rounds | type=="array") and
 ([.rounds[].outcomes[] | (.kind | type=="string")] | all)' "$SEARCH" >/dev/null 2>&1; then
  JSON_OK=1
fi
SEARCH_SHA="$(sha256sum "$SEARCH")"; SEARCH_SHA="${SEARCH_SHA%% *}"
EXTRACT_SHA="$(sha256sum "$EXTRACT")"; EXTRACT_SHA="${EXTRACT_SHA%% *}"
if [ "$JSON_OK" = 1 ]; then
  jq -n --arg source "$URL" --arg query "$QUERY" --arg utc "$START" \
    --arg build "$SHA" --arg raw "$RAW_SHA" --arg search_sha "$SEARCH_SHA" \
    --arg extract_sha "$EXTRACT_SHA" --argjson bytes "$BYTES" \
    --argjson query_rc "$QUERY_RC" --argjson extract_rc "$EXTRACT_RC" \
    --slurpfile report "$SEARCH" '
      ($report[0]) as $r |
      {schema_version:1, collected_at_utc:$utc, build_sha:$build,
       source:{url:$source,body_file:"source-body.bin",body_sha256:$raw,
         body_bytes:$bytes,transport:"huntsman_public_only_anonymous",
         semantics:"exact_transport_response_body_bytes_not_tls_wire_capture",
         admission:"complete_2xx_non_challenge",claims_verified:false},
       discovery:{query:$query,report_file:"search-discovery.json",sha256:$search_sha,
         command_exit:$query_rc,hits:($r.hits|length),rounds:($r.rounds|length),
         outcomes:[$r.rounds[].outcomes[]|{module,kind,http_status,found}],
         evidence_role:"search_leads_only_not_corrobated_claims"},
       extraction:{file:"extracted-candidates.txt",sha256:$extract_sha,
         command_exit:$extract_rc,evidence_role:"derived_candidates_not_verified"},
       hybrid_online_success:($query_rc==0 and ($r.hits|length)>0
         and ([$r.rounds[].outcomes[]|select(.kind=="success")]|length)>0),
       independent_corroboration:"not_established",
       unredacted_source_body:true,content_private_to_local_casebook:true}' \
    > "$STAGE/manifest.json"
else
  jq -n --arg url "$URL" --arg utc "$START" --arg build "$SHA" --arg raw "$RAW_SHA" \
    --arg search_sha "$SEARCH_SHA" --arg extract_sha "$EXTRACT_SHA" \
    --argjson bytes "$BYTES" --argjson query_rc "$QUERY_RC" \
    '{schema_version:1,collected_at_utc:$utc,build_sha:$build,
      source:{url:$url,body_file:"source-body.bin",body_sha256:$raw,body_bytes:$bytes,
        admission:"complete_2xx_non_challenge",claims_verified:false},
      discovery:{report_file:"search-discovery.json",sha256:$search_sha,command_exit:$query_rc,
        status:"invalid_or_absent_json"},
      extraction:{file:"extracted-candidates.txt",sha256:$extract_sha},
      hybrid_online_success:false,independent_corroboration:"not_established"}' \
    > "$STAGE/manifest.json"
fi
chmod 600 "$STAGE"/*
# Atomic publish: incomplete receipts never appear as completed case directories.
FINAL="$BASE/receipt-${STAGE##*.}"
[ ! -e "$FINAL" ] || fail 'receipt destination already exists'
mv "$STAGE" "$FINAL"
STAGE=""
cat "$FINAL/manifest.json"
printf 'raw_source=%s\nmanifest=%s\n' "$FINAL/source-body.bin" "$FINAL/manifest.json"
if jq -e '.hybrid_online_success == true' "$FINAL/manifest.json" >/dev/null; then
  printf 'PASS  one complete public source body and online discovery leads captured\n'
else
  printf 'PARTIAL  raw source saved but live discovery incomplete, blocked or unparseable\n' >&2
  exit 69
fi
