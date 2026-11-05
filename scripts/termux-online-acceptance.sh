#!/data/data/com.termux/files/usr/bin/bash
# Read-only public-network acceptance through the real Rust web-query transport.
# Never accepts investigation targets: only a fixed, non-personal test query.
set -Eeuo pipefail
umask 077

fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
for command in jq timeout date mktemp mv rm chmod; do
  command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
done
BIN="${HSE_BIN:-$(command -v huntsman-recon || true)}"
[ -n "$BIN" ] && [ -f "$BIN" ] && [ -x "$BIN" ] || fail 'huntsman-recon executable unavailable'
QUERY='site:example.org'
REPORT_DIR="${HUNTSMAN_HOME:-$HOME/.huntsman}"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR" || fail 'cannot protect report directory'
REPORT="$REPORT_DIR/online-acceptance.json"
if [ -L "$REPORT" ] || { [ -e "$REPORT" ] && [ ! -f "$REPORT" ]; }; then
  fail 'existing report is not a regular file'
fi
if [ -e "$REPORT" ]; then
  chmod 600 "$REPORT" || fail 'cannot restrict previous report'
fi
TEMP="$(mktemp -d "$REPORT_DIR/online-acceptance.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT
chmod 700 "$TEMP"

TIMEOUT="${HSE_ONLINE_TIMEOUT:-180}"
case "$TIMEOUT" in ''|*[!0-9]*) fail 'HSE_ONLINE_TIMEOUT must be an integer' ;; esac
[ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 300 ] || fail 'HSE_ONLINE_TIMEOUT must be 1..300 seconds'
SHA="$("$BIN" build-sha 2>/dev/null)" || fail 'cannot read binary build SHA'
case "$SHA" in *[!0-9a-f]*|'') fail 'binary build SHA is invalid' ;; esac
[ "${#SHA}" -eq 40 ] || fail 'binary build SHA is not 40 hex characters'

RC=0
# Exit 69 with typed JSON is expected if public engines returned no URLs.
timeout "$TIMEOUT" "$BIN" query --adaptive "$QUERY" > "$TEMP/search.json" 2> "$TEMP/stderr" || RC=$?
STRUCTURE=0
if jq -e '
  (.rounds | type == "array" and length >= 1 and length <= 3) and
  (.hits | type == "array") and
  ([.rounds[].outcomes[] | (.module | type == "string") and (.kind | type == "string")] | all) and
  (.stop_reason | type == "string")
' "$TEMP/search.json" >/dev/null 2>&1; then
  STRUCTURE=1
fi

# No result URLs, snippets, credentials or private query parameters are persisted.
if [ "$STRUCTURE" -eq 1 ]; then
  jq -n --slurpfile scan "$TEMP/search.json" \
    --arg sha "$SHA" --arg utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson exit_code "$RC" '
    ($scan[0]) as $s |
    ($s.rounds | [.[].outcomes[]]) as $outcomes |
    {
      schema_version: 1, observed_at_utc: $utc, build_sha: $sha,
      request: "fixed_public_test_query", network_requested: true,
      command_exit: $exit_code, rounds: ($s.rounds | length),
      discovered_urls: ($s.hits | length), stop_reason: $s.stop_reason,
      providers: ($outcomes | unique_by(.module) | map(.module)),
      outcomes: ($outcomes | map({module, kind, http_status, found})),
      accepted_executions: ($outcomes | map(select(.kind == "success" or .kind == "valid_zero")) | length),
      unresolved_executions: ($outcomes | map(select(.kind != "success" and .kind != "valid_zero")) | length),
      online_leads_observed: ($exit_code == 0 and ($s.hits | length) > 0 and ($outcomes | any(.kind == "success"))),
      limitation: "search_engine_results_are_discovery_leads_not_verified_primary_evidence"
    }' > "$TEMP/summary.json"
else
  jq -n --arg sha "$SHA" --arg utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson exit_code "$RC" '{
      schema_version: 1, observed_at_utc: $utc, build_sha: $sha,
      request: "fixed_public_test_query", network_requested: true,
      command_exit: $exit_code, valid_online_report: false,
      online_leads_observed: false,
      limitation: "no_valid_typed_provider_response; inspect local process/network settings"
    }' > "$TEMP/summary.json"
fi
chmod 600 "$TEMP/summary.json"
mv -f "$TEMP/summary.json" "$REPORT"
cat "$REPORT"
if [ "$STRUCTURE" -ne 1 ]; then
  printf 'FAIL  no valid typed online report (exit=%s); saved %s\n' "$RC" "$REPORT" >&2
  exit 69
fi
if jq -e '.online_leads_observed == true' "$REPORT" >/dev/null; then
  printf 'PASS  live search leads observed; NOT independent claim verification\n'
else
  printf 'INCONCLUSIVE  no usable online discovery leads; provider statuses retained\n' >&2
  exit 69
fi
