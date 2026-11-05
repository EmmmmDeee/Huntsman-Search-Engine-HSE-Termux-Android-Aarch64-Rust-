#!/usr/bin/env bash
# Offline contract tests for the on-device live-network acceptance script.
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/termux-online-acceptance.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/mock-huntsman" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = build-sha ]; then
  echo 0075d6cb8c316a9befefe30edda4b378b07c3533
  exit 0
fi
[ "$1" = query ] && [ "$2" = --adaptive ] && [ "$3" = site:example.org ] || exit 66
case "$MOCK_RESPONSE" in
  success)
    printf '%s\n' '{"rounds":[{"outcomes":[{"module":"bing","kind":"success","http_status":200,"found":1},{"module":"brave","kind":"bot_waf","http_status":403,"found":null}]}],"hits":[{"url":"https://example.org/example"}],"stop_reason":"no_safe_additional_query_variant"}'
    ;;
  empty)
    printf '%s\n' '{"rounds":[{"outcomes":[{"module":"bing","kind":"zero_yield_anomaly","http_status":200,"found":0}]}],"hits":[],"stop_reason":"no_safe_additional_query_variant"}'
    exit 69
    ;;
  forged)
    printf '%s\n' '{"rounds":[{"outcomes":[{"module":"bing","kind":"success","http_status":200,"found":1}]}],"hits":[{"url":"https://example.org/example"}],"stop_reason":"no_safe_additional_query_variant"}'
    exit 69
    ;;
  invalid)
    echo 'provider error'
    exit 69
    ;;
  *) exit 64;;
esac
MOCK
chmod +x "$tmp/mock-huntsman"
for case in success empty forged invalid; do
  mkdir -p "$tmp/$case"
  exit_code=0
  MOCK_RESPONSE="$case" HSE_BIN="$tmp/mock-huntsman" HUNTSMAN_HOME="$tmp/$case" \
    bash "$script" > "$tmp/$case/stdout" 2> "$tmp/$case/stderr" || exit_code=$?
  if [ "$case" = success ]; then
    [ "$exit_code" -eq 0 ] || { echo "success case failed: $exit_code"; exit 1; }
    jq -e '.online_leads_observed == true and .accepted_executions == 1 and .unresolved_executions == 1' \
      "$tmp/$case/online-acceptance.json" >/dev/null
  else
    [ "$exit_code" -eq 69 ] || { echo "$case unexpectedly passed: $exit_code"; exit 1; }
    jq -e '.online_leads_observed == false' "$tmp/$case/online-acceptance.json" >/dev/null
  fi
done
printf '%s\n' 'PASS  online acceptance: success, empty, forged nonzero, malformed response'
