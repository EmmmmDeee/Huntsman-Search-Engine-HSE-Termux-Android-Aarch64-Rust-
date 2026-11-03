#!/usr/bin/env bash
# Hermetic checks for unmodified byte receipts and honest partial hybrid runs.
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/termux-hybrid-evidence.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '\000\377DATA\n' > "$tmp/expected.bin"
cat > "$tmp/mock-huntsman" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  build-sha)
    echo 0075d6cb8c316a9befefe30edda4b378b07c3533
    ;;
  fetch)
    [ "$2" = https://www.example.org/public ] && [ "$3" = --raw-body ] && [ "$4" = --max-redirects ] && [ "$5" = 0 ] || exit 64
    case "$MOCK_MODE" in
      fetchfail) printf 'bad' >&2; exit 69 ;;
      *) printf '\000\377DATA\n' ;;
    esac
    ;;
  query)
    [ "$2" = --adaptive ] && [ "$3" = 'public test' ] || exit 64
    case "$MOCK_MODE" in
      success)
        printf '%s\n' '{"rounds":[{"outcomes":[{"module":"bing","kind":"success","http_status":200,"found":1}]}],"hits":[{"url":"https://example.net/lead"}],"stop_reason":"budget"}'
        ;;
      partial)
        printf '%s\n' '{"rounds":[{"outcomes":[{"module":"bing","kind":"bot_waf","http_status":403,"found":null}]}],"hits":[],"stop_reason":"unavailable"}'
        exit 69
        ;;
      invalid)
        echo not-json
        exit 69
        ;;
      *) exit 64 ;;
    esac
    ;;
  investigate)
    [ "$2" = --file ] && [ -s "$3" ] || exit 64
    echo 'entities=0'
    ;;
  *) exit 64 ;;
esac
MOCK
chmod +x "$tmp/mock-huntsman"
for mode in success partial invalid fetchfail; do
  mkdir -p "$tmp/$mode"
  result=0
  MOCK_MODE="$mode" HSE_BIN="$tmp/mock-huntsman" HUNTSMAN_HOME="$tmp/$mode" \
    bash "$script" https://www.example.org/public 'public test' \
    > "$tmp/$mode/out" 2> "$tmp/$mode/err" || result=$?
  case "$mode" in
    success) [ "$result" -eq 0 ] ;;
    partial|invalid) [ "$result" -eq 69 ] ;;
    fetchfail) [ "$result" -ne 0 ] ;;
  esac || { echo "unexpected $mode exit=$result"; exit 1; }
  mapfile -t receipts < <(find "$tmp/$mode/hybrid" -maxdepth 1 -name 'receipt-*' -type d)
  if [ "$mode" = fetchfail ]; then
    [ "${#receipts[@]}" -eq 0 ] || { echo 'bad raw response published'; exit 1; }
    continue
  fi
  [ "${#receipts[@]}" -eq 1 ] || { echo "missing receipt: $mode"; exit 1; }
  receipt="${receipts[0]}"
  cmp "$tmp/expected.bin" "$receipt/source-body.bin"
  hash="$(sha256sum "$receipt/source-body.bin")"
  hash="${hash%% *}"
  jq -e --arg digest "$hash" --argjson expected_success "$([ "$mode" = success ] && echo true || echo false)" '
    (.source.body_sha256 == $digest) and
    (.source.body_bytes == 7) and
    (.source.claims_verified == false) and
    (.hybrid_online_success == $expected_success)
  ' "$receipt/manifest.json" >/dev/null
  [ "$(stat -c %a "$receipt/source-body.bin")" = 600 ] ||
    { echo 'raw receipt permissions are not private'; exit 1; }
done
printf 'PASS  raw byte-preserving hybrid receipt: success, blocked, malformed, fetch failure\n'
