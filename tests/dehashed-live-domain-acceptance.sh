#!/usr/bin/env bash
# Offline contract checks for a separately opt-in live DeHashed search.
# All values are synthetic; this file never uses a real API key or network.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/dehashed-live-domain-acceptance.sh"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT

cat > "$temp/fake" <<'FAKE'
#!/usr/bin/env bash
[[ "$*" == "dehashed search --domain telstra.com.au --purpose security-research --size 1 --page 1" ]] || exit 65
# Real CLI failures emit stderr and return nonzero without a success header.
case "${MOCK_MODE:-record}" in
  deny_empty) printf 'AUTH-ERROR-SECRET' >&2; exit 77 ;;
  key_empty) printf 'NO-KEY-SECRET' >&2; exit 66 ;;
  outage_empty) printf 'UPSTREAM-SECRET' >&2; exit 69 ;;
  partial_empty) exit 1 ;;
esac
printf '%s\n' 'source=DeHashed' 'purpose=security-research'
case "${MOCK_MODE:-record}" in
  wrong_query) printf '%s\n' 'query=domain:other.com' ;;
  *) printf '%s\n' 'query=domain:telstra.com.au' ;;
esac
printf '%s\n' 'page=1'
case "${MOCK_MODE:-record}" in
  zero|zero_has_entry|zero_spurious_record) printf '%s\n' 'results=0' ;;
  duplicate) printf '%s\n' 'results=1' 'results=1' ;;
  wrong_count) printf '%s\n' 'results=2' ;;
  *) printf '%s\n' 'results=1' ;;
esac
printf '%s\n' 'total=72' 'balance=901'
case "${MOCK_MODE:-record}" in
  zero|missing_entry|zero_spurious_record) ;;
  extra_entry) printf '%s\n' 'entry=1' 'entry=2' ;;
  *) printf '%s\n' 'entry=1' ;;
esac
case "${MOCK_MODE:-record}" in
  zero) ;;
  *) printf '%s\n' 'database=FAKE-RECORD' 'email=DO-NOT-DISCLOSE@example.invalid' \
    'has_password=true' ;;
esac
printf '%s\n' 'DO-NOT-DISCLOSE-ERROR' >&2
case "${MOCK_MODE:-record}" in
  deny) exit 77 ;;
  key) exit 66 ;;
  outage) exit 69 ;;
  partial) exit 1 ;;
  *) exit 0 ;;
esac
FAKE
chmod 700 "$temp/fake"

check() {
  local mode="$1" expected="$2" expected_exit="$3" code=0 result=""
  result="$(MOCK_MODE="$mode" bash "$script" --allow-one-paid-search "$temp/fake")" || code=$?
  [[ "$code" == "$expected_exit" && "$result" == "$expected" ]] || {
    printf 'bad mode=%s code=%s result=%s\n' "$mode" "$code" "$result"
    exit 1
  }
  [[ "$result" != *DO-NOT-DISCLOSE* ]] || {
    echo 'raw provider result leaked'
    exit 1
  }
}

check record 'dehashed_live=api_success_with_record domain=telstra.com.au results=1' 0
check zero 'dehashed_live=api_success_no_records domain=telstra.com.au' 0
check deny 'dehashed_live=auth_or_entitlement_denied' 1
check key 'dehashed_live=missing_key' 1
check outage 'dehashed_live=upstream_unavailable' 1
check deny_empty 'dehashed_live=auth_or_entitlement_denied' 1
check key_empty 'dehashed_live=missing_key' 1
check outage_empty 'dehashed_live=upstream_unavailable' 1
check partial_empty 'dehashed_live=failed' 1
check partial 'dehashed_live=failed' 1
check wrong_query 'dehashed_live=failed' 1
check duplicate 'dehashed_live=failed' 1
check wrong_count 'dehashed_live=failed' 1
check missing_entry 'dehashed_live=failed' 1
check extra_entry 'dehashed_live=failed' 1
check zero_has_entry 'dehashed_live=failed' 1
check zero_spurious_record 'dehashed_live=failed' 1

code=0
result="$(bash "$script" "$temp/fake")" || code=$?
[[ "$code" == 64 && "$result" == 'dehashed_live=opt_in_required' ]] || exit 1

code=0
result="$(bash "$script" --allow-one-paid-search "$temp/missing")" || code=$?
[[ "$code" == 3 && "$result" == 'dehashed_live=binary_unavailable' ]] || exit 1

printf 'dehashed live-domain acceptance offline contract passed\n'
