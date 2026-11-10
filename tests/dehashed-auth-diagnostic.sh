#!/usr/bin/env bash
# Offline regression for the GitHub Actions DeHashed credential diagnostic.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/.github/scripts/dehashed-auth-diagnostic.sh"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
cat > "$temp/mock" <<'MOCK'
#!/usr/bin/env bash
[[ "${1:-}" == credential-status && "${2:-}" == --probe ]] || exit 28
printf '%s\n' 'provider=Other	state=configured	probe=valid'
printf 'provider=DeHashed\tstate=%s\tprobe=%s\tHUNTSMAN_DEHASHED_KEY=set\n' "${MOCK_STATE:-configured}" "${MOCK_PROBE:-valid}"
printf '%s\n' "${HUNTSMAN_DEHASHED_KEY:-}" >&2
MOCK
chmod 700 "$temp/mock"

check() {
  local expected_code="$1" expected_line="$2" state="$3" verdict="$4"
  local actual_code=0 actual=""
  actual="$(HUNTSMAN_DEHASHED_KEY='unit-test-credential-marker' MOCK_STATE="$state" MOCK_PROBE="$verdict" bash "$script" "$temp/mock")" || actual_code=$?
  [[ "$actual_code" == "$expected_code" ]] || { echo "unexpected exit: $actual_code vs $expected_code"; exit 1; }
  [[ "$actual" == "$expected_line" ]] || { echo "unexpected result: $actual vs $expected_line"; exit 1; }
  [[ "$actual" != *unit-test-credential-marker* ]] || { echo "credential marker leaked"; exit 1; }
}
check 0 'dehashed_auth=accepted' configured valid
check 6 'dehashed_auth=rejected' configured rejected
check 7 'dehashed_auth=rate_limited' configured rate_limited
check 8 'dehashed_auth=inconclusive' configured indeterminate
check 8 'dehashed_auth=inconclusive' configured unavailable
check 8 'dehashed_auth=inconclusive' configured unsupported
check 2 'dehashed_auth=not_configured' incomplete not_configured
check 9 'dehashed_auth=unexpected_probe_result' configured future_verdict

code=0
actual="$(env -u HUNTSMAN_DEHASHED_KEY bash "$script" "$temp/mock")" || code=$?
[[ "$code" == 2 && "$actual" == 'dehashed_auth=not_configured' ]] || exit 1

code=0
actual="$(HUNTSMAN_DEHASHED_KEY='unit-test-credential-marker' bash "$script" "$temp/missing")" || code=$?
[[ "$code" == 3 && "$actual" == 'dehashed_auth=binary_unavailable' ]] || exit 1

cat > "$temp/failing" <<'FAIL'
#!/usr/bin/env bash
printf 'some secret: %s\n' "${HUNTSMAN_DEHASHED_KEY:-}" >&2
exit 77
FAIL
chmod 700 "$temp/failing"
code=0
actual="$(HUNTSMAN_DEHASHED_KEY='unit-test-credential-marker' bash "$script" "$temp/failing")" || code=$?
[[ "$code" == 4 && "$actual" == 'dehashed_auth=probe_execution_failed' ]] || exit 1

printf 'dehashed-auth-diagnostic offline checks passed\n'
