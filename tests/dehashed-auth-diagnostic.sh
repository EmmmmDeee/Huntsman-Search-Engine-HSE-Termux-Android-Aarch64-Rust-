#!/usr/bin/env bash
# All cases synthetic/offline. The workflow must not expose an API key to a branch push.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/.github/scripts/dehashed-auth-diagnostic.sh"
workflow="$root/.github/workflows/dehashed-auth-diagnostic.yml"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT

# Static CI trust boundary: secrets are usable only in an explicitly dispatched
# workflow on main. A pull request, branch push or write permission must not
# make the credential available to branch-controlled code.
grep -q '^  workflow_dispatch:$' "$workflow"
grep -q "github.ref == 'refs/heads/main'" "$workflow"
grep -q 'persist-credentials: false' "$workflow"
grep -q '^  contents: read$' "$workflow"
if grep -Eq '^  (push|pull_request|pull_request_target|schedule):' "$workflow"; then
  echo 'credential workflow has an unsafe automatic trigger'
  exit 1
fi
if grep -Eq '^[[:space:]]+(contents|issues|pull-requests|actions): write' "$workflow"; then
  echo 'credential workflow requests write permission'
  exit 1
fi
if [[ $(grep -F -c '${{ secrets.' "$workflow") != 1 ]]; then
  echo 'credential must be injected in one probe step only'
  exit 1
fi
# The opt-in paid search must stand alone. A free probe failure is not proof
# that a correctly configured paid-search key will fail.
grep -Fq 'if [[ "${{ inputs.run_real_domain_search }}" == "true" ]]; then' "$workflow"
grep -Fq 'bash scripts/dehashed-live-domain-acceptance.sh --allow-one-paid-search' "$workflow"
grep -Fq 'bash .github/scripts/dehashed-auth-diagnostic.sh' "$workflow"
grep -q '^          else

cat > "$temp/mock" <<'MOCK'
#!/usr/bin/env bash
[[ "${1:-}" == credential-status && "${2:-}" == --probe ]] || exit 28
# Any extra provider credential reaching the mock would cause a second live probe.
[[ -z "${HUNTSMAN_SHODAN_KEY:-}" && -z "${HIBP_API_KEY:-}" && -z "${HSE_TEST_KEY:-}" ]] || exit 86
printf '%s\n' 'provider=Other	state=configured	probe=valid'
slot=set
[[ "${MOCK_STATE:-configured}" == incomplete ]] && slot=unset
printf 'provider=DeHashed\tstate=%s\tprobe=%s\tHUNTSMAN_DEHASHED_KEY=%s\n' "${MOCK_STATE:-configured}" "${MOCK_PROBE:-valid}" "$slot"
printf '%s\n' "${HUNTSMAN_DEHASHED_KEY:-}" >&2
MOCK
chmod 700 "$temp/mock"

check() {
  local expected_code="$1" expected_line="$2" state="$3" verdict="$4"
  local code=0 result=""
  result="$(HUNTSMAN_DEHASHED_KEY='offline-test-secret-marker' MOCK_STATE="$state" MOCK_PROBE="$verdict" bash "$script" "$temp/mock")" || code=$?
  [[ "$code" == "$expected_code" && "$result" == "$expected_line" ]] || {
    echo "unexpected diagnostic code=$code expected=$expected_code"
    exit 1
  }
  [[ "$result" != *offline-test-secret-marker* ]] || exit 1
}
check 0 'dehashed_probe=valid_response' configured valid
check 6 'dehashed_probe=rejected' configured rejected
check 7 'dehashed_probe=rate_limited' configured rate_limited
check 8 'dehashed_probe=inconclusive' configured indeterminate
check 8 'dehashed_probe=inconclusive' configured unavailable
check 8 'dehashed_probe=inconclusive' configured unsupported
check 2 'dehashed_probe=not_configured' incomplete not_configured
check 9 'dehashed_probe=unexpected_verdict' configured future_verdict

# The caller's other provider environment variables must never reach HUNTSMAN.
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker \
          HUNTSMAN_SHODAN_KEY=offline-other-provider-key \
          HIBP_API_KEY=offline-hibp-alias-key \
          HSE_TEST_KEY=offline-hse-slot-key \
          bash "$script" "$temp/mock")" || code=$?
[[ "$code" == 0 && "$result" == 'dehashed_probe=valid_response' ]] || {
  echo 'ambient provider credential leaked into DeHashed-only probe'
  exit 1
}

code=0
result="$(env -u HUNTSMAN_DEHASHED_KEY bash "$script" "$temp/mock")" || code=$?
[[ "$code" == 2 && "$result" == 'dehashed_probe=not_configured' ]] || exit 1
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/missing")" || code=$?
[[ "$code" == 3 && "$result" == 'dehashed_probe=binary_unavailable' ]] || exit 1

cat > "$temp/failing" <<'FAIL'
#!/usr/bin/env bash
printf '%s\n' "${HUNTSMAN_DEHASHED_KEY:-}" >&2
exit 77
FAIL
chmod 700 "$temp/failing"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/failing")" || code=$?
[[ "$code" == 4 && "$result" == 'dehashed_probe=execution_failed' ]] || exit 1

cat > "$temp/duplicate" <<'DUPLICATE'
#!/usr/bin/env bash
printf 'provider=DeHashed\tstate=configured\tprobe=valid\n'
printf 'provider=DeHashed\tstate=configured\tprobe=valid\n'
DUPLICATE
chmod 700 "$temp/duplicate"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/duplicate")" || code=$?
[[ "$code" == 5 && "$result" == 'dehashed_probe=missing_or_duplicate_provider' ]] || exit 1

cat > "$temp/malformed" <<'MALFORMED'
#!/usr/bin/env bash
printf 'provider=DeHashed\tstate=configured\tprobe=valid\tprobe=rejected\n'
MALFORMED
chmod 700 "$temp/malformed"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/malformed")" || code=$?
[[ "$code" == 9 && "$result" == 'dehashed_probe=malformed_status' ]] || exit 1

# Inconsistent state/slot fields must not turn a mock success into valid_response.
cat > "$temp/contradiction" <<'CONTRADICTION'
#!/usr/bin/env bash
printf 'provider=DeHashed\tstate=configured\tprobe=valid\tHUNTSMAN_DEHASHED_KEY=unset\n'
CONTRADICTION
chmod 700 "$temp/contradiction"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/contradiction")" || code=$?
[[ "$code" == 9 && "$result" == 'dehashed_probe=malformed_status' ]] || {
  echo 'contradictory configured/unset row accepted'
  exit 1
}

cat > "$temp/duplicate-slot" <<'DUPLICATE_SLOT'
#!/usr/bin/env bash
printf 'provider=DeHashed\tstate=configured\tprobe=valid\tHUNTSMAN_DEHASHED_KEY=set\tHUNTSMAN_DEHASHED_KEY=unset\n'
DUPLICATE_SLOT
chmod 700 "$temp/duplicate-slot"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/duplicate-slot")" || code=$?
[[ "$code" == 9 && "$result" == 'dehashed_probe=malformed_status' ]] || {
  echo 'duplicate slot row accepted'
  exit 1
}

printf 'dehashed probe offline checks passed\n'
 "$workflow"

cat > "$temp/mock" <<'MOCK'
#!/usr/bin/env bash
[[ "${1:-}" == credential-status && "${2:-}" == --probe ]] || exit 28
# Any extra provider credential reaching the mock would cause a second live probe.
[[ -z "${HUNTSMAN_SHODAN_KEY:-}" && -z "${HIBP_API_KEY:-}" && -z "${HSE_TEST_KEY:-}" ]] || exit 86
printf '%s\n' 'provider=Other	state=configured	probe=valid'
slot=set
[[ "${MOCK_STATE:-configured}" == incomplete ]] && slot=unset
printf 'provider=DeHashed\tstate=%s\tprobe=%s\tHUNTSMAN_DEHASHED_KEY=%s\n' "${MOCK_STATE:-configured}" "${MOCK_PROBE:-valid}" "$slot"
printf '%s\n' "${HUNTSMAN_DEHASHED_KEY:-}" >&2
MOCK
chmod 700 "$temp/mock"

check() {
  local expected_code="$1" expected_line="$2" state="$3" verdict="$4"
  local code=0 result=""
  result="$(HUNTSMAN_DEHASHED_KEY='offline-test-secret-marker' MOCK_STATE="$state" MOCK_PROBE="$verdict" bash "$script" "$temp/mock")" || code=$?
  [[ "$code" == "$expected_code" && "$result" == "$expected_line" ]] || {
    echo "unexpected diagnostic code=$code expected=$expected_code"
    exit 1
  }
  [[ "$result" != *offline-test-secret-marker* ]] || exit 1
}
check 0 'dehashed_probe=valid_response' configured valid
check 6 'dehashed_probe=rejected' configured rejected
check 7 'dehashed_probe=rate_limited' configured rate_limited
check 8 'dehashed_probe=inconclusive' configured indeterminate
check 8 'dehashed_probe=inconclusive' configured unavailable
check 8 'dehashed_probe=inconclusive' configured unsupported
check 2 'dehashed_probe=not_configured' incomplete not_configured
check 9 'dehashed_probe=unexpected_verdict' configured future_verdict

# The caller's other provider environment variables must never reach HUNTSMAN.
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker \
          HUNTSMAN_SHODAN_KEY=offline-other-provider-key \
          HIBP_API_KEY=offline-hibp-alias-key \
          HSE_TEST_KEY=offline-hse-slot-key \
          bash "$script" "$temp/mock")" || code=$?
[[ "$code" == 0 && "$result" == 'dehashed_probe=valid_response' ]] || {
  echo 'ambient provider credential leaked into DeHashed-only probe'
  exit 1
}

code=0
result="$(env -u HUNTSMAN_DEHASHED_KEY bash "$script" "$temp/mock")" || code=$?
[[ "$code" == 2 && "$result" == 'dehashed_probe=not_configured' ]] || exit 1
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/missing")" || code=$?
[[ "$code" == 3 && "$result" == 'dehashed_probe=binary_unavailable' ]] || exit 1

cat > "$temp/failing" <<'FAIL'
#!/usr/bin/env bash
printf '%s\n' "${HUNTSMAN_DEHASHED_KEY:-}" >&2
exit 77
FAIL
chmod 700 "$temp/failing"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/failing")" || code=$?
[[ "$code" == 4 && "$result" == 'dehashed_probe=execution_failed' ]] || exit 1

cat > "$temp/duplicate" <<'DUPLICATE'
#!/usr/bin/env bash
printf 'provider=DeHashed\tstate=configured\tprobe=valid\n'
printf 'provider=DeHashed\tstate=configured\tprobe=valid\n'
DUPLICATE
chmod 700 "$temp/duplicate"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/duplicate")" || code=$?
[[ "$code" == 5 && "$result" == 'dehashed_probe=missing_or_duplicate_provider' ]] || exit 1

cat > "$temp/malformed" <<'MALFORMED'
#!/usr/bin/env bash
printf 'provider=DeHashed\tstate=configured\tprobe=valid\tprobe=rejected\n'
MALFORMED
chmod 700 "$temp/malformed"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/malformed")" || code=$?
[[ "$code" == 9 && "$result" == 'dehashed_probe=malformed_status' ]] || exit 1

# Inconsistent state/slot fields must not turn a mock success into valid_response.
cat > "$temp/contradiction" <<'CONTRADICTION'
#!/usr/bin/env bash
printf 'provider=DeHashed\tstate=configured\tprobe=valid\tHUNTSMAN_DEHASHED_KEY=unset\n'
CONTRADICTION
chmod 700 "$temp/contradiction"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/contradiction")" || code=$?
[[ "$code" == 9 && "$result" == 'dehashed_probe=malformed_status' ]] || {
  echo 'contradictory configured/unset row accepted'
  exit 1
}

cat > "$temp/duplicate-slot" <<'DUPLICATE_SLOT'
#!/usr/bin/env bash
printf 'provider=DeHashed\tstate=configured\tprobe=valid\tHUNTSMAN_DEHASHED_KEY=set\tHUNTSMAN_DEHASHED_KEY=unset\n'
DUPLICATE_SLOT
chmod 700 "$temp/duplicate-slot"
code=0
result="$(HUNTSMAN_DEHASHED_KEY=offline-test-secret-marker bash "$script" "$temp/duplicate-slot")" || code=$?
[[ "$code" == 9 && "$result" == 'dehashed_probe=malformed_status' ]] || {
  echo 'duplicate slot row accepted'
  exit 1
}

printf 'dehashed probe offline checks passed\n'
