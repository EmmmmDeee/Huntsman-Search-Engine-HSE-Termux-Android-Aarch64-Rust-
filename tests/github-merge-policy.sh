#!/usr/bin/env bash
# Hermetic, mutation-sensitive contract tests for scripts/github/merge-policy.sh.
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat > "$tmp/bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${1:-}" == api ]] || exit 93
shift
printf '%s\n' "$*" >> "$MOCK_LOG"
if [[ "${1:-}" == --method ]]; then
  [[ "${2:-}" == POST && "${3:-}" == "repos/$GH_REPO/rulesets" && "${4:-}" == --input ]] || exit 92
  [[ -f "${5:-}" ]] || exit 91
  [[ "${MOCK_SCENARIO:-}" != post_denied ]] || { echo 'HTTP 403: Resource not accessible' >&2; exit 1; }
  printf 'created\n' > "$MOCK_STATE"
  printf '{"id":501}\n'
  exit 0
fi
p="${1:-}"
case "$p" in
  "repos/$GH_REPO/rulesets?per_page=100")
    if [[ "${MOCK_SCENARIO:-}" == forbidden ]]; then
      echo 'HTTP 403: Resource not accessible' >&2
      exit 1
    fi
    if [[ "${MOCK_SCENARIO:-}" == duplicate ]]; then
      jq -n --arg name "$(jq -r .name "$POLICY_FILE")" '[{id:501,name:$name},{id:502,name:$name}]'
    elif [[ -f "$MOCK_STATE" || "${MOCK_SCENARIO:-}" == installed || "${MOCK_SCENARIO:-}" == drift_bypass || "${MOCK_SCENARIO:-}" == drift_context || "${MOCK_SCENARIO:-}" == drift_strict || "${MOCK_SCENARIO:-}" == drift_app || "${MOCK_SCENARIO:-}" == drift_target || "${MOCK_SCENARIO:-}" == unprotected || "${MOCK_SCENARIO:-}" == auto_disabled ]]; then
      jq -n --arg name "$(jq -r .name "$POLICY_FILE")" '[{id:501,name:$name}]'
    else
      echo '[]'
    fi
    ;;
  "repos/$GH_REPO/rulesets/501")
    case "${MOCK_SCENARIO:-}" in
      drift_bypass) jq '. + {id:501} | .bypass_actors=[{"actor_id":1,"actor_type":"RepositoryRole","bypass_mode":"always"}]' "$POLICY_FILE" ;;
      drift_context) jq '. + {id:501} | .rules |= map(if .type == "required_status_checks" then .parameters.required_status_checks[0].context="unrelated" else . end)' "$POLICY_FILE" ;;
      drift_strict) jq '. + {id:501} | .rules |= map(if .type == "required_status_checks" then .parameters.strict_required_status_checks_policy=false else . end)' "$POLICY_FILE" ;;
      drift_app) jq '. + {id:501} | .rules |= map(if .type == "required_status_checks" then .parameters.required_status_checks[0].integration_id=999 else . end)' "$POLICY_FILE" ;;
      drift_target) jq '. + {id:501} | .conditions.ref_name.include=["refs/heads/*"]' "$POLICY_FILE" ;;
      *) jq '. + {id:501}' "$POLICY_FILE" ;;
    esac
    ;;
  "repos/$GH_REPO/branches/main")
    if [[ -f "$MOCK_STATE" || "${MOCK_SCENARIO:-}" == protected_other ]]; then
      echo '{"protected":true}'
    elif [[ "${MOCK_SCENARIO:-}" == none || "${MOCK_SCENARIO:-}" == post_denied || "${MOCK_SCENARIO:-}" == unprotected || "${MOCK_SCENARIO:-}" == auto_disabled_new || "${MOCK_SCENARIO:-}" == squash_disabled_new ]]; then
      echo '{"protected":false}'
    else
      echo '{"protected":true}'
    fi
    ;;
  "repos/$GH_REPO")
    case "${MOCK_SCENARIO:-}" in
      auto_disabled|auto_disabled_new) echo '{"allow_auto_merge":false,"allow_squash_merge":true}' ;;
      squash_disabled_new) echo '{"allow_auto_merge":true,"allow_squash_merge":false}' ;;
      *) echo '{"allow_auto_merge":true,"allow_squash_merge":true}' ;;
    esac
    ;;
  *) echo "unexpected mock path: $p" >&2; exit 90 ;;
esac
MOCK
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH"
export GH_REPO="EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-"
export POLICY_FILE="$root/scripts/github/merge-policy.json"
export MOCK_LOG="$tmp/log"
export MOCK_STATE="$tmp/installed"
script="$root/scripts/github/merge-policy.sh"

pass=0
fail=0
check_case() {
  local title="$1" scenario="$2" mode="$3" expected="$4" writes="$5" reason="${6:-}" status=0
  rm -f -- "$MOCK_STATE" "$MOCK_LOG"
  local output
  output="$(MOCK_SCENARIO="$scenario" bash "$script" "$mode" 2>&1)" || status=$?
  local count=0
  [[ -f "$MOCK_LOG" ]] && count="$(grep -c -- '--method POST' "$MOCK_LOG" || :)"
  if [[ "$expected" == pass && "$status" -eq 0 && "$count" -eq "$writes" ]] ||
     [[ "$expected" == fail && "$status" -ne 0 && "$status" -ne 126 && "$status" -ne 127 && "$count" -eq "$writes" && "$output" == *"$reason"* ]]; then
    echo "PASS: $title"
    pass=$((pass + 1))
  else
    echo "FAIL: $title (exit=$status, writes=$count; expected=$expected/$writes)" >&2
    echo "$output" >&2
    fail=$((fail + 1))
  fi
}

check_case 'read-only missing policy fails without writing' none check fail 0 'MISSING:'
check_case 'apply installs and validates policy' none apply pass 1
check_case 'existing correct policy verifies read-only' installed check pass 0
check_case 'existing correct policy apply remains idempotent' installed apply pass 0
check_case 'duplicate names fail without writing' duplicate apply fail 0 'duplicate named rulesets'
check_case 'API read 403 aborts without writing' forbidden apply fail 0 'HTTP 403'
check_case 'API create 403 fails closed' post_denied apply fail 1 'HTTP 403'
check_case 'protected branch with foreign policy is not overwritten' protected_other apply fail 0 'already protected differently'
check_case 'ruleset admin bypass is rejected' drift_bypass check fail 0 'DRIFT:'
check_case 'required check name drift is rejected' drift_context check fail 0 'DRIFT:'
check_case 'weak stale-branch policy is rejected' drift_strict check fail 0 'DRIFT:'
check_case 'unexpected check provider is rejected' drift_app check fail 0 'DRIFT:'
check_case 'wrong branch target is rejected' drift_target check fail 0 'DRIFT:'
check_case 'inactive branch enforcement is rejected' unprotected check fail 0 'NOT ENFORCED:'
check_case 'auto-merge disabled is rejected' auto_disabled check fail 0 'NOT READY:'
# An apply must fail BEFORE POST when the required repository merge features
# are disabled. Previously the installer wrote the ruleset then failed.
check_case 'disabled auto-merge blocks ruleset creation' auto_disabled_new apply fail 0 'NOT READY:'
check_case 'disabled squash-merge blocks ruleset creation' squash_disabled_new apply fail 0 'NOT READY:'

# A policy can retain twelve contexts while silently replacing RustSec or CodeQL gates.
# Run the real controller against a mutated local policy and require fail-closed
# validation before any GitHub API request.
mkdir -p "$tmp/mutated"
cp -- "$script" "$tmp/mutated/merge-policy.sh"
jq '(.rules[] | select(.type == "required_status_checks") |
  .parameters.required_status_checks[0].context) = "unrelated replacement"' \
  "$POLICY_FILE" > "$tmp/mutated/merge-policy.json"
original_script="$script"
original_policy="$POLICY_FILE"
script="$tmp/mutated/merge-policy.sh"
export POLICY_FILE="$tmp/mutated/merge-policy.json"
check_case 'same-count policy with substituted RustSec gate fails closed' none check fail 0 'invalid or weakened local merge policy'
if [[ -f "$MOCK_LOG" ]]; then
  echo 'FAIL: invalid local policy reached the GitHub API' >&2
  fail=$((fail + 1))
fi
# Replacing the newly mandatory CodeQL gate must also fail before any API call.
jq '(.rules[] | select(.type == "required_status_checks") |
  .parameters.required_status_checks[] | select(.context == "CodeQL rust") |
  .context) = "unrelated replacement"' \
  "$original_policy" > "$tmp/mutated/merge-policy.json"
check_case 'same-count policy with substituted CodeQL gate fails closed' none check fail 0 'invalid or weakened local merge policy'
if [[ -f "$MOCK_LOG" ]]; then
  echo 'FAIL: invalid CodeQL policy reached the GitHub API' >&2
  fail=$((fail + 1))
fi

# A policy whose review or status-check semantics are weakened must be rejected
# before a GET or POST. A post-creation drift failure is too late.
check_weakened_local_policy() {
  local label="$1" mutation="$2"
  jq "$mutation" "$original_policy" > "$tmp/mutated/merge-policy.json"
  check_case "$label" none apply fail 0 'invalid or weakened local merge policy'
  if [[ -f "$MOCK_LOG" ]]; then
    echo "FAIL: weakened local policy ($label) reached the GitHub API" >&2
    fail=$((fail + 1))
  fi
}
check_weakened_local_policy 'disabled review-thread resolution fails before API' \
  '(.rules[] | select(.type == "pull_request") | .parameters.required_review_thread_resolution) = false'
check_weakened_local_policy 'disabled strict up-to-date checks fail before API' \
  '(.rules[] | select(.type == "required_status_checks") | .parameters.strict_required_status_checks_policy) = false'
check_weakened_local_policy 'non-enforcement on ruleset creation fails before API' \
  '(.rules[] | select(.type == "required_status_checks") | .parameters.do_not_enforce_on_create) = true'
check_weakened_local_policy 'unexpected status-check parameter fails before API' \
  '(.rules[] | select(.type == "required_status_checks") | .parameters.unapproved_override) = true'

script="$original_script"
export POLICY_FILE="$original_policy"

if [[ "$fail" -ne 0 ]]; then
  echo "$fail failed / $pass passed" >&2
  exit 1
fi
echo "ALL PASS: $pass policy-contract scenarios"
