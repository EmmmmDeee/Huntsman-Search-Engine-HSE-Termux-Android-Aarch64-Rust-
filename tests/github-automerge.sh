#!/usr/bin/env bash
# Exercise the actual GraphQL call shape against an isolated fake GitHub CLI.
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat > "$tmp/bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${1:-}" == api ]] || exit 91
shift
printf '%s\n' "$*" >> "$MOCK_LOG"
if [[ "${1:-}" == graphql ]]; then
  [[ "${MOCK_SCENARIO:-}" != graphql_denied ]] || { echo '403 graphql' >&2; exit 1; }
  args="$*"
  [[ "$args" == *'expectedHeadOid: $head'* && "$args" == *'mergeMethod: SQUASH'* && "$args" == *"prId=PR_node_1434"* && "$args" == *"head=0123456789abcdef0123456789abcdef01234567"* ]] || { echo 'incorrect mutation contract' >&2; exit 97; }
  if [[ "${MOCK_SCENARIO:-}" == graphql_rejected ]]; then
    echo '{"errors":[{"message":"expected head changed"}],"data":null}'
  else
    echo '{"data":{"enablePullRequestAutoMerge":{"pullRequest":{"number":1434,"merged":false,"autoMergeRequest":{"enabledAt":"2026-10-26T11:00:00Z"}}}}}'
  fi
  exit 0
fi
p="${1:-}"
case "$p" in
  "repos/$GH_REPO/rulesets?per_page=100")
    if [[ "${MOCK_SCENARIO:-}" == no_ruleset ]]; then echo '[]'
    else jq -n --arg n "$(jq -r .name "$POLICY_FILE")" '[{id:501,name:$n}]'; fi ;;
  "repos/$GH_REPO/rulesets/501") jq '. + {id:501}' "$POLICY_FILE" ;;
  "repos/$GH_REPO/branches/main")
    [[ "${MOCK_SCENARIO:-}" == unprotected ]] && echo '{"protected":false}' || echo '{"protected":true}' ;;
  "repos/$GH_REPO")
    [[ "${MOCK_SCENARIO:-}" == auto_disabled ]] && echo '{"allow_auto_merge":false,"allow_squash_merge":true}' || echo '{"allow_auto_merge":true,"allow_squash_merge":true}' ;;
  "repos/$GH_REPO/pulls/1434")
    jq -n --arg scenario "${MOCK_SCENARIO:-}" '{node_id:"PR_node_1434",state:(if $scenario=="closed" then "closed" else "open" end),draft:($scenario=="draft"),base:{ref:(if $scenario=="wrong_target" then "dev" else "main" end)},head:{sha:"0123456789abcdef0123456789abcdef01234567"}}' ;;
  *) echo "unknown API: $p" >&2; exit 90 ;;
esac
MOCK
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" GH_REPO='EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-'
export MOCK_LOG="$tmp/log" POLICY_FILE="$root/scripts/github/merge-policy.json"
script="$root/scripts/github/enable-pr-automerge.sh"
pass=0
fail=0
case_run() {
  local label="$1" scenario="$2" number="$3" mode="$4" wanted="$5" writes="$6" reason="${7:-}" result=0
  : > "$MOCK_LOG"
  output="$(MOCK_SCENARIO="$scenario" bash "$script" "$number" "$mode" 2>&1)" || result=$?
  calls="$(grep -c '^graphql ' "$MOCK_LOG" || :)"
  if [[ "$wanted" == pass && "$result" -eq 0 && "$calls" -eq "$writes" ]] ||
     [[ "$wanted" == fail && "$result" -ne 0 && "$result" -ne 126 && "$result" -ne 127 && "$calls" -eq "$writes" && "$output" == *"$reason"* ]]; then
    printf 'PASS: %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL: %s (exit=%s graphql=%s): %s\n' "$label" "$result" "$calls" "$output" >&2
    fail=$((fail + 1))
  fi
}
case_run 'check eligible PR is read-only' ok 1434 check pass 0
case_run 'enable uses expected-head guarded squash mutation' ok 1434 enable pass 1
case_run 'GraphQL expected-head rejection fails closed' graphql_rejected 1434 enable fail 1 'did not confirm'
case_run 'GraphQL transport rejection fails closed' graphql_denied 1434 enable fail 1 '403 graphql'
case_run 'draft PR is refused' draft 1434 enable fail 0 'non-draft'
case_run 'closed PR is refused' closed 1434 enable fail 0 'open, non-draft'
case_run 'wrong target is refused' wrong_target 1434 enable fail 0 'main-targeted'
case_run 'unprotected main is refused' unprotected 1434 enable fail 0 'NOT ENFORCED'
case_run 'missing ruleset is refused' no_ruleset 1434 enable fail 0 'MISSING:'
case_run 'disabled auto merge is refused' auto_disabled 1434 enable fail 0 'NOT READY:'
case_run 'non-numeric PR is refused' ok nope enable fail 0 'positive'
[[ "$fail" -eq 0 ]] || { echo "$fail failures, $pass passed" >&2; exit 1; }
echo "ALL PASS: $pass auto-merge integration scenarios"
