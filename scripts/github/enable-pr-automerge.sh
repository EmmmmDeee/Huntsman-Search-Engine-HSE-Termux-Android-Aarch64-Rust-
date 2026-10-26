#!/usr/bin/env bash
# Expected-head-guarded GraphQL auto-merge; never runs without enforced ruleset.
set -Eeuo pipefail
[[ $# -eq 2 ]] || { echo 'usage: enable-pr-automerge.sh NUMBER [check|enable]' >&2; exit 2; }
pr="$1"
mode="$2"
[[ "$pr" =~ ^[1-9][0-9]*$ ]] || { echo 'PR number must be positive' >&2; exit 2; }
case "$mode" in check|enable) ;; *) echo 'mode must be check or enable' >&2; exit 2 ;; esac
command -v gh >/dev/null || { echo 'missing gh CLI' >&2; exit 2; }
command -v jq >/dev/null || { echo 'missing jq' >&2; exit 2; }
repo="${GH_REPO:-EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-}"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'invalid GH_REPO' >&2; exit 2; }

# A software check is not a substitute for repository ruleset enforcement.
# This fails closed on a 403, drift, unprotected main, disabled auto-merge, etc.
bash "$(dirname -- "${BASH_SOURCE[0]}")/merge-policy.sh" check >/dev/null
snapshot="$(gh api "repos/$repo/pulls/$pr")"
if ! jq -e '.state == "open" and .draft == false and .base.ref == "main" and
  (.head.sha | strings | test("^[a-f0-9]{40}$")) and
  (.node_id | strings | length > 0)' <<< "$snapshot" >/dev/null; then
  echo 'PR must be an open, non-draft main-targeted request with a valid head and node ID' >&2
  exit 1
fi
head="$(jq -r '.head.sha' <<< "$snapshot")"
node="$(jq -r '.node_id' <<< "$snapshot")"
if [[ "$mode" == check ]]; then
  printf 'ELIGIBLE: %s PR #%s, expected head %s; no mutation performed\n' "$repo" "$pr" "$head"
  exit 0
fi

# GitObjectID expectedHeadOid is crucial: reject a moving head rather than
# enabling a merge for unreviewed commits introduced between REST read and mutation.
mutation='mutation($prId: ID!, $head: GitObjectID!) {
  enablePullRequestAutoMerge(input: {pullRequestId: $prId, mergeMethod: SQUASH, expectedHeadOid: $head}) {
    pullRequest { number merged autoMergeRequest { enabledAt } }
  }
}'
result="$(gh api graphql -f query="$mutation" -f prId="$node" -f head="$head")"
if ! jq -e --argjson number "$pr" '
  (.errors // [] | length) == 0 and
  .data.enablePullRequestAutoMerge.pullRequest.number == $number and
  (.data.enablePullRequestAutoMerge.pullRequest.merged == true or
   (.data.enablePullRequestAutoMerge.pullRequest.autoMergeRequest.enabledAt | strings | length > 0))
' <<< "$result" >/dev/null; then
  echo 'GitHub did not confirm auto-merge activation; no success asserted' >&2
  exit 1
fi
printf 'ACTIVATED: PR #%s, SQUASH, expected head %s; GitHub enforces required gates\n' "$pr" "$head"
