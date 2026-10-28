#!/usr/bin/env bash
# Audit or install Huntsman's main-branch CI gates. Read-only unless explicitly "apply".
# Requires a GitHub credential with repository Administration:write for the apply mode.
set -Eeuo pipefail

mode="${1:-check}"
case "$mode" in check|apply) ;; *) echo 'usage: merge-policy.sh [check|apply]' >&2; exit 2 ;; esac
command -v gh >/dev/null || { echo 'missing gh CLI' >&2; exit 2; }
command -v jq >/dev/null || { echo 'missing jq' >&2; exit 2; }

repo="${GH_REPO:-EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-}"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo 'GH_REPO must be owner/name' >&2
  exit 2
}
policy="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/merge-policy.json"
api="repos/$repo"
name="$(jq -er '.name | strings | select(length > 0)' "$policy")"

# Refuse malformed policy before any network mutation; pinned app ID was read from
# passing Huntsman CI checks (GitHub Actions app, 15368).
jq -e '
  .target == "branch" and .enforcement == "active" and
  (.bypass_actors == []) and
  (.conditions.ref_name.include == ["refs/heads/main"]) and
  (.conditions.ref_name.exclude == []) and
  ([.rules[].type] | sort) ==
    (["deletion","non_fast_forward","pull_request","required_status_checks"] | sort) and
  ([.rules[] | select(.type == "required_status_checks") | .parameters]
     | length == 1) and
  ([.rules[] | select(.type == "required_status_checks") |
     .parameters.required_status_checks[] | .context] | sort) ==
  ([
    "cargo audit (RustSec advisories)",
    "CodeQL rust",
    "CodeQL actions",
    "test (1.87)",
    "test (1.99)",
    "Android aarch64 cross-build",
    "Library tests on aarch64 under qemu",
    "Web UI in a phone browser",
    "Self-hosted container smoke test",
    "Canonical Huntsman directive lock",
    "Offline MITM eligibility fixtures",
    "Generate the full repository completion register"
  ] | sort) and
  (all(.rules[] | select(.type == "required_status_checks") |
     .parameters.required_status_checks[]; .integration_id == 15368))
' "$policy" >/dev/null || { echo 'invalid or weakened local merge policy' >&2; exit 2; }

# Enumerate rather than assuming an existing policy is ours. The installer never
# overwrites an existing rule or attempts to guess among duplicate names.
list="$(gh api "$api/rulesets?per_page=100")"
if ! jq -e 'type == "array"' <<< "$list" >/dev/null; then
  echo 'unexpected ruleset response' >&2
  exit 1
fi
ids="$(jq -r --arg n "$name" '.[] | select(.name == $n) | .id' <<< "$list")"
if [[ "$(grep -c . <<< "$ids" || :)" -gt 1 ]]; then
  echo 'duplicate named rulesets; refusing an ambiguous modification' >&2
  exit 1
fi
id="$ids"

if [[ -z "$id" ]]; then
  if [[ "$mode" == check ]]; then
    echo "MISSING: $repo has no '$name' ruleset; run '$0 apply' with admin permission" >&2
    exit 1
  fi
  # If another policy already protects main, require a deliberate policy review:
  # no second ruleset is silently layered onto it.
  before="$(gh api "$api/branches/main")"
  if [[ "$(jq -r '.protected' <<< "$before")" != false ]]; then
    echo 'main is already protected differently; refusing overlapping policy' >&2
    exit 1
  fi
  echo "Creating '$name' for $repo/main (Administration:write required)"
  created="$(gh api --method POST "$api/rulesets" --input "$policy")"
  id="$(jq -er '.id' <<< "$created")"
fi

# Validate the full security-critical contract, not only rule types or check names.
actual="$(gh api "$api/rulesets/$id")"
if ! jq -e --slurpfile expected "$policy" '
  . as $got | $expected[0] as $want |
  ($got.target == $want.target) and
  ($got.enforcement == "active") and
  ($got.bypass_actors == []) and
  ($got.conditions.ref_name == $want.conditions.ref_name) and
  (([$got.rules[].type] | sort) == ([$want.rules[].type] | sort)) and
  (all($want.rules[]; . as $w |
    ([ $got.rules[] | select(.type == $w.type) ] | length) == 1 and
    (if $w.type == "pull_request" then
      ([ $got.rules[] | select(.type == $w.type) ][0].parameters) as $p |
      all($w.parameters | keys_unsorted[]; . as $key | $p[$key] == $w.parameters[$key])
    elif $w.type == "required_status_checks" then
      ([ $got.rules[] | select(.type == $w.type) ][0].parameters) as $p |
      ($p.strict_required_status_checks_policy == true) and
      ($p.do_not_enforce_on_create == false) and
      (($p.required_status_checks | sort_by(.context)) ==
       ($w.parameters.required_status_checks | sort_by(.context)))
    else true end)
  ))
' <<< "$actual" >/dev/null; then
  echo "DRIFT: $repo ruleset $id differs from the required safe policy" >&2
  exit 1
fi

branch="$(gh api "$api/branches/main")"
if [[ "$(jq -r '.protected' <<< "$branch")" != true ]]; then
  echo 'NOT ENFORCED: main still unprotected despite ruleset response' >&2
  exit 1
fi

settings="$(gh api "$api")"
if ! jq -e '.allow_auto_merge == true and .allow_squash_merge == true' <<< "$settings" >/dev/null; then
  echo 'NOT READY: repository auto-merge or squash merging is disabled' >&2
  exit 1
fi

echo "VERIFIED: $repo/main protected by '$name' ($id); 12 required GitHub Actions CI checks"
