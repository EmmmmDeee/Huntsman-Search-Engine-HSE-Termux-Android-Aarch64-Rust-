#!/usr/bin/env bash
set -euo pipefail

mode="${1:-audit}"
case "$mode" in
  audit|delete) ;;
  -h|--help)
    echo "usage: bash scripts/cleanup-unverified-prereleases.sh [audit|delete]"
    exit 0
    ;;
  *) echo "invalid mode: $mode" >&2; exit 64 ;;
esac

root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$root/.github/unverified-prereleases.json"
repo="${GH_REPO:-${GITHUB_REPOSITORY:-EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-}}"

for tool in gh jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done
[[ -f "$manifest" ]] || { echo "missing manifest: $manifest" >&2; exit 1; }

jq -c '.entries[]' "$manifest" | while IFS= read -r row; do
  tag="$(jq -r .tag <<<"$row")"
  commit="$(jq -r .commit <<<"$row")"
  ci_run="$(jq -r .ci_run_id <<<"$row")"

  release="$(gh api "repos/$repo/releases/tags/$tag" 2>/dev/null || true)"
  if [[ -z "$release" ]]; then
    printf '%s\tmissing\n' "$tag"
    continue
  fi

  [[ "$(jq -r .prerelease <<<"$release")" == "true" ]] || {
    echo "$tag: refusing; release is not a prerelease" >&2
    exit 1
  }

  actual="$(jq -r .target_commitish <<<"$release")"
  [[ "$actual" == "$commit" ]] || {
    echo "$tag: refusing; target $actual != manifest $commit" >&2
    exit 1
  }

  run="$(gh api "repos/$repo/actions/runs/$ci_run")"
  [[ "$(jq -r .head_sha <<<"$run")" == "$commit" ]] || {
    echo "$tag: refusing; CI run targets another commit" >&2
    exit 1
  }
  [[ "$(jq -r .conclusion <<<"$run")" == "failure" ]] || {
    echo "$tag: refusing; CI run is no longer classified failure" >&2
    exit 1
  }

  if [[ "$mode" == "delete" ]]; then
    gh release delete "$tag" --repo "$repo" --yes --cleanup-tag
    printf '%s\tdeleted\n' "$tag"
  else
    printf '%s\tquarantined\tci=failure\n' "$tag"
  fi
done
