#!/usr/bin/env bash
# Verify Git branch/tag references and the main tip after repository import.
# Usage: bash scripts/gitlab-migration-verify.sh SOURCE_URL DESTINATION_URL
set -Eeuo pipefail
IFS=$'\n\t'

if (( $# != 2 )); then
  printf 'usage: %s SOURCE_GIT_URL DESTINATION_GIT_URL\n' "$0" >&2
  exit 2
fi
for bin in git diff mktemp sort awk; do
  command -v "$bin" >/dev/null 2>&1 || {
    printf 'missing command: %s\n' "$bin" >&2
    exit 2
  }
done

source_url="$1"
destination_url="$2"
case "$source_url $destination_url" in
  *'@'*'://'*|*'://'*'@'*)
    printf 'refusing credential-bearing URL; use a credential helper or SSH agent\n' >&2
    exit 2
    ;;
esac

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

fetch_refs() {
  local url="$1" output="$2"
  git ls-remote --refs --heads --tags "$url" \
    | awk 'NF == 2 { print $2 "\t" $1 }' \
    | LC_ALL=C sort > "$output"
  [[ -s "$output" ]] || {
    printf 'ERROR: remote has no branch/tag refs\n' >&2
    return 1
  }
}

fetch_refs "$source_url" "$scratch/source"
fetch_refs "$destination_url" "$scratch/destination"
if ! diff -u "$scratch/source" "$scratch/destination"; then
  printf 'FAIL: branch/tag references differ; do not cut over\n' >&2
  exit 1
fi

main_sha="$(awk '$1 == "refs/heads/main" { print $2 }' "$scratch/source")"
if [[ ! "$main_sha" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'FAIL: source does not have a valid main branch\n' >&2
  exit 1
fi

printf 'PASS: all %s branch/tag refs match\n' "$(wc -l < "$scratch/source" | tr -d ' ')"
printf 'Verified main commit: %s\n' "$main_sha"
printf 'Note: compare CI status, project permissions, Git LFS objects and releases separately.\n'
