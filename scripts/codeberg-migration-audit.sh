#!/usr/bin/env bash
# Read-only Git reference parity gate for a proposed GitHub -> Codeberg migration.
# The script never pushes, pulls, checks out, or modifies a repository.
# Override both remote URLs in tests or for an intentionally renamed destination.
set -Eeuo pipefail
umask 077
export LC_ALL=C
export GIT_TERMINAL_PROMPT=0

if (( $# > 1 )) || [[ "\${1:-audit}" != audit ]]; then
  printf 'usage: bash scripts/codeberg-migration-audit.sh [audit]\n' >&2
  exit 2
fi
command -v git >/dev/null 2>&1 || {
  printf 'FAIL: git is required\n' >&2
  exit 2
}

source_remote="\${HUNTSMAN_SOURCE_REMOTE:-https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git}"
dest_remote="\${HUNTSMAN_DEST_REMOTE:-https://codeberg.org/EmmmmDeee/HuntsmanSearchEngine.git}"
if [[ -z "$source_remote" || -z "$dest_remote" || "$source_remote" == "$dest_remote" ]]; then
  printf 'FAIL: distinct, non-empty source and destination remotes are required\n' >&2
  exit 2
fi

tmp="$(mktemp -d "\${TMPDIR:-/tmp}/hse-codeberg-audit.XXXXXXXX")" || exit 2
trap 'rm -rf -- "$tmp"' EXIT

# Only branch and tag refs matter for clone identity. --refs excludes annotated-tag
# peeled pseudo-refs, which are not independently writable Git refs.
fetch_refs() {
  local remote="$1" outfile="$2" raw="$tmp/raw"
  if ! git ls-remote --refs --exit-code "$remote" 'refs/heads/*' 'refs/tags/*' > "$raw" 2> "$tmp/git-error"; then
    printf 'FAIL: cannot enumerate %s repository refs (or no branches/tags found)\n' "$3" >&2
    return 1
  fi
  # Normalize to name<TAB>OID, ensuring lexical order independent of remote output.
  awk -F '\t' 'NF == 2 && $1 ~ /^[0-9a-f]{40,64}$/ && $2 ~ /^refs\/(heads|tags)\// {print $2 "\t" $1}' "$raw" \
    | sort > "$outfile"
  if [[ ! -s "$outfile" ]] || [[ "$(wc -l < "$raw")" != "$(wc -l < "$outfile")" ]]; then
    printf 'FAIL: malformed or incomplete %s Git refs\n' "$3" >&2
    return 1
  fi
}

fetch_refs "$source_remote" "$tmp/source-before" source
fetch_refs "$dest_remote" "$tmp/destination" destination
fetch_refs "$source_remote" "$tmp/source-after" source

if ! cmp -s "$tmp/source-before" "$tmp/source-after"; then
  printf 'FAIL: source refs moved during audit; rerun against a stable source\n' >&2
  exit 1
fi
if ! grep -q $'^refs/heads/main\t' "$tmp/source-before"; then
  printf 'FAIL: source refs/heads/main is absent\n' >&2
  exit 1
fi
if ! cmp -s "$tmp/source-before" "$tmp/destination"; then
  printf 'FAIL: Codeberg refs differ from GitHub; migration is not validated\n' >&2
  diff -u --label source --label destination "$tmp/source-before" "$tmp/destination" || true
  exit 1
fi
main_sha="$(awk -F '\t' '$1 == "refs/heads/main" {print $2}' "$tmp/source-before")"
ref_count="$(wc -l < "$tmp/source-before")"
printf 'PASS: %s branch/tag refs match exactly\n' "$ref_count"
printf 'main=%s\n' "$main_sha"
printf 'NOTE: Git refs only; issues, releases, license policy, CI, LFS, and installer URL migration remain unverified\n'
