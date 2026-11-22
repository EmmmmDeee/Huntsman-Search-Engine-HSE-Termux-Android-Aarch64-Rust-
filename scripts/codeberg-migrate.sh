#!/usr/bin/env bash
# Safe Huntsman Git-history migration to a NEW Codeberg repo, with resumable recovery.
# Does not delete, force-push, rewrite history, or change any local Git remote.
set -euo pipefail
umask 077

SOURCE_DEFAULT='https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git'
usage() {
  printf 'Usage: bash %s plan|push|resume|verify CODEBERG_USER/REPOSITORY\n' "$0" >&2
  printf 'Codeberg repository must already exist and be EMPTY before push.\n' >&2
  exit 64
}
fail() { printf 'codeberg-migrate: %s\n' "$*" >&2; exit 1; }

[[ $# == 2 ]] || usage
mode=$1
project=$2
[[ "$mode" == plan || "$mode" == push || "$mode" == resume || "$mode" == verify ]] || usage
[[ ${#project} -le 180 && "$project" =~ ^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$ ]] || fail 'Use a simple CODEBERG_USER/REPOSITORY path (no URLs or credentials).'
source_url=${HUNTSMAN_MIGRATION_SOURCE:-$SOURCE_DEFAULT}
destination="git@codeberg.org:${project}.git"
# Local test fixtures can inject a file:// bare remote, but normal runs refuse
# any destination other than codeberg.org. Never accept HTTP URLs with tokens.
if [[ ${HUNTSMAN_MIGRATION_TEST_MODE:-0} == 1 ]]; then
  destination=${HUNTSMAN_MIGRATION_TEST_DESTINATION:?test mode requires destination}
elif [[ "$source_url" != "$SOURCE_DEFAULT" ]]; then
  fail 'Noncanonical source override refused outside offline test mode.'
fi

command -v git >/dev/null || fail 'git is required: pkg install git (on Termux)'
command -v sort >/dev/null || fail 'sort is required: pkg install coreutils (on Termux)'
command -v awk >/dev/null || fail 'awk is required: pkg install gawk (on Termux)'
command -v diff >/dev/null || fail 'diff is required: pkg install diffutils (on Termux)'

if [[ "$mode" == plan ]]; then
  printf 'Source: %s\nDestination: %s\n' "$source_url" "$destination"
  printf 'Create an empty Codeberg repository first; attach a verified SSH key to that account.\n'
  printf 'Then run: bash %s push %s\n' "$0" "$project"
  printf 'After an interrupted/partial push, run: bash %s resume %s\n' "$0" "$project"
  printf 'No source, destination, or local Git configuration has been changed.\n'
  exit 0
fi

# Exit status of ls-remote is critical: a destination permission denial must
# never be mistaken for an empty repo.
read_refs() {
  git -c credential.interactive=never ls-remote --heads --tags "$1" |
    awk '$2 !~ /\^\{\}$/ { print $1 "\t" $2 }' | LC_ALL=C sort
}

work=$(mktemp -d "${TMPDIR:-/tmp}/huntsman-codeberg.XXXXXXXX") || fail 'Cannot create a private temporary directory'
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

# Take a source snapshot, including every ordinary branch and tag. Do not use
# --mirror: it can include GitHub-internal pull-request refs and force-deletions.
git -c credential.interactive=never clone --bare -- "$source_url" "$work/clone.git" >&2 || fail 'Could not clone the source. No changes made.'
[[ -n $(git -C "$work/clone.git" rev-parse --verify refs/heads/main 2>/dev/null) ]] || fail 'Source lacks main branch'
git -C "$work/clone.git" show-ref --heads --tags |
  awk '{ print $1 "\t" $2 }' | LC_ALL=C sort > "$work/source.refs"
[[ -s "$work/source.refs" ]] || fail 'Source has no branch or tag refs'

# An explicit expected SHA is an optional freshness guard for a pinned deployment.
# If the canonical source's main moved after the last operator review, stop before writes.
if [[ -n ${HUNTSMAN_MIGRATION_EXPECT_MAIN:-} ]]; then
  [[ ${HUNTSMAN_MIGRATION_EXPECT_MAIN} =~ ^[0-9a-fA-F]{40}$ ]] || fail 'Expected main must be exactly 40 hex characters.'
  actual_main=$(git -C "$work/clone.git" rev-parse refs/heads/main)
  [[ "$actual_main" == "${HUNTSMAN_MIGRATION_EXPECT_MAIN,,}" ]] || fail 'Source main differs from expected commit; no changes made.'
fi

# Every existing remote branch or tag must also exist at the EXACT same SHA in
# the source snapshot. A matching subset may be resumed, but an unrelated
# branch or advanced/divergent ref always blocks the migration.
validate_remote_subset() {
  awk 'FILENAME == ARGV[1] { source[$2] = $1; next }
    !($2 in source) { print "Unexpected remote ref: " $2 > "/dev/stderr"; bad=1; next }
    source[$2] != $1 { print "Divergent remote ref: " $2 > "/dev/stderr"; bad=1 }
    END { exit bad }' "$work/source.refs" "$1"
}

# Push only refs that are absent. An empty --force-with-lease=<ref>: is a
# conditional-create guard: it rejects a concurrent writer who created this
# ref after our read. It can NEVER replace a preexisting branch or tag.
push_new_refs() {
  local ref
  local -a leases=() refspecs=()
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    leases+=("--force-with-lease=$ref:")
    refspecs+=("$ref:$ref")
    if [[ ${#refspecs[@]} -ge 48 ]]; then
      git -C "$work/clone.git" -c credential.interactive=never push "${leases[@]}" "$destination" "${refspecs[@]}" || return 1
      leases=() refspecs=()
    fi
  done < "$1"
  if [[ ${#refspecs[@]} -gt 0 ]]; then
    git -C "$work/clone.git" -c credential.interactive=never push "${leases[@]}" "$destination" "${refspecs[@]}" || return 1
  fi
}

if [[ "$mode" == push || "$mode" == resume ]]; then
  read_refs "$destination" > "$work/before.refs" || fail 'Destination unavailable or authentication failed; no changes made.'
  if [[ "$mode" == push && -s "$work/before.refs" ]]; then
    fail 'Destination is not empty; refusing to overwrite it. Use resume for a matching partial migration or verify for a complete one.'
  fi
  validate_remote_subset "$work/before.refs" || fail 'Destination has unexpected or divergent refs; refusing every write.'
  awk 'FILENAME == ARGV[1] { seen[$2]=1; next } !($2 in seen) { print $2 }' "$work/before.refs" "$work/source.refs" > "$work/missing.refs"
  if grep -Fxq 'refs/heads/main' "$work/missing.refs"; then
    printf '%s\n' refs/heads/main > "$work/main.refs"
    push_new_refs "$work/main.refs" || fail 'Main push failed; run resume after resolving the issue.'
    grep -Fxv 'refs/heads/main' "$work/missing.refs" > "$work/remaining.refs" || true
  else
    cp "$work/missing.refs" "$work/remaining.refs"
  fi
  push_new_refs "$work/remaining.refs" || fail 'Some refs could not be pushed. Run resume; no existing refs will be replaced.'
fi

read_refs "$destination" > "$work/destination.refs" || fail 'Could not read destination refs; migration status unknown.'
if ! diff -u "$work/source.refs" "$work/destination.refs"; then
  fail 'Destination branches/tags differ from the source snapshot. No automatic repair or force-push.'
fi
printf 'VERIFIED: %s\n' "$destination"
printf 'main SHA: %s\n' "$(git -C "$work/clone.git" rev-parse refs/heads/main)"
printf 'refs: %s\n' "$(wc -l < "$work/source.refs" | tr -d ' ')"
printf 'GitHub origin, source repository and local remotes were not changed.\n'
printf 'Metadata such as issues, PR comments, releases and secrets were not migrated by this Git-only operation.\n'
