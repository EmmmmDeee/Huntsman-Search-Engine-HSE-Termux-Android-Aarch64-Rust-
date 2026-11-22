#!/usr/bin/env bash
# Safe, one-time Huntsman Git-history migration to a NEW, EMPTY Codeberg repo.
# Does not delete, force-push, rewrite history, or change any local Git remote.
set -euo pipefail
umask 077

SOURCE_DEFAULT='https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git'
usage() {
  printf 'Usage: bash %s plan|push|verify CODEBERG_USER/REPOSITORY\n' "$0" >&2
  printf 'Codeberg repository must already exist and be EMPTY before push.\n' >&2
  exit 64
}
fail() { printf 'codeberg-migrate: %s\n' "$*" >&2; exit 1; }

[[ $# == 2 ]] || usage
mode=$1
project=$2
[[ "$mode" == plan || "$mode" == push || "$mode" == verify ]] || usage
[[ ${#project} -le 180 && "$project" =~ ^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$ ]] || fail 'Use a simple CODEBERG_USER/REPOSITORY path (no URLs or credentials).'
source_url=${HUNTSMAN_MIGRATION_SOURCE:-$SOURCE_DEFAULT}
destination="git@codeberg.org:${project}.git"
# Local test fixtures can inject a file:// bare remote, but normal runs refuse
# any destination other than codeberg.org. Never accept HTTP URLs with tokens.
if [[ ${HUNTSMAN_MIGRATION_TEST_MODE:-0} == 1 ]]; then
  destination=${HUNTSMAN_MIGRATION_TEST_DESTINATION:?test mode requires destination}
fi

command -v git >/dev/null || fail 'git is required: pkg install git (on Termux)'
command -v sort >/dev/null || fail 'sort is required: pkg install coreutils (on Termux)'

if [[ "$mode" == plan ]]; then
  printf 'Source: %s\nDestination: %s\n' "$source_url" "$destination"
  printf 'Create an empty Codeberg repository first; attach a verified SSH key to that account.\n'
  printf 'Then run: bash %s push %s\n' "$0" "$project"
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

if [[ "$mode" == push ]]; then
  # Never write to a repository with existing refs: it may contain unique
  # work, and neither a force-push nor a delete is appropriate.
  read_refs "$destination" > "$work/before.refs" || fail 'Destination is unavailable or authentication failed; no changes made.'
  [[ ! -s "$work/before.refs" ]] || fail 'Destination is not empty; refusing to overwrite it. Use verify for an already migrated repo.'
  # Pushing main first gives a new empty Codeberg repository a clear default.
  git -C "$work/clone.git" -c credential.interactive=never push "$destination" refs/heads/main:refs/heads/main || fail 'Main push failed; verify the remote manually.'
  git -C "$work/clone.git" -c credential.interactive=never push "$destination" --all || fail 'Branch push failed; verify the remote manually.'
  git -C "$work/clone.git" -c credential.interactive=never push "$destination" --tags || fail 'Tag push failed; verify the remote manually.'
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
