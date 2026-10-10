#!/usr/bin/env bash
# check-protected.sh BASE
#
# Refuses a working-tree change that the issue-fix agent is not allowed to make.
# The comparison is against BASE, the commit the job checked out, so a commit the
# agent might make cannot hide a change. Allowed: any change under src/, and a
# new (added) file under tests/. Refused: a modified, deleted, or renamed file
# under tests/, and any change elsewhere, including untracked files.
set -euo pipefail

base="${1:?usage: check-protected.sh BASE}"
bad=()

allowed() {
  local status="$1" path="$2"
  case "$path" in
    src/*) return 0 ;;
    tests/*) [[ "$status" == "A" ]] ;;
    *) return 1 ;;
  esac
}

while IFS=$'\t' read -r status first second; do
  [[ -n "${status:-}" ]] || continue
  case "$status" in
    R*|C*)
      allowed D "$first" || bad+=("$status $first -> $second")
      allowed A "$second" || bad+=("$status $first -> $second")
      ;;
    *)
      allowed "${status:0:1}" "$first" || bad+=("$status $first")
      ;;
  esac
done < <(git diff --name-status -M "$base" --)

while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  allowed A "$path" || bad+=("?? $path")
done < <(git ls-files --others --exclude-standard)

if ((${#bad[@]})); then
  printf 'check-protected: refused changes against %s:\n' "$base" >&2
  printf '  %s\n' "${bad[@]}" >&2
  exit 1
fi
printf 'check-protected: ok against %s\n' "$base"
