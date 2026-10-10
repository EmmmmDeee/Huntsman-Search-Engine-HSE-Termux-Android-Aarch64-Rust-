#!/usr/bin/env bash
# check-protected.sh BASE
#
# Refuses a working-tree change that the issue-fix agent is not allowed to make.
# The comparison is against BASE, the commit the change was made on, so a commit
# the agent might make cannot hide a change. Allowed:
#
#   - a change under src/ that stays above the file's test code. Test code starts
#     at the first #[cfg(test)] or #[test] line of the file at BASE and runs to the
#     end of the file. A change that touches it is refused. So is deleting or
#     renaming away a file that holds test code.
#   - a new (added) file under src/ or tests/.
#
# Refused: a modified, deleted, or renamed file under tests/; any change outside
# src/ and tests/, including untracked files; and any symbolic link or submodule.
set -euo pipefail

base="${1:?usage: check-protected.sh BASE}"
bad=()
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# The line where test code starts in PATH at BASE, or 0 when the file has none.
test_start() {
  if ! git show "$base:$1" > "$scratch/base" 2>/dev/null; then
    echo 0
    return
  fi
  awk '/^[[:space:]]*#\[(cfg(_attr)?\(.*test|[A-Za-z_:]*test([^A-Za-z_]|$)|rstest)/ { print NR; found = 1; exit }
       END { if (!found) print 0 }' "$scratch/base"
}

# True (status 0) when a change to PATH at BASE touches its test code. A diff that
# cannot be read counts as a touch, so the change is refused.
touches_tests() {
  local start
  start="$(test_start "$1")"
  [[ "$start" -gt 0 ]] || return 1
  git diff -U0 --no-ext-diff "$base" -- "$1" > "$scratch/diff" || return 0
  awk -v start="$start" '
    /^@@ / {
      split($2, old, ",")
      first = substr(old[1], 2) + 0
      count = (old[2] == "" ? 1 : old[2] + 0)
      last = (count == 0 ? first : first + count - 1)
      if (last >= start) hit = 1
    }
    END { exit (hit ? 0 : 1) }' "$scratch/diff"
}

allowed() {
  local status="$1" path="$2"
  case "$path" in
    src/*)
      case "$status" in
        A) return 0 ;;
        M)
          if touches_tests "$path"; then return 1; fi
          return 0
          ;;
        D) [[ "$(test_start "$path")" -eq 0 ]] ;;
        *) return 1 ;;
      esac
      ;;
    tests/*) [[ "$status" == "A" ]] ;;
    *) return 1 ;;
  esac
}

while IFS=$'\t' read -r status first second; do
  [[ -n "${status:-}" ]] || continue
  case "$status" in
    R*)
      allowed D "$first" || bad+=("$status $first -> $second")
      allowed A "$second" || bad+=("$status $first -> $second")
      ;;
    C*)
      allowed A "$second" || bad+=("$status $first -> $second")
      ;;
    *)
      allowed "${status:0:1}" "$first" || bad+=("$status $first")
      ;;
  esac
done < <(git diff --name-status -M --no-ext-diff "$base" --)

# A symbolic link (mode 120000) or a submodule (mode 160000) is never allowed.
while read -r _src dst _rest; do
  case "$dst" in
    120000|160000) bad+=("link or submodule (mode $dst) in the diff") ;;
  esac
done < <(git diff --raw -M --no-ext-diff "$base" --)

while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  if [[ -L "$path" ]]; then
    bad+=("?? $path (symbolic link)")
  elif ! allowed A "$path"; then
    bad+=("?? $path")
  fi
done < <(git ls-files --others --exclude-standard)

if ((${#bad[@]})); then
  printf 'check-protected: refused changes against %s:\n' "$base" >&2
  printf '  %s\n' "${bad[@]}" >&2
  exit 1
fi
printf 'check-protected: ok against %s\n' "$base"
