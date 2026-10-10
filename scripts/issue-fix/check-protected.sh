#!/usr/bin/env bash
# check-protected.sh BASE
#
# Refuses a working-tree change that the issue-fix agent is not allowed to make.
# BASE is the commit the change was made on, so a commit the agent might make cannot
# hide a change. Allowed:
#
#   - a new (added) file under src/ or tests/;
#   - a change under src/ that stays above the test code of its file. Test code starts at
#     the first test marker (#[cfg(test)], #[test], or another crate's test attribute)
#     and runs to the end of the file.
#
# Refused:
#   - any change to a file that is wholly test code at BASE: a file named tests.rs,
#     test.rs, *_tests.rs or *_test.rs; a file under a tests/ directory; a file that
#     opens with #![cfg(test)]; and every file that a module declared in test code loads,
#     including a file named by #[path] and everything under its directory;
#   - a modified, deleted, or renamed file under tests/;
#   - a change to test code in src/, including deleting or renaming away a file that
#     holds test code;
#   - any change outside src/ and tests/, including untracked files;
#   - a symbolic link or submodule, added or removed.
#
# Every git command ignores in-tree attributes (--attr-source), so a .gitattributes file
# in the change cannot run a filter or hide a hunk, and every diff is read as text. Git
# output is read NUL-separated, so no file name can be split. A git failure is a refusal,
# never a pass.
#
# A marker inside a string literal also starts test code, so an edit below it is refused
# even when it is not test code. That refusal is safe, and it can be a false one.
set -euo pipefail

base="${1:?usage: check-protected.sh BASE}"
EMPTY_TREE=4b825dc642cb6eb9a060e54bf8d69288fbee4904
bad=()
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

g() { git --attr-source="$EMPTY_TREE" "$@"; }

die() {
  echo "check-protected: $*; refusing" >&2
  exit 1
}

if ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
  die "$base is not a commit"
fi

# The first line that starts test code, or 0 when there is none.
MARKER_AWK='
  /^[[:space:]]*#[[:space:]]*\[[[:space:]]*(cfg(_attr)?[[:space:]]*\(.*test|[A-Za-z_:]*test(_case)?([^A-Za-z_]|$)|rstest)/ { print NR; found = 1; exit }
  END { if (!found) print 0 }'

# Lists the files that a module declaration loads, as "file:PATH" and "dir:PATH" lines. A
# module is test code when it carries a cfg that names test, or when it is declared on or
# after the first test marker of its file (tstart). A #[path] attribute is followed. A
# path that is absolute, or that leaves its directory, protects all of src/, because the
# check cannot follow it.
# The awk program is single-quoted on purpose: $0 and the other awk variables are not shell.
# shellcheck disable=SC2016
LOADS_AWK='
  function dirof(p) { sub(/\/[^\/]*$/, "", p); return p }
  function stemof(p) { n = p; sub(/^.*\//, "", n); sub(/\.rs$/, "", n); return n }
  /^[[:space:]]*$/ { next }
  /^[[:space:]]*\/\// { next }
  /^[[:space:]]*#\[path[[:space:]]*=/ {
    pathattr = $0; sub(/^[^"]*"/, "", pathattr); sub(/".*$/, "", pathattr); next
  }
  /^[[:space:]]*#\[/ && !/mod[[:space:]]/ {
    if ($0 ~ /cfg[[:space:]]*\(.*test/) armed = 1
    next
  }
  /mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*;/ {
    if (armed || $0 ~ /cfg[[:space:]]*\(.*test/ || (tstart > 0 && NR >= tstart)) {
      name = $0; sub(/^.*mod[[:space:]]+/, "", name); sub(/[[:space:]]*;.*$/, "", name)
      if (decl ~ /(^|\/)(mod|lib|main)\.rs$/) childdir = dirof(decl)
      else childdir = dirof(decl) "/" stemof(decl)
      if (pathattr != "") {
        if (pathattr ~ /^\// || pathattr ~ /(^|\/)\.\.(\/|$)/) {
          print "dir:src/"
        } else {
          file = dirof(decl) "/" pathattr
          print "file:" file
          print "dir:" dirof(file) "/"
        }
      } else {
        print "file:" childdir "/" name ".rs"
        print "file:" childdir "/" name "/mod.rs"
        print "dir:" childdir "/" name "/"
      }
    }
    armed = 0; pathattr = ""; next
  }
  { armed = 0; pathattr = "" }'

# Sets START to the line where test code starts in PATH at BASE, or 0 when the file has
# none or is absent at BASE. A git failure stops the check.
START=0
test_start() {
  START=0
  g cat-file -e "$base:$1" 2>/dev/null || return 0
  g cat-file blob "$base:$1" > "$scratch/base" || die "cannot read $1 at $base"
  START="$(awk "$MARKER_AWK" "$scratch/base")" || die "cannot scan $1 at $base"
}

# True (status 0) when a change to PATH at BASE touches its test code. A diff that cannot
# be read counts as a touch, so the change is refused.
touches_tests() {
  test_start "$1"
  [[ "$START" -gt 0 ]] || return 1
  g diff -U0 --text --no-ext-diff "$base" -- "$1" > "$scratch/diff" || return 0
  awk -v start="$START" '
    /^@@ / {
      split($2, old, ",")
      first = substr(old[1], 2) + 0
      count = (old[2] == "" ? 1 : old[2] + 0)
      last = (count == 0 ? first : first + count - 1)
      if (last >= start) hit = 1
    }
    END { exit (hit ? 0 : 1) }' "$scratch/diff"
}

test_files=()
test_dirs=()
modules_loaded=0

load_test_modules() {
  [[ "$modules_loaded" -eq 0 ]] || return 0
  modules_loaded=1
  g ls-tree -r -z --name-only "$base" -- src > "$scratch/tree" || die "git ls-tree failed against $base"
  local decl entry
  while IFS= read -r -d '' decl; do
    [[ "$decl" == *.rs ]] || continue
    test_start "$decl"
    g cat-file blob "$base:$decl" > "$scratch/decl" || die "cannot read $decl at $base"
    awk -v decl="$decl" -v tstart="$START" "$LOADS_AWK" "$scratch/decl" > "$scratch/entries" \
      || die "cannot scan the modules of $decl"
    while IFS= read -r entry; do
      case "$entry" in
        file:*) test_files+=("${entry#file:}") ;;
        dir:*) test_dirs+=("${entry#dir:}") ;;
      esac
    done < "$scratch/entries"
  done < "$scratch/tree"
}

is_loaded_test_module() {
  local p="$1" f d
  for f in "${test_files[@]:-}"; do
    if [[ "$p" == "$f" ]]; then
      return 0
    fi
  done
  for d in "${test_dirs[@]:-}"; do
    if [[ -n "$d" && "$p" == "$d"* ]]; then
      return 0
    fi
  done
  return 1
}

# True when PATH at BASE is wholly test code (see the header for the rules).
wholly_test_code() {
  local path="$1"
  case "$(basename "$path")" in
    tests.rs | test.rs | *_tests.rs | *_test.rs) return 0 ;;
  esac
  case "$path" in
    */tests/*) return 0 ;;
  esac
  if g cat-file -e "$base:$path" 2>/dev/null; then
    g cat-file blob "$base:$path" > "$scratch/whole" || die "cannot read $path at $base"
    if grep -q -E '^[[:space:]]*#![[:space:]]*\[[[:space:]]*cfg[[:space:]]*\(.*test' "$scratch/whole"; then
      return 0
    fi
  fi
  load_test_modules
  is_loaded_test_module "$path"
}

allowed() {
  local status="$1" path="$2"
  case "$path" in
    src/*)
      case "$status" in
        A) return 0 ;;
        M)
          if wholly_test_code "$path" || touches_tests "$path"; then
            return 1
          fi
          return 0
          ;;
        D)
          if wholly_test_code "$path"; then
            return 1
          fi
          test_start "$path"
          [[ "$START" -eq 0 ]]
          ;;
        *) return 1 ;;
      esac
      ;;
    tests/*) [[ "$status" == "A" ]] ;;
    *) return 1 ;;
  esac
}

# The raw diff, NUL-separated: a metadata field (":src_mode dst_mode sha sha STATUS"),
# then one path, or two for a rename or copy.
g diff --raw -z -M --no-ext-diff "$base" -- > "$scratch/raw" || die "git diff failed against $base"
exec 3< "$scratch/raw"
while IFS= read -r -d '' meta <&3; do
  read -r src_mode dst_mode _src_sha _dst_sha status <<< "${meta#:}"
  read -r -d '' first <&3 || die "malformed diff output against $base"
  second=""
  case "$status" in
    R* | C*) read -r -d '' second <&3 || die "malformed diff output against $base" ;;
  esac
  for mode in "$src_mode" "$dst_mode"; do
    case "$mode" in
      120000 | 160000) bad+=("link or submodule (mode $mode) in the diff: $first") ;;
    esac
  done
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
done
exec 3<&-

g ls-files -z --others --exclude-standard > "$scratch/untracked" || die "git ls-files failed"
while IFS= read -r -d '' path; do
  if [[ -L "$path" ]]; then
    bad+=("?? $path (symbolic link)")
  elif ! allowed A "$path"; then
    bad+=("?? $path")
  fi
done < "$scratch/untracked"

if ((${#bad[@]})); then
  printf 'check-protected: refused changes against %s:\n' "$base" >&2
  printf '  %s\n' "${bad[@]}" >&2
  exit 1
fi
printf 'check-protected: ok against %s\n' "$base"
