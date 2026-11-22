#!/usr/bin/env bash
# Adopt an EXISTING single-README Codeberg root into Huntsman without rewriting its history.
# The new main is a two-parent merge: existing Codeberg main and original GitHub main.
# A new github-main branch retains the original main SHA exactly.
set -euo pipefail
umask 077
export GIT_TERMINAL_PROMPT=0
SOURCE_DEFAULT='https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git'
usage() {
  printf 'Usage: bash %s plan|adopt|resume|verify CODEBERG_USER/REPO\n' "$0" >&2
  exit 64
}
fail() { printf 'codeberg-adopt: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 2 ]] || usage
mode=$1 project=$2
[[ "$mode" == plan || "$mode" == adopt || "$mode" == resume || "$mode" == verify ]] || usage
[[ ${#project} -le 180 && "$project" =~ ^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$ ]] || fail 'Invalid Codeberg USER/REPO path.'
source_url="$SOURCE_DEFAULT"
destination="git@codeberg.org:${project}.git"
if [[ ${HUNTSMAN_MIGRATION_TEST_MODE:-0} == 1 ]]; then
  source_url=${HUNTSMAN_MIGRATION_SOURCE:?missing test source}
  destination=${HUNTSMAN_MIGRATION_TEST_DESTINATION:?missing test destination}
fi
for program in git awk sort diff mktemp cmp grep; do
  command -v "$program" >/dev/null || fail "Missing $program"
done

expected_remote=${HUNTSMAN_CODEBERG_EXPECT_MAIN:-}
expected_source=${HUNTSMAN_MIGRATION_EXPECT_MAIN:-}
# Operators must explicitly pin both verified existing heads for a modifying adoption.
if [[ "$mode" != plan ]]; then
  [[ "$expected_remote" =~ ^[0-9a-fA-F]{40}$ ]] || fail 'Set HUNTSMAN_CODEBERG_EXPECT_MAIN to the verified 40-character original Codeberg main SHA.'
  [[ "$expected_source" =~ ^[0-9a-fA-F]{40}$ ]] || fail 'Set HUNTSMAN_MIGRATION_EXPECT_MAIN to the verified 40-character GitHub main SHA.'
  expected_remote=${expected_remote,,}
  expected_source=${expected_source,,}
fi
if [[ "$mode" == plan ]]; then
  printf 'Source: %s\nDestination: %s\n' "$source_url" "$destination"
  printf 'Existing Codeberg main must be a single-README root commit. No refs or history will be deleted.\n'
  printf 'Set HUNTSMAN_CODEBERG_EXPECT_MAIN and HUNTSMAN_MIGRATION_EXPECT_MAIN before adopt.\n'
  printf 'adopt creates a two-parent merge; github-main keeps canonical GitHub main SHA.\n'
  exit 0
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/hse-codeberg-adopt.XXXXXXXX") || fail 'Cannot create temporary checkout.'
trap 'rm -rf -- "$work"' EXIT
# Freeze source before inspecting destination. This retains all source branches and tags.
git -c credential.interactive=never clone --bare -- "$source_url" "$work/source.git" >&2 || fail 'Cannot clone canonical source.'
git -C "$work/source.git" rev-parse -q --verify refs/heads/main >/dev/null || fail 'Source has no main ref.'
source_main=$(git -C "$work/source.git" rev-parse refs/heads/main)
[[ "$source_main" == "$expected_source" ]] || fail "Source main moved (actual $source_main); no writes."
if git -C "$work/source.git" show-ref --verify -q refs/heads/github-main; then
  fail 'Canonical source already contains reserved branch github-main.'
fi
if git -C "$work/source.git" cat-file -e 'refs/heads/main:docs/legacy-codeberg-README.md' 2>/dev/null; then
  fail 'Canonical source already owns reserved docs/legacy-codeberg-README.md.'
fi

# Capture refs through the network. Failure is NOT interpreted as an empty result.
read_refs() {
  git -c credential.interactive=never ls-remote --heads --tags "$destination" |
    awk '$2 !~ /\^\{\}$/ { printf "%s\t%s\n", $1, $2 }' | LC_ALL=C sort
}
read_refs > "$work/remote.refs" || fail 'Cannot list Codeberg refs; check SSH access.'
[[ -s "$work/remote.refs" ]] || fail 'Codeberg is empty; use codeberg-migrate.sh instead of adopt.'
# Explicit root anchor must still exist, even after a completed adoption.
git -C "$work/source.git" -c credential.interactive=never fetch --no-tags "$destination" \
  refs/heads/main:refs/remotes/codeberg/current >/dev/null 2>&1 || fail 'Cannot fetch Codeberg main.'
remote_main=$(git -C "$work/source.git" rev-parse refs/remotes/codeberg/current)

# Validate the preserved Codeberg initial root, whether adoption happened yet or not.
# Fetching main has already transferred the original root object when it is
# still reachable. Avoid direct-SHA fetch: Forgejo may refuse unadvertised SHAs.
git -C "$work/source.git" cat-file -e "${expected_remote}^{commit}" || fail 'Pinned Codeberg root is not reachable from current main.'
[[ -z $(git -C "$work/source.git" rev-list --parents -n 1 "$expected_remote" | awk '{print $2}') ]] || fail 'Pinned Codeberg commit is not a root commit.'
[[ $(git -C "$work/source.git" ls-tree -r --name-only "$expected_remote") == README.md ]] || fail 'Pinned Codeberg root contains more than README.md; refuse adoption.'

# In a completed adoption main is the two-parent merge, with the Codeberg root
# first (fast-forward anchor) and the canonical GitHub main second.
validate_adopted_main() {
  local parents raw diff_names archived_blob initial_blob
  raw=$(git -C "$work/source.git" rev-list --parents -n 1 "$remote_main")
  read -r -a parents <<< "$raw"
  [[ ${#parents[@]} -eq 3 && ${parents[1]} == "$expected_remote" && ${parents[2]} == "$source_main" ]] ||
    fail 'Codeberg main is not the expected two-parent adoption merge.'
  git -C "$work/source.git" merge-base --is-ancestor "$expected_remote" "$remote_main" || fail 'Codeberg root missing from adoption history.'
  git -C "$work/source.git" merge-base --is-ancestor "$source_main" "$remote_main" || fail 'GitHub main missing from adoption history.'
  diff_names=$(git -C "$work/source.git" diff --name-status "$source_main" "$remote_main")
  [[ "$diff_names" == $'A\tdocs/legacy-codeberg-README.md' ]] || fail 'Adoption changed files other than the archived Codeberg README.'
  archived_blob=$(git -C "$work/source.git" rev-parse "$remote_main:docs/legacy-codeberg-README.md")
  initial_blob=$(git -C "$work/source.git" rev-parse "$expected_remote:README.md")
  [[ "$archived_blob" == "$initial_blob" ]] || fail 'Archived Codeberg README differs from original.'
}

# For the one and only adoption commit, the destination must contain main only,
# at the exact pinned root. Never update a destination with other owner work.
if [[ "$mode" == adopt ]]; then
  [[ "$remote_main" == "$expected_remote" ]] || fail 'Codeberg main is not pinned initial commit; use resume or inspect manually.'
  [[ $(cat "$work/remote.refs") == "${expected_remote}"$'\t''refs/heads/main' ]] || fail 'Codeberg has more than the pinned main branch; refuse adoption.'
  # Construct a tree with the exact GitHub main contents, adding only an archived
  # copy of the Codeberg README. Do not import it over the real GitHub README.
  git -C "$work/source.git" worktree add --detach "$work/merge-tree" "$source_main" >/dev/null 2>&1 || fail 'Cannot create merge worktree.'
  mkdir -p "$work/merge-tree/docs"
  git -C "$work/source.git" show "$expected_remote:README.md" > "$work/merge-tree/docs/legacy-codeberg-README.md"
  git -C "$work/merge-tree" add docs/legacy-codeberg-README.md || fail 'Cannot stage archived README.'
  merged_tree=$(git -C "$work/merge-tree" write-tree) || fail 'Cannot build adoption tree.'
  merge_commit=$(GIT_AUTHOR_NAME='Huntsman migration' GIT_AUTHOR_EMAIL='migration@users.noreply.invalid' \
    GIT_COMMITTER_NAME='Huntsman migration' GIT_COMMITTER_EMAIL='migration@users.noreply.invalid' \
    git -C "$work/source.git" commit-tree "$merged_tree" -p "$expected_remote" -p "$source_main" \
      -m 'chore(hosting): preserve Codeberg root and incorporate canonical Huntsman main') || fail 'Cannot create adoption merge.'
  git -C "$work/source.git" merge-base --is-ancestor "$expected_remote" "$merge_commit" || fail 'Invalid fast-forward merge ancestry.'
  git -C "$work/source.git" merge-base --is-ancestor "$source_main" "$merge_commit" || fail 'Canonical source ancestry not preserved.'
  # Empty remote changes or parallel writers are rejected by the exact lease;
  # the constructed commit is ALSO a fast-forward from the pinned remote root.
  git -C "$work/source.git" -c credential.interactive=never push \
    "--force-with-lease=refs/heads/main:$expected_remote" "$destination" "$merge_commit:refs/heads/main" ||
      fail 'Adoption push refused; inspect remote main, do not force-push.'
  remote_main=$merge_commit
else
  validate_adopted_main
fi

# Push exact SHA of original GitHub main under a distinct branch, then other
# branches and tags. Ref creation uses an EMPTY expected SHA (no overwrite).
# This local alias is a new destination branch; it NEVER changes source main.
git -C "$work/source.git" update-ref refs/heads/github-main "$source_main" || fail 'Cannot create local source-main alias.'
source_refs="$work/source.refs"
git -C "$work/source.git" show-ref --heads --tags |
  awk '$2 != "refs/heads/main" { printf "%s\t%s\n", $1, $2 }' |
  LC_ALL=C sort > "$source_refs"
LC_ALL=C sort -o "$source_refs" "$source_refs"

# Refresh and validate existing refs before pushing any missing ref.
read_refs > "$work/remote.refs" || fail 'Cannot re-read Codeberg refs.'
[[ $(awk '$2 == "refs/heads/main" { print $1 }' "$work/remote.refs") == "$remote_main" ]] || fail 'Codeberg main changed concurrently.'
awk '$2 != "refs/heads/main" { print }' "$work/remote.refs" > "$work/other.refs"
awk 'FILENAME == ARGV[1] { expected[$2]=$1; next }
  !($2 in expected) { print "Unexpected Codeberg ref " $2 > "/dev/stderr"; bad=1; next }
  expected[$2] != $1 { print "Divergent Codeberg ref " $2 > "/dev/stderr"; bad=1 }
  END { exit bad }' "$source_refs" "$work/other.refs" || fail 'Remote has nonmatching refs; no additional writes.'
awk 'FILENAME == ARGV[1] { present[$2]=1; next }
  !($2 in present) { print $2 }' "$work/other.refs" "$source_refs" > "$work/missing.refs"
if [[ "$mode" == adopt || "$mode" == resume ]]; then
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    git -C "$work/source.git" -c credential.interactive=never push \
      "--force-with-lease=$ref:" "$destination" "$ref:$ref" || fail "Cannot create $ref; rerun resume after checking remote."
  done < "$work/missing.refs"
fi

# Verify complete ref equality, including the synthesized two-parent main and
# the exact original source main alias. Also verify default symbolic HEAD.
read_refs > "$work/final.refs" || fail 'Cannot verify destination refs.'
printf '%s\t%s\n' "$remote_main" refs/heads/main >> "$source_refs"
LC_ALL=C sort -o "$source_refs" "$source_refs"
diff -u "$source_refs" "$work/final.refs" || fail 'Destination refs do not exactly match expected history.'
head_advertisement=$(git -c credential.interactive=never ls-remote --symref "$destination" HEAD) || fail 'Cannot query Codeberg default HEAD.'
remote_default=$(printf '%s\n' "$head_advertisement" | awk '$1 == "ref:" && $3 == "HEAD" { print $2 }')
remote_tip=$(printf '%s\n' "$head_advertisement" | awk '$2 == "HEAD" && $1 != "ref:" { print $1 }')
[[ "$remote_default" == refs/heads/main && "$remote_tip" == "$remote_main" ]] ||
  fail 'Destination HEAD is not the expected adopted main.'
validate_adopted_main
printf 'VERIFIED ADOPTION: %s\n' "$destination"
printf 'Codeberg original: %s\nGitHub main: %s\nCodeberg merge: %s\n' "$expected_remote" "$source_main" "$remote_main"
printf 'The existing Codeberg initial commit and every canonical Huntsman commit remain reachable.\n'
