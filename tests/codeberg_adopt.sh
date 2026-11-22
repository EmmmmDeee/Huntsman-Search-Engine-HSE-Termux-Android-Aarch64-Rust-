#!/usr/bin/env bash
# Offline adoption contract with real local git object IDs and two-parent merge.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
s="$root/scripts/codeberg-adopt.sh"
bash -n "$s"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hse-codeberg-adopt-test.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/github" "$tmp/codeberg-init"
for dir in github codeberg-init; do
  git -C "$tmp/$dir" init -q -b main
  git -C "$tmp/$dir" config user.name 'Test'
  git -C "$tmp/$dir" config user.email 'test@example.invalid'
done
printf '# Canonical Huntsman\n' > "$tmp/github/README.md"
mkdir "$tmp/github/src"; printf 'fn main() {}\n' > "$tmp/github/src/main.rs"
git -C "$tmp/github" add . && git -C "$tmp/github" commit -qm 'source root'
git -C "$tmp/github" branch review/test
git -C "$tmp/github" tag -a v1 -m 'tag'
printf '# Existing Codeberg stub\n' > "$tmp/codeberg-init/README.md"
git -C "$tmp/codeberg-init" add . && git -C "$tmp/codeberg-init" commit -qm 'initial Codeberg README'
git init -q --bare "$tmp/host.git"
git --git-dir="$tmp/host.git" symbolic-ref HEAD refs/heads/main
git -C "$tmp/codeberg-init" push -q "$tmp/host.git" main
export HUNTSMAN_MIGRATION_TEST_MODE=1
export HUNTSMAN_MIGRATION_SOURCE="$tmp/github"
export HUNTSMAN_MIGRATION_TEST_DESTINATION="$tmp/host.git"
export HUNTSMAN_MIGRATION_EXPECT_MAIN=$(git -C "$tmp/github" rev-parse HEAD)
export HUNTSMAN_CODEBERG_EXPECT_MAIN=$(git -C "$tmp/codeberg-init" rev-parse HEAD)
# A simple push must refuse a populated destination, and pre-adoption verify
# must fail instead of silently counting the stub README as migrated source.
if [[ -f "$root/scripts/codeberg-migrate.sh" ]]; then
  if bash "$root/scripts/codeberg-migrate.sh" push example/huntsman > "$tmp/blocked-simple.txt" 2>&1; then
    echo 'FAIL: simple migration overwrote initialized Codeberg destination' >&2; exit 1
  fi
else
  printf 'NOTE: legacy migration script absent; tested adoption workflow independently\n' >&2
fi
bash "$s" plan example/huntsman > "$tmp/plan.log"
if bash "$s" verify example/huntsman > "$tmp/before.log" 2>&1; then
 echo 'FAIL: verified a repository before adoption' >&2;exit 1
fi
bash "$s" adopt example/huntsman > "$tmp/adopt.log" 2>&1 || { cat "$tmp/adopt.log"; exit 1; }
grep -q 'VERIFIED ADOPTION' "$tmp/adopt.log"
bash "$s" verify example/huntsman > "$tmp/verify.log" 2>&1 || { cat "$tmp/verify.log"; exit 1; }
grep -q 'VERIFIED ADOPTION' "$tmp/verify.log"
new_main=$(git --git-dir="$tmp/host.git" rev-parse refs/heads/main)
[[ "$new_main" != "$HUNTSMAN_CODEBERG_EXPECT_MAIN" ]]
git --git-dir="$tmp/host.git" merge-base --is-ancestor "$HUNTSMAN_CODEBERG_EXPECT_MAIN" "$new_main"
git --git-dir="$tmp/host.git" merge-base --is-ancestor "$HUNTSMAN_MIGRATION_EXPECT_MAIN" "$new_main"
[[ $(git --git-dir="$tmp/host.git" rev-parse refs/heads/github-main) == "$HUNTSMAN_MIGRATION_EXPECT_MAIN" ]]
[[ $(git --git-dir="$tmp/host.git" show "$new_main:docs/legacy-codeberg-README.md") == '# Existing Codeberg stub' ]]
[[ $(git --git-dir="$tmp/host.git" show "$new_main:README.md") == '# Canonical Huntsman' ]]
# Repeated resume/verify cannot move main.
bash "$s" resume example/huntsman > "$tmp/resume.log" 2>&1
[[ $(git --git-dir="$tmp/host.git" rev-parse refs/heads/main) == "$new_main" ]]
# Missing source branch (e.g., network drop after moving main) is restored.
git --git-dir="$tmp/host.git" update-ref -d refs/heads/review/test
if bash "$s" verify example/huntsman > "$tmp/partial.log" 2>&1;then
 echo 'FAIL: missing branch incorrectly accepted' >&2;exit 1
fi
bash "$s" resume example/huntsman > "$tmp/recovered.log" 2>&1
bash "$s" verify example/huntsman > "$tmp/reverified.log" 2>&1
# Additional Codeberg author work blocks recovery and is not deleted.
git --git-dir="$tmp/host.git" update-ref refs/heads/foreign "$new_main"
if bash "$s" resume example/huntsman > "$tmp/foreign.log" 2>&1;then
 echo 'FAIL: foreign ref was silently accepted' >&2;exit 1
fi
[[ $(git --git-dir="$tmp/host.git" rev-parse refs/heads/foreign) == "$new_main" ]]
git --git-dir="$tmp/host.git" update-ref -d refs/heads/foreign
# Changed pinned SHA fails on source clone before touching remote.
export HUNTSMAN_MIGRATION_EXPECT_MAIN=0000000000000000000000000000000000000000
if bash "$s" resume example/huntsman > "$tmp/stale.log" 2>&1;then
 echo 'FAIL: source pin ignored' >&2;exit 1
fi
[[ $(git --git-dir="$tmp/host.git" rev-parse refs/heads/main) == "$new_main" ]]
# An unrelated branch or tag must block a new adoption, before any write.
# Use another local initialized repo to prove refusal without touching the
# successfully adopted fixture.
git init -q --bare "$tmp/host-extra.git"
git --git-dir="$tmp/host-extra.git" symbolic-ref HEAD refs/heads/main
git -C "$tmp/codeberg-init" push -q "$tmp/host-extra.git" main
git --git-dir="$tmp/host-extra.git" update-ref refs/heads/unrelated "$HUNTSMAN_CODEBERG_EXPECT_MAIN"
export HUNTSMAN_MIGRATION_EXPECT_MAIN=$(git -C "$tmp/github" rev-parse HEAD)
export HUNTSMAN_MIGRATION_TEST_DESTINATION="$tmp/host-extra.git"
if bash "$s" adopt example/huntsman > "$tmp/preexisting.txt" 2>&1; then
  echo 'FAIL: unrelated Codeberg branch was overwritten' >&2; exit 1
fi
grep -q 'more than the pinned main branch' "$tmp/preexisting.txt"
[[ $(git --git-dir="$tmp/host-extra.git" rev-parse refs/heads/main) == "$HUNTSMAN_CODEBERG_EXPECT_MAIN" ]]
# A Codeberg repository with an existing unknown default branch is not
# acceptable as a successful migration, even when refs match.
export HUNTSMAN_MIGRATION_TEST_DESTINATION="$tmp/host.git"
git --git-dir="$tmp/host.git" symbolic-ref HEAD refs/heads/master
if bash "$s" verify example/huntsman > "$tmp/default.txt" 2>&1; then
  echo 'FAIL: invalid default branch was accepted' >&2; exit 1
fi
grep -q 'Destination HEAD' "$tmp/default.txt"
git --git-dir="$tmp/host.git" symbolic-ref HEAD refs/heads/main
bash "$s" verify example/huntsman > "$tmp/final.log"
printf 'Codeberg initialized-repository adoption: PASS (merge ancestry, README, refs, resume, divergence, source pin, unrelated refs, HEAD)\n'
