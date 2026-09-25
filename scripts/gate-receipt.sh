#!/usr/bin/env bash
# Gate receipts — the record that `scripts/gate.sh` passed on one exact tree.
#
# Why this exists (REQ-HARNESS-001): the repository meant to refuse a push the
# gate had not passed, but the hook that said so was registered under a hook
# event Claude Code does not have (`StopBeforePush`), so it never ran. Running
# the whole gate inside a push hook is also the wrong shape: it takes minutes
# and repeats work already done. A receipt splits the two jobs. The gate
# writes one when it passes; the push hook (`.claude/hooks/pre-push-gate.sh`)
# only has to look one up.
#
# A receipt names a git TREE id, not a commit. The gate normally runs before
# the commit exists, and a tree id is content-addressed: the tree the gate
# checked and the tree of the commit made from it afterwards are the same id
# exactly when the commit holds what was checked and nothing else. An amend
# that changes content, a rebase onto a new base, a file added after the run:
# each is a different tree, and needs a new gate run.
#
# Usage (run from anywhere inside the checkout):
#   scripts/gate-receipt.sh tree
#       Print the tree id this working tree would commit as under `git add -A`:
#       tracked edits plus untracked files that are not ignored. It is computed
#       in a scratch index, so the real index is never touched.
#   scripts/gate-receipt.sh record <mode> <start-tree> <passed> <failed> <skipped>
#       Called once by gate.sh at the end of a run. Writes the receipt only
#       when nothing failed, at least one check ran, and the tree is still
#       <start-tree>. Otherwise it says why it wrote none. Exits 0 either way:
#       the gate's own exit status is the verdict on the checks.
#   scripts/gate-receipt.sh check [<rev>]
#       Exit 0 when <rev>'s tree (default HEAD) has a receipt, 1 when it has
#       none, 3 when <rev> does not resolve.
#   scripts/gate-receipt.sh dir
#       Print the receipt directory.
#
# Receipts live in `$(git rev-parse --git-common-dir)/hse-gate/`. That is one
# directory per clone, shared by all of its worktrees (a tree id is the same
# in each). It is never committed, and it is outside `target/`, so `cargo
# clean` keeps it.
#
# A receipt is a record, not a signature. Anyone who can write to `.git` can
# forge one. It exists so that a push of an unchecked tree is refused unless
# someone deliberately goes around it.
set -uo pipefail

die() { printf 'gate-receipt: %s\n' "$*" >&2; exit 2; }

TOP="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not inside a git checkout"
COMMON="$(git -C "$TOP" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
    || die "cannot locate the git directory of $TOP"
DIR="$COMMON/hse-gate"

# The tree `git add -A && git commit` would record, from a scratch copy of the
# index. Copying the real index keeps its stat cache, so only files that
# changed are re-hashed.
worktree_tree() {
    local scratch real
    scratch="$(mktemp -d)" || die "mktemp failed"
    real="$(git -C "$TOP" rev-parse --path-format=absolute --git-path index)"
    if [ -f "$real" ]; then
        cp "$real" "$scratch/index" || { rm -rf "$scratch"; die "cannot copy the index"; }
    fi
    local tree
    if GIT_INDEX_FILE="$scratch/index" git -C "$TOP" add -A -- . 2>/dev/null \
        && tree="$(GIT_INDEX_FILE="$scratch/index" git -C "$TOP" write-tree)"; then
        rm -rf "$scratch"
        printf '%s\n' "$tree"
    else
        rm -rf "$scratch"
        die "cannot compute the working tree's tree id"
    fi
}

is_count() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

cmd_record() {
    [ "$#" -eq 5 ] || die "usage: record <mode> <start-tree> <passed> <failed> <skipped>"
    local mode="$1" start="$2" passed="$3" failed="$4" skipped="$5"
    case "$mode" in quick|full) ;; *) die "mode must be quick or full, got '$mode'" ;; esac
    if ! is_count "$passed" || ! is_count "$failed" || ! is_count "$skipped"; then
        die "check counts must be non-negative integers"
    fi

    if [ "$failed" -gt 0 ]; then
        printf 'gate receipt: none recorded (%s check(s) failed)\n' "$failed"
        return 0
    fi
    if [ "$passed" -eq 0 ]; then
        printf 'gate receipt: none recorded (no check executed)\n'
        return 0
    fi
    if [ -z "$start" ]; then
        printf 'gate receipt: none recorded (the tree could not be read when the gate started)\n'
        return 0
    fi
    local now
    now="$(worktree_tree)" || {
        printf 'gate receipt: none recorded (the tree could not be read when the gate finished)\n'
        return 0
    }
    if [ "$now" != "$start" ]; then
        # The checks saw a mix of two trees, so neither one was verified.
        printf 'gate receipt: none recorded (the tree changed while the gate ran: %s -> %s)\n' \
            "$start" "$now"
        return 0
    fi

    mkdir -p "$DIR" || die "cannot create $DIR"
    local head tmp
    head="$(git -C "$TOP" rev-parse --verify --quiet HEAD 2>/dev/null || echo none)"
    tmp="$(mktemp "$DIR/.receipt.XXXXXX")" || die "cannot write in $DIR"
    {
        printf 'tree=%s\n' "$start"
        printf 'mode=%s\n' "$mode"
        printf 'head=%s\n' "$head"
        printf 'passed=%s\n' "$passed"
        printf 'skipped=%s\n' "$skipped"
        printf 'recorded=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'host=%s\n' "$(uname -sm 2>/dev/null || echo unknown)"
    } >"$tmp" || { rm -f "$tmp"; die "cannot write the receipt"; }
    # Renamed into place, so a reader never sees a half-written receipt.
    mv -f "$tmp" "$DIR/$start" || { rm -f "$tmp"; die "cannot store the receipt"; }
    printf 'gate receipt: recorded for tree %s (%s gate, %s passed, %s skipped)\n' \
        "$start" "$mode" "$passed" "$skipped"
}

cmd_check() {
    [ "$#" -le 1 ] || die "usage: check [<rev>]"
    local rev="${1:-HEAD}" tree
    tree="$(git -C "$TOP" rev-parse --verify --quiet "$rev^{tree}" 2>/dev/null)" || {
        printf 'gate receipt: %s does not name a commit or tree here\n' "$rev" >&2
        return 3
    }
    local receipt="$DIR/$tree"
    # The file must name the tree it is filed under; an empty or foreign file
    # at that path is not a record of a gate run.
    if [ -f "$receipt" ] && grep -qx "tree=$tree" "$receipt"; then
        printf 'gate receipt: %s (tree %s) passed the %s gate at %s\n' "$rev" "$tree" \
            "$(sed -n 's/^mode=//p' "$receipt")" "$(sed -n 's/^recorded=//p' "$receipt")"
        return 0
    fi
    printf 'gate receipt: none for %s (tree %s)\n' "$rev" "$tree" >&2
    return 1
}

case "${1:-}" in
    tree)   shift; [ "$#" -eq 0 ] || die "usage: tree"; worktree_tree ;;
    record) shift; cmd_record "$@" ;;
    check)  shift; cmd_check "$@" ;;
    dir)    printf '%s\n' "$DIR" ;;
    *)      die "usage: gate-receipt.sh tree | record <mode> <start-tree> <passed> <failed> <skipped> | check [<rev>] | dir" ;;
esac
