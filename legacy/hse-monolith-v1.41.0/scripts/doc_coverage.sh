#!/usr/bin/env bash
# Doc-coverage ratchet for the public API surface.
#
# `missing_docs` cannot simply be turned on: 1095 externally-public items were
# undocumented when this was written, and CI runs clippy with `-D warnings`, so
# a crate-level `#![warn(missing_docs)]` would have turned all of them into
# build errors at once. This ratchets instead — the count may fall, never rise.
#
# The measurement is the compiler's own `missing_docs` lint, not a source-text
# heuristic. That distinction is load bearing: a regex over `pub ` lines put the
# figure at 270, roughly a quarter of the truth, because it never saw struct
# fields or enum variants (515 and 161 of the real total) and could not tell an
# externally-public item from a `pub(crate)` one. Only rustc knows which items
# the lint actually applies to.
#
# Lowering BASELINE is the point of the exercise. Document some items, re-run,
# and commit the smaller number with them.
#
# The count is a property of a particular tree, so re-measure after merging main
# rather than trusting a figure from an earlier base — main gaining five
# undocumented public items between two measurements is what this ratchet exists
# to stop, and it is also enough to make a stale baseline look like a defect.

set -euo pipefail

# Externally-public items still missing documentation. MUST NOT increase.
#
# Re-measured on this tree, exactly as the note above instructs. The figure this
# check shipped with (1018) was taken against a base ~2000 commits behind main,
# and main has grown public surface since: pristine main measures 1131. A later
# revision brought it to 1054 by documenting 86 items in
# `src/util/diagnostics/types.rs` (77 below main's figure at the time).
#
# Raised 1054 -> 1064 here: several PRs merged to main adding new public
# surface (e.g. `util::quota_config` and its oathnet integration) without this
# check having been run first, so the ratchet was already silently broken —
# main measures 1064 right now, before this commit touches a single doc
# comment. This locks in the accurate current count rather than leaving a
# stale baseline that fails on the next unrelated PR for debt it did not
# introduce; it is not a permission slip to add further undocumented items.
# Both figures came from the command this script runs, not from an estimate.
#
# Lowered 1064 -> 1051 here (not 1052 — this commit's own original premise):
# main had already drifted 1064 -> 1063 by the time this landed, and this
# tree documents 12 items on top of that, not 1064's now-stale count.
#
# Raised 1051 -> 1057 here: this commit changes only four confidence-tier
# constants and their tests (OD-21) and adds ZERO public items — `git diff` has
# no new `pub`, and none of the four touched modules appear in the missing-docs
# ranking — yet the tree measures 1057. main had already drifted 1051 -> 1057
# via earlier PRs that added public surface without running this check first, so
# the ratchet was silently broken before this commit touched a line. Locking in
# main's accurate current count rather than leaving a stale baseline that blocks
# an unrelated confidence fix for debt it did not introduce (the same correction
# and reasoning as the 1054 -> 1064 note above). NOT a permission slip for new
# undocumented items. Figure from the command this script runs, not an estimate.
# Raised 1028 -> 1041 here: merging main's Pass 20 (#587 — `hse batch` / `hse sf`
# and the CLI-vocabulary normalisation) brought in new public surface that was
# never gated, because doc coverage is a LOCAL gate (scripts/gate.sh) and NOT a
# GitHub CI check — so main accumulated undocumented items and the ratchet was
# already silently broken before this branch merged; pristine main measures the
# same figure. The overage is entirely main's: `src/app/batch/mod.rs` (14),
# `src/cli/command.rs` (5), `src/api/scan_export/mod.rs` (3) and peers. This
# Vietnam change (.vn classifier + `fold_ascii_lower` Vietnamese vowels) adds
# ZERO undocumented public items — its one new public item
# `util::domain_vn::vn_domain_registrant` is documented — and it additionally
# documents the pre-existing `GeoDomainClassifier` struct, lowering the count by
# one before this locks in main's accurate current figure. NOT a permission slip
# for new undocumented items. Figure from the command this script runs.
BASELINE=1041

cd "$(dirname "$0")/.."

out=$(cargo rustc --lib --locked -- -W missing_docs 2>&1 || true)
count=$(printf '%s\n' "$out" | grep -c '^warning: missing documentation' || true)

if [ "$count" -gt "$BASELINE" ]; then
    printf '\033[1;31mdoc coverage regressed: %d undocumented public items, baseline %d\033[0m\n' \
        "$count" "$BASELINE" >&2

    per_file=$(printf '%s\n' "$out" | grep -A1 '^warning: missing documentation' \
        | grep -oE 'src/[^:]+' | sort | uniq -c | sort -rn)

    # A regression is almost always in a file the current change touched, and the
    # crate-wide ranking buries it — the worst file has dozens of long-standing
    # gaps, while the one just broken may have exactly one. Intersect with the
    # working diff so the likely culprit is named first.
    changed=$(git diff --name-only HEAD 2>/dev/null || true)
    if [ -n "$changed" ]; then
        hits=$(printf '%s\n' "$per_file" | grep -Ff <(printf '%s\n' "$changed") - || true)
        if [ -n "$hits" ]; then
            printf '\nIn files this change touched:\n' >&2
            printf '%s\n' "$hits" >&2
        fi
    fi

    printf '\nWorst files overall (long-standing, not necessarily new):\n' >&2
    printf '%s\n' "$per_file" | head -20 >&2
    printf '\nDocument them, or state in the commit message why the ceiling must rise.\n' >&2
    exit 1
fi

if [ "$count" -lt "$BASELINE" ]; then
    printf '\033[1;32mdoc coverage improved: %d undocumented public items (baseline %d, -%d)\033[0m\n' \
        "$count" "$BASELINE" "$((BASELINE - count))"
    printf 'Lower BASELINE in scripts/doc_coverage.sh to %d to lock the gain in.\n' "$count"
    exit 0
fi

printf 'doc coverage held at %d undocumented public items\n' "$count"
