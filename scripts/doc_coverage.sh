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
BASELINE=1018

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
