#!/usr/bin/env python3
"""Resolve an `.agent/state.json` merge conflict between two concurrent loop sessions.

Two automated sessions run the five-slot loop on separate branches and both
write this file, so it conflicts on essentially every merge from main. The
resolution is always the same shape, so it is scripted rather than redone by
hand each time — a hand-merge of a 20 KB JSON file is exactly where a record
silently loses an entry.

main's copy is the canonical record and always wins on the keys it owns: it
advances the cycle counter, the slot lists and the shared defect/rejection
registers. This branch's contributions are re-applied on top, under keys main
does not use, so neither side is overwritten and the provenance stays explicit.

Usage, mid-conflict:

    git show :2:.agent/state.json > /tmp/ours.json     # this branch
    git show :3:.agent/state.json > /tmp/theirs.json   # origin/main
    python3 .agent/merge_state.py /tmp/ours.json /tmp/theirs.json [BRANCH]
    git add .agent/state.json

BRANCH defaults to the branch this helper shipped on; pass it explicitly when
a different session reuses the resolver so the provenance keys match its work.
"""

import collections
import json
import sys

# The branch this helper originally shipped on; used as the default when the
# caller does not name one. Overridable as the optional third CLI argument so a
# different concurrent session can reuse the resolver without editing the file.
DEFAULT_BRANCH = "claude/huntsman-price-analysis-ewy20t"

USAGE = "usage: python3 .agent/merge_state.py OURS.json THEIRS.json [BRANCH]"

CONCURRENCY_NOTE = [
    "",
    "CONCURRENCY: two automated sessions ran this loop at the same time on",
    "separate branches and both wrote this file, with different schemas and",
    "overlapping slot numbers. They are merged as a union, not reconciled into",
    "one sequence — the cycle_N_slots lists are the other session's run, and",
    "`concurrent_session_runs` is this branch's. A future cycle should pick ONE",
    "shape before adding to either, or every merge from main will conflict here.",
    "The resolution is scripted: .agent/merge_state.py.",
]

def corroboration(branch):
    """The shared-rejection annotation, tagged with the resolving branch."""
    return (
        "Reached independently by the session on " + branch + ", which measured "
        "the inline tests those 8 modules already carried: bluesky_user 15, "
        "codeberg_user 9, devto 7, gitlab_user 8, lobsters 8, mastodon_user 8, "
        "stackoverflow_user 11, url_extract 5 — 71 tests, not zero. Two detectors, "
        "same artefact, same conclusion. Note the layout count is three, not two: "
        'include!("tests.rs") 191 files, `mod tests;` 107, tests inline in mod.rs '
        "~129 — and every_src_file_is_wired_into_the_module_tree accepts all of them."
    )


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=collections.OrderedDict)


def merge(ours, theirs, branch=DEFAULT_BRANCH):
    """main's copy (`theirs`) is the base; re-apply this branch's additions."""
    out = theirs

    # Drop any previously appended note in full — it runs from its marker line
    # to the end of the list, so matching only the marker leaves the tail behind
    # and each re-run appends a duplicate.
    base_comment = list(out.get("$comment", []))
    marker = next(
        (i for i, c in enumerate(base_comment) if "CONCURRENCY:" in c), len(base_comment)
    )
    base_comment = base_comment[:marker]
    while base_comment and not base_comment[-1].strip():
        base_comment.pop()
    out["$comment"] = base_comment + CONCURRENCY_NOTE

    # Keys main does not use: carried across verbatim from this branch.
    for key in ("concurrent_session_runs", "incidents"):
        if key in ours:
            out[key] = ours[key]

    # Annotate the shared rejection both sessions reached independently.
    for c in out.get("rejected_candidates", []):
        if c["candidate"].startswith("Add test coverage to the 8"):
            c["corroboration"] = corroboration(branch)

    # This branch's rejections and defects, keyed so re-running is idempotent.
    seen = {c["candidate"] for c in out.get("rejected_candidates", [])}
    for c in ours.get("rejected_candidates", []):
        if c.get("source_branch") == branch and c["candidate"] not in seen:
            out["rejected_candidates"].append(c)

    ids = {d["id"] for d in out.get("open_defects", [])}
    for d in ours.get("open_defects", []):
        if d["id"].startswith("PA-") and d["id"] not in ids:
            out["open_defects"].append(d)

    return out


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(USAGE)
    ours_path, theirs_path = sys.argv[1], sys.argv[2]
    branch = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_BRANCH
    merged = merge(load(ours_path), load(theirs_path), branch)
    with open(".agent/state.json", "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("cycle_count:", merged.get("cycle_count"))
    print("rejected_candidates:", len(merged.get("rejected_candidates", [])))
    print("open_defects:", [d["id"] for d in merged.get("open_defects", [])])
    print("incidents:", len(merged.get("incidents", [])))
    print("concurrent_session_runs:", len(merged.get("concurrent_session_runs", [])))
