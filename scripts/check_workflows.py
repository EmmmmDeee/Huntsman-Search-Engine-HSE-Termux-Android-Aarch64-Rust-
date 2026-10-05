#!/usr/bin/env python3
"""Structural lint for `.github/workflows/*.yml`.

GitHub validates a workflow file against its own schema and, when it fails,
reports a *startup failure*: a run record that completes in zero seconds with
no job ever executing. On the blocking `ci.yml` that is indistinguishable at a
glance from "CI has not started yet", so a broken workflow can sit unnoticed
while the branch appears merely slow. This lint exists so that failure is
caught on the developer's machine instead.

Two invariants, both learned from real breakage on this repo:

1. **No duplicate mapping keys.** A generic `yaml.safe_load` silently ACCEPTS a
   duplicate key and keeps the last value, so it cannot see this class of
   defect at all — a workflow with two `with:` blocks on one step parses
   "fine" in Python and is rejected outright by GitHub. A hand-edit that
   introduced exactly that shape shipped once because `safe_load` called it
   valid. This lint uses a loader that refuses duplicates and names the line.

2. **Every `pull_request` checkout is pinned to the PR's real head.**
   `actions/checkout` defaults to `refs/pull/N/merge`, a merge commit GitHub
   computes asynchronously and routinely serves STALE to a run that starts
   right after a push — so CI compiles a tree that is not the branch. This
   repo observed doctest failures reported at source lines the branch does not
   have. Since `push` is scoped to `main`, a feature branch's only CI signal is
   the `pull_request` run, which means a stale ref can just as easily mask a
   real regression as invent a phantom one. The pin is the fix; this check is
   what stops it being dropped again.

3. **The local gate does not silently omit a CI check.** `scripts/gate.sh`
   exists to be "every check CI runs on a pull request, in one command", and
   its own header promises that a check which cannot run locally is "reported
   as SKIPPED with the reason, never silently omitted: a gate that quietly
   drops a check is worse than no gate, because it reports success it did not
   establish". It had nonetheless drifted: `secret-scan.yml`'s `gitleaks` job
   — the credential scanner that exists because this repository once shipped
   live provider keys in a public tree — was neither run nor skip-listed, so
   the gate printed "All N executed check(s) passed" without ever counting it.
   Every other gate check catches a defect a later commit can fix; that one
   catches a disclosure no commit can undo (REQ-GATE-002).

   This invariant is what stops the drift recurring, because a one-off
   addition re-drifts the next time CI gains a job. [`GATE_COVERAGE`] must
   account for every `pull_request` job, and is checked in BOTH directions:
   every job is mapped, and every gate label named in the map really exists in
   `gate.sh`. A map naming a label that has been renamed away is as broken as
   an unmapped job.

Exits non-zero, naming the file and the reason, when any invariant breaks.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - environment without PyYAML
    print("check_workflows: PyYAML not installed — skipping", file=sys.stderr)
    sys.exit(0)

WORKFLOW_DIR = Path(".github/workflows")

# The exact expression every `pull_request` checkout must carry. The
# `|| github.sha` fallback is what keeps non-PR events (push, schedule,
# workflow_dispatch) on precisely the ref they used before: outside a
# `pull_request` event `github.event.pull_request` is null.
EXPECTED_REF = "${{ github.event.pull_request.head.sha || github.sha }}"

GATE_SCRIPT = Path("scripts/gate.sh")

# Every `pull_request` job, mapped to the `gate.sh` check label(s) that stand
# in for it locally. A job whose coverage is a single label still uses a tuple.
#
# ADDING A CI JOB? Add it here in the same commit, exactly as `gate.sh`'s
# header requires ("a gate that has drifted from CI is a defect, not a
# convenience"). This lint is what turns that instruction into an enforced one.
GATE_COVERAGE: dict[str, tuple[str, ...]] = {
    "audit.yml::audit": ("cargo-audit / deny / machete / dep-cooldown",),
    "ci.yml::check": (
        "fmt",
        "check",
        "clippy",
        "rustdoc lints",
        "test",
        "doctests",
        "doc coverage",
    ),
    "ci.yml::sibling-crates": (
        "fmt (hse-core)",
        "clippy (hse-core)",
        "rustdoc lints (hse-core)",
        "test (hse-core)",
        "fmt (wasm-ui)",
        "clippy (wasm-ui)",
        "test (wasm-ui, native)",
        "wasm-ui/pkg drift check",
    ),
    "ci.yml::msrv": ("MSRV ($MSRV)",),
    "ci.yml::aarch64-android": ("cross-build ($TARGET)", "cross-test-compile ($TARGET)"),
    "ci.yml::install-script": ("install.sh syntax", "reconcile.sh syntax", "shellcheck"),
    "rust-clippy.yml::rust-clippy-analyze": ("clippy",),
    "secret-scan.yml::gitleaks": ("secret scan (gitleaks)",),
}

# Jobs that are deliberately NOT gate checks, each with the reason. Kept
# separate from `GATE_COVERAGE` so "exempt" is a stated decision rather than an
# omission that looks like one.
GATE_EXEMPT: dict[str, str] = {
    # Provisions a toolchain for GitHub's Copilot agent; it verifies nothing
    # about the tree, so there is no local equivalent to run or to skip.
    "copilot-setup-steps.yml::copilot-setup-steps": "environment setup, not a verification check",
}


class StrictLoader(yaml.SafeLoader):
    """A SafeLoader that refuses duplicate mapping keys instead of silently
    keeping the last one, which is what makes `safe_load` blind here."""


def _no_duplicate_keys(loader: StrictLoader, node, deep: bool = False) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(
                f"duplicate key {key!r} at line {key_node.start_mark.line + 1} "
                f"— GitHub rejects the workflow, though PyYAML's default "
                f"loader accepts it"
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys
)


def _triggers_on_pull_request(doc: dict) -> bool:
    # `on:` is the YAML 1.1 boolean `True` once parsed, not the string "on".
    triggers = doc.get("on", doc.get(True, {}))
    if isinstance(triggers, dict):
        return "pull_request" in triggers
    if isinstance(triggers, list):
        return "pull_request" in triggers
    return triggers == "pull_request"


AUDIT_WORKFLOW = WORKFLOW_DIR / "audit.yml"

# The `git diff --quiet HEAD -- …` line in gate.sh that mirrors audit.yml's path
# filter. Anchored on the first path so a reordering does not silently match a
# different `git diff` call in the same script (there is more than one).
AUDIT_SKIP_RE = re.compile(r"git diff --quiet HEAD -- (Cargo\.toml[^\n]*?) 2>/dev/null")


def _expand_workflow_path(pattern: str) -> set[str]:
    """Expand one workflow path filter against the REAL tree.

    Computing the expansion is the point. `gate.sh` carried `**/Cargo.{toml,lock}`
    hand-expanded into eight literal paths, which was correct on the day it was
    written and silently wrong the moment a ninth crate appears. A lint that
    compared two hand-written lists would just relocate the hand-maintenance.
    """
    if "*" not in pattern:
        return {pattern.rstrip("/")}
    # `src/bin/dep_cooldown/**` — a directory subtree. gate.sh names the
    # directory, which `git diff -- <dir>` already covers recursively.
    if pattern.endswith("/**"):
        return {pattern[: -len("/**")]}
    # `**/Cargo.toml` — every such file the next commit could contain: tracked,
    # or untracked and not ignored. That is the set a workflow path filter can
    # ever match, since GitHub filters on a commit's changed paths. This walked
    # the filesystem with `rglob`, excluding only `target/`, so it also found
    # every nested checkout under an ignored directory. A Claude Code worktree
    # (`.claude/worktrees/agent-*/`, which the `hse-falsifier` subagent creates
    # by design) holds a full copy of the repository's manifests, and each one
    # became a "missing" gate path, so the lint failed on paths CI can never
    # see (REQ-GATE-005). Asking git drops build output, nested worktrees and
    # any other ignored tree without listing them. Untracked files still count,
    # so a new crate is flagged before it is staged, as eagerly as before.
    if pattern.startswith("**/"):
        leaf = pattern[len("**/") :]
        return {p for p in _committable_files() if Path(p).name == leaf} | {leaf}
    return {pattern}


def _committable_files() -> list[str]:
    """The paths `git add -A` would commit: tracked, plus untracked and not
    ignored. The same set the gate receipt's tree is computed from
    (`scripts/gate-receipt.sh tree`), so the two cannot disagree about which
    files exist."""
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
    ).stdout
    return [p for p in out.decode().split("\0") if p]


def _check_audit_paths() -> list[str]:
    """Invariant 4 — `gate.sh`'s audit skip-list must cover audit.yml's filter.

    `gate.sh` skips the cargo-audit / deny / machete / dep-cooldown block when
    no manifest changed, mirroring `audit.yml`'s own path filter by hand. Its
    comment states the consequence of drift: "a mismatch here means this script
    silently SKIPS the check locally ... while CI still runs it" — the same
    silent-omission class as REQ-GATE-002, one section below it, and equally
    unenforced until now.

    The gate must be **at least as eager as CI**, never looser: it is compared
    against the UNION of every event's `paths`, because a developer running the
    gate wants to know about anything CI will run, and it is harmless for the
    local gate to run a check CI would have skipped.

    Two things are checked, because REQ-GATE-003 fixed only the first and
    REQ-GATE-004 found the second was the larger half: the path LIST must cover
    the filter, and the COMPARISON BASE must include `origin/main...HEAD`. A
    guard that asks "do I have uncommitted manifest edits?" answers a different
    question from CI's "does this PR change a manifest?", and on a clean tree —
    the normal state before a push — it skips regardless of how correct the
    path list is. `push` and `pull_request`
    carry DIFFERENT filters here (the PR one omits `dep-cooldown.toml` and
    `src/bin/dep_cooldown/**`), so mirroring only one of them — as the comment
    said it did — leaves the other's paths unguarded (REQ-GATE-003).
    """
    problems: list[str] = []
    try:
        doc = yaml.load(AUDIT_WORKFLOW.read_text(), Loader=StrictLoader)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"audit paths: cannot read {AUDIT_WORKFLOW} — {exc}"]

    triggers = doc.get("on", doc.get(True, {}))
    if not isinstance(triggers, dict):
        return [f"audit paths: {AUDIT_WORKFLOW} has no mapping `on:` to read filters from"]

    required: set[str] = set()
    for event, block in triggers.items():
        if isinstance(block, dict):
            for pattern in block.get("paths") or []:
                required |= _expand_workflow_path(pattern)

    # Vacuity guard: a filter that expanded to nothing would satisfy every
    # assertion below while proving nothing (REQ-GATE-002's M4b lesson).
    if len(required) < 4:
        return [
            f"audit paths: only {len(required)} path(s) expanded from "
            f"{AUDIT_WORKFLOW} — the filter is not being read, so this check "
            f"proves nothing"
        ]

    try:
        gate_src = GATE_SCRIPT.read_text()
    except OSError as exc:
        return [f"audit paths: cannot read {GATE_SCRIPT} — {exc}"]

    match = AUDIT_SKIP_RE.search(gate_src)
    if not match:
        return [
            f"audit paths: no `git diff --quiet HEAD -- Cargo.toml …` line found in "
            f"{GATE_SCRIPT} — the audit skip-list this check exists to verify is gone"
        ]
    listed = {p.rstrip("/") for p in match.group(1).split()}

    # WHAT is compared, not only WHICH paths (REQ-GATE-004). `git diff HEAD`
    # sees uncommitted edits only, so on a clean tree the gate skipped whatever
    # the path list said — while CI's `pull_request` filter matches the
    # branch's CUMULATIVE diff against the base. The audit guard must ask both
    # questions, as the wasm-ui/pkg drift gate in the same script already does.
    guard = match.group(0)
    tail = gate_src[match.end() : match.end() + 600]
    if "origin/main...HEAD" not in guard + tail:
        problems.append(
            f"audit paths: {GATE_SCRIPT}'s audit guard compares only `git diff HEAD` "
            f"(uncommitted edits). CI's pull_request filter matches the branch's "
            f"cumulative diff, so on a clean tree this gate skips a check CI runs. "
            f"Check `origin/main...HEAD` too — the wasm-ui/pkg drift gate in this "
            f"same script shows the shape"
        )

    for path in sorted(required - listed):
        problems.append(
            f"audit paths: `{path}` is in {AUDIT_WORKFLOW.name}'s path filter but not in "
            f"{GATE_SCRIPT}'s audit skip-list — a commit touching only that path would "
            f"run the audit in CI and be SKIPPED locally, which is the looser direction"
        )
    return problems


def _check_gate_coverage(pr_jobs: list[str]) -> list[str]:
    """Invariant 3 — see the module docstring.

    Checked in both directions, and guarded against vacuity: a walk that found
    no jobs would otherwise satisfy every assertion below while proving
    nothing, which is exactly how the registry in REQ-GEOGATE-001 stayed green
    over seven modules it never looked at.
    """
    problems: list[str] = []

    if len(pr_jobs) < 5:
        return [
            f"gate coverage: only {len(pr_jobs)} pull_request job(s) discovered — "
            f"the walk is not finding the workflows, so this check proves nothing"
        ]

    try:
        gate_src = GATE_SCRIPT.read_text()
    except OSError as exc:
        return [f"gate coverage: cannot read {GATE_SCRIPT} — {exc}"]

    # Forward: every pull_request job is either covered or explicitly exempt.
    for job in sorted(pr_jobs):
        if job in GATE_COVERAGE or job in GATE_EXEMPT:
            continue
        problems.append(
            f"gate coverage: `{job}` runs on pull_request but {GATE_SCRIPT} neither "
            f"runs nor skip-lists it, and it is not in GATE_EXEMPT — the gate would "
            f"report success it did not establish. Add the check to gate.sh (or, if "
            f"it cannot run locally, a `skip` with the reason) and map it in "
            f"GATE_COVERAGE"
        )

    # Backward: every label the map names must really exist in gate.sh. A label
    # renamed in gate.sh and not here leaves the map pointing at nothing, which
    # would keep this lint green while the coverage claim became false.
    for job, labels in sorted(GATE_COVERAGE.items()):
        for label in labels:
            if f'"{label}"' in gate_src:
                continue
            problems.append(
                f"gate coverage: `{job}` is mapped to gate.sh check {label!r}, "
                f"which no `run`/`skip` in {GATE_SCRIPT} declares — the map has "
                f"drifted from the script it describes"
            )

    # A mapped job that no longer runs on pull_request is stale bookkeeping.
    for job in sorted(set(GATE_COVERAGE) | set(GATE_EXEMPT)):
        if job not in pr_jobs:
            problems.append(
                f"gate coverage: `{job}` is mapped but no longer runs on "
                f"pull_request — remove it so the map stays a true description"
            )

    return problems


def main() -> int:
    if not WORKFLOW_DIR.is_dir():
        print(f"check_workflows: {WORKFLOW_DIR} not found", file=sys.stderr)
        return 1

    problems: list[str] = []
    pr_jobs: list[str] = []
    checked = pinned_total = 0

    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        checked += 1
        try:
            doc = yaml.load(path.read_text(), Loader=StrictLoader)
        except ValueError as exc:
            problems.append(f"{path}: {exc}")
            continue
        except yaml.YAMLError as exc:
            problems.append(f"{path}: not parseable — {exc}")
            continue

        if not isinstance(doc, dict) or "jobs" not in doc:
            problems.append(f"{path}: no `jobs:` mapping")
            continue

        if not _triggers_on_pull_request(doc):
            continue

        for job_name, job in doc["jobs"].items():
            pr_jobs.append(f"{path.name}::{job_name}")
            if not isinstance(job, dict):
                continue
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                if "actions/checkout" not in str(step.get("uses", "")):
                    continue
                ref = (step.get("with") or {}).get("ref")
                if ref == EXPECTED_REF:
                    pinned_total += 1
                else:
                    problems.append(
                        f"{path}: job `{job_name}` checks out with ref={ref!r}; "
                        f"a pull_request checkout must pin {EXPECTED_REF} or it "
                        f"takes GitHub's stale-prone refs/pull/N/merge default"
                    )

    problems.extend(_check_gate_coverage(pr_jobs))
    problems.extend(_check_audit_paths())

    if problems:
        print("check_workflows: FAILED", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(
        f"check_workflows: {checked} workflow file(s) parsed strictly; "
        f"{pinned_total} pull_request checkout(s) pinned to the PR head; "
        f"{len(GATE_COVERAGE)} pull_request job(s) covered by gate.sh, "
        f"{len(GATE_EXEMPT)} exempt"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
