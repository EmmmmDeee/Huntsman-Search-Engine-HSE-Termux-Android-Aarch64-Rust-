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

Exits non-zero, naming the file and the reason, when either invariant breaks.
"""

from __future__ import annotations

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


def main() -> int:
    if not WORKFLOW_DIR.is_dir():
        print(f"check_workflows: {WORKFLOW_DIR} not found", file=sys.stderr)
        return 1

    problems: list[str] = []
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

    if problems:
        print("check_workflows: FAILED", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(
        f"check_workflows: {checked} workflow file(s) parsed strictly; "
        f"{pinned_total} pull_request checkout(s) pinned to the PR head"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
