#!/usr/bin/env python3
"""Read-only Huntsman tracked-file inventory. Python 3 stdlib only."""
import argparse
import collections
import datetime
import json
import pathlib
import re
import subprocess

def git(root, *args):
    try:
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None

def render_tree(paths):
    root = {}
    for path in paths:
        node = root
        for part in path.split("/"):
            node = node.setdefault(part, {})
    lines = []
    def walk(node, prefix=""):
        for index, (name, children) in enumerate(sorted(node.items())):
            last = index == len(node) - 1
            lines.append(prefix + ("└── " if last else "├── ") + name)
            if children:
                walk(children, prefix + ("    " if last else "│   "))
    walk(root)
    return "\n".join(lines)

def inventory(root):
    output = git(root, "ls-files", "-z")
    if output is None:
        raise SystemExit("A Git checkout is required; refusing incomplete filesystem inventory")
    paths = sorted({p for p in output.split("\0") if p and (root / p).is_file()})
    findings = []
    known = set(paths)
    for path in paths:
        if not path.endswith(".rs"):
            continue
        try:
            source = (root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        # Heuristic only. #[path], inline modules, cfg and generated sources
        # require human verification; do not delete or auto-fix.
        for match in re.finditer(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", source):
            name = match.group(1)
            parent = pathlib.PurePosixPath(path).parent
            base = parent if path.endswith("/mod.rs") else parent / pathlib.PurePosixPath(path).stem
            if path in ("src/lib.rs", "src/main.rs"):
                base = pathlib.PurePosixPath("src")
            options = [str(base / (name + ".rs")), str(base / name / "mod.rs")]
            if not any(candidate in known for candidate in options):
                findings.append({"type": "potential_missing_module", "path": path,
                                 "module": name, "expected": options,
                                 "confidence": "low", "verified": False})
    folded = collections.defaultdict(list)
    for path in paths:
        folded[path.casefold()].append(path)
    for matches in folded.values():
        if len(matches) > 1:
            findings.append({"type": "case_collision", "paths": matches,
                             "confidence": "high", "verified": False})
    return paths, findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="docs/HUNTSMAN_REPOSITORY_TREE.md")
    parser.add_argument("--json", default="docs/huntsman-inventory.json")
    args = parser.parse_args()
    root = pathlib.Path(args.root).resolve()
    paths, findings = inventory(root)
    revision = git(root, "rev-parse", "HEAD")
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    counts = collections.Counter(p.split("/")[0] for p in paths)
    lines = [
        "# Huntsman — Generated Complete Repository Tree", "",
        f"Generated UTC: {stamp}", f"Git commit: `{revision}`",
        f"Present tracked files: {len(paths)}", "",
        "All entries are EXISTING/UNCLASSIFIED until reachability and compatibility",
        "are established with reproducible evidence. No source files are modified.", "",
        "## Full tree", "", "```text", render_tree(paths), "```", "",
        "## Inventory counts", "",
    ]
    lines.extend(f"- {key}: {value}" for key, value in sorted(counts.items()))
    lines.extend(["", "## Structural heuristics — not confirmed defects", ""])
    lines.extend("- " + json.dumps(item, sort_keys=True) for item in findings)
    if not findings:
        lines.append("None detected. This does not prove full wiring.")
    report = root / args.output
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    data = {"schema": 1, "revision": revision, "generated_utc": stamp,
            "files": paths, "findings": findings,
            "counts": dict(counts)}
    output = root / args.json
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(paths)} tracked files; {len(findings)} unverified findings; {report}")

if __name__ == "__main__":
    main()
