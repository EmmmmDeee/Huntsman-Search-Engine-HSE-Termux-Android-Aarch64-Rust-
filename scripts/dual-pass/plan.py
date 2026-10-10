#!/usr/bin/env python3
"""Deterministic pass 1. No model endpoint, no API key, no prompt cache."""
import hashlib
import json
import re
import sys
from pathlib import Path

# Run with -I, which keeps the working directory off sys.path, so a generated test
# cannot shadow this module. The helper sits beside this file, so it is imported by path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from patchpaths import PatchError, patch_paths  # noqa: E402

SCHEMA = "huntsman-dual-pass/1"
PROTECTED_PREFIXES = ("tests/", ".github/", "Cargo")
PROTECTED_EXACT = {
    "Cargo.toml",
    "Cargo.lock",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/dual-pass.yml",
}
FORBIDDEN_KEYS = {
    "model",
    "prompt",
    "api_key",
    "apikey",
    "xai",
    "openai",
    "anthropic",
    "endpoint",
    "base_url",
}
ASSERT_CALL = re.compile(r"\b(?:debug_)?assert(?:_eq|_ne)?!\s*\(")
SIG_RE = re.compile(
    r"^(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:fn|struct|enum|trait|type)\s+(\w+)",
    re.M,
)


def die(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def walk_keys(value, found):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_KEYS:
                found.append(key)
            walk_keys(child, found)
    elif isinstance(value, list):
        for child in value:
            walk_keys(child, found)


def signatures(path: Path) -> list[str]:
    if not path.is_file():
        return []
    found = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if SIG_RE.match(stripped) and not stripped.startswith("//"):
            found.append(stripped.rstrip("{").strip())
    return found[:40]


def dependency_tree(root: Path) -> list[dict]:
    lock = root / "Cargo.lock"
    rows = []
    if lock.is_file():
        name = None
        version = None
        for line in lock.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("name = "):
                name = line.split("=", 1)[1].strip().strip('"')
                version = None
            elif line.startswith("version = ") and name and version is None:
                version = line.split("=", 1)[1].strip().strip('"')
                rows.append({"crate": name, "version": version})
                name = None
        return rows[:80]
    manifest = root / "Cargo.toml"
    if not manifest.is_file():
        return []
    section = None
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("["):
            section = line.strip()
            continue
        if section == "[dependencies]" and "=" in line and not line.strip().startswith("#"):
            crate, spec = line.split("=", 1)
            rows.append({"crate": crate.strip(), "version": spec.strip().strip('"')})
    return rows


def context_digest(root: Path) -> str:
    parts = []
    for rel in ("scripts/dual-pass/static-context.md", "Cargo.toml", "Cargo.lock"):
        path = root / rel
        if path.is_file():
            parts.append(path.read_bytes())
    return hashlib.sha256(b"\n".join(parts)).hexdigest()


def fenced_blocks(body: str) -> list[tuple[str, str]]:
    """Each fenced block as (language, text). A fence opened and never closed is refused, so
    a stray fence cannot hide the plan that follows it."""
    blocks = []
    lang = None
    lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if lang is None:
            if stripped.startswith("```"):
                lang = stripped[3:].strip()
                lines = []
        elif stripped == "```":
            blocks.append((lang, "\n".join(lines)))
            lang = None
        else:
            lines.append(line)
    if lang is not None:
        die("issue body has a code fence that is never closed")
    return blocks


def extract_plan(body: str) -> dict:
    plans = [text for lang, text in fenced_blocks(body) if lang == "json"]
    if not plans:
        die("issue body has no fenced json plan")
    if len(plans) > 1:
        die(f"issue body has {len(plans)} fenced json blocks; keep exactly one plan")
    try:
        plan = json.loads(plans[0])
    except json.JSONDecodeError as exc:
        die(f"plan json is not parseable: {exc}")
    if not isinstance(plan, dict):
        die("plan json must be an object")
    return plan


def target_allowed(root: Path, path: str) -> bool:
    """The path policy's rule for a target, as check-protected.sh applies it: a path under
    src/, or a new file under tests/. Any other target would be refused at publish, so it
    is refused here, before any build or model work."""
    if path.startswith("src/"):
        return True
    return path.startswith("tests/") and not (root / path).exists()


def validate(plan: dict, root: Path) -> dict:
    forbidden = []
    walk_keys(plan, forbidden)
    if forbidden:
        die(f"plan contains model or endpoint fields: {sorted(set(forbidden))}")
    if plan.get("llm") is True:
        die("plan.llm must not be true")
    targets = plan.get("targets") or []
    tests = plan.get("new_tests") or []
    patches = plan.get("patches") or []
    if not targets:
        die("targets must name at least one file")
    if not tests:
        die("new_tests must name at least one generated test")
    if not 1 <= len(patches) <= 3:
        die("patches must contain 1 to 3 items")
    allowed = set()
    for item in targets:
        path = item.get("path") or ""
        if not path or ".." in Path(path).parts or path.startswith("/"):
            die(f"target path is empty or escapes the repo: {path!r}")
        if not target_allowed(root, path):
            die(f"target is outside the path policy (a path under src/, or a new file under tests/): {path}")
        if "signatures" not in item:
            die(f"target missing signatures: {path}")
        allowed.add(path)
    for item in tests:
        path = item.get("path") or ""
        name = path[len("tests/") :] if path.startswith("tests/") else path
        if not path.startswith("tests/generated_") or not path.endswith(".rs") or "/" in name:
            die(f"test path must be tests/generated_*.rs: {path}")
        if (root / path).exists():
            die(f"new test path already exists on main: {path}")
        if "source" not in item or "signatures" not in item:
            die(f"test missing source or signatures: {path}")
        source = item["source"]
        # Only an assertion macro call counts. The word alone does not, and a comment is not code.
        code = re.sub(r"//[^\n]*", "", source)
        if not ASSERT_CALL.search(code):
            die(f"test source has no assertion macro call: {path}")
        if re.search(r"assert!\(\s*true\s*\)", source):
            die(f"tautological assertion rejected: {path}")
        if re.search(r"assert_eq!\(\s*([^,()]+)\s*,\s*\1\s*\)", source):
            die(f"tautological equality rejected: {path}")
    for index, patch in enumerate(patches, 1):
        try:
            touched = patch_paths(patch.get("diff") or "")
        except PatchError as exc:
            die(f"patch {index}: {exc}")
        for rel in sorted(touched):
            if rel.startswith(PROTECTED_PREFIXES) or rel in PROTECTED_EXACT:
                die(f"patch {index} touches protected path {rel}")
            if rel not in allowed:
                die(f"patch {index} touches undeclared path {rel}")
        for op in patch.get("ops") or []:
            if op.get("kind") != "replace_fn":
                die(f"patch {index} has unsupported op {op.get('kind')}")
            if op.get("path") not in allowed:
                die(f"patch {index} op escapes declared targets: {op.get('path')}")
            if not op.get("name") or not op.get("body"):
                die(f"patch {index} op missing name or body")
    interfaces = []
    for item in targets:
        path = root / item["path"]
        interfaces.append({"path": item["path"], "live_signatures": signatures(path)})
    plan = dict(plan)
    plan["schema"] = SCHEMA
    plan["llm"] = False
    plan["context_digest"] = context_digest(root)
    plan["dependency_tree"] = dependency_tree(root)
    plan["interfaces"] = interfaces
    return plan


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    body_path = Path(sys.argv[2] if len(sys.argv) > 2 else ".issue-body.md")
    plan = validate(extract_plan(body_path.read_text(encoding="utf-8")), root)
    out = root / "execution-plan.json"
    out.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    print(f"plan ok targets={len(plan['targets'])} patches={len(plan['patches'])} llm=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
