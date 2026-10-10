#!/usr/bin/env python3
"""Apply a unified diff, or else replace named Rust functions through the Rust grammar.

Patches may only touch paths declared by the caller. No network. The function replace
needs tree-sitter and tree-sitter-rust, and it refuses rather than guesses: a name that
matches no function, or more than one, is an error, and a file is edited only as bytes
that the grammar placed.
"""
import json
import subprocess
import sys
from pathlib import Path

# Run with -I, so the working directory is not on sys.path. The helper is imported by path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from patchpaths import PatchError, patch_paths  # noqa: E402


def git_apply(diff: str) -> bool:
    path = Path(".dual-pass.patch")
    path.write_text(diff if diff.endswith("\n") else diff + "\n", encoding="utf-8")
    try:
        subprocess.run(
            ["git", "apply", "--whitespace=nowarn", "--recount", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False
    finally:
        path.unlink(missing_ok=True)


class ReplaceError(Exception):
    pass


def function_spans(source: bytes, name: str) -> list[tuple[int, int]]:
    """Byte spans of every function named NAME, from its visibility through its closing brace.
    A trait's declaration without a body is a function_signature_item, and it is matched too."""
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_rust
    except ImportError as exc:
        raise ReplaceError(f"function replace needs tree-sitter and tree-sitter-rust: {exc}") from exc
    tree = Parser(Language(tree_sitter_rust.language())).parse(source)
    wanted = name.encode("utf-8")
    spans = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in {"function_item", "function_signature_item"} and any(
            child.type == "identifier" and source[child.start_byte : child.end_byte] == wanted
            for child in node.children
        ):
            spans.append((node.start_byte, node.end_byte))
        stack.extend(node.children)
    return sorted(spans)


def replace_fn(path: Path, name: str, body: str) -> None:
    # The file is read and spliced as bytes, because the grammar reports byte offsets. A
    # str slice at a byte offset would move the edit inside any non-ASCII text above it.
    raw = path.read_bytes()
    raw.decode("utf-8")
    spans = function_spans(raw, name)
    if not spans:
        raise ReplaceError(f"function {name} not found in {path}")
    if len(spans) > 1:
        raise ReplaceError(f"function {name} matches {len(spans)} functions in {path}; name one")
    start, end = spans[0]
    # The text after the closing brace keeps its own line ending, so a second replace adds nothing.
    path.write_bytes(raw[:start] + body.rstrip().encode("utf-8") + raw[end:])


def main() -> int:
    payload = json.loads(sys.stdin.read() or "{}")
    allowed = set(payload.get("allowed") or [])
    diff = payload.get("diff") or ""
    try:
        touched = patch_paths(diff)
    except PatchError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    if any(path not in allowed for path in touched):
        print(json.dumps({"error": "diff escapes declared targets", "paths": sorted(touched)}))
        return 1
    if diff and git_apply(diff):
        print(json.dumps({"applied": "git-apply"}))
        return 0
    ops = payload.get("ops") or []
    done = 0
    for op in ops:
        if op.get("kind") != "replace_fn":
            print(json.dumps({"error": f"unsupported op {op.get('kind')}"}))
            return 1
        path = Path(op["path"])
        if str(path) not in allowed:
            print(json.dumps({"error": f"op escapes declared targets: {path}"}))
            return 1
        if not path.is_file():
            print(json.dumps({"error": f"missing {path}"}))
            return 1
        try:
            replace_fn(path, op["name"], op["body"])
        except (ReplaceError, UnicodeError, OSError) as exc:
            print(json.dumps({"error": str(exc)}))
            return 1
        done += 1
    if done:
        print(json.dumps({"applied": "function-replace", "ops": done}))
        return 0
    print(json.dumps({"error": "neither git apply nor function replace applied"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
