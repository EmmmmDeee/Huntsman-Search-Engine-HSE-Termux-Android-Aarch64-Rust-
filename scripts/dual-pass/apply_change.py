#!/usr/bin/env python3
"""Apply a unified diff, then fall back to a Rust function-node replace."""
import json
import subprocess
import sys
from pathlib import Path


def git_apply(diff: str) -> bool:
    path = Path(".dual-pass.patch")
    path.write_text(diff, encoding="utf-8")
    try:
        subprocess.run(["git", "apply", "--whitespace=nowarn", str(path)], check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    finally:
        path.unlink(missing_ok=True)


def replace_fn(path: Path, name: str, body: str) -> bool:
    text = path.read_text(encoding="utf-8")
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_rust

        parser = Parser(Language(tree_sitter_rust.language()))
        tree = parser.parse(text.encode())
        target = None

        def walk(node):
            nonlocal target
            if node.type in {"function_item", "function_signature_item"}:
                for child in node.children:
                    if child.type == "identifier" and text[child.start_byte:child.end_byte] == name:
                        target = node
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        if target is None:
            return False
        updated = text[: target.start_byte] + body.rstrip() + "\n" + text[target.end_byte :]
        path.write_text(updated, encoding="utf-8")
        return True
    except Exception:
        start = text.find(f"fn {name}")
        if start < 0:
            return False
        # Brace match from the first '{' after the signature.
        brace = text.find("{", start)
        if brace < 0:
            return False
        depth = 0
        end = None
        for i, ch in enumerate(text[brace:], brace):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is None:
            return False
        path.write_text(text[:start] + body.rstrip() + "\n" + text[end:], encoding="utf-8")
        return True


def main() -> int:
    payload = json.loads(sys.stdin.read())
    diff = payload.get("diff") or ""
    if diff and git_apply(diff):
        print(json.dumps({"applied": "git-apply"}))
        return 0
    ops = payload.get("ops") or []
    done = 0
    for op in ops:
        if op.get("kind") != "replace_fn":
            continue
        path = Path(op["path"])
        if not path.is_file():
            print(json.dumps({"error": f"missing {path}"}))
            return 1
        if not replace_fn(path, op["name"], op["body"]):
            print(json.dumps({"error": f"function {op['name']} not found in {path}"}))
            return 1
        done += 1
    if done:
        print(json.dumps({"applied": "ast-fallback", "ops": done}))
        return 0
    print(json.dumps({"error": "neither git apply nor function replace applied"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
