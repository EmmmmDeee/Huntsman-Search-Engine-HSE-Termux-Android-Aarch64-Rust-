#!/usr/bin/env python3
"""Python mirror of `analysis::parse_response`'s shape check, plus the
informational diagnostics the Evaluation section of
docs/OSINT_MODEL_FINE_TUNING.md tracks across a held-out eval set.

    python3 scripts/finetune/validate_response.py eval_responses.jsonl

Dev-tooling only: nothing here is a dependency of the
hse/huntsman_search_engine Rust crate; none of it runs in scripts/gate.sh.
`eval_responses.jsonl` is one raw model-response string per line (JSON-encoded,
so a multi-line response stays one JSONL record).
"""
import json
import sys

MAX_FINDINGS = 5


def validate(raw: str) -> tuple[bool, str]:
    """Shape check mirroring analysis::parse_response's hard-reject rules —
    every check here is a real Err in the Rust parser, not a warning."""
    try:
        parsed = json.loads(raw.strip())
    except json.JSONDecodeError as e:
        return False, f"not valid JSON: {e}"
    if "summary" not in parsed or not isinstance(parsed["summary"], str):
        return False, "missing or non-string 'summary'"
    findings = parsed.get("findings", [])
    if not isinstance(findings, list):
        return False, "'findings' is not a list"
    for f in findings:
        if "description" not in f or "severity" not in f:
            return False, f"finding missing a required field: {f}"
        if not isinstance(f["description"], str):
            return False, f"description is not a string: {f}"
        if not isinstance(f["severity"], int):
            return False, f"severity is not an integer: {f}"
    return True, "ok"


def diagnostics(raw: str) -> dict:
    """Informational-only metrics: parse_response never rejects on these (it
    silently `.take(MAX_FINDINGS)`s and `.clamp(0, 100)`s instead), so a
    violation here is not a validate() failure — just a signal the model
    hasn't yet learned to respect bounds the Rust side quietly enforces for it."""
    parsed = json.loads(raw.strip())
    findings = parsed.get("findings", [])
    severities = [f.get("severity") for f in findings if isinstance(f.get("severity"), int)]
    return {
        "finding_count": len(findings),
        "finding_count_within_bounds": len(findings) <= MAX_FINDINGS,
        "severities_within_bounds": all(0 <= s <= 100 for s in severities),
    }


def main() -> None:
    (responses_path,) = sys.argv[1:2]
    total = 0
    parse_ok = 0
    with open(responses_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            raw = json.loads(line)
            ok, reason = validate(raw)
            if ok:
                parse_ok += 1
                diag = diagnostics(raw)
                if not diag["finding_count_within_bounds"] or not diag["severities_within_bounds"]:
                    print(f"[warn] response {total}: out-of-bounds but parse_response would clamp it: {diag}")
            else:
                print(f"[fail] response {total}: {reason}")
    rate = (parse_ok / total * 100) if total else 0.0
    print(f"\nparse-success rate: {parse_ok}/{total} ({rate:.1f}%)")


if __name__ == "__main__":
    main()
