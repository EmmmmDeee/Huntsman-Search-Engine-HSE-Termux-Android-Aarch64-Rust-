#!/usr/bin/env python3
"""Regenerate src/core/attack/{TACTICS,ENTERPRISE} from an official Enterprise STIX bundle.

Does not vendor the multi-MB bundle. Reads a local JSON path, writes the two
const arrays in src/core/attack/mod.rs, and prints the SHA-256 to stamp
ATTACK_VERSION's provenance comment.

Usage:
  python3 scripts/regen-attack-catalogue.py \\
      --bundle enterprise-attack.json \\
      --version 19.2

The bundle must be the official MITRE/CTI Enterprise file for that tag
(e.g. https://raw.githubusercontent.com/mitre/cti/ATT&CK-v19.2/enterprise-attack/enterprise-attack.json).
Revoked and deprecated objects are dropped. Techniques without a mitre-attack
kill-chain phase are dropped. Output is sorted by ATT&CK id.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def parse_technique_id(tid: str) -> tuple[int, int]:
    core = tid[1:]
    if "." in core:
        base, sub = core.split(".", 1)
        return (int(base), int(sub))
    return (int(core), -1)


def rust_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def load_current(bundle: dict) -> tuple[list[dict], list[dict]]:
    tactics = []
    techniques = []
    for obj in bundle["objects"]:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        kind = obj.get("type")
        if kind == "x-mitre-tactic":
            tid = ext_id(obj)
            if not tid:
                continue
            tactics.append(
                {
                    "id": tid,
                    "shortname": obj["x_mitre_shortname"],
                    "name": obj["name"],
                }
            )
        elif kind == "attack-pattern":
            tid = ext_id(obj)
            if not tid or not tid.startswith("T"):
                continue
            phases = sorted(
                {
                    phase["phase_name"]
                    for phase in obj.get("kill_chain_phases") or []
                    if phase.get("kill_chain_name")
                    in ("mitre-attack", "mitre-enterprise")
                    and phase.get("phase_name")
                }
            )
            if not phases:
                continue
            techniques.append(
                {
                    "id": tid,
                    "name": obj["name"],
                    "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                    "tactics": phases,
                }
            )
    tactics.sort(key=lambda row: row["id"])
    techniques.sort(key=lambda row: parse_technique_id(row["id"]))
    bases = {
        parse_technique_id(row["id"])[0]
        for row in techniques
        if not row["is_subtechnique"]
    }
    orphans = [
        row["id"]
        for row in techniques
        if row["is_subtechnique"] and parse_technique_id(row["id"])[0] not in bases
    ]
    if orphans:
        raise SystemExit(f"sub-techniques without a parent: {orphans}")
    return tactics, techniques


def emit_tactics(tactics: list[dict]) -> str:
    lines = ["pub const TACTICS: &[Tactic] = &["]
    for row in tactics:
        lines.extend(
            [
                "    Tactic {",
                f"        id: {rust_str(row['id'])},",
                f"        shortname: {rust_str(row['shortname'])},",
                f"        name: {rust_str(row['name'])},",
                "    },",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def emit_enterprise(techniques: list[dict]) -> str:
    lines = ["pub const ENTERPRISE: &[Technique] = &["]
    for row in techniques:
        tactics = ", ".join(rust_str(name) for name in row["tactics"])
        lines.extend(
            [
                "    Technique {",
                f"        id: {rust_str(row['id'])},",
                f"        name: {rust_str(row['name'])},",
                f"        is_subtechnique: {str(row['is_subtechnique']).lower()},",
                f"        tactics: &[{tactics}],",
                "    },",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def replace_block(text: str, start_marker: str, end_marker: str, replacement: str) -> str:
    start = text.find(start_marker)
    end = text.find(end_marker)
    if start < 0 or end < 0 or end <= start:
        raise SystemExit(f"could not locate {start_marker!r} .. {end_marker!r}")
    return text[:start] + replacement + text[end:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--mod",
        type=Path,
        default=Path("src/core/attack/mod.rs"),
    )
    args = parser.parse_args()
    raw = args.bundle.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    tactics, techniques = load_current(json.loads(raw))
    text = args.mod.read_text()
    text = replace_block(
        text,
        "pub const TACTICS: &[Tactic] = &[",
        "/// The complete MITRE ATT&CK Enterprise technique catalogue",
        emit_tactics(tactics) + "\n",
    )
    text = replace_block(
        text,
        "pub const ENTERPRISE: &[Technique] = &[",
        "/// The catalogued technique with this ID, if any.",
        emit_enterprise(techniques) + "\n",
    )
    args.mod.write_text(text)
    recon = sum(1 for row in techniques if "reconnaissance" in row["tactics"])
    print(
        f"wrote {args.mod} version={args.version} "
        f"tactics={len(tactics)} techniques={len(techniques)} recon={recon} "
        f"sha256={digest}",
        file=sys.stderr,
    )
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
