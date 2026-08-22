#!/usr/bin/env python3
"""Regenerate `src/util/oui/ieee.bin` from the IEEE MA-L registry.

    python3 scripts/gen_oui.py            # fetch and regenerate
    python3 scripts/gen_oui.py --check    # verify the committed blob is current

Why a packed binary rather than generated Rust: the registry is ~40,000
assignments. As a `const` array of string literals that is a multi-megabyte
source file that must be parsed and monomorphised on every build, and ~20,000
`&'static str` fat pointers each needing a load-time relocation. As one
`include_bytes!` blob it costs nothing to compile, nothing to start, and is
searched in place with no allocation and no decode step.

Layout, little-endian throughout, all sections 4-byte aligned by construction:

    magic     8   b"HSEOUI\\x01\\x00"
    count     4   number of OUI assignments
    vcount    4   number of distinct vendor names
    prefixes  4 × count      u32, the 24-bit OUI, ASCENDING (binary searched)
    vidx      2 × count      u16 index into the vendor table, parallel to prefixes
    pad       0 or 2         so `voff` starts 4-byte aligned
    voff      4 × (vcount+1) u32 byte offsets into blob; entry i spans [i, i+1)
    blob      …              concatenated UTF-8 vendor names, no separators

Determinism: assignments are emitted in ascending prefix order and vendor names
in first-appearance order over that same sequence, so the same registry input
always produces byte-identical output.
"""

import argparse
import csv
import hashlib
import io
import pathlib
import struct
import sys
import urllib.request

REGISTRY_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = pathlib.Path(__file__).resolve().parent.parent / "src/util/oui/ieee.bin"
MAGIC = b"HSEOUI\x01\x00"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "hse-gen-oui/1"})
    with urllib.request.urlopen(req, timeout=180) as fh:
        return fh.read()


def build(csv_bytes: bytes) -> bytes:
    text = csv_bytes.decode("utf-8", errors="replace")
    rows = csv.DictReader(io.StringIO(text))

    seen: dict[int, str] = {}
    for row in rows:
        raw = (row.get("Assignment") or "").strip().upper()
        vendor = " ".join((row.get("Organization Name") or "").split())
        if len(raw) != 6 or not all(c in "0123456789ABCDEF" for c in raw):
            continue
        if not vendor or vendor.lower() in ("private", "ieee registration authority"):
            # `Private` is the registry's placeholder for a withheld name — it
            # identifies nobody, and surfacing it as a vendor would read as an
            # attribution rather than the absence of one.
            continue
        prefix = int(raw, 16)
        # A duplicate assignment should not exist; if the registry ever emits
        # one, keep the first so the output stays a function of the input order.
        seen.setdefault(prefix, vendor)

    prefixes = sorted(seen)
    vendor_id: dict[str, int] = {}
    vidx: list[int] = []
    for p in prefixes:
        v = seen[p]
        if v not in vendor_id:
            vendor_id[v] = len(vendor_id)
        vidx.append(vendor_id[v])

    if len(vendor_id) > 0xFFFF:
        sys.exit(
            f"vendor count {len(vendor_id)} exceeds the u16 index width; "
            "widen `vidx` to u32 in both this script and src/util/oui/ieee.rs"
        )

    blob = bytearray()
    voff = [0]
    for v in vendor_id:  # dict preserves insertion order
        blob += v.encode("utf-8")
        voff.append(len(blob))

    out = bytearray()
    out += MAGIC
    out += struct.pack("<II", len(prefixes), len(vendor_id))
    out += b"".join(struct.pack("<I", p) for p in prefixes)
    out += b"".join(struct.pack("<H", i) for i in vidx)
    if len(out) % 4:
        out += b"\x00" * (4 - len(out) % 4)
    out += b"".join(struct.pack("<I", o) for o in voff)
    out += blob
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify the committed blob matches the live registry")
    ap.add_argument("--from-file", help="read the CSV from a path instead of the network")
    args = ap.parse_args()

    raw = pathlib.Path(args.from_file).read_bytes() if args.from_file else fetch(REGISTRY_URL)
    packed = build(raw)

    if args.check:
        if not OUT.exists():
            sys.exit(f"{OUT} is missing")
        current = OUT.read_bytes()
        if current == packed:
            print(f"up to date ({len(current)} bytes)")
            return
        sys.exit(
            f"stale: committed {hashlib.sha256(current).hexdigest()[:16]} "
            f"({len(current)} B) != generated {hashlib.sha256(packed).hexdigest()[:16]} "
            f"({len(packed)} B) — re-run scripts/gen_oui.py"
        )

    OUT.write_bytes(packed)
    count, vcount = struct.unpack("<II", packed[8:16])
    print(f"wrote {OUT} — {count} assignments, {vcount} vendors, {len(packed)} bytes")
    print(f"sha256 {hashlib.sha256(packed).hexdigest()}")


if __name__ == "__main__":
    main()
