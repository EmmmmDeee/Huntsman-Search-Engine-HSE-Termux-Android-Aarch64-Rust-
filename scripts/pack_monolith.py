#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pack the entire HSE repository into one topologically ordered, loss-less
monolithic text file (and unpack it back).

The artifact it produces (``HSE_MONOLITH.glm5.txt`` by default) is a single,
self-describing file that captures **100 % of every git-tracked file** in the
repository — every byte, every path — concatenated in *dependency-topological*
order so that an agent (e.g. a GLM 5.2 Agent) reading top-to-bottom always
sees a layer's dependencies before the code that uses them.

Design goals
------------
* **Complete.**   Every file reported by ``git ls-files`` is included (the
  output artifact itself is the only exclusion). Binary files are embedded
  base64. Nothing is summarised, truncated, or sampled.
* **Topological.** Files are grouped into the crate's architectural layers
  (``util -> core -> storage -> modules -> api -> cli -> audit -> selftest``,
  then the crate roots ``lib.rs``/``main.rs`` which *depend on* all of the
  above, then ``tests``/``benches`` which depend on the whole crate, then the
  non-code appendix). Within a layer, a directory's own ``mod.rs`` precedes its
  sub-modules, mirroring Rust's module-declaration tree.
* **Loss-less & reversible.** ``--unpack`` reconstructs a byte-identical tree;
  every record carries a SHA-256 and a whole-tree digest fingerprints the set.
* **Deterministic.** No wall-clock timestamps or randomness — the output is a
  pure function of the working tree, so the same commit always yields the same
  bytes (same ethos as the repo's own ``build.rs`` source manifest).

Usage
-----
    python3 scripts/pack_monolith.py            # write HSE_MONOLITH.glm5.txt
    python3 scripts/pack_monolith.py -o OUT     # custom output path
    python3 scripts/pack_monolith.py --unpack HSE_MONOLITH.glm5.txt DESTDIR
    python3 scripts/pack_monolith.py --verify HSE_MONOLITH.glm5.txt   # round-trip check
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import subprocess
import sys

# --------------------------------------------------------------------------- #
# Sentinels & constants                                                       #
# --------------------------------------------------------------------------- #

PACKER_VERSION = "1"
DEFAULT_OUTPUT = "HSE_MONOLITH.glm5.txt"

# Per-file payload delimiters. These are guaranteed (and re-checked at pack
# time) never to occur at the start of a line inside any file's content, so a
# parser can split records unambiguously by scanning for them at column 0.
BEGIN = "@@HSE-BEGIN@@"          # text payload (UTF-8 verbatim)
END = "@@HSE-END@@"
BEGIN_B64 = "@@HSE-BEGIN-B64@@"  # binary payload (base64, 76-col wrapped)
END_B64 = "@@HSE-END-B64@@"
SENTINELS = (BEGIN, END, BEGIN_B64, END_B64)

RULE = "=" * 100
THIN = "-" * 100

# Extensions treated as syntax-highlightable text → language tag for the agent.
LANG_BY_EXT = {
    "rs": "rust", "toml": "toml", "lock": "toml", "md": "markdown",
    "txt": "text", "sh": "bash", "yml": "yaml", "yaml": "yaml",
    "json": "json", "js": "javascript", "css": "css", "html": "html",
    "der": "binary", "py": "python", "gitignore": "gitignore",
}


# --------------------------------------------------------------------------- #
# Topology: architectural layers, in strict dependency order                   #
# --------------------------------------------------------------------------- #
#
# Lower rank == earlier == fewer dependencies. The ordering is the linearisation
# of the dependency DAG enforced by tests/architecture.rs:
#   util (leaf)  ->  core (uses util, defines ports)  ->  storage (impl ports)
#   ->  modules (use core types + util; never engine/storage)  ->  api  ->  cli
#   ->  audit/selftest  ->  crate roots (declare everything)  ->  tests/benches
#   ->  tooling/docs appendix.

LAYER_RANKS: list[tuple[int, str, str]] = [
    # (rank, label, human description) — matched in order by classify_layer().
    (0,  "build",      "Build & dependency foundation (manifest, lockfile, build script, lints)"),
    (1,  "util",       "src/util — leaf utilities; no intra-crate deps above this layer"),
    (2,  "core",       "src/core — engine, entities, correlation; uses util, defines ports"),
    (3,  "storage",    "src/storage — persistence implementing core's StoragePort"),
    (4,  "modules",    "src/modules — OSINT collectors; use core+util, never engine/storage"),
    (5,  "api",        "src/api — HTTP/axum surface over core (via ports, not storage)"),
    (6,  "cli",        "src/cli — command-line orchestration wiring all layers"),
    (7,  "audit",      "src/audit — cross-cutting audit trail"),
    (8,  "selftest",   "src/selftest — built-in self-test harness"),
    (9,  "crate-root", "Crate roots — lib.rs/main.rs declare & depend on every module above"),
    (10, "web",        "src/web — static SPA assets served by the api layer"),
    (11, "src-other",  "src/* — remaining source not otherwise classified"),
    (12, "tests",      "tests/ — integration & architecture tests (depend on whole crate)"),
    (13, "benches",    "benches/ — performance benchmarks"),
    (14, "scripts",    "scripts/ — developer & CI shell tooling"),
    (15, "ci",         ".github/ — CI/CD workflow definitions"),
    (16, "proptest",   "proptest-regressions/ — recorded property-test seeds"),
    (17, "meta",       ".claude/ — agent & tooling configuration"),
    (18, "docs",       "docs/ & root prose — design docs, READMEs, analyses, license"),
]
RANK_DESC = {label: desc for _, label, desc in LAYER_RANKS}

# A few foundation files get an explicit head-of-file order; everything else is
# ordered structurally (see sort_key()).
EXPLICIT_ORDER = {
    "Cargo.toml": 0, "Cargo.lock": 1, "build.rs": 2,
    "rust-toolchain.toml": 3, "rust-toolchain": 3, "deny.toml": 4,
    ".cargo/config.toml": 5, ".gitignore": 9,
}


def classify_layer(path: str) -> tuple[int, str]:
    """Return ``(rank, label)`` for *path*'s architectural layer.

    Only the crate-root build files are "foundation". A per-module ``build.rs``
    (e.g. ``src/modules/photon/build.rs``) belongs WITH its module and is left to
    fall through to the ``modules`` layer, so a module stays contiguous.
    """
    if path in EXPLICIT_ORDER or path.startswith(".cargo/"):
        return 0, "build"
    if path.startswith("src/util/"):
        return 1, "util"
    if path.startswith("src/core/"):
        return 2, "core"
    if path.startswith("src/storage/"):
        return 3, "storage"
    if path.startswith("src/modules/"):
        return 4, "modules"
    if path.startswith("src/api/"):
        return 5, "api"
    if path.startswith("src/cli/"):
        return 6, "cli"
    if path.startswith("src/audit/"):
        return 7, "audit"
    if path.startswith("src/selftest/"):
        return 8, "selftest"
    if path in ("src/lib.rs", "src/lib_tests.rs", "src/main.rs", "src/main_tests.rs"):
        return 9, "crate-root"
    if path.startswith("src/web/"):
        return 10, "web"
    if path.startswith("src/"):
        return 11, "src-other"
    if path.startswith("tests/"):
        return 12, "tests"
    if path.startswith("benches/"):
        return 13, "benches"
    if path.startswith("scripts/"):
        return 14, "scripts"
    if path.startswith(".github/"):
        return 15, "ci"
    if path.startswith("proptest-regressions/"):
        return 16, "proptest"
    if path.startswith(".claude/") or path.startswith(".cargo/"):
        return 17, "meta"
    return 18, "docs"


def module_token_key(path: str) -> list:
    """Structural sort key so a directory's own files (``mod.rs`` first) sort
    before its sub-directories — i.e. parent module before child modules."""
    parts = path.split("/")
    key: list = []
    for d in parts[:-1]:               # directory components -> marker 1
        key.append((1, d))
    fname = parts[-1]                   # the file itself -> marker 0 (sorts first)
    key.append((0, 0 if fname == "mod.rs" else 1, fname))
    return key


def sort_key(path: str):
    rank, _label = classify_layer(path)
    return (rank, EXPLICIT_ORDER.get(path, 10_000), module_token_key(path))


def category_note(path: str) -> str:
    """Provenance hint so the agent knows non-authored / generated files."""
    if path.startswith("src/web/vendor/"):
        return "vendored third-party asset (not HSE-authored)"
    if path == "Cargo.lock":
        return "generated dependency lockfile"
    if path.startswith("proptest-regressions/"):
        return "generated property-test regression seeds"
    if path.endswith(".der"):
        return "binary test fixture (DER certificate)"
    if path.startswith("src/web/") and not path.startswith("src/web/vendor/"):
        return "hand-rolled SPA front-end asset"
    return ""


# --------------------------------------------------------------------------- #
# File model                                                                  #
# --------------------------------------------------------------------------- #

class Entry:
    __slots__ = ("path", "data", "is_binary", "sha256", "lines",
                 "eof_newline", "rank", "label", "note")

    def __init__(self, path: str, data: bytes):
        self.path = path
        self.data = data
        self.is_binary = is_binary(data)
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.eof_newline = data.endswith(b"\n") if data else True
        self.rank, self.label = classify_layer(path)
        self.note = category_note(path)
        if self.is_binary:
            self.lines = 0
        else:
            self.lines = data.count(b"\n") + (0 if (not data or self.eof_newline) else 1)


def is_binary(data: bytes) -> bool:
    """A file is binary if it has a NUL byte or is not valid UTF-8."""
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def lang_for(path: str, is_bin: bool) -> str:
    if is_bin:
        return "binary"
    base = path.rsplit("/", 1)[-1]
    if base.startswith(".") and "." not in base[1:]:
        ext = base[1:]
    else:
        ext = base.rsplit(".", 1)[-1] if "." in base else ""
    return LANG_BY_EXT.get(ext.lower(), "text")


# --------------------------------------------------------------------------- #
# Git plumbing                                                                #
# --------------------------------------------------------------------------- #

def repo_root() -> str:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def git_tracked_files(root: str) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root,
                         capture_output=True, check=True)
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def sanitize_remote(url: str) -> str:
    """Reduce a remote URL to its ``owner/repo`` slug, dropping any embedded
    credentials or local-proxy host (the sandbox rewrites origin through a
    ``local_proxy@127.0.0.1:PORT`` URL we must not bake into the artifact)."""
    u = url
    if "://" in u:
        u = u.split("://", 1)[1]
    if "@" in u:
        u = u.rsplit("@", 1)[1]
    if "/git/" in u:                 # proxy form: host/git/<owner>/<repo>
        u = u.split("/git/", 1)[1]
    if u.endswith(".git"):
        u = u[:-4]
    return u or "(unknown)"


def git_info(root: str) -> dict[str, str]:
    def g(*args: str) -> str:
        try:
            return subprocess.run(["git", *args], cwd=root,
                                  capture_output=True, text=True, check=True).stdout.strip()
        except subprocess.CalledProcessError:
            return "(unknown)"
    return {
        "commit": g("rev-parse", "HEAD"),
        "short": g("rev-parse", "--short", "HEAD"),
        "branch": g("rev-parse", "--abbrev-ref", "HEAD"),
        "date": g("log", "-1", "--format=%cd", "--date=iso-strict"),
        "subject": g("log", "-1", "--format=%s"),
        "remote": sanitize_remote(g("config", "--get", "remote.origin.url")),
    }


# --------------------------------------------------------------------------- #
# Directory tree rendering                                                     #
# --------------------------------------------------------------------------- #

def render_tree(paths: list[str]) -> list[str]:
    """ASCII directory tree (lexical order) for at-a-glance navigation."""
    tree: dict = {}
    for p in paths:
        node = tree
        for part in p.split("/"):
            node = node.setdefault(part, {})
    lines: list[str] = ["."]

    def walk(node: dict, prefix: str) -> None:
        items = sorted(node.items(), key=lambda kv: (not kv[1], kv[0]))  # dirs first
        for i, (name, child) in enumerate(items):
            last = i == len(items) - 1
            branch = "`-- " if last else "|-- "
            suffix = "/" if child else ""
            lines.append(f"{prefix}{branch}{name}{suffix}")
            if child:
                walk(child, prefix + ("    " if last else "|   "))

    walk(tree, "")
    return lines


# --------------------------------------------------------------------------- #
# Packing                                                                      #
# --------------------------------------------------------------------------- #

def build_entries(root: str, exclude: set[str]) -> list[Entry]:
    entries: list[Entry] = []
    for path in git_tracked_files(root):
        if path in exclude:
            continue
        with open(os.path.join(root, path), "rb") as fh:
            entries.append(Entry(path, fh.read()))
    entries.sort(key=lambda e: sort_key(e.path))
    return entries


def assert_no_sentinel_collision(entries: list[Entry]) -> None:
    for e in entries:
        if e.is_binary:
            continue
        for ln in e.data.decode("utf-8").splitlines():
            if any(ln.startswith(s) for s in SENTINELS):
                sys.exit(f"FATAL: sentinel collision in {e.path}: {ln[:60]!r}\n"
                         f"       A file's content begins a line with a reserved "
                         f"@@HSE-...@@ marker; choose a different sentinel.")


def tree_digest(entries: list[Entry]) -> str:
    h = hashlib.sha256()
    for e in entries:
        h.update(e.path.encode("utf-8"))
        h.update(b"\0")
        h.update(e.sha256.encode("ascii"))
        h.update(b"\0")
    return h.hexdigest()


def human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or unit == "GiB":
            return f"{f:,.1f} {unit}" if unit != "B" else f"{n:,} B"
        f /= 1024
    return f"{n} B"


def pack(root: str, out_path: str) -> None:
    rel_out = os.path.relpath(os.path.abspath(out_path), root)
    entries = build_entries(root, exclude={rel_out})
    assert_no_sentinel_collision(entries)

    info = git_info(root)
    total_bytes = sum(len(e.data) for e in entries)
    total_lines = sum(e.lines for e in entries)
    n_binary = sum(1 for e in entries if e.is_binary)
    digest = tree_digest(entries)

    with open(out_path, "w", encoding="utf-8", newline="\n") as o:
        w = o.write
        # ---- Banner -------------------------------------------------------- #
        w(RULE + "\n")
        w("  HSE :: HUNTSMAN SEARCH ENGINE  --  MONOLITHIC CODEBASE SNAPSHOT\n")
        w("  Topologically ordered, loss-less, single-file capture of the entire repository.\n")
        w("  Designed for whole-repo ingestion by an LLM agent (GLM 5.2 Agent compatible).\n")
        w(RULE + "\n\n")

        w(f"packer-version : {PACKER_VERSION}\n")
        w(f"generator      : scripts/pack_monolith.py (deterministic; pure function of the tree)\n")
        w(f"repository     : {info['remote']}\n")
        w(f"branch         : {info['branch']}\n")
        w(f"commit         : {info['commit']}\n")
        w(f"commit-date    : {info['date']}\n")
        w(f"commit-subject : {info['subject']}\n")
        w(f"files          : {len(entries):,}  ({n_binary} binary, {len(entries) - n_binary} text)\n")
        w(f"total-bytes    : {total_bytes:,}  ({human(total_bytes)})\n")
        w(f"total-lines    : {total_lines:,}\n")
        w(f"tree-digest    : sha256:{digest}\n")
        w("                 (sha256 over `path\\0filesha256\\0` for every record, in order)\n\n")

        # ---- Format spec --------------------------------------------------- #
        w(THIN + "\n")
        w("FORMAT SPECIFICATION  (read this first)\n")
        w(THIN + "\n")
        w("""\
This file is a loss-less concatenation of every git-tracked file in the repo,
in dependency-topological order. It is line-oriented UTF-8. Structure:

    monolith := BANNER  SPEC  TOPOLOGY  TREE  MANIFEST  BODY  FOOTER
    BODY     := record*
    record   := metablock  payload
    metablock:= ("### " <key> " : " <value> "\\n")+        # human-readable, parseable
    payload  := text_payload | base64_payload

    text_payload   := "%(BEGIN)s " <path> "\\n"  <bytes...>  "\\n%(END)s " <path> "\\n"
    base64_payload := "%(BEGIN_B64)s " <path> "\\n" <base64 76-col> "\\n%(END_B64)s " <path> "\\n"

EXTRACTING ONE FILE
  1. Find the line that is exactly:  `%(BEGIN)s <path>`   (or the B64 variant).
  2. The file content is every byte AFTER that line's terminating newline, up to
     (and not including) the newline that immediately precedes the matching
     `%(END)s <path>` line.
  3. If the record's `meta` shows `eof-newline : false`, drop that single trailing
     separator newline (the original file did not end in one).
  4. For B64 records, base64-decode the enclosed block to recover raw bytes.

GUARANTEES
  * The `%(BEGIN)s` / `%(END)s` sentinels never appear at the start of any line
    inside file content (verified at pack time), so records split unambiguously.
  * Each record's `### sha256` is the SHA-256 of the ORIGINAL file bytes; verify
    after decoding. The `tree-digest` above fingerprints the whole set.
  * Order is topological: a layer always appears after the layers it depends on
    (see TOPOLOGY). The MANIFEST lists every record with its byte offset cue.

REFERENCE UNPACKER (Python; reconstructs the byte-exact tree):
    python3 scripts/pack_monolith.py --unpack <this-file> <destdir>
""" % {"BEGIN": BEGIN, "END": END, "BEGIN_B64": BEGIN_B64, "END_B64": END_B64})
        w("\n")

        # ---- Topology ------------------------------------------------------ #
        w(THIN + "\n")
        w("TOPOLOGY  (layers in dependency order; files are emitted in exactly this order)\n")
        w(THIN + "\n")
        present: dict[str, int] = {}
        for e in entries:
            present[e.label] = present.get(e.label, 0) + 1
        for rank, label, desc in LAYER_RANKS:
            if label in present:
                w(f"  [{rank:2d}] {label:<11} {present[label]:>4} files  -- {desc}\n")
        w("\n  Rule: every dependency edge points to an EARLIER layer. Crate roots\n")
        w("  (lib.rs/main.rs) declare all modules and so are emitted AFTER them;\n")
        w("  tests/benches depend on the whole crate and follow the roots.\n\n")

        # ---- Directory tree ------------------------------------------------ #
        w(THIN + "\n")
        w("DIRECTORY TREE  (lexical; full repository layout)\n")
        w(THIN + "\n")
        for line in render_tree([e.path for e in entries]):
            w(line + "\n")
        w("\n")

        # ---- Manifest ------------------------------------------------------ #
        w(THIN + "\n")
        w("FILE MANIFEST  (emission order == topological order; seek by index or path)\n")
        w(THIN + "\n")
        w(f"  {'#':>4}  {'layer':<11} {'lines':>7} {'bytes':>9}  {'sha256':<12} path\n")
        for i, e in enumerate(entries, 1):
            flag = "B" if e.is_binary else " "
            w(f"  {i:>4}{flag} {e.label:<11} {e.lines:>7} {len(e.data):>9}  "
              f"{e.sha256[:12]} {e.path}\n")
        w("\n")

        # ---- Body ---------------------------------------------------------- #
        w(RULE + "\n")
        w("BODY  --  FILE CONTENTS (topological order)\n")
        w(RULE + "\n\n")
        n = len(entries)
        for i, e in enumerate(entries, 1):
            w(THIN + "\n")
            w(f"### file     : {i} / {n}\n")
            w(f"### path     : {e.path}\n")
            w(f"### layer    : {e.label}  (rank {e.rank})\n")
            w(f"### lang     : {lang_for(e.path, e.is_binary)}\n")
            w(f"### bytes    : {len(e.data)}\n")
            w(f"### lines    : {e.lines}\n")
            w(f"### sha256   : {e.sha256}\n")
            w(f"### encoding : {'base64' if e.is_binary else 'utf-8'}\n")
            if not e.is_binary:
                w(f"### eof-newline : {'true' if e.eof_newline else 'false'}\n")
            if e.note:
                w(f"### note     : {e.note}\n")
            w(THIN + "\n")
            if e.is_binary:
                w(f"{BEGIN_B64} {e.path}\n")
                b64 = base64.b64encode(e.data).decode("ascii")
                for j in range(0, len(b64), 76):
                    w(b64[j:j + 76] + "\n")
                w(f"{END_B64} {e.path}\n\n")
            else:
                w(f"{BEGIN} {e.path}\n")
                text = e.data.decode("utf-8")
                w(text)
                if not e.eof_newline:
                    w("\n")        # separator only; flagged by eof-newline:false
                w(f"{END} {e.path}\n\n")

        # ---- Footer -------------------------------------------------------- #
        w(RULE + "\n")
        w("END OF MONOLITH\n")
        w(f"  records     : {len(entries):,}\n")
        w(f"  total-bytes : {total_bytes:,} ({human(total_bytes)})\n")
        w(f"  total-lines : {total_lines:,}\n")
        w(f"  tree-digest : sha256:{digest}\n")
        w(f"  commit      : {info['commit']}\n")
        w(RULE + "\n")

    art_size = os.path.getsize(out_path)
    print(f"[pack] {len(entries):,} files  ->  {out_path}")
    print(f"[pack] source bytes : {total_bytes:,} ({human(total_bytes)})")
    print(f"[pack] artifact size: {art_size:,} ({human(art_size)})")
    print(f"[pack] tree-digest  : sha256:{digest}")


# --------------------------------------------------------------------------- #
# Unpacking (round-trip verification)                                          #
# --------------------------------------------------------------------------- #

def unpack(mono_path: str, dest: str) -> list[tuple[str, str]]:
    """Reconstruct the tree under *dest*. Returns ``[(path, sha256), ...]``."""
    with open(mono_path, "r", encoding="utf-8", newline="\n") as fh:
        lines = fh.readlines()  # each retains its trailing "\n"

    restored: list[tuple[str, str]] = []
    i = 0
    expected_sha: str | None = None
    expected_eof_nl = True
    while i < len(lines):
        line = lines[i]
        # Track the most recent record metadata so we can honour eof-newline
        # and verify the SHA after decoding.
        if line.startswith("### sha256   : "):
            expected_sha = line[len("### sha256   : "):].strip()
        elif line.startswith("### eof-newline : "):
            expected_eof_nl = line[len("### eof-newline : "):].strip() == "true"

        if line.startswith(BEGIN_B64 + " "):
            path = line[len(BEGIN_B64) + 1:].rstrip("\n")
            i += 1
            buf: list[str] = []
            while not lines[i].startswith(END_B64 + " "):
                buf.append(lines[i].rstrip("\n"))
                i += 1
            data = base64.b64decode("".join(buf))
            _write(dest, path, data, restored, expected_sha)
            expected_sha, expected_eof_nl = None, True
        elif line.startswith(BEGIN + " "):
            path = line[len(BEGIN) + 1:].rstrip("\n")
            i += 1
            start = i
            while not lines[i].startswith(END + " "):
                i += 1
            # content == lines[start:i], minus the single separator newline that
            # precedes the END marker when the original had no trailing newline.
            body = "".join(lines[start:i])
            if not expected_eof_nl and body.endswith("\n"):
                body = body[:-1]
            _write(dest, path, body.encode("utf-8"), restored, expected_sha)
            expected_sha, expected_eof_nl = None, True
        i += 1
    return restored


def _write(dest: str, path: str, data: bytes, acc: list, expected_sha: str | None) -> None:
    got = hashlib.sha256(data).hexdigest()
    if expected_sha and got != expected_sha:
        sys.exit(f"FATAL: sha mismatch on extract for {path}: "
                 f"expected {expected_sha[:12]}, got {got[:12]}")
    full = os.path.join(dest, path)
    os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
    with open(full, "wb") as fh:
        fh.write(data)
    acc.append((path, got))


def verify(root: str, mono_path: str) -> int:
    """Pack-independent check: unpack to a temp dir and diff vs. the work tree."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        restored = unpack(mono_path, tmp)
        tracked = {p for p in git_tracked_files(root)
                   if p != os.path.relpath(os.path.abspath(mono_path), root)}
        got = {p for p, _ in restored}
        missing = tracked - got
        extra = got - tracked
        mism = []
        for p, sha in restored:
            with open(os.path.join(root, p), "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != sha:
                    mism.append(p)
        ok = not (missing or extra or mism)
        print(f"[verify] restored {len(got):,} files; tracked {len(tracked):,}")
        if missing:
            print(f"[verify] MISSING ({len(missing)}): {sorted(missing)[:10]}")
        if extra:
            print(f"[verify] EXTRA ({len(extra)}): {sorted(extra)[:10]}")
        if mism:
            print(f"[verify] CONTENT MISMATCH ({len(mism)}): {sorted(mism)[:10]}")
        print(f"[verify] {'OK — byte-exact, 100% capture' if ok else 'FAILED'}")
        return 0 if ok else 1


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Pack/unpack the HSE repo as one monolithic file.")
    ap.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="output artifact path")
    ap.add_argument("--unpack", nargs=2, metavar=("MONOLITH", "DESTDIR"),
                    help="reconstruct the tree from a monolith")
    ap.add_argument("--verify", metavar="MONOLITH",
                    help="round-trip verify a monolith against the working tree")
    args = ap.parse_args(argv)

    root = repo_root()
    if args.unpack:
        out = unpack(args.unpack[0], args.unpack[1])
        print(f"[unpack] wrote {len(out):,} files to {args.unpack[1]}")
        return 0
    if args.verify:
        return verify(root, args.verify)
    pack(root, os.path.join(root, args.output) if not os.path.isabs(args.output) else args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
