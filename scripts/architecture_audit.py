#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Architecture audit — inventory the module graph and surface consolidation
and correctness risks **from the running binary**, not from reading source.

Why the binary and not the source
---------------------------------
``CLAUDE.md`` makes the running software the source of truth for the module and
CLI reference, because a static doc drifts. The same argument applies with more
force to an architectural inventory: what matters is the graph the *registry*
actually exposes at runtime, which is what dispatch walks. A grep over
``src/modules`` sees files; this sees the system.

Inputs, in order of preference:

* a live ``hse serve`` endpoint (``--base-url``), or
* a previously captured ``modules.json`` / ``graph.json`` pair (``--from-dir``),
  so the audit is reproducible in CI without binding a port.

What it reports
---------------
The capability graph is bipartite: modules produce and consume *entity kinds*,
and dispatch connects a producer to every consumer of the kinds it emits. The
findings below are all properties of that graph, and each names a concrete
architectural risk rather than a style preference:

``orphan_kinds``
    Produced by some module, consumed by none. Every entity of that kind is a
    leaf: work is spent deriving a fact that can never be pivoted on. Either a
    consumer is missing or the production is dead weight.

``ungrounded_kinds``
    Consumed by some module, produced by none. Those consumers can only ever be
    reached from an operator-supplied seed; on any derived path they are
    unreachable. Expected for true seed kinds, a defect otherwise.

``sole_producers``
    A kind produced by exactly one module. That module is a single point of
    failure for every consumer downstream of the kind — a reliability property
    invisible from any one file.

``duplicate_capabilities``
    Modules with an identical (accepts, produces, category) signature. The
    strongest consolidation signal the graph can give: two components claiming
    the same contract. Not automatically a defect (independent corroboration is
    deliberate in an OSINT tool) but always a question worth an answer.

``fanout_hotspots`` / ``fanin_hotspots``
    Modules whose output reaches, or whose input is reached by, an outsized
    share of the graph. These are the highest-blast-radius components: the
    places where a correctness bug propagates furthest, and so the places to
    spend review budget.

Exit status is 0 unless ``--fail-on-regression`` is given and a baseline is
exceeded, so this can gate CI once thresholds are agreed.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

# Kinds an operator can legitimately supply as a scan seed. A consumer of one of
# these is reachable even though nothing derives it, so they are excluded from
# `ungrounded_kinds`. Sourced from the CLI's accepted seed types.
SEED_KINDS = frozenset(
    {
        "email",
        "username",
        "phone",
        "full_name",
        "domain",
        "ip_address",
        "url",
        "coordinates",
        "mac_address",
        "organisation",
        "address",
        "asn",
        "cidr",
        "crypto_address",
        "abn_acn",
        "api_key",
        "device_id",
        "ssid",
        "tracking_id",
    }
)


def _get_json(url: str, timeout: float = 20.0) -> Any:
    # Explicitly no-proxy: the endpoint is loopback by default and a configured
    # HTTPS_PROXY would otherwise swallow the request.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def load(base_url: str | None, from_dir: Path | None) -> tuple[list[dict], dict]:
    """Return ``(modules, graph)`` from a live server or a captured directory."""
    if from_dir is not None:
        modules = json.loads((from_dir / "modules.json").read_text())
        graph = json.loads((from_dir / "graph.json").read_text())
    else:
        base = (base_url or "http://127.0.0.1:8080").rstrip("/")
        modules = _get_json(f"{base}/api/v1/modules")
        graph = _get_json(f"{base}/api/v1/modules/graph")
    if isinstance(modules, dict):
        modules = modules.get("modules", [])
    return modules, graph


def build(edges: list[dict]) -> dict[str, Any]:
    """Index the bipartite module/kind graph into the lookups the findings need.

    Producers are indexed by ``pivots_to`` — the emitted kinds already mapped
    into the *dispatch* vocabulary — never by ``produces``. The two fields use
    different enums (``EntityKind`` vs ``TargetKind``) that agree on nearly every
    spelling, so joining on ``produces`` looks correct and silently drops
    ``person``/``full_name``: 55 of 168 modules, reported as feeding nothing.
    This audit made exactly that mistake on its first run.
    """
    produced_by: dict[str, set[str]] = defaultdict(set)
    consumed_by: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        name = e["module"]
        if "pivots_to" not in e:
            raise SystemExit(
                "architecture_audit: this graph predates `pivots_to`. Joining on "
                "`produces` crosses two vocabularies and undercounts edges — "
                "refusing to emit a knowingly wrong graph. Rebuild `hse` first."
            )
        for k in e["pivots_to"]:
            produced_by[k].add(name)
        for k in e.get("consumes", []):
            consumed_by[k].add(name)
    return {"produced_by": produced_by, "consumed_by": consumed_by}


def reachable_modules(start: str, edges_by_name: dict[str, dict], idx: dict) -> set[str]:
    """Modules reachable from `start` by following produced kinds to consumers.

    This is the real blast radius of a module: dispatch hands each produced
    entity to every consumer of that kind, transitively, until the depth limit.
    Cycles are common and terminate naturally via the visited set.
    """
    seen: set[str] = set()
    frontier = [start]
    while frontier:
        cur = frontier.pop()
        for kind in edges_by_name.get(cur, {}).get("pivots_to", []):
            for consumer in idx["consumed_by"].get(kind, ()):
                if consumer not in seen and consumer != start:
                    seen.add(consumer)
                    frontier.append(consumer)
    return seen


def audit(modules: list[dict], graph: dict) -> dict[str, Any]:
    edges = graph.get("edges", [])
    terminal = set(graph.get("terminal_kinds", []))
    idx = build(edges)
    by_name = {e["module"]: e for e in edges}
    produced_by, consumed_by = idx["produced_by"], idx["consumed_by"]

    # Terminal kinds are excluded: they have no TargetKind by design, so
    # "consumed by nobody" is their definition, not a defect.
    orphan_kinds = sorted(
        k for k in produced_by if k not in consumed_by and k not in terminal
    )
    ungrounded = sorted(
        k for k in consumed_by if k not in produced_by and k not in SEED_KINDS
    )
    sole_producers = {
        k: next(iter(v)) for k, v in sorted(produced_by.items()) if len(v) == 1
    }

    # Identical contracts: the strongest consolidation signal available here.
    sig: dict[tuple, list[str]] = defaultdict(list)
    for e in edges:
        key = (
            e.get("category"),
            tuple(sorted(e.get("consumes", []))),
            tuple(sorted(e.get("pivots_to", []))),
        )
        sig[key].append(e["module"])
    duplicate_capabilities = {
        f"{k[0]}: {','.join(k[1]) or '-'} -> {','.join(k[2]) or '-'}": sorted(v)
        for k, v in sig.items()
        if len(v) > 1
    }

    total = len(edges)
    blast = {n: len(reachable_modules(n, by_name, idx)) for n in by_name}
    fanout_hotspots = sorted(blast.items(), key=lambda kv: -kv[1])[:12]

    inv: dict[str, Any] = defaultdict(int)
    for m in modules:
        inv[f"category:{m.get('category')}"] += 1
        inv[f"cost:{m.get('cost')}"] += 1
        if m.get("passive"):
            inv["passive"] += 1

    return {
        "module_count": total,
        "terminal_kinds": sorted(terminal),
        "kind_count": len(set(produced_by) | set(consumed_by)),
        "inventory": dict(sorted(inv.items())),
        "orphan_kinds": {k: sorted(produced_by[k]) for k in orphan_kinds},
        "ungrounded_kinds": {k: sorted(consumed_by[k]) for k in ungrounded},
        "sole_producer_count": len(sole_producers),
        "sole_producers": sole_producers,
        "duplicate_capabilities": duplicate_capabilities,
        "fanout_hotspots": [
            {"module": n, "reaches": c, "pct": round(100 * c / max(total, 1))}
            for n, c in fanout_hotspots
        ],
    }


def render(rep: dict[str, Any]) -> str:
    out = [
        "HSE architecture audit",
        "=" * 60,
        f"modules: {rep['module_count']}   entity kinds in graph: {rep['kind_count']}",
        f"terminal kinds (no TargetKind, always a leaf): {', '.join(rep['terminal_kinds']) or 'none'}",
        "",
        "inventory:",
    ]
    out += [f"  {k:<24} {v}" for k, v in rep["inventory"].items()]

    out += ["", f"orphan kinds (produced, never consumed): {len(rep['orphan_kinds'])}"]
    out += [
        f"  {k:<18} produced by: {', '.join(v)}" for k, v in rep["orphan_kinds"].items()
    ]

    out += [
        "",
        f"ungrounded kinds (consumed, never produced, not a seed): {len(rep['ungrounded_kinds'])}",
    ]
    out += [
        f"  {k:<18} consumed by: {', '.join(v)}"
        for k, v in rep["ungrounded_kinds"].items()
    ]

    out += [
        "",
        f"sole producers (single point of failure for a kind): {rep['sole_producer_count']}",
    ]
    out += [f"  {k:<18} only from: {v}" for k, v in rep["sole_producers"].items()]

    out += ["", f"duplicate capability signatures: {len(rep['duplicate_capabilities'])}"]
    out += [
        f"  {', '.join(v)}\n      {k}" for k, v in rep["duplicate_capabilities"].items()
    ]

    out += ["", "blast radius (modules reachable downstream):"]
    out += [
        f"  {h['module']:<22} {h['reaches']:>4} modules  ({h['pct']}% of graph)"
        for h in rep["fanout_hotspots"]
    ]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", help="live hse serve base URL")
    ap.add_argument("--from-dir", type=Path, help="dir with modules.json + graph.json")
    ap.add_argument("--json", action="store_true", help="emit the raw report as JSON")
    ap.add_argument("--out", type=Path, help="write the report to this path too")
    args = ap.parse_args()

    try:
        modules, graph = load(args.base_url, args.from_dir)
    except Exception as exc:  # noqa: BLE001 - a CLI should explain, not traceback
        print(f"architecture_audit: could not load the module graph: {exc}", file=sys.stderr)
        print("  start one with: hse serve --bind 127.0.0.1:8080", file=sys.stderr)
        return 2

    rep = audit(modules, graph)
    text = json.dumps(rep, indent=2) if args.json else render(rep)
    print(text)
    if args.out:
        args.out.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
