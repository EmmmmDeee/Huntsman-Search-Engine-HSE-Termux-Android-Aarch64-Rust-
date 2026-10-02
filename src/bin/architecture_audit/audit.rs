//! Pure graph-audit logic. No I/O, no network — everything `main.rs` needs to
//! unit-test directly against JSON fixtures.
//!
//! Ported line-for-line from the Python original this tool replaces
//! (`scripts/architecture_audit.py`), including its Python-dict ordering
//! semantics where they are observable in `--json` output: `inventory`,
//! `orphan_kinds`, `ungrounded_kinds`, and `sole_producers` are all built from
//! an *already-sorted* key sequence in the original (sorted-by-key insertion
//! order into a dict == sorted iteration), which a [`BTreeMap`] reproduces for
//! free; `duplicate_capabilities` is the one field the original leaves in
//! first-appearance order rather than sorted, which needs the explicit
//! order-preserving serialisation below since this crate's `serde_json` is
//! not built with the `preserve_order` feature.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use huntsman_search_engine::core::dependency::ALL_TARGET_KINDS;
use huntsman_search_engine::core::scan::TargetKind;

/// The kinds an operator can legitimately supply as a scan seed — every
/// `TargetKind` variant, canonical-string form. A consumer of one of these is
/// reachable even though nothing derives it, so [`audit`] excludes them from
/// `ungrounded_kinds`.
///
/// Derived from [`ALL_TARGET_KINDS`] rather than hand-copied the way the
/// Python original's `SEED_KINDS` literal was — that literal was a second,
/// unchecked copy of the enum's string vocabulary with no compiler check
/// tying it to the real type, exactly the drift class this port exists to
/// close (the original's own docstring documents the *other* half of that
/// same bug class: joining on `produces` instead of `pivots_to` silently
/// undercounted 55 of 168 modules on this tool's first run). Any future
/// `TargetKind` variant is picked up automatically, and `ALL_TARGET_KINDS`
/// itself is guarded elsewhere against missing a variant
/// (`all_target_kinds_lists_every_enum_variant`).
pub(crate) fn seed_kinds() -> BTreeSet<&'static str> {
    ALL_TARGET_KINDS
        .iter()
        .map(TargetKind::canonical_str)
        .collect()
}

/// One entry in the `modules` list — `GET /api/v1/modules`'s per-module shape
/// (a subset; only the fields the audit reads).
#[derive(Debug, Deserialize)]
pub(crate) struct ModuleInfo {
    /// Present in every real response; `Option` only so a malformed capture
    /// degrades to a clean miss on this one field rather than failing the
    /// whole parse.
    #[serde(default)]
    pub(crate) category: Option<String>,
    #[serde(default)]
    pub(crate) cost: Option<String>,
    #[serde(default)]
    pub(crate) passive: bool,
}

/// Either shape `load()` may hand `audit()` a `modules.json` in: the live
/// `GET /api/v1/modules` response (`{"modules": [...], "count": N}`) or a
/// bare array, matching the Python original's
/// `if isinstance(modules, dict): modules = modules.get("modules", [])`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum ModulesPayload {
    Wrapped { modules: Vec<ModuleInfo> },
    Bare(Vec<ModuleInfo>),
}

impl ModulesPayload {
    pub(crate) fn into_modules(self) -> Vec<ModuleInfo> {
        match self {
            Self::Wrapped { modules } => modules,
            Self::Bare(modules) => modules,
        }
    }
}

/// One entry in `graph.edges` — `PivotEdge`'s wire shape
/// (`src/core/dependency/mod.rs`), read generically here rather than
/// importing that type directly: `PivotEdge`'s fields are `&'static str`
/// (correct for the server that only ever serialises it), which cannot
/// derive `Deserialize` without a borrowed lifetime this owned, long-lived
/// CLI value doesn't have.
#[derive(Debug, Deserialize)]
pub(crate) struct Edge {
    pub(crate) module: String,
    #[serde(default)]
    pub(crate) category: Option<String>,
    #[serde(default)]
    pub(crate) consumes: Vec<String>,
    /// `None` when the key is absent — distinguished from `Some(vec![])` so
    /// [`build_index`] can refuse a pre-`pivots_to` graph capture exactly
    /// like the Python original did, rather than silently auditing a graph
    /// joined on the wrong vocabulary (`produces` vs `pivots_to` — the exact
    /// bug the original's own docstring confesses to on its first run).
    pub(crate) pivots_to: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Graph {
    pub(crate) edges: Vec<Edge>,
    #[serde(default)]
    pub(crate) terminal_kinds: Vec<String>,
}

/// Indexed view of the bipartite module/kind graph: which modules produce
/// (via `pivots_to`, never `produces` — see [`Edge::pivots_to`]) and consume
/// each kind.
#[derive(Debug)]
pub(crate) struct Index {
    pub(crate) produced_by: BTreeMap<String, BTreeSet<String>>,
    pub(crate) consumed_by: BTreeMap<String, BTreeSet<String>>,
}

/// Build [`Index`] from the graph's edges.
///
/// # Errors
///
/// Returns `Err` if any edge lacks `pivots_to` entirely — a graph captured
/// before that field existed, which cannot be audited correctly (joining on
/// `produces` instead crosses two different vocabularies, `EntityKind` and
/// `TargetKind`, that agree on nearly every spelling but not all).
pub(crate) fn build_index(edges: &[Edge]) -> Result<Index, String> {
    let mut produced_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut consumed_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for e in edges {
        let Some(pivots_to) = &e.pivots_to else {
            return Err(
                "architecture-audit: this graph predates `pivots_to`. Joining on `produces` \
                 crosses two vocabularies and undercounts edges — refusing to emit a knowingly \
                 wrong graph. Rebuild `hse` first."
                    .to_string(),
            );
        };
        for k in pivots_to {
            produced_by
                .entry(k.clone())
                .or_default()
                .insert(e.module.clone());
        }
        for k in &e.consumes {
            consumed_by
                .entry(k.clone())
                .or_default()
                .insert(e.module.clone());
        }
    }
    Ok(Index {
        produced_by,
        consumed_by,
    })
}

/// Modules reachable from `start` by following its produced kinds to their
/// consumers, transitively — the real blast radius of a module: dispatch
/// hands each produced entity to every consumer of that kind. Cycles
/// terminate naturally via the visited set.
pub(crate) fn reachable_modules(
    start: &str,
    edges_by_name: &HashMap<&str, &Edge>,
    consumed_by: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<&str> = vec![start];
    while let Some(cur) = frontier.pop() {
        let Some(edge) = edges_by_name.get(cur) else {
            continue;
        };
        let Some(pivots_to) = &edge.pivots_to else {
            continue;
        };
        for kind in pivots_to {
            let Some(consumers) = consumed_by.get(kind) else {
                continue;
            };
            for consumer in consumers {
                if consumer != start && seen.insert(consumer.clone()) {
                    frontier.push(consumer.as_str());
                }
            }
        }
    }
    seen
}

#[derive(Debug, Serialize, PartialEq)]
pub(crate) struct FanoutHotspot {
    pub(crate) module: String,
    pub(crate) reaches: usize,
    pub(crate) pct: i64,
}

/// The full report, field order matching the Python original's `dict`
/// insertion order exactly (`--json` serialises struct fields in declaration
/// order, so this order alone makes `--json` output byte-identical on that
/// axis — see the module doc for the per-field ordering rationale).
#[derive(Debug, Serialize, PartialEq)]
pub(crate) struct Report {
    pub(crate) module_count: usize,
    pub(crate) terminal_kinds: Vec<String>,
    pub(crate) kind_count: usize,
    pub(crate) inventory: BTreeMap<String, u64>,
    pub(crate) orphan_kinds: BTreeMap<String, Vec<String>>,
    pub(crate) ungrounded_kinds: BTreeMap<String, Vec<String>>,
    pub(crate) sole_producer_count: usize,
    pub(crate) sole_producers: BTreeMap<String, String>,
    #[serde(serialize_with = "serialize_ordered_map")]
    pub(crate) duplicate_capabilities: Vec<(String, Vec<String>)>,
    pub(crate) fanout_hotspots: Vec<FanoutHotspot>,
}

/// Serialise first-appearance-ordered pairs as a JSON object in that same
/// order. `serializer.collect_map` writes entries in the iterator's own
/// order regardless of the `Serializer`'s map type — unlike collecting into
/// a `BTreeMap` first (which would silently re-sort them alphabetically) or
/// relying on `serde_json`'s `preserve_order` feature (not enabled in this
/// crate), this needs neither.
fn serialize_ordered_map<S>(
    pairs: &[(String, Vec<String>)],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_map(pairs.iter().map(|(k, v)| (k, v)))
}

/// Build the full audit report from a `modules` list and its `graph`.
///
/// # Errors
///
/// Propagates [`build_index`]'s error for a pre-`pivots_to` graph capture.
pub(crate) fn audit(modules: &[ModuleInfo], graph: &Graph) -> Result<Report, String> {
    let terminal: HashSet<&str> = graph.terminal_kinds.iter().map(String::as_str).collect();
    let index = build_index(&graph.edges)?;
    let edges_by_name: HashMap<&str, &Edge> =
        graph.edges.iter().map(|e| (e.module.as_str(), e)).collect();
    let seeds = seed_kinds();

    // Terminal kinds are excluded: they have no TargetKind by design, so
    // "consumed by nobody" is their definition, not a defect.
    let orphan_kinds: BTreeMap<String, Vec<String>> = index
        .produced_by
        .iter()
        .filter(|(k, _)| {
            !index.consumed_by.contains_key(k.as_str()) && !terminal.contains(k.as_str())
        })
        .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
        .collect();
    let ungrounded_kinds: BTreeMap<String, Vec<String>> = index
        .consumed_by
        .iter()
        .filter(|(k, _)| !index.produced_by.contains_key(k.as_str()) && !seeds.contains(k.as_str()))
        .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
        .collect();
    let sole_producers: BTreeMap<String, String> = index
        .produced_by
        .iter()
        .filter(|(_, v)| v.len() == 1)
        .map(|(k, v)| {
            (
                k.clone(),
                v.iter().next().expect("len == 1 checked above").clone(),
            )
        })
        .collect();

    // Identical (category, consumes, pivots_to) contracts — the strongest
    // consolidation signal available: two components claiming the same
    // capability. First-appearance order preserved (not sorted) to match
    // the Python original's dict-insertion-order `--json` output: `sig`
    // there is a `defaultdict(list)` appended to while iterating `edges`, so
    // a signature's position is fixed at its first occurrence.
    type Signature = (Option<String>, Vec<String>, Vec<String>);
    let mut sig_order: Vec<Signature> = Vec::new();
    let mut sig_index: HashMap<Signature, usize> = HashMap::new();
    let mut sig_modules: Vec<Vec<String>> = Vec::new();
    for e in &graph.edges {
        let mut consumes_sorted = e.consumes.clone();
        consumes_sorted.sort_unstable();
        let mut pivots_sorted = e.pivots_to.clone().unwrap_or_default();
        pivots_sorted.sort_unstable();
        let key: Signature = (e.category.clone(), consumes_sorted, pivots_sorted);
        let idx = *sig_index.entry(key.clone()).or_insert_with(|| {
            sig_order.push(key);
            sig_modules.push(Vec::new());
            sig_order.len() - 1
        });
        sig_modules[idx].push(e.module.clone());
    }
    let mut duplicate_capabilities: Vec<(String, Vec<String>)> = Vec::new();
    for (idx, (category, consumes, pivots)) in sig_order.into_iter().enumerate() {
        let mut mods = std::mem::take(&mut sig_modules[idx]);
        if mods.len() > 1 {
            mods.sort_unstable();
            let category_str = category.unwrap_or_else(|| "None".to_string());
            let consumes_str = if consumes.is_empty() {
                "-".to_string()
            } else {
                consumes.join(",")
            };
            let pivots_str = if pivots.is_empty() {
                "-".to_string()
            } else {
                pivots.join(",")
            };
            duplicate_capabilities.push((
                format!("{category_str}: {consumes_str} -> {pivots_str}"),
                mods,
            ));
        }
    }

    let total = graph.edges.len();
    // `blast`/`fanout_hotspots`: computed for every module named in `edges`,
    // in first-occurrence order (matches the Python original's `by_name`
    // dict, whose iteration order is each module's first appearance).
    let mut module_order: Vec<&str> = Vec::new();
    let mut seen_modules: HashSet<&str> = HashSet::new();
    for e in &graph.edges {
        if seen_modules.insert(e.module.as_str()) {
            module_order.push(e.module.as_str());
        }
    }
    let blast: Vec<(String, usize)> = module_order
        .iter()
        .map(|&n| {
            (
                n.to_string(),
                reachable_modules(n, &edges_by_name, &index.consumed_by).len(),
            )
        })
        .collect();
    let mut fanout_hotspots: Vec<FanoutHotspot> = blast
        .into_iter()
        .map(|(module, reaches)| FanoutHotspot {
            pct: python_round_percent(reaches, total),
            module,
            reaches,
        })
        .collect();
    // Stable sort descending by `reaches` — ties keep first-occurrence order,
    // matching Python's stable `sorted(..., key=lambda kv: -kv[1])`.
    // `sort_by_key` is documented stable, same as `sort_by`; `Reverse` only
    // flips the comparison, not the stability.
    fanout_hotspots.sort_by_key(|h| std::cmp::Reverse(h.reaches));
    fanout_hotspots.truncate(12);

    let mut inventory: BTreeMap<String, u64> = BTreeMap::new();
    for m in modules {
        let category = m.category.clone().unwrap_or_else(|| "None".to_string());
        *inventory.entry(format!("category:{category}")).or_insert(0) += 1;
        let cost = m.cost.clone().unwrap_or_else(|| "None".to_string());
        *inventory.entry(format!("cost:{cost}")).or_insert(0) += 1;
        if m.passive {
            *inventory.entry("passive".to_string()).or_insert(0) += 1;
        }
    }

    let kind_count = index
        .produced_by
        .keys()
        .chain(index.consumed_by.keys())
        .collect::<HashSet<_>>()
        .len();

    Ok(Report {
        module_count: total,
        terminal_kinds: {
            let mut t: Vec<String> = graph.terminal_kinds.clone();
            t.sort_unstable();
            t
        },
        kind_count,
        inventory,
        orphan_kinds,
        ungrounded_kinds,
        sole_producer_count: sole_producers.len(),
        sole_producers,
        duplicate_capabilities,
        fanout_hotspots,
    })
}

/// Python's `round()` on `100 * c / max(total, 1)` uses banker's rounding
/// (round-half-to-even) on an exact rational, not the round-half-away-from-
/// zero a naive `f64::round()` gives — they disagree exactly on ties (e.g.
/// 12.5% vs 13%), which real module-graph percentages hit often enough
/// (small integer ratios) that this needs to be exact, not "close enough".
fn python_round_percent(reaches: usize, total: usize) -> i64 {
    let total = total.max(1) as i64;
    let numerator = 100 * reaches as i64;
    let quotient = numerator / total;
    let remainder = numerator % total;
    // remainder/total compared to 1/2, i.e. 2*remainder vs total.
    let twice = 2 * remainder;
    match twice.cmp(&total) {
        std::cmp::Ordering::Less => quotient,
        std::cmp::Ordering::Greater => quotient + 1,
        std::cmp::Ordering::Equal => {
            // Exactly half: round to even.
            if quotient % 2 == 0 {
                quotient
            } else {
                quotient + 1
            }
        }
    }
}

/// Render the plain-text report — the default (non-`--json`) output.
/// Padding widths match the Python original's f-string field specs exactly
/// (`{:<24}`, `{:<18}`, `{:<22}` left-pad; `{:>4}` right-pad).
pub(crate) fn render(rep: &Report) -> String {
    let mut out: Vec<String> = vec![
        "HSE architecture audit".to_string(),
        "=".repeat(60),
        format!(
            "modules: {}   entity kinds in graph: {}",
            rep.module_count, rep.kind_count
        ),
        format!(
            "terminal kinds (no TargetKind, always a leaf): {}",
            if rep.terminal_kinds.is_empty() {
                "none".to_string()
            } else {
                rep.terminal_kinds.join(", ")
            }
        ),
        String::new(),
        "inventory:".to_string(),
    ];
    for (k, v) in &rep.inventory {
        out.push(format!("  {k:<24} {v}"));
    }

    out.push(String::new());
    out.push(format!(
        "orphan kinds (produced, never consumed): {}",
        rep.orphan_kinds.len()
    ));
    for (k, v) in &rep.orphan_kinds {
        out.push(format!("  {k:<18} produced by: {}", v.join(", ")));
    }

    out.push(String::new());
    out.push(format!(
        "ungrounded kinds (consumed, never produced, not a seed): {}",
        rep.ungrounded_kinds.len()
    ));
    for (k, v) in &rep.ungrounded_kinds {
        out.push(format!("  {k:<18} consumed by: {}", v.join(", ")));
    }

    out.push(String::new());
    out.push(format!(
        "sole producers (single point of failure for a kind): {}",
        rep.sole_producer_count
    ));
    for (k, v) in &rep.sole_producers {
        out.push(format!("  {k:<18} only from: {v}"));
    }

    out.push(String::new());
    out.push(format!(
        "duplicate capability signatures: {}",
        rep.duplicate_capabilities.len()
    ));
    for (k, v) in &rep.duplicate_capabilities {
        out.push(format!("  {}\n      {k}", v.join(", ")));
    }

    out.push(String::new());
    out.push("blast radius (modules reachable downstream):".to_string());
    for h in &rep.fanout_hotspots {
        out.push(format!(
            "  {:<22} {:>4} modules  ({}% of graph)",
            h.module, h.reaches, h.pct
        ));
    }

    out.join("\n")
}

#[cfg(test)]
mod tests {
    include!("audit_tests.rs");
}
