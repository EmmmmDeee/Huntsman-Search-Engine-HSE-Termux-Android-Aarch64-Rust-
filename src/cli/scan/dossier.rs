//! Dossier renderer for `hse scan --output dossier`.
//!
//! Separated from the scan command loop so the render logic is independently
//! readable and testable.

use crate::core::{correlator::Correlation, entity::Entity, relation::Relation, scan::Scan};

/// Bundled args for [`print_dossier`] — a plain struct rather than 8 loose
/// parameters (`clippy::too_many_arguments`), mirroring the `DispatchCx`/
/// `DispatchState` precedent (`PROBLEM_TREE` T2.5) rather than an `#[allow]`.
pub(super) struct DossierArgs<'a> {
    pub(super) scan: &'a Scan,
    pub(super) entities: &'a [Entity],
    pub(super) correlations: &'a [Correlation],
    pub(super) relations: &'a [Relation],
    pub(super) kind: &'a str,
    pub(super) value: &'a str,
    pub(super) leverage: &'a [crate::core::engine::LeverageRanked],
    pub(super) store: &'a dyn crate::core::port::StoragePort,
}

/// Curated display order for the dossier's entity-kind sections. Kinds not listed
/// here are still rendered — appended after, in deterministic key order, by
/// [`order_dossier_kinds`] — so no finding is ever dropped from the dossier.
const DOSSIER_KIND_ORDER: &[&str] = &[
    "person",
    "email",
    "phone",
    "username",
    "credential",
    "api_key",
    "password",
    "address",
    "coordinates",
    "organisation",
    "abn_acn",
    "asn",
    "domain",
    "ip_address",
    "url",
    "mac_address",
    "device_id",
    "cidr",
    "ssid",
    "tracking_id",
    "crypto_address",
];

/// The order to render the dossier's entity-kind sections in: the curated
/// [`DOSSIER_KIND_ORDER`] (those present) first, then EVERY other present kind —
/// a rarer `EntityKind` or an `other:<custom>` — in deterministic (sorted-key)
/// order. The dossier previously iterated a fixed allowlist and silently dropped
/// any unlisted kind (`cidr`, `ssid`, `tracking_id`, `crypto_address`, every
/// `other:*`); this guarantees it is a COMPLETE view of the working set. Pure.
fn order_dossier_kinds<'a>(
    by_kind: &'a std::collections::BTreeMap<String, Vec<&Entity>>,
) -> Vec<&'a str> {
    let mut ordered: Vec<&str> = DOSSIER_KIND_ORDER
        .iter()
        .copied()
        .filter(|k| by_kind.contains_key(*k))
        .collect();
    // Catch-all: every present kind not in the curated list, in BTreeMap key
    // order (deterministic), so nothing is dropped and the output is stable.
    for k in by_kind.keys() {
        if !DOSSIER_KIND_ORDER.contains(&k.as_str()) {
            ordered.push(k.as_str());
        }
    }
    ordered
}

/// The dossier header's "Entities:" line: the count actually rendered by the
/// kind sections below (`shown` — the caller's already infra-filtered
/// entities), with a disclosure when the scan's raw persisted total
/// (`raw_total`, `Scan::entity_count`, set before any display-layer filter
/// runs) exceeds it. Previously this line always printed the RAW total even
/// though every section below renders the filtered list — a scan with
/// platform-infra entities showed a header count higher than anything
/// actually listed, with no explanation of the gap (`--include-infra` shows
/// them and closes it).
fn entities_header_line(shown: usize, raw_total: usize) -> String {
    if raw_total > shown {
        format!(
            "  Entities:  {shown} ({} platform-infra excluded of {raw_total} total — pass \
             --include-infra to show)",
            raw_total - shown
        )
    } else {
        format!("  Entities:  {shown}")
    }
}

/// The trailing "… N more" disclosure for a ranked list truncated to `shown`
/// of `total` — `None` when the full list already fits. The SAME wording
/// TIMELINE/CONNECTIONS already print; applied to the sections that
/// previously truncated with no indication at all (cross-scan leverage,
/// module yield, source confidence, enrichment lineage).
fn truncation_note(shown: usize, total: usize) -> Option<String> {
    (total > shown).then(|| format!("  … {} more", total - shown))
}

/// The subset of `relations` whose BOTH endpoints are present in `entities` —
/// the same confinement [`crate::core::relation::sorted_confined_adjacency`]
/// applies for CONNECTIONS/RESOLVED IDENTITIES/CONNECTION BROKERS below.
/// Previously the raw RELATIONS section printed every relation regardless, so
/// an edge to/from a platform-infra (or otherwise excluded) entity rendered as
/// a bare hex UID stub with no explanation for why that node appears nowhere
/// else in the dossier.
fn confine_relations_to_visible<'a>(
    entities: &[Entity],
    relations: &'a [Relation],
) -> Vec<&'a Relation> {
    let visible: std::collections::HashSet<&str> =
        entities.iter().map(|e| e.uid.as_str()).collect();
    relations
        .iter()
        .filter(|r| visible.contains(r.from_uid.as_str()) && visible.contains(r.to_uid.as_str()))
        .collect()
}

pub(super) fn print_dossier(args: DossierArgs<'_>) {
    let DossierArgs {
        scan,
        entities,
        correlations,
        relations,
        kind,
        value,
        leverage,
        store,
    } = args;
    use std::collections::BTreeMap;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  HUNTSMAN SEARCH ENGINE — INTELLIGENCE DOSSIER              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    {kind} = {value}");
    println!("  Scan ID:   {}", &scan.id[..16]);
    println!("  Status:    {}", scan.status.as_str());
    println!(
        "{}",
        entities_header_line(entities.len(), scan.entity_count)
    );
    println!("  Modules:   {}", scan.module_accounting_line());
    // Expansion timeline — the scan's expansion curve: how many entities were
    // first surfaced in each generation as the working graph expanded outward
    // from the seed. Shown only when expansion reached beyond the seed round
    // (more than one generation present).
    let timeline = crate::core::entity::expansion_timeline(entities);
    if timeline.len() > 1 {
        let parts: Vec<String> = timeline
            .iter()
            .map(|(g, n)| format!("gen{g}:{n}"))
            .collect();
        println!("  Expansion: {}", parts.join(" → "));
    }

    // Exposure Index — the calibrated 0–100 headline (with its transparent
    // breakdown) an operator reads first, aggregated from the breach/sensitive-PII/
    // identifier/correlation signals already computed below.
    let exposure = crate::core::exposure::assess(entities, correlations);
    println!("  {}", exposure.summary_line());
    for c in &exposure.components {
        println!(
            "    · {:<22} {:>2}/{:<2}  {}",
            c.name, c.score, c.max, c.detail
        );
    }
    println!();

    // Cross-scan enrichment leverage — this scan's identifiers that also appear in
    // earlier investigations in the local intelligence base, ranked by how many
    // they bridge (data_retention_design §4.1). Only genuine bridges (degree ≥ 2)
    // are shown here; the complete ranking is in `--output json`. Absent on a
    // first-ever scan, where nothing bridges yet — that is correct, not a gap.
    let bridges: Vec<&crate::core::engine::LeverageRanked> = leverage
        .iter()
        .filter(|l| l.cross_scan_degree >= 2)
        .collect();
    if !bridges.is_empty() {
        const SHOWN: usize = 8;
        println!(
            "  Cross-scan leverage ({} identifiers bridging prior investigations):",
            bridges.len()
        );
        for l in bridges.iter().take(SHOWN) {
            println!(
                "    · {} {} — bridges {} investigations",
                l.kind, l.value, l.cross_scan_degree
            );
        }
        if let Some(note) = truncation_note(SHOWN, bridges.len()) {
            println!("{note}");
        }
        println!();
    }

    let mut by_kind: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
    for e in entities {
        by_kind.entry(e.kind.to_string()).or_default().push(e);
    }

    // Render the curated kinds first, then EVERY remaining present kind (a rarer
    // `EntityKind` or an `other:<custom>`) — see [`order_dossier_kinds`]. The
    // previous fixed allowlist silently DROPPED any kind not listed, hiding real,
    // collected intel from the operator's dossier.
    for kind_name in order_dossier_kinds(&by_kind) {
        let group = &by_kind[kind_name];
        let header = match kind_name {
            "person" => "PERSONS",
            "email" => "EMAIL ADDRESSES",
            "phone" => "PHONE NUMBERS",
            "username" => "USERNAMES / HANDLES",
            "credential" => "CREDENTIALS (from breach/stealer data)",
            "api_key" => "API KEYS (from breach/stealer data)",
            "password" => "PASSWORDS (from breach/stealer data)",
            "address" => "PHYSICAL ADDRESSES / LOCATIONS",
            "coordinates" => "GPS COORDINATES",
            "organisation" => "ORGANISATIONS",
            "abn_acn" => "ABN / ACN (Australian Business Numbers)",
            "domain" => "DOMAINS",
            "ip_address" => "IP ADDRESSES",
            "url" => "URLS / PROFILES",
            "mac_address" => "MAC ADDRESSES (network devices)",
            "device_id" => "DEVICE IDENTIFIERS",
            "asn" => "ASN (autonomous systems)",
            "cidr" => "CIDR RANGES (network blocks)",
            "ssid" => "WIFI NETWORKS (SSIDs)",
            "tracking_id" => "TRACKING IDENTIFIERS",
            "crypto_address" => "CRYPTOCURRENCY ADDRESSES",
            other => other,
        };

        println!("━━━ {} ({}) ━━━", header, group.len());
        println!();

        let mut sorted = group.clone();
        sorted.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for e in &sorted {
            let c_eff = e.c_effective();
            let class = e.classify();
            println!(
                "  {} [{}]  conf={:.2}  c_eff={:.2}  corr={}",
                e.value, class, e.confidence, c_eff, e.corroboration
            );

            if !e.tags.is_empty() {
                println!("    tags: {}", e.tags.join(", "));
            }

            // Compact MITRE ATT&CK provenance: the inline `attack:<ID>` tags the
            // engine stamps onto every admitted entity, resolved to their
            // Reconnaissance technique names. Surfaces, per finding, exactly which
            // collection technique(s) produced it — the alignment lives in the
            // data, not a separate coverage report. (CLI may import core::attack.)
            let mitre: Vec<String> = e
                .tags
                .iter()
                .filter_map(|t| t.strip_prefix("attack:"))
                .map(|id| {
                    crate::core::attack::technique(id)
                        .map_or_else(|| id.to_string(), |t| format!("{} {}", t.id, t.name))
                })
                .collect();
            if !mitre.is_empty() {
                println!("    MITRE ATT&CK: {}", mitre.join("; "));
            }

            for ev in &e.evidence {
                println!(
                    "    ├─ {src} — {summary}",
                    src = ev.source,
                    summary = ev.summary
                );
                for (k, v) in &ev.attributes {
                    if !v.is_empty() {
                        println!("    │  {k}: {v}");
                    }
                }
            }
            println!();
        }
    }

    if !correlations.is_empty() {
        println!("━━━ CORRELATIONS ({}) ━━━", correlations.len());
        println!();
        for c in correlations {
            let sev = match c.severity.to_string().as_str() {
                "CRITICAL" => "🔴 CRITICAL",
                "HIGH" => "🟠 HIGH",
                "MEDIUM" => "🟡 MEDIUM",
                _ => "🔵 LOW",
            };
            println!("  {} [{}] {}", c.rule_id, sev, c.rule_name);
            println!("    {}", c.description);
            println!();
        }
    }

    if !relations.is_empty() {
        use std::collections::HashMap;
        let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
        let label = |uid: &str| {
            super::super::relation_endpoint_label(&by_uid, uid, |e| {
                super::super::truncate(&e.value, 40)
            })
        };
        let confined = confine_relations_to_visible(entities, relations);
        let hidden = relations.len() - confined.len();
        if hidden > 0 {
            println!(
                "━━━ RELATIONS ({} of {} — {hidden} hidden, endpoint excluded from view) ━━━",
                confined.len(),
                relations.len()
            );
        } else {
            println!("━━━ RELATIONS ({}) ━━━", relations.len());
        }
        println!();
        for r in &confined {
            println!(
                "  {}  ──{}──▶  {}   (conf={:.2})",
                label(&r.from_uid),
                r.kind,
                label(&r.to_uid),
                r.confidence
            );
        }
        println!();
    }

    print_connections(entities, relations);
    print_derivation_trails(entities, relations);
    print_resolved_identities(entities, relations);
    print_connection_brokers(entities, relations);

    print_diagnostics(scan, entities, kind, value, &scan.id, store);
}

/// DERIVATION TRAILS — the causal chain of pivots that surfaced each of the
/// deepest findings, seed → … → entity. Where CONNECTIONS shows how identities
/// link to each other, this shows how the SCAN itself REACHED a finding: which
/// entity's expansion led to which, generation by generation out from the seed.
/// Reuses the [`crate::core::relation::provenance_chain`] primitive so the
/// rendered path and the stored `DerivedFrom` lineage can never disagree. Only
/// the entities expansion actually reached (generation > 0) have a trail worth
/// narrating; a seed-round find is trivially its own root.
fn print_derivation_trails(entities: &[Entity], relations: &[Relation]) {
    use std::collections::HashMap;

    let mut deep: Vec<&Entity> = entities.iter().filter(|e| e.generation > 0).collect();
    if deep.is_empty() {
        return;
    }
    // Deepest first (the most "how did we even get here" findings), then by
    // effective confidence, then uid for a deterministic total order.
    deep.sort_by(|a, b| {
        b.generation
            .cmp(&a.generation)
            .then_with(|| {
                b.c_effective()
                    .partial_cmp(&a.c_effective())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.uid.cmp(&b.uid))
    });

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let label = |uid: &str| -> String {
        by_uid.get(uid).map_or_else(
            || format!("{}…", &uid[..uid.len().min(8)]),
            |e| super::super::truncate(&e.value, 32),
        )
    };

    const SHOWN: usize = 12;
    println!(
        "━━━ DERIVATION TRAILS ({}) — how the deepest leads were reached ━━━",
        deep.len()
    );
    println!();
    println!("  The pivot chain from the seed out to each finding (gen = pivots from the seed):");
    println!();
    for e in deep.iter().take(SHOWN) {
        // provenance_chain is entity→root; reverse it for a seed→entity reading.
        let mut chain = crate::core::relation::provenance_chain(&e.uid, relations);
        chain.reverse();
        let rendered = chain
            .iter()
            .copied()
            .map(label)
            .collect::<Vec<_>>()
            .join("  →  ");
        println!("  [gen {}] {}  ({})", e.generation, rendered, e.kind);
    }
    if let Some(note) = truncation_note(SHOWN, deep.len()) {
        println!("{note}");
    }
    println!();
}

/// CONNECTIONS — graph-free link analysis (PROBLEM_TREE C1, the
/// "Maltego-without-graphs" play). Renders the shortest typed *thread* tying
/// each discovered identity back through the graph — the analytic conclusion an
/// analyst would otherwise pivot a canvas to find. Reuses the very
/// [`crate::core::relation::identity_paths`] primitive AU-060 fires on, so the
/// rendered chain and the correlation can never disagree.
fn print_connections(entities: &[Entity], relations: &[Relation]) {
    use std::collections::HashMap;

    let connections = crate::core::relation::identity_paths(entities, relations, 4);
    if connections.is_empty() {
        return;
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    // A uid label: the entity's (truncated) value + its kind, or a short uid
    // stub if the node is somehow absent. UIDs are hex (ASCII) — byte-safe slice.
    let label = |uid: &str| -> (String, String) {
        by_uid.get(uid).map_or_else(
            || (format!("{}…", &uid[..uid.len().min(8)]), "?".to_string()),
            |e| (super::super::truncate(&e.value, 36), e.kind.to_string()),
        )
    };

    const SHOWN: usize = 25;
    println!(
        "━━━ CONNECTIONS ({}) — identity link analysis ━━━",
        connections.len()
    );
    println!();
    println!("  The shortest typed path tying each identity back through the graph");
    println!("  (a chain is only as strong as its weakest edge):");
    println!();
    // Build the traversal graph ONCE and reuse it for every connection's
    // corroboration-multiplicity lookup below.
    let adj = crate::core::relation::sorted_confined_adjacency(entities, relations);
    for c in connections.iter().take(SHOWN) {
        let (fv, fk) = label(&c.from_uid);
        let mut line = format!("  {fv} ({fk})");
        let last = c.steps.len().saturating_sub(1);
        for (i, step) in c.steps.iter().enumerate() {
            let (sv, sk) = label(&step.to_uid);
            if i == last {
                // Annotate the destination identity with its kind.
                line.push_str(&format!("  ──{}──▶  {sv} ({sk})", step.kind));
            } else {
                line.push_str(&format!("  ──{}──▶  {sv}", step.kind));
            }
        }
        println!("{line}");
        // Corroboration multiplicity: how many edge-disjoint routes confirm this
        // link (AU-062's signal). >1 means the connection survives any single
        // pathway going dark — the orthogonal-route robustness.
        let routes =
            crate::core::relation::disjoint_pathways_in(&adj, &c.from_uid, &c.to_uid, 5, 4).len();
        let corroboration = if routes >= 2 {
            format!(" · corroborated via {routes} independent pathways")
        } else {
            String::new()
        };
        // Best-achievable reliability: the widest (max-bottleneck) route's weakest
        // link, shown when it beats the shortest path's — the most-trustworthy way
        // these two connect may be stronger than the shortest chain suggests
        // (AU-069's signal). Reuses the adjacency already built above.
        let best = crate::core::relation::strongest_path_in(&adj, &c.from_uid, &c.to_uid, 5)
            .map_or(c.min_confidence, |p| p.min_confidence);
        let best_route = if best > c.min_confidence + 1e-9 {
            format!(" · strongest route conf {best:.2}")
        } else {
            String::new()
        };
        println!(
            "    {} hop{}, weakest edge conf={:.2}{}{}",
            c.hops,
            if c.hops == 1 { "" } else { "s" },
            c.min_confidence,
            best_route,
            corroboration
        );
        println!();
    }
    if connections.len() > SHOWN {
        println!("  … {} more connection(s)", connections.len() - SHOWN);
        println!();
    }
}

/// RESOLVED IDENTITIES — the cluster-level synthesis of CONNECTIONS (AU-067).
/// Where the link analysis above ties identities together pairwise, this collapses
/// every transitively-connected identity into one *resolved identity* — the
/// connected component of the identity graph — held together only as firmly as its
/// weakest link. Reuses [`crate::core::relation::resolve_identity_clusters`], so
/// the grouping can't disagree with the pairwise threads above or the AU-067
/// correlation. Shows only ≥3-member resolutions; a 2-member cluster is a single
/// link already rendered under CONNECTIONS.
fn print_resolved_identities(entities: &[Entity], relations: &[Relation]) {
    use std::collections::HashMap;

    // Same weakest-link floor AU-067 resolves under (Probable tier): a link below
    // it is too weak to *bind* two identities, so a single tenuous edge can't fuse
    // dozens of unrelated namesakes into "one person" in this section.
    const MIN_CONF: f64 = 0.50;

    let clusters: Vec<_> =
        crate::core::relation::resolve_identity_clusters(entities, relations, 4, MIN_CONF)
            .into_iter()
            .filter(|c| c.members.len() >= 3)
            .collect();
    if clusters.is_empty() {
        return;
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let label = |uid: &str| -> String {
        by_uid.get(uid).map_or_else(
            || format!("{}…", &uid[..uid.len().min(8)]),
            |e| format!("{} ({})", super::super::truncate(&e.value, 36), e.kind),
        )
    };

    println!(
        "━━━ RESOLVED IDENTITIES ({}) — distinct identifiers that are one person ━━━",
        clusters.len()
    );
    println!();
    println!("  Every identity transitively linked into one (weakest-link confidence):");
    println!();
    for (i, c) in clusters.iter().enumerate() {
        println!(
            "  #{} — {} identifiers, weakest link conf={:.2}:",
            i + 1,
            c.members.len(),
            c.min_confidence
        );
        for uid in &c.members {
            println!("      • {}", label(uid));
        }
        println!();
    }
}

/// CONNECTION BROKERS — the node-criticality synthesis (AU-070). Where CONNECTIONS
/// ties identities pairwise and RESOLVED IDENTITIES collapses them into clusters,
/// this names the **single nodes the network hangs on**: an entity whose removal
/// would fragment ≥3 otherwise-linked identities (the graph's articulation points,
/// in identity terms). Reuses [`crate::core::relation::connection_brokers`] over the
/// same confined adjacency the threads above traverse, so it can't disagree with
/// them or the AU-070 correlation. These are the prime pivots: corroborating a
/// broker hardens every connection that runs through it.
fn print_connection_brokers(entities: &[Entity], relations: &[Relation]) {
    use std::collections::HashMap;

    // Same Probable confidence floor and ≥3-identity floor AU-070 fires under: a
    // weak link can't make a node a broker (no fusing strangers), and a 2-identity
    // bridge is a single fragile pair already rendered under CONNECTIONS.
    const MIN_CONF: f64 = 0.50;
    let adj = crate::core::relation::sorted_confined_adjacency(entities, relations);
    let ids = crate::core::relation::identity_uids(entities);
    let brokers: Vec<_> = crate::core::relation::connection_brokers(&adj, &ids, MIN_CONF)
        .into_iter()
        .filter(|b| b.brokered.len() >= 3)
        .collect();
    if brokers.is_empty() {
        return;
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let label = |uid: &str| -> String {
        by_uid.get(uid).map_or_else(
            || format!("{}…", &uid[..uid.len().min(8)]),
            |e| format!("{} ({})", super::super::truncate(&e.value, 36), e.kind),
        )
    };

    println!(
        "━━━ CONNECTION BROKERS ({}) — single points that hold the network together ━━━",
        brokers.len()
    );
    println!();
    println!("  Remove one of these and the identities beneath it fall apart — the prime");
    println!("  pivots to corroborate (hardening a broker hardens every link through it):");
    println!();
    for (i, b) in brokers.iter().enumerate() {
        println!(
            "  #{} — {} brokers {} identities:",
            i + 1,
            label(&b.uid),
            b.brokered.len()
        );
        for uid in &b.brokered {
            println!("      • {}", label(uid));
        }
        println!();
    }
}

/// A near-certain misconfiguration/dead-target signal (PROBLEM_TREE T2.14):
/// every dispatched module ran and the scan still yielded ZERO entities.
/// Distinct from the per-module "many modules found nothing for this target
/// kind" case (normal — a 40-module scan routinely leaves most modules at
/// zero yield for a given kind, so flooding one line per module would be
/// noise, not signal, per T2.14's own analysis): this fires at most once per
/// scan, only when the scan-wide total is zero despite modules actually
/// having run — never when every module was gate-skipped (`modules_run ==
/// 0`, e.g. an unsupported target kind excluded every candidate module
/// before dispatch), which is a different, already-explained situation. Pure
/// and deterministic so it's testable without a live scan.
fn total_dead_scan_hint(entities: &[Entity], modules_run: usize) -> Option<String> {
    (entities.is_empty() && modules_run > 0).then(|| {
        format!(
            "{modules_run} module(s) ran and found nothing scan-wide — check the target is \
             reachable/valid, or this seed kind may be unsupported"
        )
    })
}

/// The dossier's one-line "online since X" headline — the same tenure/
/// recency computation `api::scan_handlers::intel::scan_timeline` already
/// returns as `tenure`/`recency` JSON fields, rendered for the CLI. Pure so
/// the exact wording is testable without a live scan.
fn tenure_headline(
    tenure: &crate::core::timeline::OnlineTenure,
    recency: &crate::core::timeline::FootprintRecency,
) -> String {
    format!(
        "Online since {} — {}y span, {} breach exposure{}, footprint {}",
        tenure.earliest_iso,
        tenure.span_years,
        tenure.breach_count,
        if tenure.breach_count == 1 { "" } else { "s" },
        recency.status.as_str()
    )
}

fn print_diagnostics(
    scan: &Scan,
    entities: &[Entity],
    kind: &str,
    value: &str,
    sid: &str,
    store: &dyn crate::core::port::StoragePort,
) {
    let wall_ms = scan
        .finished_at
        .and_then(|f| f.checked_sub(scan.started_at))
        .unwrap_or(0)
        .saturating_mul(1000);
    let mut diag = crate::util::diagnostics::analyse(sid, kind, value, wall_ms, entities);
    if let Some(hint) = total_dead_scan_hint(entities, scan.modules_run) {
        diag.optimization_hints.insert(0, hint);
    }

    println!("━━━ DIAGNOSTICS ━━━");
    println!();
    println!("  Scan wall-time:  {} ms", diag.wall_time_ms);

    use crate::core::module::ModuleCost;
    let cost_by_module: std::collections::HashMap<String, ModuleCost> = crate::modules::registry()
        .iter()
        .map(|m| (m.name().to_string(), m.cost()))
        .collect();
    let cost_label = |name: &str| match cost_by_module.get(name) {
        Some(ModuleCost::Free) => "free",
        Some(ModuleCost::KeyGated) => "key",
        Some(ModuleCost::Paid) => "paid",
        None => "·",
    };

    const MODULES_SHOWN: usize = 15;
    println!(
        "  Modules ranked by yield ({}, cost tier shown for ROI tuning):",
        diag.modules_by_yield.len()
    );
    for m in diag.modules_by_yield.iter().take(MODULES_SHOWN) {
        let kinds = m.unique_kinds.join(",");
        println!(
            "    {:4}  {:<5} {:<22} conf={:.2}  novelty={:5.1}%  kinds={}",
            m.entities_emitted,
            cost_label(&m.name),
            m.name,
            m.mean_confidence,
            m.novelty_ratio * 100.0,
            kinds
        );
    }
    if let Some(note) = truncation_note(MODULES_SHOWN, diag.modules_by_yield.len()) {
        println!("{note}");
    }
    let events = store.events_for_scan(sid).unwrap_or_default();
    let wasted =
        crate::util::diagnostics::keyed_or_paid_zero_yield_modules(&events, &cost_by_module);
    if !wasted.is_empty() {
        println!(
            "  ROI: {} keyed/paid module(s) yielded nothing — consider --exclude {}",
            wasted.len(),
            wasted.join(",")
        );
    }
    // T2.14: event-sourced hints analyse() cannot compute itself (no
    // StoragePort access) — a scan-level time+budget signal and a
    // noise-bounded per-module summary, appended here where `events` and the
    // cost map are already in scope.
    crate::util::diagnostics::append_event_sourced_hints(&mut diag, &events, &cost_by_module);
    println!();

    const SOURCES_SHOWN: usize = 15;
    let mut srcs: Vec<_> = diag.source_confidence.iter().collect();
    println!(
        "  Source confidence ({}, n / mean / p50 / p90):",
        srcs.len()
    );
    srcs.sort_by_key(|(_, s)| std::cmp::Reverse(s.n));
    for (src, s) in srcs.iter().take(SOURCES_SHOWN) {
        println!(
            "    {:<22} n={:<4} mean={:.2}  p50={:.2}  p90={:.2}",
            src, s.n, s.mean, s.p50, s.p90
        );
    }
    if let Some(note) = truncation_note(SOURCES_SHOWN, srcs.len()) {
        println!("{note}");
    }
    println!();

    let g = &diag.geo_precision;
    println!("━━━ GEO INTELLIGENCE ━━━");
    println!();
    // Headline answer first: the single best location estimate when AU-059's
    // cross-seed synergy gate fires (≥2 AU coordinates across ≥2 orthogonal
    // source classes). Same structured fix the API export and the AU-059 finding
    // carry — one computation, three renderings.
    if let Some(fix) = crate::core::correlator::au059_synergy_fix(entities) {
        println!(
            "  Best location estimate: {:.4},{:.4} ± {:.1} km  (geohash={}, state={})",
            fix.lat, fix.lon, fix.radius_km, fix.geohash, fix.state
        );
        println!(
            "    cross-seed synergy: {} AU coordinate(s) across {} orthogonal source class(es) [{}], confidence {:.2}",
            fix.count,
            fix.class_names.len(),
            fix.class_names.join(", "),
            fix.synergy_confidence
        );
        println!();
    } else if let Some(est) = crate::core::correlator::best_au_location_estimate(entities) {
        // Single-signal fallback: the common scan has one location signal, not the
        // ≥2-class synergy AU-059 requires. Surface the best available fix anyway —
        // every located subject gets a headline answer with its precision + basis.
        let near = est
            .locality
            .as_deref()
            .map_or_else(String::new, |l| format!(", near {l}"));
        println!(
            "  Best location estimate: {:.4},{:.4} ± {:.1} km  (geohash={}, state={}{})",
            est.lat, est.lon, est.radius_km, est.geohash, est.state, near
        );
        println!(
            "    basis: {} (confidence {:.2}) — single-signal fix",
            est.basis, est.confidence
        );
        println!();
    }
    println!(
        "  Coordinates: {} total ({} with geohash, {} with timezone)",
        g.coordinates_count, g.coords_with_geohash, g.coords_with_timezone
    );
    println!(
        "  Addresses:   {} total ({} state, {} country, {} ISO, {} postal)",
        g.address_count,
        g.addresses_with_state,
        g.addresses_with_country,
        g.addresses_with_iso,
        g.addresses_with_postal
    );
    if !g.iso_countries.is_empty() {
        println!("  ISO countries: {}", g.iso_countries.join(", "));
    }
    if !g.timezones.is_empty() {
        println!("  Timezones:     {}", g.timezones.join(", "));
    }
    println!(
        "  Multi-source convergence: {}",
        if g.multi_source_convergence {
            "YES (≥2 coords within 5km)"
        } else {
            "no"
        }
    );
    println!();

    if !diag.proximity_graph.is_empty() {
        println!("  Proximity graph (top 15 closest coord pairs):");
        for edge in diag.proximity_graph.iter().take(15) {
            let label = if edge.same_country {
                format!(
                    " [same country: {}]",
                    edge.from_country.as_deref().unwrap_or("?")
                )
            } else if edge.from_country.is_some() || edge.to_country.is_some() {
                format!(
                    " [{} ↔ {}]",
                    edge.from_country.as_deref().unwrap_or("?"),
                    edge.to_country.as_deref().unwrap_or("?")
                )
            } else {
                String::new()
            };
            println!(
                "    {:>10.3} km   {} ↔ {}{}",
                edge.distance_km, edge.from_value, edge.to_value, label
            );
        }
        println!();
    }

    let timeline = crate::core::timeline::reconstruct(entities);
    println!("━━━ TIMELINE ({} events) ━━━", timeline.len());
    println!();
    // Headline first: the same tenure/recency summary the JSON timeline API
    // already computes and returns (api::scan_handlers::intel::scan_timeline)
    // but which, until now, only the API surfaced — the CLI dossier
    // re-listed every event with no "online since X, Nyr span, footprint
    // status" answer at the top. One computation (`online_tenure` +
    // `footprint_recency`), now two renderings. `now` is the scan's own
    // completion time, not a fresh clock read, so a re-rendered dossier for
    // an old scan reports the recency as of when the data was gathered.
    if let Some(tenure) = crate::core::timeline::online_tenure(&timeline) {
        let now = i64::try_from(scan.finished_at.unwrap_or(scan.started_at)).unwrap_or(i64::MAX);
        let recency = crate::core::timeline::footprint_recency(tenure.latest_ts, now);
        println!("  {}", tenure_headline(&tenure, &recency));
        println!();
    }
    if timeline.is_empty() {
        println!("  No dated events reconstructed from the current entity set.");
    } else {
        for ev in timeline.iter().take(40) {
            println!(
                "  {:<19}  {:<16}  {} [{}]",
                ev.iso,
                ev.kind.as_str(),
                ev.entity_value,
                ev.source
            );
        }
        if timeline.len() > 40 {
            println!("  … {} more", timeline.len() - 40);
        }
    }
    println!();

    if let Some(movement) = crate::core::timeline::movement_path(&timeline) {
        println!(
            "━━━ MOVEMENT ({} fixes, {:.1} km) ━━━",
            movement.locations_visited, movement.total_km
        );
        println!();
        for leg in &movement.legs {
            println!(
                "  {}  {}  →  {}  {}   ({:.1} km)",
                leg.from_iso, leg.from_coords, leg.to_iso, leg.to_coords, leg.distance_km
            );
        }
        println!();
    }

    const LINEAGE_SHOWN: usize = 20;
    let mut lineage_sorted = diag.enrichment_lineage.clone();
    println!("━━━ ENRICHMENT LINEAGE ({}) ━━━", lineage_sorted.len());
    println!();
    lineage_sorted.sort_by_key(|n| std::cmp::Reverse(n.source_chain.len()));
    for node in lineage_sorted.iter().take(LINEAGE_SHOWN) {
        println!(
            "  [{}] {} (conf={:.2}, corr={})",
            node.kind, node.value_preview, node.confidence, node.corroboration
        );
        println!("    sources: {}", node.source_chain.join(" → "));
    }
    if let Some(note) = truncation_note(LINEAGE_SHOWN, lineage_sorted.len()) {
        println!("{note}");
    }
    println!();

    println!("━━━ OPTIMIZATION HINTS ━━━");
    println!();
    for hint in &diag.optimization_hints {
        println!("  • {hint}");
    }
    println!();

    println!("━━━ END OF DOSSIER ━━━");
}

#[cfg(test)]
mod tests {
    use super::{
        DOSSIER_KIND_ORDER, confine_relations_to_visible, entities_header_line,
        order_dossier_kinds, truncation_note,
    };
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::event::{Event, EventKind};
    use crate::core::module::ModuleCost;
    use crate::core::relation::{Relation, RelationKind};
    use crate::util::diagnostics::keyed_or_paid_zero_yield_modules;
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn dossier_renders_every_present_kind_never_dropping_one() {
        // Regression: the dossier used to iterate a fixed allowlist and silently
        // drop any kind not in it — `cidr`, `ssid`, `tracking_id`,
        // `crypto_address`, and every `other:<custom>` vanished from the operator's
        // output. `order_dossier_kinds` must surface EVERY present kind.
        let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.9, "s");
        let ents = [
            mk(EntityKind::Email, "a@b.com"),
            mk(EntityKind::CryptoAddress, "bc1qexample"),
            mk(EntityKind::Ssid, "HOME-WIFI"),
            mk(EntityKind::TrackingId, "UA-12345-6"),
            mk(EntityKind::Cidr, "10.0.0.0/8"),
            mk(EntityKind::Other("passport".to_string()), "X1234567"),
            mk(EntityKind::Person, "Jane Doe"),
        ];
        let mut by_kind: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
        for e in &ents {
            by_kind.entry(e.kind.to_string()).or_default().push(e);
        }

        let ordered = order_dossier_kinds(&by_kind);

        // Every present kind appears exactly once — none dropped.
        assert_eq!(
            ordered.len(),
            by_kind.len(),
            "the ordering must cover every present kind, ordered was {ordered:?}"
        );
        for k in by_kind.keys() {
            assert!(
                ordered.contains(&k.as_str()),
                "kind {k:?} was dropped from the dossier ordering {ordered:?}"
            );
        }
        // The previously-dropped kinds are specifically present.
        for dropped in [
            "crypto_address",
            "ssid",
            "tracking_id",
            "cidr",
            "other:passport",
        ] {
            assert!(
                ordered.contains(&dropped),
                "the formerly-dropped kind {dropped} must now render"
            );
        }

        // Curated kinds keep their relative order (person before email), and the
        // uncurated `other:*` kind is appended AFTER all curated ones.
        let pos = |k: &str| ordered.iter().position(|x| *x == k).unwrap();
        assert!(pos("person") < pos("email"));
        assert!(pos("crypto_address") < pos("other:passport"));
        assert!(
            DOSSIER_KIND_ORDER.contains(&"crypto_address"),
            "crypto_address must be in the curated order, not just the catch-all"
        );
    }

    fn costs() -> HashMap<String, ModuleCost> {
        [
            ("shodan".to_string(), ModuleCost::Paid),
            ("hunter_io".to_string(), ModuleCost::KeyGated),
            ("search_engines".to_string(), ModuleCost::Free),
        ]
        .into_iter()
        .collect()
    }

    /// The whole point of this helper: a `KeyGated`/`Paid` module that ran and
    /// found nothing must be reported, even though it is entirely absent from
    /// `ScanDiagnostics::modules_by_yield` (built only from emitted entities).
    #[test]
    fn flags_a_zero_yield_keyed_or_paid_module() {
        let events = vec![Event::new(
            "s",
            EventKind::ModuleDone {
                module: "shodan".into(),
                found: 0,
            },
        )];
        assert_eq!(
            keyed_or_paid_zero_yield_modules(&events, &costs()),
            vec!["shodan".to_string()]
        );
    }

    /// A module that DID find something must not be flagged, however costly.
    #[test]
    fn ignores_a_module_that_found_something() {
        let events = vec![Event::new(
            "s",
            EventKind::ModuleDone {
                module: "shodan".into(),
                found: 3,
            },
        )];
        assert!(keyed_or_paid_zero_yield_modules(&events, &costs()).is_empty());
    }

    /// A free module that yields nothing is not a wasted spend — nothing to
    /// warn about, so it must not appear.
    #[test]
    fn ignores_a_free_module_with_zero_yield() {
        let events = vec![Event::new(
            "s",
            EventKind::ModuleDone {
                module: "search_engines".into(),
                found: 0,
            },
        )];
        assert!(keyed_or_paid_zero_yield_modules(&events, &costs()).is_empty());
    }

    /// Output is sorted and deduped — deterministic regardless of event order
    /// or a module appearing more than once (e.g. re-dispatched on expansion).
    #[test]
    fn output_is_sorted_and_deduped() {
        let mk = |m: &str| {
            Event::new(
                "s",
                EventKind::ModuleDone {
                    module: m.into(),
                    found: 0,
                },
            )
        };
        let events = vec![mk("shodan"), mk("hunter_io"), mk("shodan")];
        assert_eq!(
            keyed_or_paid_zero_yield_modules(&events, &costs()),
            vec!["hunter_io".to_string(), "shodan".to_string()]
        );
    }

    use super::tenure_headline;
    use crate::core::timeline::{FootprintRecency, FootprintStatus, OnlineTenure};

    fn tenure(breach_count: usize) -> OnlineTenure {
        OnlineTenure {
            earliest_ts: 0,
            earliest_iso: "2008-01-01".into(),
            latest_ts: 100,
            latest_iso: "2025-01-01".into(),
            span_years: 17,
            event_count: 9,
            breach_count,
        }
    }

    fn recency(status: FootprintStatus) -> FootprintRecency {
        FootprintRecency {
            years_since_latest: 0,
            status,
        }
    }

    #[test]
    fn tenure_headline_pluralises_breach_count() {
        assert_eq!(
            tenure_headline(&tenure(1), &recency(FootprintStatus::Active)),
            "Online since 2008-01-01 — 17y span, 1 breach exposure, footprint active"
        );
        assert_eq!(
            tenure_headline(&tenure(9), &recency(FootprintStatus::Dormant)),
            "Online since 2008-01-01 — 17y span, 9 breach exposures, footprint dormant"
        );
        assert_eq!(
            tenure_headline(&tenure(0), &recency(FootprintStatus::Recent)),
            "Online since 2008-01-01 — 17y span, 0 breach exposures, footprint recent"
        );
    }

    use super::total_dead_scan_hint;

    /// The whole point of this hint: every dispatched module ran and the scan
    /// still yielded nothing at all — a near-certain misconfiguration/dead-
    /// target signal, distinct from the normal "many modules found nothing
    /// for this kind" case.
    #[test]
    fn total_dead_scan_hint_fires_when_modules_ran_and_found_nothing() {
        let hint = total_dead_scan_hint(&[], 12).expect("must fire");
        assert!(hint.contains("12"));
        assert!(hint.contains("scan-wide"));
    }

    /// Every candidate module was gate-skipped before dispatch (e.g. an
    /// unsupported target kind) — a different, already-explained situation,
    /// not "ran and found nothing". Must not fire.
    #[test]
    fn total_dead_scan_hint_is_silent_when_nothing_was_even_dispatched() {
        assert_eq!(total_dead_scan_hint(&[], 0), None);
    }

    /// A normal successful scan — must never fire regardless of module count.
    #[test]
    fn total_dead_scan_hint_is_silent_when_entities_were_found() {
        let entities = vec![Entity::new(EntityKind::Email, "a@b.com", 0.5, "s")];
        assert_eq!(total_dead_scan_hint(&entities, 12), None);
    }

    #[test]
    fn entities_header_line_discloses_infra_excluded_gap() {
        // The bug: the header always printed the RAW `scan.entity_count`, even
        // though every section below renders the caller's infra-filtered list —
        // a scan with platform-infra entities showed a header count higher than
        // anything actually listed, with no explanation of the gap.
        assert_eq!(
            entities_header_line(42, 50),
            "  Entities:  42 (8 platform-infra excluded of 50 total — pass --include-infra to show)"
        );
    }

    #[test]
    fn entities_header_line_is_plain_when_nothing_was_excluded() {
        assert_eq!(entities_header_line(50, 50), "  Entities:  50");
    }

    #[test]
    fn truncation_note_discloses_the_hidden_count() {
        assert_eq!(truncation_note(8, 20), Some("  … 12 more".to_string()));
        assert_eq!(truncation_note(20, 20), None);
        assert_eq!(
            truncation_note(20, 5),
            None,
            "fewer than the cap: nothing hidden"
        );
    }

    #[test]
    fn confine_relations_to_visible_drops_edges_with_an_excluded_endpoint() {
        // Mirrors `core::relation::sorted_confined_adjacency`'s own confinement:
        // an edge is only traversable/renderable when BOTH endpoints are in the
        // visible entity set. Previously the raw RELATIONS section ignored this
        // entirely and printed every relation regardless.
        let a = Entity::new(EntityKind::Domain, "a.example", 0.9, "s");
        let b = Entity::new(EntityKind::Domain, "b.example", 0.9, "s");
        let hidden_uid = "deadbeef00000000000000000000000000000000000000000000000000000";
        let entities = [a.clone(), b.clone()];
        let relations = [
            Relation::new(
                a.uid.clone(),
                b.uid.clone(),
                RelationKind::CoLocatedWith,
                0.8,
                "s",
            ),
            Relation::new(
                a.uid.clone(),
                hidden_uid,
                RelationKind::CoLocatedWith,
                0.8,
                "s",
            ),
        ];
        let confined = confine_relations_to_visible(&entities, &relations);
        assert_eq!(confined.len(), 1, "only the fully-visible edge survives");
        assert_eq!(confined[0].to_uid, b.uid);
    }
}
