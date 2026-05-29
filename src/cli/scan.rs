//! `hse scan` — run a single scan and print the entities.
//!
//! Surfaces every `ScanOptions` field as a CLI flag, applies the
//! `--auto` / `--recursive` / `--adaptive` heuristics, runs the
//! scan, then formats output as table / json / dossier.

use crate::core::module::ModuleContext;
use crate::core::scan::{Scan, ScanOptions, Target};
use crate::util::{http::build_client, keys, uid::scan_id};

use super::{
    build_runtime, color_confidence, color_severity, parse_target_kind, split_csv, truncate,
    use_color,
};

pub(super) struct ScanCmd {
    pub kind: String,
    pub value: String,
    pub modules: Option<String>,
    pub exclude: Option<String>,
    pub throttle_ms: u64,
    pub min_confidence: Option<f64>,
    pub free_only: bool,
    pub passive_only: bool,
    pub module_timeout_ms: Option<u64>,
    pub depth: u32,
    pub recursive: bool,
    pub auto: bool,
    pub min_expand_confidence: f64,
    pub max_entities: Option<usize>,
    pub max_wall_time_secs: Option<u64>,
    pub max_concurrent: usize,
    pub adaptive: bool,
    pub max_roi: bool,
    pub min_marginal_yield: Option<f64>,
    pub expansion_strategy: String,
    pub seeknow_scan_cap: Option<u32>,
    pub output: String,
}

pub(super) async fn cmd_scan(cmd: ScanCmd) -> crate::core::error::Result<()> {
    let target_kind = parse_target_kind(&cmd.kind)?;
    let target = Target::new(target_kind, cmd.value.clone());

    let (depth, min_expand_confidence, max_concurrent) = if cmd.auto && cmd.depth == 0 {
        let has_paid = keys::load().contains_key("HUNTSMAN_OATHNET_KEY");
        let (auto_depth, auto_conf) = crate::core::scan::optimal_depth(target_kind, has_paid);
        eprintln!(
            "auto: depth={auto_depth} min_conf={auto_conf:.2} (paid_keys={})",
            has_paid
        );
        (auto_depth, auto_conf, cmd.max_concurrent.max(4))
    } else if cmd.recursive && cmd.depth == 0 {
        (
            7,
            cmd.min_expand_confidence.min(0.40),
            cmd.max_concurrent.max(4),
        )
    } else {
        (cmd.depth, cmd.min_expand_confidence, cmd.max_concurrent)
    };

    let mut exclude_modules = split_csv(cmd.exclude).unwrap_or_default();
    if cmd.adaptive {
        // Closed feedback loop: read the ledger, skip historically
        // zero-yield modules. Log the decision so the operator sees
        // what the self-optimization actually did.
        let routing = crate::util::diagnostics::read_adaptive_routing();
        if routing.ledger_scans == 0 {
            eprintln!(
                "adaptive: no ledger yet (run a few scans first to populate ~/.huntsman/module_stats.json)"
            );
        } else {
            let added: Vec<String> = routing
                .recommended_skips
                .iter()
                .filter(|m| !exclude_modules.iter().any(|e| e == *m))
                .cloned()
                .collect();
            if !added.is_empty() {
                eprintln!(
                    "adaptive: ledger has {} scans; skipping {} historically zero-yield modules: {}",
                    routing.ledger_scans,
                    added.len(),
                    added.join(", ")
                );
                exclude_modules.extend(added);
            } else {
                eprintln!(
                    "adaptive: ledger has {} scans; no skip recommendations",
                    routing.ledger_scans
                );
            }
        }
    }
    // Parse the strategy via `FromStr` on `ExpansionStrategy` so the
    // variant list lives in one place (core/scan.rs) — the previous
    // duplicate match here drifted whenever a new variant was added.
    let expansion_strategy: crate::core::scan::ExpansionStrategy =
        cmd.expansion_strategy.parse().map_err(|e: String| {
            crate::core::error::Error::Other(format!("--expansion-strategy: {e}"))
        })?;
    let options = ScanOptions {
        modules: split_csv(cmd.modules),
        exclude_modules,
        throttle_ms: cmd.throttle_ms,
        max_concurrent,
        module_timeout_ms: cmd.module_timeout_ms,
        min_confidence: cmd.min_confidence,
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth,
        min_expand_confidence,
        max_entities: cmd.max_entities,
        max_wall_time_secs: cmd.max_wall_time_secs,
        scan_tags: Vec::new(),
        notes: None,
        webhook_url: crate::core::webhook::webhook_url_from_env(),
        profile: None,
        max_roi: cmd.max_roi,
        min_marginal_yield: cmd.min_marginal_yield,
        expansion_strategy,
        seeknow_scan_cap: cmd.seeknow_scan_cap,
    };
    if cmd.max_roi {
        eprintln!(
            "max-roi: convergence-pruning + top-K gate + adaptive-depth (floor={:.2})",
            cmd.min_marginal_yield
                .unwrap_or(crate::core::roi::DEFAULT_MIN_MARGINAL_YIELD)
        );
    }

    let sid = scan_id(target_kind.canonical_str(), &cmd.value);
    let (store, bus, engine) = build_runtime(64)?;

    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);
    let keys = keys::populate_and_load().await;
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys,
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    };

    let scan = engine.run(scan, target, ctx).await?;
    let entities = store.entities_for_scan(&sid)?;
    let correlations = store.correlations_for_scan(&sid)?;
    let relations = store.relations_for_scan(&sid)?;

    if cmd.output == "json" {
        // Full self-optimization payload — scan + entities + correlations
        // + diagnostics (module ranking, confidence calibration, geo
        // precision report, cross-source overlaps, optimization hints,
        // enrichment lineage).
        let wall_ms = scan
            .finished_at
            .and_then(|f| f.checked_sub(scan.started_at))
            .unwrap_or(0)
            .saturating_mul(1000);
        let diag =
            crate::util::diagnostics::analyse(&sid, &cmd.kind, &cmd.value, wall_ms, &entities);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "scan": scan,
                "entities": entities,
                "correlations": correlations,
                "relations": relations,
                "diagnostics": diag,
            }))?
        );
    } else if cmd.output == "dossier" {
        print_dossier(
            &scan,
            &entities,
            &correlations,
            &relations,
            &cmd.kind,
            &cmd.value,
            &sid,
        );
    } else {
        let color = use_color();
        println!(
            "\nScan {} — {} entities for {}={}",
            &sid[..8],
            entities.len(),
            cmd.kind,
            cmd.value
        );
        if scan.modules_run > 0 {
            println!(
                "  modules: {} run, {} errored, {} timed out, {} deduped\n",
                scan.modules_run,
                scan.modules_errored,
                scan.modules_timed_out,
                scan.modules_deduped
            );
        } else {
            println!();
        }
        println!(
            "{:<16} {:<42} {:>6} {:>6}  {:<10} SRCS",
            "KIND", "VALUE", "CONF", "C_EFF", "CLASS"
        );
        println!("{}", "-".repeat(90));
        for e in &entities {
            let val = truncate(&e.value, 42);
            let c_eff = e.c_effective();
            let class = e.classify();
            let sources = e.evidence.len();
            let row = format!(
                "{:<16} {:<42} {:>6.3} {:>6.3}  {:<10} {}",
                e.kind, val, e.confidence, c_eff, class, sources
            );
            println!("{}", color_confidence(c_eff, &row, color));
        }
        if !correlations.is_empty() {
            println!("\n{} correlations:\n", correlations.len());
            println!(
                "{:<10} {:<10} {:<40} DESCRIPTION",
                "RULE", "SEVERITY", "NAME"
            );
            println!("{}", "-".repeat(86));
            for c in &correlations {
                let sev_padded = format!("{:<10}", c.severity);
                let sev_colored = color_severity(&sev_padded, color);
                println!(
                    "{:<10} {} {:<40} {}",
                    c.rule_id,
                    sev_colored,
                    truncate(&c.rule_name, 40),
                    c.description
                );
            }
        }
    }
    Ok(())
}

fn print_dossier(
    scan: &crate::core::scan::Scan,
    entities: &[crate::core::entity::Entity],
    correlations: &[crate::core::correlator::Correlation],
    relations: &[crate::core::relation::Relation],
    kind: &str,
    value: &str,
    sid: &str,
) {
    use std::collections::BTreeMap;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  HUNTSMAN SEARCH ENGINE — INTELLIGENCE DOSSIER              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    {} = {}", kind, value);
    println!("  Scan ID:   {}", &sid[..16]);
    println!("  Status:    {}", scan.status.as_str());
    println!("  Entities:  {}", scan.entity_count);
    println!(
        "  Modules:   {} run, {} errored, {} deduped",
        scan.modules_run, scan.modules_errored, scan.modules_deduped
    );
    println!();

    // Group by kind
    let mut by_kind: BTreeMap<String, Vec<&crate::core::entity::Entity>> = BTreeMap::new();
    for e in entities {
        by_kind.entry(e.kind.to_string()).or_default().push(e);
    }

    // Priority order for dossier
    let kind_order = [
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
    ];

    for kind_name in &kind_order {
        let Some(group) = by_kind.get(*kind_name) else {
            continue;
        };
        let header = match *kind_name {
            "person" => "PERSONS",
            "email" => "EMAIL ADDRESSES",
            "phone" => "PHONE NUMBERS",
            "username" => "USERNAMES / HANDLES",
            "credential" => "CREDENTIALS (from breach/stealer data)",
            "address" => "PHYSICAL ADDRESSES / LOCATIONS",
            "coordinates" => "GPS COORDINATES",
            "organisation" => "ORGANISATIONS",
            "abn_acn" => "ABN / ACN (Australian Business Numbers)",
            "domain" => "DOMAINS",
            "ip_address" => "IP ADDRESSES",
            "url" => "URLS / PROFILES",
            "mac_address" => "MAC ADDRESSES (network devices)",
            "device_id" => "DEVICE IDENTIFIERS",
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

            for ev in &e.evidence {
                println!("    ├─ {} — {}", ev.source, ev.summary);
                // Unredacted: print every non-empty attribute regardless
                // of length. The dossier surface is for the operator only;
                // truncation hides API-key context, multi-line bios, full
                // breach passwords, complete addresses, etc.
                for (k, v) in &ev.attributes {
                    if !v.is_empty() {
                        println!("    │  {}: {}", k, v);
                    }
                }
            }
            println!();
        }
    }

    // Correlations
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

    // Relations (typed attribution edges between entities)
    if !relations.is_empty() {
        use std::collections::HashMap;
        let by_uid: HashMap<&str, &crate::core::entity::Entity> =
            entities.iter().map(|e| (e.uid.as_str(), e)).collect();
        let label = |uid: &str| -> String {
            by_uid
                .get(uid)
                .map(|e| truncate(&e.value, 40))
                .unwrap_or_else(|| format!("{}…", &uid[..uid.len().min(8)]))
        };
        println!("━━━ RELATIONS ({}) ━━━", relations.len());
        println!();
        for r in relations {
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

    // ─── DIAGNOSTICS & SELF-OPTIMIZATION ──────────────────────────────
    // Surface the same data the JSON path exposes — module yield,
    // confidence calibration, geo precision, proximity graph,
    // optimization hints. Operator gets the full unredacted view.
    let wall_ms = scan
        .finished_at
        .and_then(|f| f.checked_sub(scan.started_at))
        .unwrap_or(0)
        .saturating_mul(1000);
    let diag = crate::util::diagnostics::analyse(sid, kind, value, wall_ms, entities);

    println!("━━━ DIAGNOSTICS ━━━");
    println!();
    println!("  Scan wall-time:  {} ms", diag.wall_time_ms);

    // Map each module name → cost tier so the yield table doubles as an ROI
    // ledger: a zero-yield Paid/KeyGated module is a drop candidate, a
    // zero-yield Free one is not. Built from the registry (the single source
    // of the module list); non-module evidence sources (geo_normalize,
    // entity_value, …) have no tier and render as "·". One-shot cost at
    // dossier render time, off the scan hot path.
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

    println!("  Modules ranked by yield (cost tier shown for ROI tuning):");
    for m in diag.modules_by_yield.iter().take(15) {
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
    // ROI hint: keyed/paid modules that produced nothing this scan are the
    // levers an operator can pull with `--exclude` to conserve quota.
    let wasted: Vec<&str> = diag
        .modules_by_yield
        .iter()
        .filter(|m| {
            m.entities_emitted == 0
                && matches!(
                    cost_by_module.get(&m.name),
                    Some(ModuleCost::KeyGated | ModuleCost::Paid)
                )
        })
        .map(|m| m.name.as_str())
        .collect();
    if !wasted.is_empty() {
        println!(
            "  ROI: {} keyed/paid module(s) yielded nothing — consider --exclude {}",
            wasted.len(),
            wasted.join(",")
        );
    }
    println!();

    println!("  Source confidence (n / mean / p50 / p90):");
    let mut srcs: Vec<_> = diag.source_confidence.iter().collect();
    srcs.sort_by_key(|(_, s)| std::cmp::Reverse(s.n));
    for (src, s) in srcs.iter().take(15) {
        println!(
            "    {:<22} n={:<4} mean={:.2}  p50={:.2}  p90={:.2}",
            src, s.n, s.mean, s.p50, s.p90
        );
    }
    println!();

    // ─── GEO INTELLIGENCE ──────────────────────────────────────────────
    let g = &diag.geo_precision;
    println!("━━━ GEO INTELLIGENCE ━━━");
    println!();
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

    // ─── ENRICHMENT LINEAGE (top 20 highest-corroboration entities) ───
    println!("━━━ ENRICHMENT LINEAGE ━━━");
    println!();
    let mut lineage_sorted = diag.enrichment_lineage.clone();
    lineage_sorted.sort_by_key(|n| std::cmp::Reverse(n.source_chain.len()));
    for node in lineage_sorted.iter().take(20) {
        println!(
            "  [{}] {} (conf={:.2}, corr={})",
            node.kind, node.value_preview, node.confidence, node.corroboration
        );
        println!("    sources: {}", node.source_chain.join(" → "));
    }
    println!();

    // ─── OPTIMIZATION HINTS ────────────────────────────────────────────
    println!("━━━ OPTIMIZATION HINTS ━━━");
    println!();
    for hint in &diag.optimization_hints {
        println!("  • {}", hint);
    }
    println!();

    println!("━━━ END OF DOSSIER ━━━");
}
