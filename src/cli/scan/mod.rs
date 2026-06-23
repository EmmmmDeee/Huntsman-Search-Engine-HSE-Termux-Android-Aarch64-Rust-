//! `hse scan` — run a single scan and print the entities.
//!
//! Surfaces every `ScanOptions` field as a CLI flag, applies the
//! `--auto` / `--recursive` / `--adaptive` heuristics, runs the
//! scan, then formats output as table / json / dossier.

mod dossier;

use crate::core::module::ModuleContext;
use crate::core::scan::{Scan, ScanOptions, Target};
use crate::util::{keys, uid::scan_id};

use super::{
    build_runtime, color_confidence, color_severity, parse_target_kind, split_csv, truncate,
    use_color,
};

pub(super) struct ScanCmd {
    /// `None` (or `"auto"`) auto-detects the kind from `value` — the unified scan.
    pub kind: Option<String>,
    pub value: String,
    pub modules: Option<String>,
    pub exclude: Option<String>,
    pub throttle_ms: u64,
    pub min_confidence: Option<f64>,
    pub free_only: bool,
    pub passive_only: bool,
    pub module_timeout_ms: Option<u64>,
    /// `None` ⇒ apply the product default ([`crate::core::scan::DEFAULT_SCAN_DEPTH`]) unless
    /// `--auto`/`--recursive` chooses one; `Some(n)` is an explicit override.
    pub depth: Option<u32>,
    pub recursive: bool,
    pub auto: bool,
    pub min_expand_confidence: f64,
    pub max_entities: Option<usize>,
    pub max_wall_time_secs: Option<u64>,
    pub max_concurrent: usize,
    pub adaptive: bool,
    pub max_roi: bool,
    pub convex_budget: bool,
    pub regional_search: bool,
    pub min_marginal_yield: Option<f64>,
    pub expansion_strategy: String,
    pub seeknow_scan_cap: Option<u32>,
    pub expand_all_identities: bool,
    pub profile: Option<String>,
    pub output: String,
}

pub(super) async fn cmd_scan(cmd: ScanCmd) -> crate::core::error::Result<()> {
    // Unified scan: an omitted (or `auto`) --kind is inferred from the value's
    // shape; an explicit kind is parsed as before. Detection is reported on
    // stderr so the operator sees (and can override) what was chosen.
    let kind_arg = cmd.kind.as_deref().map_or("", str::trim);
    let target_kind = if kind_arg.is_empty() || kind_arg.eq_ignore_ascii_case("auto") {
        let detected = crate::core::scan::detect_kind(&cmd.value);
        eprintln!(
            "auto-detected target kind: {} (override with --kind)",
            detected.canonical_str()
        );
        detected
    } else {
        parse_target_kind(kind_arg)?
    };
    let kind_str = target_kind.canonical_str();
    let target = Target::new(target_kind, cmd.value.clone());

    // Reject junk/placeholder seeds at the CLI boundary too (the HTTP API
    // already does this via `validated_target`). Without it, `hse scan --kind
    // domain --value example.com` would dispatch every module against a reserved
    // documentation domain — exactly the "example anything" the engine must not
    // scan.
    if let Err(msg) = target.validate() {
        return Err(crate::core::error::Error::Other(format!(
            "invalid target '{}': {msg}",
            target.value
        )));
    }

    // Depth resolution. `--auto`/`--recursive` only kick in when the operator
    // gave no explicit `--depth` (sentinel: `cmd.depth.is_none()`); otherwise an
    // omitted `--depth` falls back to the comprehensive product default
    // (DEFAULT_SCAN_DEPTH = MAX_DEPTH). `--recursive`'s `.min(0.40)` never raises
    // the floor above the operator's value, so with the comprehensive default it
    // stays at the 0.20 expansion floor.
    let (depth, min_expand_confidence, max_concurrent) = if cmd.auto && cmd.depth.is_none() {
        let has_paid = keys::load().contains_key("HUNTSMAN_OATHNET_KEY");
        let (auto_depth, auto_conf) = crate::core::scan::optimal_depth(target_kind, has_paid);
        eprintln!("auto: depth={auto_depth} min_conf={auto_conf:.2} (paid_keys={has_paid})");
        (auto_depth, auto_conf, cmd.max_concurrent.max(2))
    } else if cmd.recursive && cmd.depth.is_none() {
        (
            crate::core::scan::MAX_DEPTH,
            cmd.min_expand_confidence.min(0.40),
            cmd.max_concurrent.max(2),
        )
    } else {
        (
            cmd.depth.unwrap_or(crate::core::scan::DEFAULT_SCAN_DEPTH),
            cmd.min_expand_confidence,
            cmd.max_concurrent,
        )
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
        // No CLI flag yet; a category focus is supplied by a profile (e.g.
        // `--profile skiptrace`) and overlaid below.
        category_focus: Vec::new(),
        throttle_ms: cmd.throttle_ms,
        max_concurrent,
        module_timeout_ms: cmd.module_timeout_ms,
        min_confidence: cmd.min_confidence,
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth,
        min_expand_confidence,
        // Comprehensive-but-bounded: apply the product-default entity ceiling when
        // the operator gave none, so the deep (MAX_DEPTH) low-floor default sweep
        // can't run the frontier away and OOM a Termux device. `--max-entities`
        // overrides; a profile's own cap wins via the overlay below.
        max_entities: cmd
            .max_entities
            .or(Some(crate::core::scan::DEFAULT_MAX_ENTITIES)),
        max_wall_time_secs: cmd.max_wall_time_secs,
        scan_tags: Vec::new(),
        notes: None,
        webhook_url: crate::core::webhook::webhook_url_from_env(),
        profile: None,
        max_roi: cmd.max_roi,
        convex_budget: cmd.convex_budget,
        regional_search: cmd.regional_search,
        min_marginal_yield: cmd.min_marginal_yield,
        expansion_strategy,
        seeknow_scan_cap: cmd.seeknow_scan_cap,
        expand_all_identities: cmd.expand_all_identities,
        // `hse scan` is a manual scan: the live device sensors stay off (they are
        // `hse radar`-only). No CLI flag enables them here by design.
        allow_live_sensors: false,
    }
    .clamp_depth();

    // `--profile <name>` overlays a preset's tuning (depth / free-only / passive /
    // expansion threshold / concurrency / budgets) on top of the per-flag options,
    // leaving the orthogonal selection/output flags (`--modules`, `--exclude`,
    // `--output`, `--throttle`, webhook) intact. `recommended` is the zero-setup
    // out-of-box bundle. Resolution is shared with the API via `core::profiles`,
    // so CLI and web agree on what a profile means.
    let options = if let Some(name) = cmd.profile.as_deref() {
        let p = crate::core::profiles::resolve_profile(name).ok_or_else(|| {
            crate::core::error::Error::Other(format!(
                "unknown --profile '{name}' (try: recommended, passive, footprint, \
                 investigate, fast, skiptrace)"
            ))
        })?;
        eprintln!("profile: {name}");
        ScanOptions {
            free_only: p.free_only,
            passive_only: p.passive_only,
            depth: p.depth,
            min_expand_confidence: p.min_expand_confidence,
            max_concurrent: p.max_concurrent,
            max_entities: p.max_entities,
            max_wall_time_secs: p.max_wall_time_secs,
            // A profile's category focus has no per-flag equivalent, so carry it
            // through the overlay — otherwise `--profile skiptrace` would lose
            // the very focus that defines it.
            category_focus: p.category_focus,
            ..options
        }
        .clamp_depth()
    } else {
        options
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
        // Stamp outbound calls with this scan's id so a proxy/upstream access log
        // can be matched back to the scan (and its NDJSON logs carry the same id).
        http: crate::util::http::build_client_with_trace(&sid),
        keys,
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    };

    let scan = engine.run(scan, target, ctx).await?;
    let entities = store.entities_for_scan(&sid)?;
    let correlations = store.correlations_for_scan(&sid)?;
    let relations = store.relations_for_scan(&sid)?;

    // Guarantee maximum-detail output on EVERY search: auto-write the full
    // dossier (every entity, full provenance, every raw API response embedded)
    // and announce its path on stderr — regardless of the chosen stdout format.
    // Best-effort: a dossier write failure must never fail the scan itself.
    match crate::cli::export::write_full_dossier(store.as_ref(), &sid) {
        Ok(path) => eprintln!("full dossier: {}", path.display()),
        Err(e) => eprintln!("warning: could not write full dossier: {e}"),
    }

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
            crate::util::diagnostics::analyse(&sid, kind_str, &cmd.value, wall_ms, &entities);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "scan": scan,
                "entities": entities,
                "correlations": correlations,
                "relations": relations,
                "diagnostics": diag,
                "exposure": crate::core::exposure::assess(&entities, &correlations),
                // Which of this scan's identifiers most bridge to the local
                // intelligence base (data_retention_design §4.1) — ranked by
                // realised cross-scan degree. A live cross-scan view (it grows as
                // investigations accumulate), so it belongs in this live output, NOT
                // the byte-deterministic debug bundle.
                "enrichment_leverage":
                    crate::core::engine::rank_enrichment_leverage(store.as_ref(), &entities, entities.len()),
            }))?
        );
    } else if cmd.output == "dossier" {
        dossier::print_dossier(
            &scan,
            &entities,
            &correlations,
            &relations,
            kind_str,
            &cmd.value,
            &sid,
        );
    } else {
        let color = use_color();
        println!(
            "\nScan {} — {} entities for {}={}",
            &sid[..8],
            entities.len(),
            kind_str,
            cmd.value
        );
        if scan.modules_run > 0 {
            // `skipped` is shown so toggle effects are observable in the
            // standard view: excluding a module (`--exclude`) or disabling one
            // (`hse config module.<name> off`) moves it out of `run` and into
            // `skipped` here, without needing `--output json`.
            println!(
                "  modules: {} run, {} errored, {} timed out, {} deduped, {} skipped\n",
                scan.modules_run,
                scan.modules_errored,
                scan.modules_timed_out,
                scan.modules_deduped,
                scan.modules_skipped
            );
        } else {
            println!();
        }
        println!(
            "{:<16} {:>6} {:>6}  {:<10} {:<26} VALUE",
            "KIND", "CONF", "C_EFF", "CLASS", "SOURCES"
        );
        println!("{}", "-".repeat(90));
        for e in &entities {
            let c_eff = e.c_effective();
            let class = e.classify();
            // Raw source names (not just a count) for at-a-glance traceability;
            // the full per-source records are in `--output dossier` / `json`.
            let sources = entity_source_labels(e);
            // VALUE is the LAST column and printed IN FULL — complete URLs (and
            // every other value) are never truncated in the standard results
            // view (no omission). Long values run to the end of the line.
            let row = format!(
                "{:<16} {:>6.3} {:>6.3}  {:<10} {:<26} {}",
                e.kind, e.confidence, c_eff, class, sources, e.value
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

/// Resolve the effective `(depth, min_expand_confidence, max_concurrent)` from
/// the scan-mode flags. **Pure**: the `--auto` tuning is supplied lazily through
/// `optimal`, so no key/file IO (nor its `eprintln`) happens off the auto path.
///
/// * `--auto` and `--recursive` take effect **only** when the operator gave no
///   explicit `--depth`. An explicit depth always wins.
/// * `--auto` outranks `--recursive` when both are set.
/// * Either mode raises concurrency to at least 2; `--recursive` additionally
///   clamps the expansion floor to ≤ 0.40.
#[cfg(test)]
fn resolve_scan_tuning(
    auto: bool,
    recursive: bool,
    explicit_depth: Option<u32>,
    base_min_expand_conf: f64,
    base_max_concurrent: usize,
    optimal: impl FnOnce() -> (u32, f64),
) -> (u32, f64, usize) {
    if auto && explicit_depth.is_none() {
        let (auto_depth, auto_conf) = optimal();
        (auto_depth, auto_conf, base_max_concurrent.max(2))
    } else if recursive && explicit_depth.is_none() {
        (
            crate::core::scan::MAX_DEPTH,
            base_min_expand_conf.min(0.40),
            base_max_concurrent.max(2),
        )
    } else {
        (
            explicit_depth.unwrap_or(crate::core::scan::DEFAULT_SCAN_DEPTH),
            base_min_expand_conf,
            base_max_concurrent,
        )
    }
}

/// The adaptive `recommended` skips not already excluded by the operator,
/// preserving recommendation order. **Pure** so the dedup-against-existing
/// logic is unit-tested without a ledger on disk.
#[cfg(test)]
fn new_adaptive_skips(existing: &[String], recommended: &[String]) -> Vec<String> {
    recommended
        .iter()
        .filter(|m| !existing.iter().any(|e| e == *m))
        .cloned()
        .collect()
}

/// Distinct raw source labels behind an entity — the breach / DB / provider
/// names (from each evidence record's `source` attribute, else the producing
/// module name). Surfaced in the table view so results show their RAW sources,
/// not just an evidence count. All distinct sources are listed (no truncation —
/// the column is last on the row).
fn entity_source_labels(e: &crate::core::entity::Entity) -> String {
    let mut seen = std::collections::BTreeSet::new();
    for ev in &e.evidence {
        let label = ev
            .attributes
            .get("source")
            .cloned()
            .unwrap_or_else(|| ev.source.clone());
        seen.insert(label);
    }
    if seen.is_empty() {
        return "—".to_string();
    }
    seen.into_iter()
        .enumerate()
        .fold(String::new(), |mut acc, (i, s)| {
            if i > 0 {
                acc.push_str(", ");
            }
            acc.push_str(&s);
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use std::cell::Cell;

    #[test]
    fn tuning_explicit_depth_overrides_modes_and_keeps_optimal_lazy() {
        // Explicit --depth wins over both --auto and --recursive, the auto
        // closure must NOT run (no key IO), and --max-concurrent is preserved.
        let called = Cell::new(false);
        let (d, c, mc) = resolve_scan_tuning(true, true, Some(5), 0.25, 1, || {
            called.set(true);
            (9, 0.9)
        });
        assert_eq!((d, mc), (5, 1));
        assert!((c - 0.25).abs() < 1e-9);
        assert!(
            !called.get(),
            "optimal() must stay lazy when --depth is explicit"
        );
    }

    #[test]
    fn tuning_auto_outranks_recursive_and_bumps_concurrency() {
        let (d, c, mc) = resolve_scan_tuning(true, true, None, 0.25, 0, || (4, 0.30));
        assert_eq!(d, 4);
        assert!((c - 0.30).abs() < 1e-9);
        assert_eq!(mc, 2, "auto raises concurrency to >= 2");
    }

    #[test]
    fn tuning_recursive_uses_max_depth_and_clamps_floor() {
        let (d, c, mc) = resolve_scan_tuning(false, true, None, 0.80, 5, || (0, 0.0));
        assert_eq!(d, crate::core::scan::MAX_DEPTH);
        assert!((c - 0.40).abs() < 1e-9, "floor clamped to <= 0.40");
        assert_eq!(mc, 5, "concurrency already >= 2 is kept as-is");
    }

    #[test]
    fn tuning_recursive_keeps_floor_already_below_clamp() {
        let (_, c, _) = resolve_scan_tuning(false, true, None, 0.10, 2, || (0, 0.0));
        assert!(
            (c - 0.10).abs() < 1e-9,
            "min() keeps an already-lower floor"
        );
    }

    #[test]
    fn tuning_plain_falls_back_to_default_depth() {
        let (d, c, mc) = resolve_scan_tuning(false, false, None, 0.33, 3, || (9, 0.9));
        assert_eq!(d, crate::core::scan::DEFAULT_SCAN_DEPTH);
        assert!((c - 0.33).abs() < 1e-9);
        assert_eq!(mc, 3, "plain mode never bumps concurrency");
    }

    #[test]
    fn adaptive_skips_drops_already_excluded_and_preserves_order() {
        let existing = vec!["a".to_string(), "c".to_string()];
        let recommended = vec![
            "c".to_string(),
            "b".to_string(),
            "a".to_string(),
            "d".to_string(),
        ];
        assert_eq!(
            new_adaptive_skips(&existing, &recommended),
            vec!["b".to_string(), "d".to_string()]
        );
    }

    #[test]
    fn adaptive_skips_empty_when_all_already_present() {
        let existing = vec!["a".to_string(), "b".to_string()];
        assert!(new_adaptive_skips(&existing, &["a".to_string(), "b".to_string()]).is_empty());
    }

    #[test]
    fn source_labels_prefer_source_attr_then_dedup_and_sort() {
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.5, "s");
        // A "source" attr overrides the raw evidence source name.
        e.add_evidence(Evidence::new("modB", "m").with_attr("source", "haveibeenpwned"));
        // No "source" attr → falls back to ev.source ("modA")…
        e.add_evidence(Evidence::new("modA", "m"));
        // …and a repeat of that label collapses to one.
        e.add_evidence(Evidence::new("modA", "m2"));
        // BTreeSet ⇒ sorted, deduped: 'h' (0x68) < 'm' (0x6D).
        assert_eq!(entity_source_labels(&e), "haveibeenpwned, modA");
    }

    #[test]
    fn source_labels_em_dash_when_no_evidence() {
        let e = Entity::new(EntityKind::Email, "x@y.com", 0.5, "s");
        assert_eq!(entity_source_labels(&e), "—");
    }
}
