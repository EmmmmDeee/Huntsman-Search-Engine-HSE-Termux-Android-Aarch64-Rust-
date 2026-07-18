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

#[derive(Clone)]
pub(super) struct ScanCmd {
    /// `None` (or `"auto"`) auto-detects the kind from `value` — the unified scan.
    pub kind: Option<String>,
    pub value: String,
    /// Batch mode: a path to a file of seeds (one target per line). When set,
    /// `value` is ignored and the same scan pipeline runs once per file seed.
    pub input_file: Option<String>,
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
    pub gate_speculative: bool,
    pub profile: Option<String>,
    pub output: String,
    /// Include platform-infrastructure entities (cloud buckets, CDN IPs,
    /// analytics tracking IDs) in the printed/JSON/dossier output. Mirrors
    /// `build_scan_report`'s `include_infra` filter so the same scan reads
    /// consistently whether viewed via `hse scan`, `hse export`, or the API.
    pub include_infra: bool,
}

/// Parse a batch seed-list file body into ordered, de-duplicated seeds: one
/// target per line, blank lines and `#`-comment lines skipped, surrounding
/// whitespace trimmed. **Pure** (no IO) so the parsing is unit-tested directly.
pub(super) fn parse_seed_list(body: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| seen.insert(l.to_string()))
        .map(str::to_string)
        .collect()
}

/// Batch mode: run the SAME scan pipeline for every seed in `--input-file`,
/// reusing [`cmd_scan`] per seed. This is HSE's keyless, any-seed generalisation
/// of a "process this list of targets" batch tool — each seed's findings are
/// scanned, stored (exportable afterwards per `scan_id` via `hse export`), and a
/// per-seed failure is reported without aborting the run (one bad target must
/// not sink the whole list).
async fn run_batch(base: ScanCmd, path: &str) -> crate::core::error::Result<()> {
    let body = std::fs::read_to_string(path).map_err(|e| {
        crate::core::error::Error::Other(format!("cannot read --input-file '{path}': {e}"))
    })?;
    let seeds = parse_seed_list(&body);
    if seeds.is_empty() {
        return Err(crate::core::error::Error::Other(format!(
            "no seeds in --input-file '{path}' (one target per line; blank and # lines ignored)"
        )));
    }
    let total = seeds.len();
    eprintln!("batch: scanning {total} seed(s) from {path}");
    let (mut ok, mut failed) = (0usize, 0usize);
    for (i, seed) in seeds.into_iter().enumerate() {
        eprintln!("\n── batch [{}/{total}] {seed} ──", i + 1);
        let mut per = base.clone();
        per.value = seed.clone();
        per.input_file = None; // guard against re-entry
        // Box the recursive call: cmd_scan ↔ run_batch is a cycle, so at least
        // one edge must be heap-indirected to keep the future finite-sized.
        match Box::pin(cmd_scan(per)).await {
            Ok(()) => ok += 1,
            Err(e) => {
                failed += 1;
                eprintln!("batch: seed '{seed}' failed: {e}");
            }
        }
    }
    eprintln!("\nbatch complete: {ok} succeeded, {failed} failed, {total} total");
    Ok(())
}

pub(super) async fn cmd_scan(cmd: ScanCmd) -> crate::core::error::Result<()> {
    // Batch mode short-circuit: `--input-file` runs the whole pipeline once per
    // file seed, reusing this same function (value is overwritten per seed).
    if let Some(path) = cmd.input_file.clone() {
        return run_batch(cmd, &path).await;
    }
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
    if let Err(msg) = target.validate_verbose() {
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
    // Validate the requested / excluded module names against the live registry.
    // A typo, or a name removed in an upgrade, was silently ignored — a real run
    // of `--modules <removed-name>` dispatched ZERO modules with no warning,
    // leaving the operator with an empty scan and no idea why. Surface it:
    // "nothing is a black box".
    let include_modules = split_csv(cmd.modules);
    let unknown = unknown_module_names(&include_modules, &exclude_modules);
    if !unknown.is_empty() {
        eprintln!(
            "warning: ignoring {} unrecognised module name(s) in --modules/--exclude: {} \
             — run `hse modules` for the catalogue",
            unknown.len(),
            unknown.join(", ")
        );
    }
    let options = ScanOptions {
        modules: include_modules,
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
        gate_speculative: cmd.gate_speculative,
        // `hse scan` is a manual scan: the live device sensors stay off (they are
        // `hse radar`-only). No CLI flag enables them here by design.
        allow_live_sensors: false,
    }
    .clamp_depth();

    // `--profile <name>` overlays a preset's tuning (depth / free-only / passive /
    // expansion threshold / concurrency / budgets / expansion strategy /
    // regional search) on top of the per-flag options, leaving the orthogonal
    // selection/output flags (`--modules`, `--exclude`, `--output`,
    // `--throttle`, webhook) intact. `recommended` is the zero-setup
    // out-of-box bundle.
    let options = if let Some(name) = cmd.profile.as_deref() {
        let opts = apply_named_profile(name, options).map_err(crate::core::error::Error::Other)?;
        eprintln!("profile: {name}");
        opts
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
    };

    // Wire an operator Ctrl-C to the engine's cooperative cancel flag — without
    // this, SIGINT falls through to the OS default (immediate process kill),
    // skipping `finalise_scan` entirely: the scan row stays stuck at `Running`
    // forever and any in-flight module tasks are simply abandoned mid-request
    // rather than stopped. Cloning the handle before `ctx` moves into `run`
    // lets this listener signal the SAME flag the engine polls; once `run`
    // returns (normally or via cooperative cancellation, which persists a
    // clean `Aborted` scan with everything collected so far) the listener is
    // aborted so it doesn't outlive the scan.
    let cancel_on_ctrl_c = ctx.cancel.clone();
    let ctrl_c_listener = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\nstopping scan…");
            cancel_on_ctrl_c.cancel();
        }
    });
    let scan = engine.run(scan, target, ctx).await?;
    ctrl_c_listener.abort();
    let mut entities = store.entities_for_scan(&sid)?;
    filter_infra_entities(&mut entities, cmd.include_infra);
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
        let mut diag =
            crate::util::diagnostics::analyse(&sid, kind_str, &cmd.value, wall_ms, &entities);
        // T2.14: event-sourced hints analyse() cannot compute itself (no
        // StoragePort access) — enrich here, mirroring the dossier's
        // identical enrichment, so `--output json` and `--output dossier`
        // agree on optimization_hints regardless of which surface a caller uses.
        let events = store.events_for_scan(&sid).unwrap_or_default();
        let cost_by_module: std::collections::HashMap<String, crate::core::module::ModuleCost> =
            crate::modules::registry()
                .iter()
                .map(|m| (m.name().to_string(), m.cost()))
                .collect();
        crate::util::diagnostics::append_event_sourced_hints(&mut diag, &events, &cost_by_module);
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
        let leverage = crate::core::engine::rank_enrichment_leverage(
            store.as_ref(),
            &entities,
            entities.len(),
        );
        dossier::print_dossier(dossier::DossierArgs {
            scan: &scan,
            entities: &entities,
            correlations: &correlations,
            relations: &relations,
            kind: kind_str,
            value: &cmd.value,
            leverage: &leverage,
            store: store.as_ref(),
        });
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

/// Resolve `--profile <name>` and overlay its tuning onto `options` via the
/// SAME `core::profiles::apply_profile_overlay` the HTTP API uses for its
/// `"profile"` request field, so a profile means the same thing on the CLI and
/// the API — not just on what [`crate::core::profiles::resolve_profile`]
/// returns, but on how it's merged. `Err` names an unknown profile.
///
/// Previously the CLI reimplemented the overlay as a hand-written 8-field
/// `ScanOptions { ..., ..options }` construction here, which omitted
/// `expansion_strategy`/`regional_search` — dormant only because
/// `ScanOptions::default()` happened to coincide with every current profile's
/// values for those two fields, not because it was correct.
fn apply_named_profile(name: &str, options: ScanOptions) -> Result<ScanOptions, String> {
    let p = crate::core::profiles::resolve_profile(name).ok_or_else(|| {
        // Render the SINGLE-SOURCED catalogue from `core::profiles::list_profiles`
        // rather than a hand-typed name list: the previous literal
        // ("recommended, passive, …") was a copy that would silently go stale the
        // next time a profile is added, and it hid the one-line descriptions
        // `list_profiles` carries — so the help now also tells the operator what
        // each profile DOES, not just its name.
        let mut msg = format!("unknown --profile '{name}'. Available profiles:");
        for (pname, desc) in crate::core::profiles::list_profiles() {
            msg.push_str(&format!("\n  {pname} — {desc}"));
        }
        msg
    })?;
    Ok(crate::core::profiles::apply_profile_overlay(options, p).clamp_depth())
}

/// Strip platform/shared-infrastructure entities (cloud buckets, CDN IPs,
/// analytics IDs) from `hse scan`'s printed/JSON/dossier output, mirroring
/// [`crate::api::scan_export::build_scan_report`]'s `include_infra` filter so
/// the same scan reads consistently across `hse scan`, `hse export`, and the
/// API. The operator-provided seed always survives even if it is itself
/// infrastructure. A no-op when `include_infra` is `true`.
fn filter_infra_entities(entities: &mut Vec<crate::core::entity::Entity>, include_infra: bool) {
    if !include_infra {
        entities.retain(|e| !e.has_tag(crate::core::tags::PLATFORM_INFRA) || e.has_tag("seed"));
    }
}

/// The `--modules` / `--exclude` names that are not registered modules
/// (deduplicated, sorted), checked against the live registry. A typo, or a name
/// removed in an upgrade, was silently dropped from the filter; surfacing it
/// lets the operator see why a scan ran fewer modules than they requested.
fn unknown_module_names(requested: &Option<Vec<String>>, excluded: &[String]) -> Vec<String> {
    let known: std::collections::HashSet<&str> = crate::modules::registry()
        .iter()
        .map(|m| m.name())
        .collect();
    requested
        .iter()
        .flatten()
        .chain(excluded.iter())
        .filter(|m| !known.contains(m.as_str()))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
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
    fn parse_seed_list_skips_blanks_comments_and_dedups() {
        let body = "\
8.8.8.8
  1.1.1.1

# a comment line
example.com
8.8.8.8
# another comment
alice@example.com
";
        let seeds = parse_seed_list(body);
        // Order preserved, whitespace trimmed, blanks + # lines dropped, the
        // duplicate 8.8.8.8 collapsed to its first occurrence.
        assert_eq!(
            seeds,
            vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
                "example.com".to_string(),
                "alice@example.com".to_string(),
            ]
        );
        // An all-blank / all-comment body yields no seeds (run_batch errors on it).
        assert!(parse_seed_list("\n\n#only a comment\n   \n").is_empty());
    }

    #[test]
    fn unknown_module_names_flags_typos_and_removed_modules() {
        // Derived from a real run: `--modules ipapi` — a name removed when that
        // module was consolidated into ip_whois_geo — dispatched ZERO modules
        // with no warning. Pin that an unregistered name is flagged while a real
        // one is not, against the LIVE registry (so it tracks real renames).
        let req = Some(vec![
            "ip_geo".to_string(),        // registered → must NOT be flagged
            "ipapi".to_string(),         // removed     → must be flagged
            "totally_bogus".to_string(), // typo        → must be flagged
        ]);
        let unknown = unknown_module_names(&req, &[]);
        assert!(
            !unknown.iter().any(|m| m == "ip_geo"),
            "a registered module must not be flagged"
        );
        assert!(
            unknown.iter().any(|m| m == "ipapi"),
            "a removed module name must be flagged"
        );
        assert!(
            unknown.iter().any(|m| m == "totally_bogus"),
            "a typo'd name must be flagged"
        );
        // Excluded names are validated too; output is sorted + deduplicated.
        let unknown_ex =
            unknown_module_names(&None, &["whois".to_string(), "no_such_excl".to_string()]);
        assert_eq!(unknown_ex, vec!["no_such_excl".to_string()]);
        // An all-valid request flags nothing.
        assert!(unknown_module_names(&Some(vec!["ip_geo".to_string()]), &[]).is_empty());
    }

    #[test]
    fn filter_infra_entities_hides_platform_infra_by_default() {
        // The `--include-infra` flag used to be parsed by clap but discarded at
        // the `Command::Scan` dispatch (`include_infra: _`) — `hse scan` always
        // showed platform-infra entities regardless of the flag, unlike
        // `hse export` / the API which quarantine them by default. Pin the
        // actual filter behaviour the flag now drives.
        let mut infra = Entity::new(EntityKind::IpAddress, "104.16.0.1", 0.6, "s");
        infra.tag(crate::core::tags::PLATFORM_INFRA);
        let subject = Entity::new(EntityKind::Domain, "example-subject.test", 0.9, "s");
        let mut entities = vec![infra, subject];

        filter_infra_entities(&mut entities, false);
        assert_eq!(entities.len(), 1, "platform-infra entity must be dropped");
        assert_eq!(entities[0].kind, EntityKind::Domain);
    }

    #[test]
    fn filter_infra_entities_restores_infra_when_flag_set() {
        let mut infra = Entity::new(EntityKind::IpAddress, "104.16.0.1", 0.6, "s");
        infra.tag(crate::core::tags::PLATFORM_INFRA);
        let mut entities = vec![infra];

        filter_infra_entities(&mut entities, true);
        assert_eq!(
            entities.len(),
            1,
            "--include-infra must restore platform-infra entities"
        );
    }

    #[test]
    fn filter_infra_entities_never_drops_the_seed_even_if_infra_tagged() {
        // A scan seeded with a datacenter/CDN IP that an IP module re-emits as
        // `hosting`, which then merges `platform-infra` onto the seed anchor —
        // the seed must still appear in its own report.
        let mut seed = Entity::new(EntityKind::IpAddress, "104.16.0.1", 0.9, "s");
        seed.tag(crate::core::tags::PLATFORM_INFRA);
        seed.tag("seed");
        let mut entities = vec![seed];

        filter_infra_entities(&mut entities, false);
        assert_eq!(entities.len(), 1, "the seed must always survive the filter");
    }

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

    #[test]
    fn apply_named_profile_preserves_client_flags_and_applies_every_tuning_field() {
        // The bug this guards: the CLI's old hand-written overlay listed only 8
        // of the profile-tuning fields, omitting `expansion_strategy` and
        // `regional_search` — dormant only because `ScanOptions::default()`
        // happened to coincide with every profile's values for those two
        // fields (both `GeoConverge`/`true`, same as `skiptrace`'s). Pin the
        // base options to the OPPOSITE values so the overlay is actually
        // required to override them from the named profile.
        let options = ScanOptions {
            modules: Some(vec!["hunter_io".to_string()]),
            min_confidence: Some(0.7),
            expansion_strategy: crate::core::scan::ExpansionStrategy::BreadthFirst,
            regional_search: false,
            ..ScanOptions::default()
        };
        let merged = apply_named_profile("skiptrace", options.clone()).unwrap();
        assert_eq!(
            merged.modules, options.modules,
            "--modules must survive the overlay"
        );
        assert_eq!(
            merged.min_confidence, options.min_confidence,
            "--min-confidence must survive the overlay"
        );
        let skiptrace = crate::core::profiles::resolve_profile("skiptrace").unwrap();
        assert_eq!(merged.depth, skiptrace.depth);
        assert_eq!(
            merged.expansion_strategy, skiptrace.expansion_strategy,
            "expansion_strategy must be carried by the CLI overlay"
        );
        assert_eq!(
            merged.regional_search, skiptrace.regional_search,
            "regional_search must be carried by the CLI overlay"
        );
    }

    #[test]
    fn apply_named_profile_rejects_unknown_name() {
        let err = apply_named_profile("not-a-real-profile", ScanOptions::default()).unwrap_err();
        assert!(
            err.starts_with("unknown --profile "),
            "error must carry the client-facing prefix, got: {err}"
        );
        // The help is rendered from the single-sourced `core::profiles::list_profiles`
        // catalogue, so it can't drift from the selectable set: every profile's
        // NAME and its one-line DESCRIPTION must appear. This ties the CLI's
        // unknown-profile help to the catalogue the way the module-count guard
        // ties the README to the registry — add a profile and this fails until
        // the help is sourced from the shared list, not a hand-typed literal.
        // (Fails against the pre-wire error, which listed bare names and no
        // descriptions at all.)
        for (name, desc) in crate::core::profiles::list_profiles() {
            assert!(
                err.contains(name),
                "unknown-profile help must list every profile name — missing '{name}': {err}"
            );
            assert!(
                err.contains(desc),
                "unknown-profile help must render each profile's description — missing '{name}'s: {err}"
            );
        }
    }
}
