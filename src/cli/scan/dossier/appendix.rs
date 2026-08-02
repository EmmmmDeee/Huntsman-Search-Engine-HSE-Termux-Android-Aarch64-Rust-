//! The dossier's back matter: the supporting material an operator consults
//! after reading the findings, not before.
//!
//! These sections answer "how do I trust this, and what should I run next" —
//! what collection ran and what it cost, where the subject is, when they were
//! active, which source chain produced each enriched value, and what to tune.
//! None of them are findings, which is why they sit behind
//! [`super::findings`] and [`super::analysis`] rather than between them.
//!
//! Lettering is not decided here. [`super::plan`] assigns contiguous letters to
//! the appendices actually present and prints the dividers; each function below
//! renders only its body.

use crate::core::{entity::Entity, module::ModuleCost, scan::Scan};

use super::truncation_note;

/// A near-certain misconfiguration/dead-target signal (PROBLEM_TREE T2.14):
/// every dispatched module ran and the scan still yielded ZERO entities.
///
/// Distinct from the per-module "many modules found nothing for this target
/// kind" case (normal — a 40-module scan routinely leaves most modules at zero
/// yield for a given kind, so flooding one line per module would be noise, not
/// signal, per T2.14's own analysis): this fires at most once per scan, only
/// when the scan-wide total is zero despite modules actually having run — never
/// when every module was gate-skipped (`modules_run == 0`, e.g. an unsupported
/// target kind excluded every candidate module before dispatch), which is a
/// different, already-explained situation. Pure and deterministic so it is
/// testable without a live scan.
pub(super) fn total_dead_scan_hint(entities: &[Entity], modules_run: usize) -> Option<String> {
    (entities.is_empty() && modules_run > 0).then(|| {
        format!(
            "{modules_run} module(s) ran and found nothing scan-wide — check the target is \
             reachable/valid, or this seed kind may be unsupported"
        )
    })
}

/// The timeline appendix's one-line "online since X" headline — the same
/// tenure/recency computation `api::scan_handlers::intel::scan_timeline`
/// already returns as `tenure`/`recency` JSON fields, rendered for the CLI.
/// Pure so the exact wording is testable without a live scan.
pub(super) fn tenure_headline(
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

/// Everything the collection/geo/lineage/hints appendices render, computed
/// once up front.
///
/// It has to be computed before anything prints, because whether the lineage
/// and hints appendices exist at all is part of the document's structure (see
/// [`super::plan`]) — and a CONTENTS index cannot be written after the body it
/// indexes.
pub(super) struct Collection {
    diag: crate::util::diagnostics::ScanDiagnostics,
    events: Vec<crate::core::event::Event>,
    costs: std::collections::HashMap<String, ModuleCost>,
}

impl Collection {
    pub(super) fn build(
        scan: &Scan,
        entities: &[Entity],
        kind: &str,
        value: &str,
        sid: &str,
        store: &dyn crate::core::port::StoragePort,
    ) -> Self {
        let wall_ms = scan
            .finished_at
            .and_then(|f| f.checked_sub(scan.started_at))
            .unwrap_or(0)
            .saturating_mul(1000);
        let events = store.events_for_scan(sid).unwrap_or_default();
        let mut diag =
            crate::util::diagnostics::analyse(sid, kind, value, wall_ms, entities, &events);
        if let Some(hint) = total_dead_scan_hint(entities, scan.modules_run) {
            diag.optimization_hints.insert(0, hint);
        }

        let costs: std::collections::HashMap<String, ModuleCost> = crate::modules::registry()
            .iter()
            .map(|m| (m.name().to_string(), m.cost()))
            .collect();

        // T2.14: the cost-gated "wasted keyed/paid modules" + per-module noise-
        // bounded summary need the module cost map `analyse()` doesn't have (it
        // has no StoragePort/registry access) — appended here, with the rest of
        // the computation, so `optimization_hints` is final before the plan
        // reads it to decide whether that appendix exists.
        crate::util::diagnostics::append_event_sourced_hints(&mut diag, &events, &costs);

        Self {
            diag,
            events,
            costs,
        }
    }

    pub(super) fn has_lineage(&self) -> bool {
        !self.diag.enrichment_lineage.is_empty()
    }

    pub(super) fn has_hints(&self) -> bool {
        !self.diag.optimization_hints.is_empty()
    }

    fn cost_label(&self, name: &str) -> &'static str {
        match self.costs.get(name) {
            Some(ModuleCost::Free) => "free",
            Some(ModuleCost::KeyGated) => "key",
            Some(ModuleCost::Paid) => "paid",
            None => "·",
        }
    }

    /// What ran, what it cost, what it yielded, and which paid keys were
    /// wasted.
    pub(super) fn print_collection(&self) {
        println!("  Scan wall-time:  {} ms", self.diag.wall_time_ms);

        const MODULES_SHOWN: usize = 15;
        println!(
            "  Modules ranked by yield ({}, cost tier shown for ROI tuning):",
            self.diag.modules_by_yield.len()
        );
        for m in self.diag.modules_by_yield.iter().take(MODULES_SHOWN) {
            println!(
                "    {:4}  {:<5} {:<22} conf={:.2}  novelty={:5.1}%  kinds={}",
                m.entities_emitted,
                self.cost_label(&m.name),
                m.name,
                m.mean_confidence,
                m.novelty_ratio * 100.0,
                m.unique_kinds.join(",")
            );
        }
        if let Some(note) = truncation_note(MODULES_SHOWN, self.diag.modules_by_yield.len()) {
            println!("{note}");
        }

        let wasted =
            crate::util::diagnostics::keyed_or_paid_zero_yield_modules(&self.events, &self.costs);
        if !wasted.is_empty() {
            println!(
                "  ROI: {} keyed/paid module(s) yielded nothing — consider --exclude {}",
                wasted.len(),
                wasted.join(",")
            );
        }
        println!();

        const SOURCES_SHOWN: usize = 15;
        let mut srcs: Vec<_> = self.diag.source_confidence.iter().collect();
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
    }

    /// Where the subject is, how precisely, and on what basis.
    pub(super) fn print_geo(&self, entities: &[Entity]) {
        // Headline answer first: the single best location estimate when AU-059's
        // cross-seed synergy gate fires (≥2 AU coordinates across ≥2 orthogonal
        // source classes). Same structured fix the API export and the AU-059
        // finding carry — one computation, three renderings.
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
            // Single-signal fallback: the common scan has one location signal,
            // not the ≥2-class synergy AU-059 requires. Surface the best
            // available fix anyway — every located subject gets a headline
            // answer with its precision + basis.
            let near = est
                .locality
                .as_deref()
                .map_or_else(String::new, |l| format!(", near {l}"));
            // The state is AU-only enrichment: a subject located outside
            // Australia still gets the fix, just without a state to name.
            let state = est
                .state
                .map_or_else(String::new, |s| format!(", state={s}"));
            println!(
                "  Best location estimate: {:.4},{:.4} ± {:.1} km  (geohash={}{}{})",
                est.lat, est.lon, est.radius_km, est.geohash, state, near
            );
            println!(
                "    basis: {} (confidence {:.2}) — single-signal fix",
                est.basis, est.confidence
            );
            println!();
        }

        let g = &self.diag.geo_precision;
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

        if !self.diag.proximity_graph.is_empty() {
            const PAIRS_SHOWN: usize = 15;
            println!(
                "  Proximity graph ({} coord pairs, closest first):",
                self.diag.proximity_graph.len()
            );
            for edge in self.diag.proximity_graph.iter().take(PAIRS_SHOWN) {
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
            if let Some(note) = truncation_note(PAIRS_SHOWN, self.diag.proximity_graph.len()) {
                println!("{note}");
            }
            println!();
        }
    }

    /// The source chain behind each enriched finding — which module handed off
    /// to which, for the values that took the most hops to reach.
    pub(super) fn print_lineage(&self) {
        const LINEAGE_SHOWN: usize = 20;
        let mut lineage = self.diag.enrichment_lineage.clone();
        lineage.sort_by_key(|n| std::cmp::Reverse(n.source_chain.len()));
        println!(
            "  {} enriched finding(s), deepest chain first:",
            lineage.len()
        );
        println!();
        for node in lineage.iter().take(LINEAGE_SHOWN) {
            println!(
                "  [{}] {} (conf={:.2}, corr={})",
                node.kind, node.value_preview, node.confidence, node.corroboration
            );
            println!("    sources: {}", node.source_chain.join(" → "));
        }
        if let Some(note) = truncation_note(LINEAGE_SHOWN, lineage.len()) {
            println!("{note}");
        }
        println!();
    }

    /// What to change before the next run.
    pub(super) fn print_hints(&self) {
        for hint in &self.diag.optimization_hints {
            println!("  • {hint}");
        }
        println!();
    }
}

/// Cross-scan enrichment leverage — this scan's identifiers that also appear in
/// earlier investigations in the local intelligence base, ranked by how many
/// they bridge (data_retention_design §4.1). Only genuine bridges (degree ≥ 2)
/// reach here; the complete ranking is in `--output json`.
///
/// Absent on a first-ever scan, where nothing bridges yet — that is correct,
/// not a gap, and the CONTENTS index says so by not listing the appendix.
pub(super) fn print_cross_scan_leverage(bridges: &[&crate::core::engine::LeverageRanked]) {
    const SHOWN: usize = 8;
    println!(
        "  {} identifier(s) bridging prior investigations:",
        bridges.len()
    );
    println!();
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

/// Dated events reconstructed from the working set, and the movement path
/// between geolocated fixes.
pub(super) fn print_timeline(scan: &Scan, entities: &[Entity]) {
    let timeline = crate::core::timeline::reconstruct(entities);

    // Headline first: the same tenure/recency summary the JSON timeline API
    // computes and returns (`api::scan_handlers::intel::scan_timeline`) but
    // which, until now, only the API surfaced — the CLI dossier re-listed every
    // event with no "online since X, Nyr span, footprint status" answer at the
    // top. One computation, two renderings. `now` is the scan's own completion
    // time, not a fresh clock read, so a re-rendered dossier for an old scan
    // reports the recency as of when the data was gathered.
    if let Some(tenure) = crate::core::timeline::online_tenure(&timeline) {
        let now = i64::try_from(scan.finished_at.unwrap_or(scan.started_at)).unwrap_or(i64::MAX);
        let recency = crate::core::timeline::footprint_recency(tenure.latest_ts, now);
        println!("  {}", tenure_headline(&tenure, &recency));
        println!();
    }

    const EVENTS_SHOWN: usize = 40;
    if timeline.is_empty() {
        println!("  No dated events reconstructed from the current entity set.");
    } else {
        println!("  {} dated event(s):", timeline.len());
        println!();
        for ev in timeline.iter().take(EVENTS_SHOWN) {
            println!(
                "  {:<19}  {:<16}  {} [{}]",
                ev.iso,
                ev.kind.as_str(),
                ev.entity_value,
                ev.source
            );
        }
        if let Some(note) = truncation_note(EVENTS_SHOWN, timeline.len()) {
            println!("{note}");
        }
    }
    println!();

    if let Some(movement) = crate::core::timeline::movement_path(&timeline) {
        println!(
            "  Movement: {} fixes, {:.1} km travelled",
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
}
