//! `hse oathnet-batch` — generate (and optionally execute) a large batch of
//! OathNet queries from a single seed.
//!
//! The query plan is built by the pure `util::oathnet_batch` generator, which
//! fans one seed out across breach/stealer surfaces, derived selector fields,
//! and value permutations. By default the command only PRINTS the plan (free,
//! no quota spent); `--execute` dispatches it, bounded by the shared OathNet
//! per-session budget so a batch can't silently blow the daily allowance.

use std::collections::{HashMap, HashSet};

use futures::future::join_all;

use crate::core::error::{Error, Result};
use crate::core::scan::detect_kind;
use crate::util::oathnet;
use crate::util::oathnet_batch::{self, BatchOptions, BatchQuery};

/// Max queries `--execute` dispatches concurrently. The generated queries are
/// mutually independent, so concurrency here is pure latency hiding on the
/// round-trip-bound mobile radio HSE targets — but it is kept deliberately small
/// so a large fanned-out plan can't stampede the paid OathNet API, which meters
/// per lookup. The per-lookup budget (`oathnet::search`'s atomic reservation)
/// remains the hard ceiling regardless of how many run at once.
const BATCH_CONCURRENCY: usize = 4;

/// The set of (lowercased) query values worth initialising an OathNet search
/// session for: exactly those that appear on **two or more** queries in the plan.
///
/// A session lets multiple calls on one query value collapse to a single billed
/// lookup (the vendor's "#1 optimisation") — but `init_session` itself costs a
/// network round-trip while billing no lookup, so it only pays off when a value
/// is actually queried more than once (the breach+stealer PAIR the generator
/// emits for every stealer-indexable selector). For a value queried only once,
/// the single search costs exactly one lookup with or without a session, so the
/// init POST is pure latency the batch run can drop — a real saving on the
/// low-power mobile networks HSE targets. Pure and deterministic, so it is
/// unit-tested directly without a live dispatch.
fn values_worth_sessioning(plan: &[BatchQuery]) -> HashSet<String> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for q in plan {
        *counts.entry(q.value.to_lowercase()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .filter(|(_, n)| *n >= 2)
        .map(|(value, _)| value)
        .collect()
}

/// Parsed `oathnet-batch` arguments (mirrors the clap `Command::OathnetBatch`
/// variant; kept as a struct so the command body is testable in isolation).
pub struct BatchCmd {
    pub value: String,
    pub kind: Option<String>,
    pub no_stealer: bool,
    pub no_permute: bool,
    pub synthesize_emails: bool,
    pub recurse_depth: u32,
    pub max: usize,
    pub page_size: u32,
    pub execute: bool,
    pub json: bool,
}

pub async fn cmd_oathnet_batch(cmd: BatchCmd) -> Result<()> {
    let value = cmd.value.trim().to_string();
    if value.is_empty() {
        return Err(Error::Other(
            "oathnet-batch: --value must not be empty".into(),
        ));
    }
    // A zero page size would dispatch `page_size=0` requests that OathNet rejects
    // — reject it up front rather than spending the round-trip to find out.
    if cmd.page_size == 0 {
        return Err(Error::Other(
            "oathnet-batch: --page-size must be at least 1".into(),
        ));
    }

    // Resolve the seed kind: explicit `--kind`, else auto-detect from the value.
    let kind = match cmd
        .kind
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
    {
        Some(k) => super::parse_target_kind(k)?,
        None => detect_kind(&value),
    };

    let opts = BatchOptions {
        include_stealer: !cmd.no_stealer,
        permute_handles: !cmd.no_permute,
        synthesize_emails: cmd.synthesize_emails,
        recurse_depth: cmd.recurse_depth,
        max_queries: cmd.max,
    };

    let plan = oathnet_batch::generate(kind, &value, &opts);
    if plan.is_empty() {
        return Err(Error::Other(format!(
            "oathnet-batch: no queries generated for {value:?} (kind {}). OathNet indexes \
             email / username / name / phone / ip / domain seeds.",
            kind.canonical_str()
        )));
    }

    if cmd.execute {
        execute_plan(&plan, cmd.page_size, cmd.json).await
    } else {
        print_plan(&plan, kind.canonical_str(), &value, cmd.json);
        Ok(())
    }
}

/// Render the generated plan without dispatching it (the free default).
fn print_plan(plan: &[BatchQuery], kind: &str, value: &str, json: bool) {
    if json {
        let arr: Vec<serde_json::Value> = plan
            .iter()
            .map(|q| {
                serde_json::json!({
                    "surface": q.surface.label(),
                    "path":    q.surface.path(),
                    "field":   q.field,
                    "value":   q.value,
                    "origin":  q.origin.label(),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "seed":    value,
            "kind":    kind,
            "count":   plan.len(),
            "queries": arr,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return;
    }

    println!(
        "OathNet batch plan for {value} ({kind}) — {} quer{} (preview only; pass --execute to run):\n",
        plan.len(),
        if plan.len() == 1 { "y" } else { "ies" }
    );
    println!(
        "  {:<8}  {:<10}  {:<20}  VALUE",
        "SURFACE", "FIELD", "ORIGIN"
    );
    println!("  {:-<8}  {:-<10}  {:-<20}  {:-<30}", "", "", "", "");
    for q in plan {
        println!(
            "  {:<8}  {:<10}  {:<20}  {}",
            q.surface.label(),
            q.field,
            q.origin.label(),
            q.value
        );
    }
    let breach = plan
        .iter()
        .filter(|q| q.surface == oathnet::Surface::Breach)
        .count();
    let stealer = plan.len() - breach;
    println!("\n  totals: {breach} breach, {stealer} stealer");
    println!(
        "  note: executing spends OathNet credits (1 per query) and is bounded by the per-session budget."
    );
}

/// Dispatch the plan against OathNet, bounded by the shared per-session budget.
async fn execute_plan(plan: &[BatchQuery], page_size: u32, json: bool) -> Result<()> {
    let loaded = crate::util::keys::load();
    // No embedded default: refuse the batch rather than firing every planned
    // query with an empty key and burning the run on uniform 401s.
    let key = crate::util::keys::resolve_key(loaded.get(oathnet::KEY_ENV).map(String::as_str))
        .ok_or_else(|| crate::core::error::Error::MissingKey(oathnet::KEY_ENV.to_string()))?;

    // Deliberate batch: start from a fresh per-scan counter and lift the tight
    // per-scan cap so the run is bounded by the per-session ceiling, not the
    // 4-per-scan default sized for automated expansion.
    oathnet::reset_budget();
    oathnet::set_scan_cap_override(plan.len().min(u32::MAX as usize) as u32);

    let mut dispatched = 0usize;
    let mut total_hits = 0usize;
    let mut stopped_on_budget = false;
    let mut rows: Vec<(usize, &BatchQuery, usize)> = Vec::new();

    // Session IDs, keyed by lowercased target value. The generator
    // (`oathnet_batch::query_gen::add`) deliberately emits a breach+stealer PAIR
    // on the identical field+value for every stealer-indexable selector so a
    // session covers both (the vendor's own "#1 optimisation": N calls on one
    // query = 1 lookup instead of N). Only values queried 2+ times are worth a
    // session — for a singleton the init POST saves no lookup and just costs a
    // round-trip (see `values_worth_sessioning`).
    let session_values = values_worth_sessioning(plan);
    // Pre-initialise every worth-sessioning value's session ONCE, up front and
    // sequentially, BEFORE any concurrent dispatch — so two concurrent same-value
    // queries in a chunk below can't race to double-init (or silently pick up a
    // foreign session). `init_session` bills no lookup, so this pre-pass spends
    // only round-trips, and only for the (few) repeated values; it is still
    // budget-gated so we never init a session the run has no budget to use.
    let mut sessioned: HashMap<String, Option<String>> = HashMap::new();
    for q in plan {
        let lower_value = q.value.to_lowercase();
        if session_values.contains(&lower_value) && !sessioned.contains_key(&lower_value) {
            if !oathnet::has_budget() {
                break;
            }
            let sid = oathnet::init_session(key, &q.value).await;
            sessioned.insert(lower_value, sid);
        }
    }

    // Dispatch in bounded-concurrency chunks, each sized to the LIVE remaining
    // budget. The generated queries are mutually independent (distinct
    // surface/field/value), so within a chunk they run CONCURRENTLY — a decisive
    // wall-clock win on the latency-bound mobile radio HSE targets, where a
    // strictly sequential loop stalls one full round-trip per query. Concurrency
    // is capped at `BATCH_CONCURRENCY` so a large plan can't stampede the paid API.
    //
    // The chunk is sized to `min(BATCH_CONCURRENCY, budget_remaining)` — NOT a flat
    // `BATCH_CONCURRENCY` — because `oathnet::search` silently short-circuits an
    // over-budget query to an empty result (no network call). Launching a flat
    // chunk would let that surplus be counted as `dispatched` and would hide the
    // "stopped at the budget" signal; sizing to the budget means every query in a
    // chunk actually runs, so `dispatched` and `stopped_on_budget` stay accurate.
    // The budget is re-read each iteration, so cached queries (which spend no
    // budget) don't prematurely end the run.
    let mut idx = 0usize;
    while idx < plan.len() {
        let remaining = {
            let snap = oathnet::budget_snapshot();
            let scan_left = snap.scan_cap.saturating_sub(snap.scan_used);
            let session_left = snap.session_cap.saturating_sub(snap.session_used);
            scan_left.min(session_left)
        };
        if remaining == 0 || oathnet::is_quota_exhausted() {
            stopped_on_budget = true;
            break;
        }
        let take = BATCH_CONCURRENCY
            .min(remaining as usize)
            .min(plan.len() - idx);
        let chunk = &plan[idx..idx + take];
        idx += take;
        let futures = chunk.iter().map(|q| {
            // Resolve this query's session synchronously into an owned value, then
            // move it into the async task — the shared `sessioned` map is only
            // read here (never across an await), so the concurrent tasks in a
            // chunk share nothing mutable.
            let session_id: Option<String> =
                sessioned.get(&q.value.to_lowercase()).cloned().flatten();
            // Clamp to this surface's own documented ceiling — Breach and Stealer
            // differ (1000 vs 100), so one flat `--page-size` can't be passed
            // through uncapped to a plan spanning both.
            let effective_page_size = page_size.min(q.surface.max_page_size());
            async move {
                let res = oathnet::search(
                    key,
                    q.surface.path(),
                    q.field,
                    &q.value,
                    effective_page_size,
                    session_id.as_deref(),
                )
                .await;
                (q, res)
            }
        });
        // `join_all` preserves input order, so `rows` stays deterministic.
        for (q, res) in join_all(futures).await {
            match res {
                Ok(found) => {
                    dispatched += 1;
                    total_hits += found.items.len();
                    // A short enumeration is real data, but the row count is a
                    // COVERAGE claim — say so rather than let the summary read
                    // as the complete answer.
                    if let Some(reason) = found.completeness.reason() {
                        tracing::warn!(
                            surface = q.surface.label(),
                            field = q.field,
                            value = %q.value,
                            fetched = found.items.len(),
                            "oathnet-batch result is PARTIAL: {reason}"
                        );
                    }
                    if !found.items.is_empty() {
                        rows.push((dispatched, q, found.items.len()));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        surface = q.surface.label(),
                        field = q.field,
                        value = %q.value,
                        "oathnet-batch query failed: {e}"
                    );
                }
            }
        }
    }

    if json {
        let hits: Vec<serde_json::Value> = rows
            .iter()
            .map(|(_, q, n)| {
                serde_json::json!({
                    "surface": q.surface.label(),
                    "field":   q.field,
                    "value":   q.value,
                    "origin":  q.origin.label(),
                    "records": n,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "planned":           plan.len(),
            "dispatched":        dispatched,
            "queries_with_hits": rows.len(),
            "total_records":     total_hits,
            "stopped_on_budget": stopped_on_budget,
            "hits":              hits,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return Ok(());
    }

    println!(
        "OathNet batch: dispatched {dispatched}/{} quer{} — {} with hits, {total_hits} record(s) total.",
        plan.len(),
        if plan.len() == 1 { "y" } else { "ies" },
        rows.len()
    );
    if !rows.is_empty() {
        println!(
            "\n  {:<8}  {:<10}  {:<20}  VALUE",
            "RECORDS", "FIELD", "ORIGIN"
        );
        println!("  {:-<8}  {:-<10}  {:-<20}  {:-<30}", "", "", "", "");
        for (_, q, n) in &rows {
            println!(
                "  {:<8}  {:<10}  {:<20}  {}",
                n,
                q.field,
                q.origin.label(),
                q.value
            );
        }
    }
    if stopped_on_budget {
        println!(
            "\n  stopped early at the OathNet per-session budget. Raise HUNTSMAN_OATHNET_SESSION_CAP \
             to run more of the plan."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::oathnet::Surface;
    use crate::util::oathnet_batch::Origin;

    fn q(surface: Surface, field: &'static str, value: &str) -> BatchQuery {
        BatchQuery {
            surface,
            field,
            value: value.to_string(),
            origin: Origin::Seed,
        }
    }

    #[test]
    fn empty_plan_sessions_nothing() {
        assert!(values_worth_sessioning(&[]).is_empty());
    }

    #[test]
    fn singleton_value_is_not_sessioned() {
        // One breach-only query for a value → a session would save no lookup.
        let plan = vec![q(Surface::Breach, "phone", "+15551234567")];
        assert!(values_worth_sessioning(&plan).is_empty());
    }

    #[test]
    fn paired_value_is_sessioned() {
        // The breach+stealer pair the generator emits for a login-indexable
        // selector — the exact case a session collapses to one lookup.
        let plan = vec![
            q(Surface::Breach, "email", "a@b.com"),
            q(Surface::Stealer, "email", "a@b.com"),
        ];
        let s = values_worth_sessioning(&plan);
        assert_eq!(s.len(), 1);
        assert!(s.contains("a@b.com"));
    }

    #[test]
    fn multiplicity_is_counted_case_insensitively() {
        // The dispatch loop keys sessions on the lowercased value, so the
        // worth-sessioning test must agree: two differently-cased spellings of
        // the same value are one value queried twice, hence worth a session.
        let plan = vec![
            q(Surface::Breach, "username", "Alice"),
            q(Surface::Stealer, "username", "alice"),
        ];
        let s = values_worth_sessioning(&plan);
        assert_eq!(s.len(), 1);
        assert!(s.contains("alice"));
        assert!(
            !s.contains("Alice"),
            "the set is keyed on the lowercased value"
        );
    }

    #[test]
    fn mixed_plan_sessions_only_the_repeated_values() {
        let plan = vec![
            // Repeated (breach+stealer) → sessioned.
            q(Surface::Breach, "email", "a@b.com"),
            q(Surface::Stealer, "email", "a@b.com"),
            // Two distinct singletons → not sessioned.
            q(Surface::Breach, "domain", "b.com"),
            q(Surface::Breach, "phone", "+15551234567"),
        ];
        let s = values_worth_sessioning(&plan);
        assert_eq!(s.len(), 1);
        assert!(s.contains("a@b.com"));
        assert!(!s.contains("b.com"));
        assert!(!s.contains("+15551234567"));
    }
}
