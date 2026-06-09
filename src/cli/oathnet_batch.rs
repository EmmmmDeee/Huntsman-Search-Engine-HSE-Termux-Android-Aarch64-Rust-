//! `hse oathnet-batch` — generate (and optionally execute) a large batch of
//! OathNet queries from a single seed.
//!
//! The query plan is built by the pure `util::oathnet_batch` generator, which
//! fans one seed out across breach/stealer surfaces, derived selector fields,
//! and value permutations. By default the command only PRINTS the plan (free,
//! no quota spent); `--execute` dispatches it, bounded by the shared OathNet
//! per-session budget so a batch can't silently blow the daily allowance.

use crate::core::error::{Error, Result};
use crate::core::scan::detect_kind;
use crate::util::oathnet;
use crate::util::oathnet_batch::{self, BatchOptions, BatchQuery};

/// Parsed `oathnet-batch` arguments (mirrors the clap `Command::OathnetBatch`
/// variant; kept as a struct so the command body is testable in isolation).
pub struct BatchCmd {
    pub value: String,
    pub kind: Option<String>,
    pub no_stealer: bool,
    pub no_permute: bool,
    pub synthesize_emails: bool,
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
    let key = oathnet::resolve_key(loaded.get(oathnet::KEY_ENV).map(String::as_str));

    // Deliberate batch: start from a fresh per-scan counter and lift the tight
    // per-scan cap so the run is bounded by the per-session ceiling, not the
    // 4-per-scan default sized for automated expansion.
    oathnet::reset_budget();
    oathnet::set_scan_cap_override(plan.len().min(u32::MAX as usize) as u32);

    let mut dispatched = 0usize;
    let mut total_hits = 0usize;
    let mut stopped_on_budget = false;
    let mut rows: Vec<(usize, &BatchQuery, usize)> = Vec::new();

    for q in plan {
        if !oathnet::has_budget() {
            stopped_on_budget = true;
            break;
        }
        match oathnet::search(key, q.surface.path(), q.field, &q.value, page_size).await {
            Ok(items) => {
                dispatched += 1;
                total_hits += items.len();
                if !items.is_empty() {
                    rows.push((dispatched, q, items.len()));
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
