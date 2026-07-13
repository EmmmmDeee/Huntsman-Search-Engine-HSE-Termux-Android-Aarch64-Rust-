//! `hse doctor` — health-check subcommand.
//!
//! Reports Termux detection, DB path, key path, module/cost counts,
//! HUNTSMAN_* keys loaded, a per-source scraper health signal derived from
//! the persisted event log (`PROBLEM_TREE` T2.7 / `SOLUTION_TREE`
//! SOL-HEALTH-SIGNAL — see [`crate::util::scraper_health`]), a cross-scan
//! **weak findings** review list (every stored entity below the confidence
//! review threshold — see [`crate::storage::Store::low_confidence_evidence`]),
//! the local cell-tower database's freshness (no auto-resync exists yet, so a
//! months-stale import is a real "check for a refresh" signal — see
//! [`crate::util::cell_db::is_stale`]), and a live WiGLE account
//! introspection that surfaces the email-unverified throttling warning
//! before it starts silently truncating result sets.

use crate::core::error::Result;
use crate::{
    default_db_path, is_termux,
    modules::registry,
    storage::{EvidenceAnomaly, Store},
    util::{cell_db, keys, scraper_health, timefmt},
};

use super::cost_label;

pub(super) async fn cmd_doctor() -> Result<()> {
    let mods = registry();
    println!("HSE v{} — doctor\n", crate::VERSION);
    println!(
        "Termux:    {}",
        if is_termux() {
            "detected"
        } else {
            "not detected"
        }
    );
    println!("DB path:   {}", default_db_path());
    println!("Keys path: {}", keys::env_path());

    println!("\nStorage:");
    let db_path = default_db_path();
    // Kept as a `Result` (not unwrapped into the match arm) so the same open
    // handle can back the scraper-health section further down without a
    // second `Store::open` — the DB is opened once per `doctor` run either way.
    let store_result = Store::open(&db_path);
    match &store_result {
        Ok(store) => {
            println!("  ok — database opens cleanly");
            // Explicit corruption check (T5): a healthy DB reports a single "ok".
            match store.integrity_check() {
                Ok(rows) if rows.iter().all(|r| r == "ok") => {
                    println!("  integrity:  ok");
                }
                Ok(rows) => {
                    println!("  integrity:  FAIL — {} issue(s) reported:", rows.len());
                    for r in rows.iter().take(10) {
                        println!("                {r}");
                    }
                }
                Err(e) => println!("  integrity:  could not run check — {e}"),
            }
            // WAL high-water mark: a never-checkpointed `-wal` can grow without
            // bound under a long-lived process. Report it so the operator can
            // see (and a TRUNCATE checkpoint at the next scan boundary resets it).
            if let Ok(meta) = std::fs::metadata(format!("{db_path}-wal")) {
                let kib = meta.len() / 1024;
                println!("  WAL size:   {kib} KiB");
                if meta.len() > 64 * 1024 * 1024 {
                    println!(
                        "                (large — runs a TRUNCATE checkpoint at the next scan)"
                    );
                }
            }
        }
        Err(e) => println!("  FAIL — {e}"),
    }

    println!("\nExternal tools:");
    let curl_ok = std::process::Command::new("curl")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if curl_ok {
        println!("  curl:      present");
    } else {
        println!("{}", curl_missing_message());
    }

    println!("\nModules ({} registered):", mods.len());
    let mut by_cost = std::collections::BTreeMap::<&str, usize>::new();
    for m in &mods {
        *by_cost.entry(cost_label(m.cost())).or_default() += 1;
    }
    for (cost, count) in &by_cost {
        println!("  {cost:<10} {count}");
    }

    let loaded = keys::load();
    let huntsman_keys: Vec<_> = loaded
        .keys()
        .filter(|k| k.starts_with("HUNTSMAN_"))
        .collect();
    println!("\nHUNTSMAN_* keys loaded: {}", huntsman_keys.len());
    for k in &huntsman_keys {
        println!("  - {k}");
    }
    if huntsman_keys.is_empty() {
        println!("  (none set; all free modules still work)");
    }

    // ── Unset keys + where to get them (mostly free), ranked by acquisition ──
    // The "failing modules" in a scan are usually just these — unconfigured
    // optional providers, which skip cleanly rather than erroring. Ranked by
    // ROI tier (see `rank_unset_keys`) so the operator registers the keys that
    // unlock the most collection first, each with its free-signup hint.
    let missing = rank_unset_keys(|k| loaded.contains_key(k));
    if !missing.is_empty() {
        println!(
            "\nUnset keys ({}), ranked by acquisition value — modules needing \
             these skip cleanly (not errors). Register multiplier-tier keys first:",
            missing.len()
        );
        for (k, roi) in missing {
            let tier = roi.label();
            match keys::signup_hint(k) {
                Some(hint) => println!("  - [{tier:<10}] {k}\n      → {hint}"),
                None => println!("  - [{tier:<10}] {k}"),
            }
        }
    }

    // ── Per-source scraper health (T2.7 / SOL-HEALTH-SIGNAL) ──────────
    // Derived from the persisted event log across ALL scans (a rolling
    // window — see `recent_module_outcome_events`'s doc), not just this
    // process: a source that has errored on every one of its last N runs is
    // real drift an operator should know about even if the failing scans
    // happened days ago in unrelated invocations.
    println!("\nScraper health (recent window):");
    match &store_result {
        Ok(store) => match store.recent_module_outcome_events(scraper_health::RECENT_EVENTS_WINDOW)
        {
            Ok(events) => {
                let health = scraper_health::aggregate_source_health(&events);
                let drifted: Vec<_> = health.iter().filter(|h| h.is_drifted()).collect();
                println!(
                    "  {} source(s) tracked over {} recent outcome event(s)",
                    health.len(),
                    events.len()
                );
                if drifted.is_empty() {
                    println!("  no drifted sources");
                } else {
                    println!(
                        "  {} DRIFTED (>= {} consecutive failures with no success in between):",
                        drifted.len(),
                        scraper_health::DRIFTED_THRESHOLD
                    );
                    for h in &drifted {
                        let last_ok = h
                            .last_success_at
                            .and_then(|ts| timefmt::ymd_utc(ts as i64))
                            .unwrap_or_else(|| "no success in this window".to_string());
                        println!(
                            "    - {:<20} {} consecutive failures, last success: {}",
                            h.module, h.consecutive_failures, last_ok
                        );
                        if let Some(err) = &h.last_error {
                            println!("      last error: {err}");
                        }
                    }
                }

                // ── Silent zero-yield ("parse-rate") drift ──────────────
                // Distinct from a hard failure: the module completes
                // without erroring but has quietly stopped finding
                // anything, on a source proven capable of yielding —
                // consistent with a layout change breaking extraction
                // rather than the target genuinely having nothing.
                let yield_drifted: Vec<_> =
                    health.iter().filter(|h| h.is_yield_drifted()).collect();
                if yield_drifted.is_empty() {
                    println!("  no silent zero-yield (parse-rate) drift");
                } else {
                    println!(
                        "  {} YIELD-DRIFTED (>= {} trailing zero-result runs on a source that has \
                         previously found something):",
                        yield_drifted.len(),
                        scraper_health::YIELD_DRIFT_THRESHOLD
                    );
                    for h in &yield_drifted {
                        println!(
                            "    - {:<20} {} trailing zero-result runs",
                            h.module, h.consecutive_zero_yield
                        );
                    }
                }
            }
            Err(e) => println!("  could not read event log — {e}"),
        },
        Err(_) => println!("  skipped — database did not open (see Storage above)"),
    }

    // ── Weak findings review (cross-scan) ───────────────────────────────
    // `Store::low_confidence_evidence` has no `scan_id` filter by design — it
    // queries the WHOLE local intelligence DB, not one investigation. That is
    // exactly why this lives here, in the cross-scan operator dashboard
    // (alongside the scraper-health signal just above), and NOT as an `hse
    // audit` report section: `hse audit` scores one scan/source's evidentiary
    // quality, and silently blending in weak entities from OTHER, unrelated
    // scans would itself be the wrong-scope evidentiary contamination this
    // project's correlator audits (AU-056/AU-085, AU-105, the GEXF
    // co-occurrence fix) have repeatedly closed elsewhere.
    println!(
        "\nWeak findings (last 7 days, confidence < {:.2}):",
        Store::DEFAULT_LOW_CONFIDENCE_THRESHOLD
    );
    match &store_result {
        Ok(store) => match store.low_confidence_evidence(
            Store::DEFAULT_LOW_CONFIDENCE_THRESHOLD,
            crate::core::port::EVENTS_RETENTION_SECS as i64,
        ) {
            Ok(anomalies) => print!("{}", format_weak_findings(&anomalies)),
            Err(e) => println!("  could not query weak findings — {e}"),
        },
        Err(_) => println!("  skipped — database did not open (see Storage above)"),
    }

    // ── Cell tower database freshness ──────────────────────────────────
    // `hse cells import` is a manual trigger with no auto-resync (a named,
    // unbuilt gap in SOLUTION_TREE §4a) — surfacing staleness here at least
    // makes an operator relying on GEOINT cell-tower correlation (AU-084,
    // `cell_intel`/`cell_local`) aware their local dataset may no longer
    // reflect current tower deployments, rather than trusting it silently.
    println!("\nCell tower database:");
    match cell_db::open_ro() {
        Ok(conn) => match cell_db::last_import(&conn) {
            Ok(Some(rec)) => {
                let total = cell_db::total_count(&conn).unwrap_or(0);
                let now = crate::core::entity::unix_now() as i64;
                let age_days = now.saturating_sub(rec.imported_at).max(0) / 86_400;
                println!("  {total} towers, last import {age_days}d ago");
                if cell_db::is_stale(rec.imported_at, now) {
                    println!(
                        "  STALE (>= {}d since last import) — GEOINT cell-tower correlation \
                         is working from data that old; consider `hse cells import --country \
                         <CODE>` to refresh.",
                        cell_db::STALE_THRESHOLD_DAYS
                    );
                }
            }
            Ok(None) => println!("  populated but no import history recorded"),
            Err(e) => println!("  could not read import history — {e}"),
        },
        Err(_) => println!(
            "  not populated — run `hse cells import --country AU` (or --file PATH) to enable \
             local cell-tower lookups"
        ),
    }

    // ── WiGLE account health (network call, best-effort) ──────────────
    // Poll /api/v2/profile/user. Surfaces the "email unverified →
    // throttled" warning that the WiGLE account page calls out but which
    // our queries don't otherwise expose until they start silently
    // returning fewer results.
    println!("\nWiGLE account:");
    let wigle_user = loaded
        .get("HUNTSMAN_WIGLE_USER")
        .map_or(keys::WIGLE_DEFAULT_USER, String::as_str)
        .to_string();
    let wigle_token = loaded
        .get("HUNTSMAN_WIGLE_TOKEN")
        .map_or(keys::WIGLE_DEFAULT_TOKEN, String::as_str)
        .to_string();
    let http = crate::util::http::build_client();
    let status =
        crate::modules::wigle::refresh_account_status(&http, &wigle_user, &wigle_token).await;
    match status.verified {
        Some(true) => println!("  email-verified: yes"),
        Some(false) => println!(
            "  email-verified: NO — WiGLE throttles DB queries until email is confirmed.\n                  Log into wigle.net/account and click the verify link."
        ),
        None => println!("  email-verified: unknown — /profile/user not reachable"),
    }
    if let Some(user) = status.user.as_deref() {
        println!("  user:           {user}");
    }

    Ok(())
}

/// The `curl:      MISSING` diagnostic body — every module/command that shells
/// out to the `curl` binary with NO reqwest fallback, so it silently fails
/// rather than erroring when curl is absent. Verified against the current
/// codebase (not every module that mentions curl qualifies — e.g. `geocode`
/// tries reqwest first and only falls back to curl, so curl's absence there
/// just loses a fallback, not the whole feature):
/// - `search_engines`, `social_probe` (default modules), `see_know`,
///   `oathnet_pro`, `api_key_probe`, `abn_lookup` — each calls a curl
///   subprocess directly (or via `util::see_know`/`util::oathnet`'s
///   `CurlClient`) with no other transport, so the module returns nothing.
/// - `hse keys validate` / `hse keys import-tsv --validate`
///   (`util::key_pool::validation::validate_against_endpoint`) — a failed
///   `curl` spawn is swallowed into `false`, the SAME return value as a
///   genuinely dead key, so every key in the pool reports INVALID rather
///   than the command erroring — a materially worse failure mode than
///   "returns nothing", since it looks like the key pool died, not that a
///   tool is missing.
fn curl_missing_message() -> String {
    "  curl:      MISSING — search_engines + social_probe (default modules), plus\n             \
     see_know, oathnet_pro, api_key_probe and abn_lookup, shell out to curl and\n             \
     will silently return nothing. `hse keys validate` / `hse keys import-tsv\n             \
     --validate` also shell out to curl — without it they report every key as\n             \
     INVALID rather than erroring, which reads as a dead key pool, not a missing\n             \
     tool. Install it: pkg install curl"
        .to_string()
}

/// Rank every unset `KNOWN_KEYS` env var by acquisition ROI, highest first.
///
/// `key_roi` tiers a service by how far a key cascades into more collection:
/// a **Multiplier** (Shodan, Hunter, the breach pools, …) discovers
/// infrastructure / identities / credentials that feed back into MORE modules
/// and MORE keys; **Expansion** adds depth without chaining; **Terminal** is
/// one-and-done. So the operator who registers a multiplier-tier key first
/// unlocks the most downstream acquisition per signup. Ties within a tier sort
/// by name for stable, run-to-run-identical output.
///
/// Pure over an `is_present` predicate (true if the env var is already set) so
/// it is unit-testable without touching the filesystem or environment.
fn rank_unset_keys(
    is_present: impl Fn(&str) -> bool,
) -> Vec<(&'static str, crate::util::key_roi::KeyRoi)> {
    let env_to_service: std::collections::HashMap<&str, &str> =
        crate::util::service_defs::service_defs()
            .iter()
            .map(|d| (d.env_var, d.name))
            .collect();
    let mut missing: Vec<(&'static str, crate::util::key_roi::KeyRoi)> = keys::KNOWN_KEYS
        .iter()
        .copied()
        .filter(|k| !is_present(k))
        .map(|k| {
            // Map env var → service for tiering; an env var with no service_defs
            // entry classifies via its own string, which key_roi defaults to the
            // middle (Expansion) tier — never silently dropped from the ranking.
            let svc = env_to_service.get(k).copied().unwrap_or(k);
            (k, crate::util::key_roi::classify(svc))
        })
        .collect();
    // Highest ROI first (Terminal < Expansion < Multiplier), ties broken by name.
    missing.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    missing
}

/// Render the "Weak findings" doctor section body. `anomalies` is expected
/// already weakest-first ([`crate::storage::Store::low_confidence_evidence`]'s
/// own `ORDER BY confidence ASC`); this only formats, so it is unit-testable
/// without a store — mirroring [`scraper_health::aggregate_source_health`]'s
/// separation of query (impure) from presentation (pure).
fn format_weak_findings(anomalies: &[EvidenceAnomaly]) -> String {
    if anomalies.is_empty() {
        return "  no weak findings in the tracked window\n".to_string();
    }
    const SHOWN: usize = 20;
    let mut out = format!(
        "  {} weak finding(s) — review before trusting as evidence:\n",
        anomalies.len()
    );
    for a in anomalies.iter().take(SHOWN) {
        let observed = timefmt::ymd_utc(a.created_at).unwrap_or_else(|| "unknown date".to_string());
        // uid is a SHA-256 hex digest; the first 12 chars are enough to
        // cross-reference against `hse export`/`--output json` without
        // flooding the terminal with the full 64-char hash per row.
        let short_uid = &a.entity_uid[..a.entity_uid.len().min(12)];
        out.push_str(&format!(
            "    - conf={:.2}  {:<24} {}…  observed {}\n",
            a.confidence, a.module_name, short_uid, observed
        ));
    }
    if anomalies.len() > SHOWN {
        out.push_str(&format!("    … and {} more\n", anomalies.len() - SHOWN));
    }
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
