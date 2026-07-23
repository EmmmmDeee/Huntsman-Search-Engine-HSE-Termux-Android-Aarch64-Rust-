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
//! [`crate::util::cell_db::is_stale`]), a live WiGLE account introspection
//! that surfaces the email-unverified throttling warning before it starts
//! silently truncating result sets, and a live SeekNow account probe that
//! catches a dead/plan-lacking key before it silently zeroes out HSE's
//! highest-priority paid source (and its proactive API-key-harvesting
//! reach — see [`crate::util::key_harvest`]) on every scan.

use crate::core::error::Result;
use crate::{
    default_db_path, is_termux,
    modules::registry,
    storage::{EvidenceAnomaly, Store},
    util::{cell_db, keys, scraper_health, timefmt},
};

use super::cost_label;

pub(super) async fn cmd_doctor(live: bool) -> Result<()> {
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

    // Tracks a CRITICAL storage fault only — the database will not open, or its
    // integrity check reported corruption. Soft states (missing keys, a module
    // failure streak, a stale cell DB, a large WAL) are informational and never
    // set this. When set, `cmd_doctor` returns `Err` at the end so `hse
    // diagnostics` (which treats doctor as a fail-able section) and a scripted
    // standalone `hse doctor` both surface a broken DB via a non-zero exit
    // instead of a silent PASS — while still printing the full report first.
    let mut critical = false;

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
                    critical = true;
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
        Err(e) => {
            critical = true;
            println!("  FAIL — {e}");
        }
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

    // ── Module health (T2.7 / SOL-HEALTH-SIGNAL) ───────────────────────
    // Per-process failure streaks driven by real dispatch outcomes — quiet
    // by default (a freshly-started or fully healthy process reports
    // nothing extra), surfacing only sources actually worth investigating.
    let unhealthy = crate::core::engine::module_health_report();
    if unhealthy.is_empty() {
        println!("\nModule health: no modules currently show a failure streak");
    } else {
        println!(
            "\nModule health ({} with a failure streak this process):",
            unhealthy.len()
        );
        for h in &unhealthy {
            println!("  {}", format_module_health(h));
        }
    }

    // ── Persisted capability drift (offline, always shown) ─────────────
    // A confirmed-drift finding from a PAST live probe (`--live` here, or the
    // Web UI's "Run live capability probe" panel) is persisted to
    // `~/.huntsman/capability_drift.json` so it survives past that one
    // printout/response. Surfaced here, on every (even offline) `doctor` run,
    // so the operator doesn't have to remember to re-run `--live` to be
    // reminded a capability is known-dead. Ages out past 7 days (matches the
    // weekly CI drift-sweep cadence) — a stale finding may well be resolved by
    // now, so it is dropped rather than nagging forever.
    const DRIFT_TTL_SECS: u64 = 7 * 24 * 60 * 60;
    let persisted_drift = crate::util::capability_probe::recent_confirmed_drift(DRIFT_TTL_SECS);
    if !persisted_drift.is_empty() {
        println!(
            "\n⚠ Capability drift (from a previous live probe, last {} days):",
            DRIFT_TTL_SECS / 86_400
        );
        for (module, ts) in &persisted_drift {
            println!("  {module:<22} confirmed {}", timefmt::compact_utc(*ts));
        }
        println!("  run `hse doctor --live` to re-check whether these have recovered");
    }

    // ── Live capability preflight (opt-in, --live) ─────────────────────
    // The module-health section above is reactive — it only knows what real
    // scans in THIS process have already tried. `--live` is the proactive
    // complement: probe every keyless module against its real provider now, so
    // a drifted or dead capability shows up before an investigation relies on
    // it. Network-bound, so it is opt-in; the default `doctor` run stays offline.
    if live {
        print_live_capability_report().await;
    }

    let loaded = keys::load();
    let huntsman_keys = sorted_huntsman_keys(&loaded);
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

                // ── Key authentication (observed, not synthetically probed) ──
                // Fuse the loaded-key list with the auth-shaped drift errors
                // above: a source failing with a 401 / "invalid API key" while
                // its key IS configured means the CONFIGURED credential is being
                // rejected by the upstream — the single most actionable key
                // problem, and one otherwise reconstructed by hand across two
                // separate sections. Grounded in what real scans observed, so it
                // never mis-reports a working key the way a synthetic probe would.
                let rejected: Vec<_> = crate::util::key_health::auth_failing_sources(&health)
                    .into_iter()
                    .filter(|i| i.likely_env_var.is_some_and(|e| loaded.contains_key(e)))
                    .collect();
                if rejected.is_empty() {
                    println!("  no configured key is being rejected by its upstream");
                } else {
                    println!(
                        "  {} CONFIGURED KEY(S) REJECTED by the upstream — replace or renew:",
                        rejected.len()
                    );
                    for i in &rejected {
                        // The upstream's own words, char-safely capped so a long
                        // JSON body can't flood the terminal.
                        let detail: String = i.detail.chars().take(160).collect();
                        match i.likely_env_var {
                            Some(env) => println!("    - {:<20} {env}\n      {detail}", i.module),
                            None => println!("    - {:<20}\n      {detail}", i.module),
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

    // ── SeekNow account health (network call, best-effort) ──────────────
    // Probes /credits — a free meta-query, no scan budget spent — so a dead
    // or plan-lacking key is caught HERE, before an operator discovers it
    // only via SeekNow (HSE's highest-priority paid source, and its
    // proactive API-key-harvesting engine — see `util::key_harvest`)
    // silently returning nothing on every scan. `query_credits` now also
    // latches `is_key_invalid()` on an auth rejection — previously only the
    // data-bearing `search`/`get_path` calls did that classification, so a
    // fresh process (like this one) that only ever calls `query_credits`
    // could never detect a dead key at all.
    println!("\nSeekNow account:");
    // Print the host the probe will hit FIRST, so a resolution failure below is
    // immediately actionable ("could not resolve see-know.eu" → check the domain
    // + resolver), and an operator override is visible.
    println!("  api base: {}", crate::util::see_know::base_url());
    let seeknow_key = crate::util::see_know::resolve_key(
        loaded
            .get(crate::util::see_know::KEY_ENV)
            .map(String::as_str),
    );
    use crate::util::see_know::CreditsProbe;
    match crate::util::see_know::credits_probe(seeknow_key).await {
        CreditsProbe::Ok {
            remaining,
            daily_limit: Some(limit),
        } => println!("  credits remaining: {remaining}/{limit}"),
        CreditsProbe::Ok {
            remaining,
            daily_limit: None,
        } => println!("  credits remaining: {remaining} (daily limit not reported by this plan)"),
        CreditsProbe::InvalidKey => println!(
            "  INVALID — the configured key was rejected. Set a valid, plan-enabled key \
             via HUNTSMAN_SEEKNOW_KEY or the UI Settings panel."
        ),
        // The observed live failure: `curl exited 6` (could not resolve host).
        // Report it as a transport/DNS problem — NOT a key problem — with curl's
        // own detail and the concrete next steps, so an on-device operator can
        // fix it without guessing.
        //
        // This probe already self-heals a filtered/broken system resolver: it
        // routes through the shared `CurlClient`, which on exit 6 automatically
        // retries once via DoH (Cloudflare by default, `HUNTSMAN_DOH_URL`
        // to override) before ever reaching this branch — see `util::curl_client`.
        // Seeing this message therefore means BOTH the system resolver and that
        // automatic HTTPS fallback failed, so the guidance below only lists the
        // escalation paths beyond what already ran automatically.
        CreditsProbe::Unreachable(detail) => println!(
            "  UNREACHABLE — could not connect to the SeekNow API host: {detail}\n    \
             This is a network/DNS failure, not a key problem. An automatic DNS-over-HTTPS \
             retry already ran and also failed (see 'after DoH resolver fallback' above if \
             present), so the resolver-level self-heal is exhausted. Next steps: point \
             HUNTSMAN_DOH_URL at a different DoH endpoint (or 'off' to disable it), set \
             Android's system-wide Private DNS (Settings > Network > Private DNS) to a \
             resolver your carrier doesn't filter, or point HUNTSMAN_SEEKNOW_BASE at a \
             reachable https base for the same API."
        ),
        CreditsProbe::Unparseable => println!(
            "  reachable, but the response carried no recognised credits field — the key \
             may lack a paid plan, or the API schema changed."
        ),
    }

    if critical {
        return Err(crate::core::error::Error::Other(
            "critical storage fault — the database could not be opened or failed its \
             integrity check (see the FAIL line(s) above)"
                .into(),
        ));
    }
    Ok(())
}

/// The loaded `HUNTSMAN_*` key names, sorted for stable, run-to-run-identical
/// output — `loaded` is a `HashMap`, so an unsorted iteration would print a
/// different order on every invocation against the identical environment
/// (`docs/CONVENTIONS.md` §5: "no HashMap-iteration-order leaks into output"),
/// exactly the class of bug `rank_unset_keys` just below already guards
/// against for the unset-keys listing.
///
/// Pure over the loaded map so it is unit-testable without touching the real
/// environment.
fn sorted_huntsman_keys(loaded: &std::collections::HashMap<String, String>) -> Vec<&str> {
    let mut keys: Vec<&str> = loaded
        .keys()
        .filter(|k| k.starts_with("HUNTSMAN_"))
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

/// Render one module's health line for the `hse doctor` report.
///
/// Pure over a [`crate::core::engine::ModuleHealth`] snapshot so it is
/// unit-testable without touching real dispatch state.
fn format_module_health(h: &crate::core::engine::ModuleHealth) -> String {
    match h.last_success_at {
        Some(t) => format!(
            "{:<20} {} consecutive failure{} (last succeeded {})",
            h.name,
            h.consecutive_failures,
            if h.consecutive_failures == 1 { "" } else { "s" },
            crate::util::timefmt::compact_utc(t),
        ),
        None => format!(
            "{:<20} {} consecutive failure{} (never succeeded this process)",
            h.name,
            h.consecutive_failures,
            if h.consecutive_failures == 1 { "" } else { "s" },
        ),
    }
}

/// Run the live capability preflight and print a per-module alive/empty/
/// unreachable table plus a one-line summary. Shares the exact probe
/// implementation the weekly `live_drift` sweep uses
/// ([`crate::util::capability_probe`]), so what the operator sees on-device and
/// what CI asserts can never diverge. Confirmed drift (a curated canary that
/// reached its provider yet parsed nothing) is called out explicitly.
async fn print_live_capability_report() {
    use crate::util::capability_probe::{self, ProbeOutcome};

    println!("\nLive capability probe (keyless modules):");
    // Bounded concurrency — a full-fleet sweep without a socket storm on a phone.
    let reports = capability_probe::probe_keyless_fleet(8).await;
    if reports.is_empty() {
        println!("  (no keyless modules with a probeable target)");
        return;
    }

    let (mut alive, mut empty, mut unreachable, mut timed_out) = (0usize, 0usize, 0usize, 0usize);
    let mut drift: Vec<&str> = Vec::new();
    for r in &reports {
        let canary = if capability_probe::is_canary(r.module) {
            " [canary]"
        } else {
            ""
        };
        match &r.outcome {
            ProbeOutcome::Alive { found } => {
                alive += 1;
                println!("  alive        {:<22} {found} found{canary}", r.module);
            }
            ProbeOutcome::Empty => {
                empty += 1;
                let tag = if r.is_confirmed_drift() {
                    " — DRIFT (canary parsed nothing)"
                } else {
                    ""
                };
                println!(
                    "  empty        {:<22} ({} {}){canary}{tag}",
                    r.module,
                    r.kind.canonical_str(),
                    r.value
                );
                if r.is_confirmed_drift() {
                    drift.push(r.module);
                }
            }
            ProbeOutcome::Unreachable { reason } => {
                unreachable += 1;
                println!("  unreachable  {:<22} {reason}{canary}", r.module);
            }
            ProbeOutcome::TimedOut => {
                timed_out += 1;
                println!("  timed-out    {:<22}{canary}", r.module);
            }
        }
    }
    println!(
        "  summary: {} probed — {alive} alive, {empty} empty, {unreachable} unreachable, \
         {timed_out} timed-out",
        reports.len()
    );
    if !drift.is_empty() {
        println!(
            "  ⚠ confirmed drift in {}: {} — the upstream wire shape likely changed",
            drift.len(),
            drift.join(", ")
        );
    }
    // Persist so this finding survives past this one printout — the next
    // (offline, free) `hse doctor` run can surface it without a live re-probe.
    capability_probe::record_confirmed_drift(&reports);
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
// The unset-key acquisition ranking is the single source of truth in
// `util::key_roi` (shared with the web Settings page's acquisition guidance).
use crate::util::key_roi::rank_unset_keys;

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
