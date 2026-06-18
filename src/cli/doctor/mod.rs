//! `hse doctor` — health-check subcommand.
//!
//! Reports Termux detection, DB path, key path, module/cost counts,
//! HUNTSMAN_* keys loaded, and a live WiGLE account introspection
//! that surfaces the email-unverified throttling warning before it
//! starts silently truncating result sets.

use crate::core::error::Result;
use crate::{default_db_path, is_termux, modules::registry, storage::Store, util::keys};

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
    match Store::open(&db_path) {
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
        println!(
            "  curl:      MISSING — search_engines + social_probe (default modules), plus\n             \
             see_know, oathnet_pro, api_key_probe and abn_lookup, shell out to curl and\n             \
             will silently return nothing. Install it: pkg install curl"
        );
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

    // ── Module health (T2.7 / SOL-HEALTH-SIGNAL) ─────────────────────
    // Query the per-module health ledger. Modules with ≥3 consecutive failures
    // are flagged degraded — they may have lost connectivity, had their API key
    // revoked, or drifted from their provider's schema. Populated once modules
    // have actually run (empty database or fresh install shows "no history").
    println!("\nModule health:");
    match Store::open(&db_path) {
        Ok(store) => match store.module_health_summary() {
            Ok(rows) if rows.is_empty() => {
                println!("  no module run history (run a scan first)");
            }
            Ok(rows) => {
                let degraded: Vec<_> = rows
                    .iter()
                    .filter(|r| r.consecutive_failures >= 3)
                    .collect();
                let total_runs: u64 = rows.iter().map(|r| r.total_runs).sum();
                let total_ok: u64 = rows.iter().map(|r| r.total_successes).sum();
                let pct = if total_runs > 0 {
                    total_ok * 100 / total_runs
                } else {
                    100
                };
                println!(
                    "  {total_ok}/{total_runs} runs succeeded ({pct}%) across {} module(s)",
                    rows.len()
                );
                if degraded.is_empty() {
                    println!("  no degraded modules (none with ≥3 consecutive failures)");
                } else {
                    println!(
                        "  {} DEGRADED module(s) (≥3 consecutive failures):",
                        degraded.len()
                    );
                    for r in &degraded {
                        let since = r.last_success_at.map_or_else(
                            || "never succeeded".to_string(),
                            |t| format!("last ok {}", age_str(t)),
                        );
                        let err = r.last_error.as_deref().unwrap_or("unknown");
                        println!(
                            "  [DEGRADED] {} — {} consecutive failures, {since}",
                            r.module_name, r.consecutive_failures
                        );
                        println!("             last error: {err}");
                    }
                }
            }
            Err(e) => println!("  could not query: {e}"),
        },
        Err(e) => println!("  FAIL — {e}"),
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

/// Format a unix timestamp as a human-readable age relative to now
/// ("just now", "5 min ago", "2 h ago", "3 d ago").
fn age_str(ts: u64) -> String {
    let now = crate::core::entity::unix_now();
    let secs = now.saturating_sub(ts);
    if secs < 120 {
        "just now".to_string()
    } else if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else if secs < 86_400 {
        format!("{} h ago", secs / 3600)
    } else {
        format!("{} d ago", secs / 86_400)
    }
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

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
