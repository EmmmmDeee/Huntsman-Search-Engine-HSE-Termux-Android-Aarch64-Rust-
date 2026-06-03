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
                    println!("  integrity:  ok")
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
        .map(|s| s.success())
        .unwrap_or(false);
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

    // ── Unset keys + where to get them (mostly free) ──────────────────
    // The "failing modules" in a scan are usually just these — unconfigured
    // optional providers, which now skip cleanly rather than erroring. List
    // each missing key with its free-signup hint so enabling one is a copy-paste.
    let missing: Vec<&&str> = keys::KNOWN_KEYS
        .iter()
        .filter(|k| !loaded.contains_key(**k))
        .collect();
    if !missing.is_empty() {
        println!(
            "\nUnset keys ({}): modules needing these skip cleanly (not errors).",
            missing.len()
        );
        for k in missing {
            match keys::signup_hint(k) {
                Some(hint) => println!("  - {k}\n      → {hint}"),
                None => println!("  - {k}"),
            }
        }
    }

    // ── WiGLE account health (network call, best-effort) ──────────────
    // Poll /api/v2/profile/user + /apiUsage. Surfaces the
    // "email unverified → throttled" warning that the WiGLE account
    // page calls out but which our queries don't otherwise expose
    // until they start silently returning fewer results.
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
    if let Some(daily) = status.daily_api_calls {
        println!("  daily calls:    {daily}");
    }
    if let Some(monthly) = status.monthly_api_calls {
        println!("  monthly calls:  {monthly}");
    }

    Ok(())
}
