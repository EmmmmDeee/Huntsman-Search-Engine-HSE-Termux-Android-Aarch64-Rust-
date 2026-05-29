//! `hse doctor` — health-check subcommand.
//!
//! Plain mode reports Termux detection, DB path, key path, module/cost counts,
//! HUNTSMAN_* keys loaded, and a live WiGLE account introspection.
//!
//! `--bundle` emits a full, **redacted, offline** diagnostic report (env,
//! versions, sensor-tool availability, log tails, recent failed scans) to
//! stdout and `$HOME/.huntsman/hse-debug-report.txt` — the artefact to paste
//! to Claude Code when an install or scan misbehaves. The bundle makes no
//! network calls and spawns no subprocess: it is 100% in-process introspection
//! plus local file reads, so it's deterministic and safe to share.

use std::fmt::Write as _;

use crate::core::error::Result;
use crate::{default_db_path, is_termux, modules::registry, storage::Store, util::keys};

use super::cost_label;

pub(super) async fn cmd_doctor(bundle: bool) -> Result<()> {
    let mods = registry();
    let mut out = String::new();

    let _ = writeln!(
        out,
        "HSE v{} — doctor{}\n",
        crate::VERSION,
        if bundle { " (diagnostic bundle)" } else { "" }
    );
    let _ = writeln!(
        out,
        "Termux:    {}",
        if is_termux() {
            "detected"
        } else {
            "not detected"
        }
    );
    let _ = writeln!(out, "DB path:   {}", default_db_path());
    let _ = writeln!(out, "Keys path: {}", keys::env_path());

    let _ = writeln!(out, "\nStorage:");
    let store = Store::open(&default_db_path());
    match &store {
        Ok(_) => {
            let _ = writeln!(out, "  ok — database opens cleanly");
        }
        Err(e) => {
            let _ = writeln!(out, "  FAIL — {e}");
        }
    }

    let _ = writeln!(out, "\nModules ({} registered):", mods.len());
    let mut by_cost = std::collections::BTreeMap::<&str, usize>::new();
    for m in &mods {
        *by_cost.entry(cost_label(m.cost())).or_default() += 1;
    }
    for (cost, count) in &by_cost {
        let _ = writeln!(out, "  {cost:<10} {count}");
    }

    let loaded = keys::load();
    let huntsman_keys: Vec<_> = loaded
        .keys()
        .filter(|k| k.starts_with("HUNTSMAN_"))
        .collect();
    // NAMES only — values are never printed (secret-safe).
    let _ = writeln!(out, "\nHUNTSMAN_* keys loaded: {}", huntsman_keys.len());
    for k in &huntsman_keys {
        let _ = writeln!(out, "  - {k}");
    }
    if huntsman_keys.is_empty() {
        let _ = writeln!(out, "  (none set; all free modules still work)");
    }

    if bundle {
        append_bundle_sections(&mut out, store.as_ref().ok());
        print!("{out}");
        write_report(&out);
    } else {
        print!("{out}");
        append_wigle_status(&loaded).await;
    }

    Ok(())
}

/// Offline diagnostic sections for `--bundle`. No network, no subprocess —
/// in-process introspection + local file reads only. Everything is redacted.
fn append_bundle_sections(out: &mut String, store: Option<&Store>) {
    let _ = writeln!(out, "\n── environment ──");
    let _ = writeln!(
        out,
        "  os/arch:   {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _ = writeln!(out, "  HOME:      {}", env_or("HOME"));
    let _ = writeln!(out, "  PREFIX:    {}", env_or("PREFIX"));
    let _ = writeln!(out, "  SHELL:     {}", env_or("SHELL"));
    let _ = writeln!(out, "  TERMUX:    {}", env_or("TERMUX_VERSION"));
    let _ = writeln!(out, "  PATH:      {}", env_or("PATH"));
    let _ = writeln!(out, "  RUST_LOG:  {}", env_or("RUST_LOG"));

    // Termux:API sensor tools — which resolve on PATH (no exec, just lookup).
    let _ = writeln!(out, "\n── sensor tools (Termux:API) ──");
    for bin in [
        "termux-info",
        "termux-location",
        "termux-wifi-scaninfo",
        "termux-wifi-connectioninfo",
        "termux-telephony-cellinfo",
    ] {
        let _ = writeln!(
            out,
            "  {:<28} {}",
            bin,
            if which(bin) {
                "available"
            } else {
                "MISSING (module no-ops)"
            }
        );
    }

    // Image pipeline self-test — proves the pure-Rust decoder + perceptual
    // hash actually run on this device (the main aarch64 risk from the `image`
    // dependency). Offline encode→decode→hash round-trip; no network.
    let _ = writeln!(out, "\n── image pipeline (perceptual hash) ──");
    match crate::util::phash::self_test() {
        Ok(detail) => {
            let _ = writeln!(
                out,
                "  ok — codec + DCT pHash working (self-test detail={detail:.1})"
            );
        }
        Err(e) => {
            let _ = writeln!(out, "  FAIL — {e}");
        }
    }

    // Recent scans (surfaces failures + their errors) from the store.
    let _ = writeln!(out, "\n── recent scans ──");
    match store.map(|s| s.list_scans(10)) {
        Some(Ok(scans)) if !scans.is_empty() => {
            for s in &scans {
                let id = s.id.get(..8).unwrap_or(&s.id);
                let _ = writeln!(
                    out,
                    "  {id}  {:<9} {:>4} entities {}{}",
                    s.status.as_str(),
                    s.entity_count,
                    s.target.kind.canonical_str(),
                    s.error
                        .as_deref()
                        .map(|e| format!("  ERROR: {}", crate::util::logging::redact(e)))
                        .unwrap_or_default()
                );
            }
        }
        Some(Ok(_)) => {
            let _ = writeln!(out, "  (no scans yet)");
        }
        _ => {
            let _ = writeln!(out, "  (store unavailable)");
        }
    }

    // Log tails (already redacted by logging::tail).
    let _ = writeln!(
        out,
        "\n── runtime log tail ({}) ──",
        crate::util::logging::log_file_path().display()
    );
    let rt = crate::util::logging::tail(16 * 1024);
    let _ = writeln!(
        out,
        "{}",
        if rt.is_empty() {
            "  (no runtime log yet — run a command first)".into()
        } else {
            indent(&rt)
        }
    );

    let _ = writeln!(out, "\n── install log tail ──");
    let install = install_log_tail(16 * 1024);
    let _ = writeln!(
        out,
        "{}",
        if install.is_empty() {
            "  (no install log found)".into()
        } else {
            indent(&install)
        }
    );

    let _ = writeln!(
        out,
        "\n── end of bundle — paste the above to Claude Code ──"
    );
}

/// Live WiGLE account introspection (network, best-effort) — plain mode only.
async fn append_wigle_status(loaded: &std::collections::HashMap<String, String>) {
    println!("\nWiGLE account:");
    let wigle_user = loaded
        .get("HUNTSMAN_WIGLE_USER")
        .map_or("AID4493a33e2df9d07ab9666a27c8aead17", String::as_str)
        .to_string();
    let wigle_token = loaded
        .get("HUNTSMAN_WIGLE_TOKEN")
        .map_or("1aedb7ad0171ff3d6be5a844cca5d977", String::as_str)
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
}

fn env_or(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| "(unset)".into())
}

/// `which`-style PATH lookup — no subprocess, just filesystem existence.
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|d| d.join(bin).exists()))
}

fn install_log_tail(max_bytes: usize) -> String {
    let path = std::env::var("HOME")
        .map(|h| {
            std::path::PathBuf::from(h)
                .join(".cache")
                .join("hse-install.log")
        })
        .unwrap_or_default();
    let Ok(data) = std::fs::read(&path) else {
        return String::new();
    };
    let start = data.len().saturating_sub(max_bytes);
    crate::util::logging::redact(&String::from_utf8_lossy(&data[start..])).into_owned()
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_report(content: &str) {
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let dir = std::path::PathBuf::from(&home).join(".huntsman");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("hse-debug-report.txt");
    match std::fs::write(&path, content) {
        Ok(()) => println!("\n(report written to {})", path.display()),
        Err(e) => eprintln!("(could not write report file: {e})"),
    }
}
