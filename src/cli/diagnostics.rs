//! `hse diagnostics` — one command that runs every diagnostic.
//!
//! Combines the standalone health checks into a single pass so an operator
//! verifies the whole install with one invocation:
//!   1. `doctor`   — environment (DB, key file, Termux, module/cost counts);
//!   2. `selftest` — module registry + dispatch graph + core math + storage;
//!   3. `engines`  — live search-engine liveness sweep;
//!   4. runtime surfaces — the on-device state a scan/serve depends on but which
//!      the three checks above don't cover end-to-end as a standalone signal:
//!      the scan DB's integrity + WAL high-water mark, the OpenCelliD cell
//!      database, the egress proxy pool, and the completion-webhook config.
//!
//! Each section runs in turn under a banner; the command exits non-zero if any
//! underlying check fails, so it is CI/automation-friendly. The individual
//! commands remain available (and are what the Web UI / API call), this is the
//! convenience aggregate.
//!
//! Under `--json` the command emits a single top-level
//! `{"ok": bool, "sections": {<name>: "ok"|"fail"}, "failed": [..]}` object on
//! stdout — the one structured pass/fail document CI can consume to gate a fresh
//! install, rather than scraping per-section human output (the per-command
//! `--json` forms print their own, section-specific payloads and `selftest`
//! exits the process, so they can't be composed into one summary).

use crate::core::error::{Error, Result};
use crate::modules::search_engines::health::{EngineStatus, probe_all};
use crate::{default_db_path, storage::Store};

/// One runtime-surface check's outcome: whether it passed and a one-line,
/// operator-facing detail rendered under the human banner. Shared by the JSON
/// and text paths so both report the identical verdict from one evaluation.
struct SectionResult {
    ok: bool,
    detail: String,
}

pub(super) async fn cmd_diagnostics(json: bool) -> Result<()> {
    if json {
        return diagnostics_json().await;
    }
    diagnostics_human().await
}

/// Human-readable aggregate: banners + delegation to each standalone command,
/// then the runtime-surface section. Exits non-zero (via the returned `Err`) if
/// any section fails so it stays a usable CI gate even without `--json`.
async fn diagnostics_human() -> Result<()> {
    let mut failed: Vec<&str> = Vec::new();

    banner("1/4", "Environment — doctor");
    if let Err(e) = super::doctor::cmd_doctor().await {
        eprintln!("  ✗ doctor failed: {e}");
        failed.push("doctor");
    }

    banner("2/4", "Module + core self-test");
    if let Err(e) = super::selftest::cmd_selftest(false).await {
        eprintln!("  ✗ selftest failed: {e}");
        failed.push("selftest");
    }

    banner("3/4", "Search-engine liveness");
    if let Err(e) = super::engines::cmd_engines(false).await {
        eprintln!("  ✗ engines failed: {e}");
        failed.push("engines");
    }

    banner("4/4", "Runtime surfaces — storage, cells, proxy, webhook");
    // Storage is a standalone signal here even though `doctor` also reports it:
    // a corrupt scan DB or a runaway WAL is a hard fail of the aggregate, not a
    // line buried in the doctor output, so it gets its own pass/fail tally.
    let storage = check_storage();
    print_section("storage", &storage);
    if !storage.ok {
        failed.push("storage");
    }

    let cells = check_cells();
    print_section("cells", &cells);
    // Cells is informational: an unpopulated OpenCelliD DB is the default and
    // only disables the optional `cell_local` module, so it never fails the run.

    let proxy = check_proxy();
    print_section("proxy", &proxy);
    // Proxy is informational: an empty pool means direct egress, the default.

    let webhook = check_webhook();
    print_section("webhook", &webhook);
    // A *malformed* webhook URL is a real misconfiguration (the POST would never
    // fire), so it fails; an unset webhook is the default and passes.
    if !webhook.ok {
        failed.push("webhook");
    }

    println!();
    if failed.is_empty() {
        println!(
            "==> diagnostics: ALL PASS (doctor, selftest, engines, storage, cells, proxy, webhook)"
        );
        Ok(())
    } else {
        Err(Error::Other(format!(
            "diagnostics: {} section(s) failed: {}",
            failed.len(),
            failed.join(", ")
        )))
    }
}

/// Machine-readable aggregate: one top-level `{ok, sections, failed}` JSON object
/// on stdout. Runs the same underlying checks as the human path but composes
/// their verdicts itself rather than calling the per-command `--json` forms
/// (which print their own payloads and, for `selftest`, exit the process).
async fn diagnostics_json() -> Result<()> {
    let mut sections: Vec<(&str, bool)> = Vec::new();

    // doctor: re-run the human doctor with its stdout intact would pollute the
    // JSON document, so the environment verdict is derived from the same storage
    // open the doctor performs — a DB that opens and passes integrity is the
    // environment signal CI cares about; the verbose key/tool inventory is
    // human-only by design.
    let storage = check_storage();
    sections.push(("doctor", storage.ok));

    // selftest: the library run is offline and side-effect-free; use its `ok`
    // directly instead of `cmd_selftest` (which prints + `process::exit`s).
    let report = crate::selftest::run().await;
    sections.push(("selftest", report.ok));

    // engines: the sweep never *fails* the aggregate (a blocked/down engine is
    // expected on a phone behind CGNAT); "ok" means the probe ran and at least
    // one enabled engine is reachable, mirroring the human command's non-fatal
    // treatment while still giving CI a single boolean.
    let health = probe_all().await;
    let engines_ok = health.is_empty() || health.iter().any(|h| h.status == EngineStatus::Up);
    sections.push(("engines", engines_ok));

    sections.push(("storage", storage.ok));
    let cells = check_cells();
    sections.push(("cells", cells.ok));
    let proxy = check_proxy();
    sections.push(("proxy", proxy.ok));
    let webhook = check_webhook();
    sections.push(("webhook", webhook.ok));

    // Only storage, selftest and webhook can flip the overall verdict — the same
    // sections that fail the human run. doctor mirrors storage; engines/cells/
    // proxy are informational and never gate the result.
    let gating: [&str; 3] = ["selftest", "storage", "webhook"];
    let failed: Vec<&str> = sections
        .iter()
        .filter(|(name, ok)| !ok && gating.contains(name))
        .map(|(name, _)| *name)
        .collect();
    let overall_ok = failed.is_empty();

    let section_map: serde_json::Map<String, serde_json::Value> = sections
        .iter()
        .map(|(name, ok)| {
            (
                (*name).to_string(),
                serde_json::Value::String(if *ok { "ok" } else { "fail" }.to_string()),
            )
        })
        .collect();

    let summary = serde_json::json!({
        "ok": overall_ok,
        "version": crate::VERSION,
        "sections": section_map,
        "failed": failed,
        "details": {
            "storage": storage.detail,
            "cells": cells.detail,
            "proxy": proxy.detail,
            "webhook": webhook.detail,
            "selftest": report.summary(),
        },
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".into())
    );

    if overall_ok {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "diagnostics: {} section(s) failed: {}",
            failed.len(),
            failed.join(", ")
        )))
    }
}

/// Open the scan DB and run an explicit integrity check plus a WAL high-water
/// report. A clean open + an all-`ok` `PRAGMA integrity_check` passes; a failed
/// open or any reported corruption fails. The WAL size is informational (a large
/// `-wal` is checkpointed at the next scan boundary) and never flips the verdict.
fn check_storage() -> SectionResult {
    let db_path = default_db_path();
    let store = match Store::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            return SectionResult {
                ok: false,
                detail: format!("database failed to open: {e}"),
            };
        }
    };

    // WAL high-water mark — reported regardless of integrity so a runaway
    // `-wal` is visible. Best-effort: a missing `-wal` (DB never written in WAL
    // mode yet) is simply omitted, not an error.
    let wal = std::fs::metadata(format!("{db_path}-wal"))
        .map(|m| format!("; WAL {} KiB", m.len() / 1024))
        .unwrap_or_default();

    match store.integrity_check() {
        Ok(rows) if rows.iter().all(|r| r == "ok") => SectionResult {
            ok: true,
            detail: format!("database opens cleanly, integrity ok{wal}"),
        },
        Ok(rows) => SectionResult {
            ok: false,
            detail: format!(
                "integrity check reported {} issue(s): {}{wal}",
                rows.len(),
                rows.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
            ),
        },
        Err(e) => SectionResult {
            ok: false,
            detail: format!("integrity check could not run: {e}{wal}"),
        },
    }
}

/// Summarise the local OpenCelliD cell-tower database: tower count and last
/// import age. An unpopulated DB is the default (the `cell_local` module simply
/// skips) so it is reported as `ok` with a "not populated" note rather than a
/// failure.
fn check_cells() -> SectionResult {
    use crate::util::cell_db;

    let conn = match cell_db::open_ro() {
        Ok(c) => c,
        Err(_) => {
            return SectionResult {
                ok: true,
                detail: "not populated — run `hse cells import --country AU` to enable cell_local"
                    .to_string(),
            };
        }
    };

    let total = match cell_db::total_count(&conn) {
        Ok(n) => n,
        Err(e) => {
            return SectionResult {
                ok: false,
                detail: format!("cell DB present but unreadable: {e}"),
            };
        }
    };

    let last = match cell_db::last_import(&conn) {
        Ok(rec) => rec,
        Err(e) => {
            return SectionResult {
                ok: false,
                detail: format!("{total} towers; import history unreadable: {e}"),
            };
        }
    };

    let detail = match last {
        Some(rec) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64;
            let age = format_age((now.saturating_sub(rec.imported_at)).max(0) as u64);
            format!("{total} towers; last import {} ({age})", rec.source_file)
        }
        None => format!("{total} towers; no import history"),
    };
    SectionResult { ok: true, detail }
}

/// Report the configured egress proxy pool size from `HUNTSMAN_SEARCH_PROXY` /
/// `HUNTSMAN_PROXY` (the comma-separated lists `util::curl` rotates through). An
/// empty pool means direct egress — the default — so it is `ok` with a note;
/// a malformed entry (no extractable host) is surfaced but still non-fatal,
/// since the rotator drops it and falls back to a direct connection.
fn check_proxy() -> SectionResult {
    use crate::util::netrotate::{parse_proxy_list, proxy_host};

    let mut total = 0usize;
    let mut malformed = 0usize;
    for var in ["HUNTSMAN_SEARCH_PROXY", "HUNTSMAN_PROXY"] {
        if let Ok(raw) = std::env::var(var) {
            for spec in parse_proxy_list(&raw) {
                total += 1;
                if proxy_host(&spec).is_none() {
                    malformed += 1;
                }
            }
        }
    }

    if total == 0 {
        return SectionResult {
            ok: true,
            detail: "no proxy configured — direct egress (default)".to_string(),
        };
    }
    let detail = if malformed == 0 {
        format!("{total} proxy entr{} configured", plural_y(total))
    } else {
        format!(
            "{total} proxy entr{} configured, {malformed} with no parseable host (rotator skips these)",
            plural_y(total)
        )
    };
    SectionResult { ok: true, detail }
}

/// Sanity-check the completion-webhook config (`HUNTSMAN_WEBHOOK_URL`). Unset is
/// the default and passes. A set URL must be a syntactically valid http/https
/// URL with a host — a malformed value fails, since the POST would silently
/// never fire. The URL itself is never echoed (it may carry a secret in its
/// path, like a Slack/Discord webhook); only its host is shown.
fn check_webhook() -> SectionResult {
    webhook_verdict(crate::core::webhook::webhook_url_from_env().as_deref())
}

/// Pure verdict for [`check_webhook`] over an explicit configured value (`None`
/// ⇒ unset). Split out so the scheme/host validation is unit-testable without
/// mutating the process environment — `#![forbid(unsafe_code)]` rules out the
/// `set_var`/`remove_var` dance a `check_webhook`-level test would need.
fn webhook_verdict(url: Option<&str>) -> SectionResult {
    let Some(url) = url else {
        return SectionResult {
            ok: true,
            detail: "no webhook configured (default)".to_string(),
        };
    };

    match url::Url::parse(url) {
        // Host only — the path can carry the webhook secret, so it is never
        // rendered. The guard requires a NON-EMPTY host: `url` parses
        // `https:///x` to a `Some("")` host (no authority), which would never
        // resolve, so it must fail the same as a missing scheme.
        Ok(parsed)
            if matches!(parsed.scheme(), "http" | "https")
                && parsed.host_str().is_some_and(|h| !h.is_empty()) =>
        {
            let host = parsed.host_str().unwrap_or("<host>");
            SectionResult {
                ok: true,
                detail: format!("configured ({} → {host})", parsed.scheme()),
            }
        }
        Ok(parsed) => SectionResult {
            ok: false,
            detail: format!(
                "HUNTSMAN_WEBHOOK_URL has unsupported scheme '{}' or no host — must be http(s)://host/…",
                parsed.scheme()
            ),
        },
        Err(e) => SectionResult {
            ok: false,
            detail: format!("HUNTSMAN_WEBHOOK_URL is not a valid URL: {e}"),
        },
    }
}

/// `"y"` for a singular count, `"ies"` for plural — so "1 proxy entry" /
/// "3 proxy entries" both read correctly without a separate format branch.
fn plural_y(n: usize) -> &'static str {
    if n == 1 { "y" } else { "ies" }
}

/// Compact human age (`12s`/`5m`/`3h`/`9d` ago) for the cells last-import line.
/// Mirrors `cli::cells::format_age` so the two surfaces read identically.
fn format_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// Render one runtime-surface section's verdict under the human banner.
fn print_section(name: &str, r: &SectionResult) {
    let mark = if r.ok { '●' } else { '✗' };
    println!("  {mark} {name:<8} {}", r.detail);
}

fn banner(step: &str, title: &str) {
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  [{step}] {title}");
    println!("══════════════════════════════════════════════════════════════\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plural_y_singular_vs_plural() {
        assert_eq!(plural_y(1), "y");
        assert_eq!(plural_y(0), "ies");
        assert_eq!(plural_y(2), "ies");
    }

    #[test]
    fn format_age_buckets() {
        assert_eq!(format_age(5), "5s ago");
        assert_eq!(format_age(120), "2m ago");
        assert_eq!(format_age(7200), "2h ago");
        assert_eq!(format_age(172_800), "2d ago");
    }

    #[test]
    fn webhook_unset_passes() {
        // Pure verdict over an explicit `None`, so the test never touches the
        // process environment (`#![forbid(unsafe_code)]` bars `set_var`).
        let r = webhook_verdict(None);
        assert!(r.ok, "unset webhook must pass: {}", r.detail);
        assert!(r.detail.contains("no webhook"));
    }

    #[test]
    fn webhook_malformed_fails() {
        assert!(
            !webhook_verdict(Some("ftp://example.com/x")).ok,
            "non-http scheme must fail"
        );
        assert!(
            !webhook_verdict(Some("not a url")).ok,
            "garbage URL must fail"
        );
        assert!(
            !webhook_verdict(Some("https://")).ok,
            "empty host must fail"
        );
    }

    #[test]
    fn webhook_valid_passes_and_redacts_secret() {
        // A valid webhook carrying a secret in its PATH must report host only —
        // the path must never leak into diagnostics output.
        let r = webhook_verdict(Some("https://hooks.example.com/services/SECRET/TOKEN"));
        assert!(r.ok, "valid https webhook must pass: {}", r.detail);
        assert!(
            !r.detail.contains("SECRET") && !r.detail.contains("TOKEN"),
            "webhook secret must not leak into diagnostics output: {}",
            r.detail
        );
        assert!(r.detail.contains("hooks.example.com"));
    }
}
