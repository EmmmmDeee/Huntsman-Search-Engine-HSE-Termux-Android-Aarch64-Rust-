//! Ports `src/web/js/views/scans.js`'s pure, DOM-free rendering helpers:
//! `budgetBar`/`apiBudgetsPanel` (the dashboard's "API Budgets" panel) and
//! `renderScansTable` (the per-row scan-list table, reused by both
//! `scans.js`'s own `#/scans` page and `dash.js`'s "Recent Scans" panel).
//! `renderScans` itself (the `#/scans` page's own live filter-input wiring)
//! and `scanStats` (a plain tally with no HTML output at all — nothing here
//! for a WASM port to buy) stay in JS, like every other view's interactive
//! shell.
//!
//! `Budget`/`ScanTarget`/`ScanRow` are view-local response structs, not
//! `hse_core` domain types: the real `crate::util::budget::BudgetSnapshot`
//! and `crate::core::scan::{Scan, Target, TargetKind}` live in the main `hse`
//! binary crate, which this crate deliberately does not depend on (see this
//! crate's own `Cargo.toml`).

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, fmt_date, kind_pill};
use crate::to_js_error;

/// One provider's session quota snapshot — `src/api/handlers/mod.rs`'s
/// `budget_block()` wire shape. `scan_used`/`scan_cap` are part of the same
/// payload but unused by `budgetBar`.
#[derive(Deserialize)]
struct Budget {
    session_used: u32,
    session_cap: u32,
    quota_exhausted: bool,
}

/// `scans.js`'s `budgetBar(b)`: a thin usage bar, or "n/a" for a provider
/// slot with no snapshot at all — only reachable when the whole
/// `/api/v1/stats` fetch failed client-side (every provider is always
/// populated on a successful response; see `budget_block`).
fn budget_bar(b: Option<&Budget>) -> String {
    let Some(b) = b else {
        return "<span class=\"text-muted\">n/a</span>".to_string();
    };
    let used = b.session_used;
    let cap = b.session_cap;
    // `Math.round`, not truncating division: e.g. used=2/cap=3 must render
    // 67%, not floor(200/3)=66.
    let pct = if cap > 0 {
        (f64::from(used) * 100.0 / f64::from(cap))
            .round()
            .min(100.0)
    } else {
        0.0
    };
    let color = if b.quota_exhausted {
        "#a94442"
    } else if pct >= 80.0 {
        "#8a6d3b"
    } else {
        "#3c763d"
    };
    let label = if cap > 0 {
        format!("{used} / {cap}")
    } else {
        format!("{used}")
    };
    let full = if b.quota_exhausted {
        " <b style=\"color:var(--danger)\">FULL</b>"
    } else {
        ""
    };
    format!(
        "<div style=\"display:flex;align-items:center;gap:6px\">\n    \
         <div style=\"flex:1;background:var(--bg-elevated-2);border-radius:3px;height:8px;overflow:hidden\">\n      \
         <div style=\"width:{pct}%;height:100%;background:{color}\"></div></div>\n    \
         <span class=\"text-muted\" style=\"font-size:11px;min-width:64px;text-align:right\">{}{full}</span>\n  \
         </div>",
        escape_html(&label),
    )
}

/// `/api/v1/stats`'s `wigle.account` object.
#[derive(Deserialize)]
struct WigleAccount {
    verified: Option<bool>,
}

/// `/api/v1/stats`'s `wigle` object: four sub-budgets plus account status.
#[derive(Deserialize)]
struct Wigle {
    geo: Option<Budget>,
    bssid: Option<Budget>,
    cell: Option<Budget>,
    bluetooth: Option<Budget>,
    account: Option<WigleAccount>,
}

/// `/api/v1/stats`'s wire shape: only the three budget-related fields
/// `apiBudgetsPanel` reads (the endpoint also carries scan/module counts
/// used by other, not-yet-ported parts of the dashboard).
#[derive(Deserialize)]
struct StatsForBudgets {
    seeknow: Option<Budget>,
    oathnet: Option<Budget>,
    wigle: Option<Wigle>,
}

/// `apiBudgetsPanel`'s `verBadge`: `Some(false)` is the silent-failure case
/// (WiGLE database queries fail until the account email is verified),
/// `None` means "not yet polled this process" — distinct from the confirmed
/// `Some(true)` case.
fn verified_badge(verified: Option<bool>) -> &'static str {
    match verified {
        Some(false) => {
            "<span class=\"label label-danger\" title=\"Email-verification not confirmed \u{2014} WiGLE database queries will fail until the account email is verified at wigle.net\">account UNVERIFIED</span>"
        }
        Some(true) => "<span class=\"label label-success\">account verified</span>",
        None => {
            "<span class=\"label label-default\" title=\"Not yet polled this session\">account status unknown</span>"
        }
    }
}

/// Ports `scans.js`'s `apiBudgetsPanel(s)`: the dashboard's "API Budgets"
/// panel (SeekNow / OathNet / WiGLE's four sub-budgets + account status).
#[wasm_bindgen(js_name = renderApiBudgetsPanelHtml)]
pub fn render_api_budgets_panel_html(stats_js: JsValue) -> Result<String, JsValue> {
    let s: StatsForBudgets = serde_wasm_bindgen::from_value(stats_js).map_err(to_js_error)?;
    let verified = s
        .wigle
        .as_ref()
        .and_then(|w| w.account.as_ref())
        .and_then(|a| a.verified);
    let ver_badge = verified_badge(verified);
    let rows = [
        ("SeekNow", budget_bar(s.seeknow.as_ref())),
        ("OathNet", budget_bar(s.oathnet.as_ref())),
        (
            "WiGLE \u{b7} WiFi geo",
            budget_bar(s.wigle.as_ref().and_then(|w| w.geo.as_ref())),
        ),
        (
            "WiGLE \u{b7} BSSID",
            budget_bar(s.wigle.as_ref().and_then(|w| w.bssid.as_ref())),
        ),
        (
            "WiGLE \u{b7} cell",
            budget_bar(s.wigle.as_ref().and_then(|w| w.cell.as_ref())),
        ),
        (
            "WiGLE \u{b7} bluetooth",
            budget_bar(s.wigle.as_ref().and_then(|w| w.bluetooth.as_ref())),
        ),
    ];
    let rows_html: String = rows
        .iter()
        .map(|(k, v)| {
            format!("<tr><td style=\"width:160px;white-space:nowrap\">{k}</td><td>{v}</td></tr>")
        })
        .collect();
    Ok(format!(
        "<div class=\"panel panel-default\" style=\"margin-top:12px\">\n    \
         <div class=\"panel-heading\"><b>API Budgets</b>\n      \
         <span class=\"pull-right\" style=\"font-size:12px\">WiGLE {ver_badge}</span></div>\n    \
         <div class=\"panel-body\">\n      \
         <table class=\"table table-condensed\" style=\"margin-bottom:0\">\n        \
         {rows_html}\n      \
         </table>\n      \
         <p class=\"text-muted\" style=\"margin:8px 0 0;font-size:11px\">Session quota consumed so far. Paid GEOINT (WiGLE) is gated to fire only after the free geo layer corroborates a coordinate through recursion (\u{2265}2 sources), so the daily allowance is spent confirming the subject's real location, not chasing noise.</p>\n    \
         </div>\n  \
         </div>"
    ))
}

/// `/api/v1/scans`'s per-scan `target` object. `kind` has no data-carrying
/// variant server-side (`TargetKind` is `#[serde(rename_all =
/// "snake_case")]` over unit variants only) so — unlike `hse_core::EntityKind`
/// — it always arrives as a plain string, never a `{"other":...}` shape.
#[derive(Deserialize)]
struct ScanTarget {
    kind: Option<String>,
    value: Option<String>,
}

/// `/api/v1/scans`'s per-scan wire shape: only the fields `renderScansTable`
/// reads.
#[derive(Deserialize)]
struct ScanRow {
    id: String,
    target: Option<ScanTarget>,
    status: Option<String>,
    started_at: Option<u64>,
    finished_at: Option<u64>,
    entity_count: Option<u64>,
}

/// `helpers.js`'s `statusPill(s)`. The CSS class and the displayed text
/// default independently, exactly as the original's `m[s]||'s-pending'` /
/// `s||'pending'` do: an unrecognised non-empty status still shows its own
/// text (with the fallback class), while a missing/empty one shows the
/// literal text "pending" too.
fn status_pill(status: Option<&str>) -> String {
    let class = match status {
        Some("complete") => "s-complete",
        Some("running") => "s-running",
        Some("failed") => "s-failed",
        Some("pending") => "s-pending",
        Some("aborted") => "s-aborted",
        _ => "s-pending",
    };
    let text = match status {
        Some(s) if !s.is_empty() => s,
        _ => "pending",
    };
    format!(
        "<span class=\"status-pill {class}\">{}</span>",
        escape_html(text)
    )
}

/// `helpers.js`'s `fmtDuration(secs)`.
fn fmt_duration(secs: Option<i64>) -> String {
    let Some(secs) = secs.filter(|&s| s >= 0) else {
        return "\u{2014}".to_string();
    };
    if secs < 60 {
        return format!("{secs}s");
    }
    let m = secs / 60;
    let s = secs % 60;
    if m < 60 {
        return format!("{m}m {s}s");
    }
    let h = m / 60;
    let mm = m % 60;
    format!("{h}h {mm}m")
}

/// `renderScansTable`'s per-row `dur` computation: a finished scan's actual
/// elapsed time, a running scan's elapsed-so-far against the current clock,
/// or `None` for any other status with no `finished_at` yet.
fn row_duration(row: &ScanRow) -> Option<i64> {
    let started = row.started_at.filter(|&t| t != 0);
    let finished = row.finished_at.filter(|&t| t != 0);
    if let (Some(f), Some(st)) = (finished, started) {
        #[allow(clippy::cast_possible_wrap)]
        return Some(f as i64 - st as i64);
    }
    if row.status.as_deref() == Some("running") {
        let st = started.unwrap_or_else(hse_core::unix_now);
        #[allow(clippy::cast_possible_wrap)]
        return Some(hse_core::unix_now() as i64 - st as i64);
    }
    None
}

/// One `<tr>` of the scans table: `renderScansTable`'s row template. `id` is
/// always a lowercase-hex `hse_core::scan_id()`-generated string, so no
/// percent-encoding is needed to match the JS original's
/// `encodeURIComponent(id)` on the CSV/log download links — hex characters
/// are all URL-unreserved and pass through either way unchanged.
fn scan_row_html(row: &ScanRow) -> String {
    let kind = row
        .target
        .as_ref()
        .and_then(|t| t.kind.as_deref())
        .filter(|k| !k.is_empty())
        .unwrap_or("\u{2014}");
    let value = row
        .target
        .as_ref()
        .and_then(|t| t.value.as_deref())
        .filter(|v| !v.is_empty())
        .unwrap_or(&row.id);
    let id = escape_html(&row.id);
    let dur_secs = row_duration(row);
    let is_active = matches!(row.status.as_deref(), Some("running" | "pending"));
    let action_btn = if is_active {
        format!(
            "<button class=\"btn btn-warning btn-xs\" data-cancel=\"{id}\" title=\"Stop scan\"><i class=\"glyphicon glyphicon-stop\"></i></button>"
        )
    } else {
        format!(
            "<button class=\"btn btn-default btn-xs\" data-rerun=\"{id}\" title=\"Rescan\"><i class=\"glyphicon glyphicon-repeat\"></i></button>"
        )
    };
    format!(
        "<tr>\n      \
         <td><a href=\"#/scaninfo?id={id}\" class=\"link\">{value}</a></td>\n      \
         <td>{kind_pill}</td>\n      \
         <td>{started}</td>\n      \
         <td>{dur}</td>\n      \
         <td>{status}</td>\n      \
         <td class=\"text-right\">{entities}</td>\n      \
         <td>\n        \
         <a href=\"#/scaninfo?id={id}\" class=\"btn btn-default btn-xs\" title=\"Open\"><i class=\"glyphicon glyphicon-eye-open\"></i></a>\n        \
         {action_btn}\n        \
         <a class=\"btn btn-default btn-xs\" href=\"/api/v1/scans/{raw_id}/entities.csv\" data-download title=\"Export entities as CSV\"><i class=\"glyphicon glyphicon-download-alt\"></i></a>\n        \
         <a class=\"btn btn-default btn-xs\" href=\"/api/v1/scans/{raw_id}/events.log\" download data-download title=\"Download the scan event log (.log)\"><i class=\"glyphicon glyphicon-align-left\"></i></a>\n        \
         <button class=\"btn btn-danger btn-xs\" data-delete=\"{id}\" title=\"Delete\"><i class=\"glyphicon glyphicon-trash\"></i></button>\n      \
         </td>\n    \
         </tr>",
        value = escape_html(value),
        kind_pill = kind_pill(kind),
        started = escape_html(&fmt_date(row.started_at.unwrap_or(0))),
        dur = escape_html(&fmt_duration(dur_secs)),
        status = status_pill(row.status.as_deref()),
        entities = row.entity_count.unwrap_or(0),
        raw_id = row.id,
    )
}

/// Ports `scans.js`'s `renderScansTable(scans)`: the reusable per-row table
/// builder shared by `scans.js`'s own scan list (`#/scans`, including its
/// live filter-input re-render) and `dash.js`'s "Recent Scans" panel.
#[wasm_bindgen(js_name = renderScansTableHtml)]
pub fn render_scans_table_html(scans_js: JsValue) -> Result<String, JsValue> {
    let scans: Vec<ScanRow> = serde_wasm_bindgen::from_value(scans_js).map_err(to_js_error)?;
    if scans.is_empty() {
        return Ok(
            "<div class=\"empty-state\"><h3>No scans yet</h3>\n            \
             <p>Submit a target to start the first scan. Results stream in real-time\n               \
             and are persisted to the local database.</p>\n            \
             <a class=\"btn btn-danger\" href=\"#/newscan\"><i class=\"glyphicon glyphicon-plus\"></i>&nbsp;Run Scan Now</a></div>"
                .to_string(),
        );
    }
    let rows: String = scans.iter().map(scan_row_html).collect();
    Ok(format!(
        "<div class=\"table-responsive\"><table class=\"table table-striped table-condensed tablesorter\" id=\"scans-table\">\n    \
         <thead><tr>\n      \
         <th>Target</th><th>Type</th><th>Created</th><th>Duration</th>\n      \
         <th>Status</th><th class=\"text-right\">Entities</th>\n      \
         <th class=\"sorter-false\">Actions</th>\n    \
         </tr></thead><tbody>{rows}</tbody></table></div>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_pill_defaults_class_and_text_independently() {
        assert_eq!(
            status_pill(None),
            "<span class=\"status-pill s-pending\">pending</span>"
        );
        assert_eq!(
            status_pill(Some("weird")),
            "<span class=\"status-pill s-pending\">weird</span>"
        );
        assert_eq!(
            status_pill(Some("complete")),
            "<span class=\"status-pill s-complete\">complete</span>"
        );
    }

    #[test]
    fn fmt_duration_matches_helpers_js_thresholds() {
        assert_eq!(fmt_duration(None), "\u{2014}");
        assert_eq!(fmt_duration(Some(-1)), "\u{2014}");
        assert_eq!(fmt_duration(Some(45)), "45s");
        assert_eq!(fmt_duration(Some(125)), "2m 5s");
        assert_eq!(fmt_duration(Some(3725)), "1h 2m");
    }
}
