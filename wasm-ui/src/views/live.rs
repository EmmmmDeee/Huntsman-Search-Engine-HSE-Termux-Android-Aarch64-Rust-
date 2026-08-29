//! Ports `src/web/js/views/live.js`'s pure, DOM-free rendering helpers:
//! `renderLiveSessions` (the "Active sessions" table) and
//! `renderRadarHistory` (the "Radar history" table, sourced from the same
//! persisted-scan shape as `/api/v1/scans` — a radar sweep is a scan seeded
//! with no user-chosen target). `renderLive` itself (the live-radar and
//! session-start forms, SSE tailing via `log.js`'s `mapEvent`, and the 8s
//! session-list poll) stays in JS, like every other view's interactive
//! shell.
//!
//! `LiveSessionRow`/`SweepRow` and their nested structs are view-local
//! response structs, not `hse_core` domain types: the real
//! `crate::core::live::LiveSession` and `crate::core::scan::Scan` live in
//! the main `hse` binary crate, which this crate deliberately does not
//! depend on.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, fmt_date, kind_pill, status_pill};
use crate::to_js_error;

/// A live session's target (`crate::core::live::LiveSession::target`, itself
/// `crate::core::scan::Target`).
#[derive(Deserialize)]
struct LiveTarget {
    kind: Option<String>,
    value: Option<String>,
}

/// `crate::core::live::LiveOptions`'s wire shape: the three fields
/// `renderLiveSessions` reads.
#[derive(Deserialize)]
struct LiveOptionsRow {
    interval_secs: Option<u64>,
    iterations: Option<u32>,
    radar: Option<bool>,
}

/// `/api/v1/live`'s per-session wire shape: only the fields
/// `renderLiveSessions` reads.
#[derive(Deserialize)]
struct LiveSessionRow {
    id: String,
    target: Option<LiveTarget>,
    live_options: Option<LiveOptionsRow>,
    status: Option<String>,
    iteration: Option<u32>,
    started_at: Option<u64>,
    last_iteration_at: Option<u64>,
    scan_ids: Option<Vec<String>>,
}

/// `renderLiveSessions`'s per-row target-kind pill: `kindPill(s.target &&
/// s.target.kind)`'s JS behaviour when `target` (or its `kind`) is missing
/// runs through `kindToStr`'s own null branch — the literal text "unknown"
/// — which is *not* the em-dash `views::scans::scan_row_html` falls back to
/// for the same situation. `scans.js` and `live.js` independently wrote
/// different fallback text for a missing target kind; each is replicated
/// exactly as its own original did, not unified.
fn live_kind_pill(target: &Option<LiveTarget>) -> String {
    let kind = target
        .as_ref()
        .and_then(|t| t.kind.as_deref())
        .filter(|k| !k.is_empty())
        .unwrap_or("unknown");
    kind_pill(kind)
}

/// One `<tr>` of the "Active sessions" table: `renderLiveSessions`'s row
/// template.
fn live_session_row_html(s: &LiveSessionRow) -> String {
    let value = s
        .target
        .as_ref()
        .and_then(|t| t.value.as_deref())
        .filter(|v| !v.is_empty())
        .unwrap_or(&s.id);
    let radar_badge = if s
        .live_options
        .as_ref()
        .and_then(|o| o.radar)
        .unwrap_or(false)
    {
        " <span class=\"label label-info\" title=\"Radar: paid APIs not re-queried on covered seeds\">radar</span>"
    } else {
        ""
    };
    let iterations_suffix = match s.live_options.as_ref().and_then(|o| o.iterations) {
        Some(n) => format!(" / {n}"),
        None => String::new(),
    };
    let interval = s
        .live_options
        .as_ref()
        .and_then(|o| o.interval_secs)
        .map_or_else(|| "?".to_string(), |n| n.to_string());
    let last_iteration = s.last_iteration_at.filter(|&t| t != 0).map_or_else(
        || "<span class=\"text-muted\">\u{2014}</span>".to_string(),
        fmt_date,
    );
    let id = escape_html(&s.id);
    format!(
        "<tr>\n    \
         <td>{kind_pill} <code>{value}</code>{radar_badge}</td>\n    \
         <td>{status}</td>\n    \
         <td class=\"text-right\">{iteration}{iterations_suffix}</td>\n    \
         <td class=\"text-right\">{interval}s</td>\n    \
         <td>{started}</td>\n    \
         <td>{last_iteration}</td>\n    \
         <td class=\"text-right\">{scan_count}</td>\n    \
         <td class=\"text-right\">\n      \
         <button class=\"btn btn-info btn-xs\" data-livestream=\"{id}\" data-lval=\"{value}\" title=\"Tail this session's live events\"><i class=\"glyphicon glyphicon-transfer\"></i></button>\n      \
         <button class=\"btn btn-danger btn-xs\" data-livestop=\"{id}\" title=\"Stop\"><i class=\"glyphicon glyphicon-stop\"></i></button>\n    \
         </td>\n  \
         </tr>",
        kind_pill = live_kind_pill(&s.target),
        value = escape_html(value),
        status = status_pill(s.status.as_deref()),
        iteration = s.iteration.unwrap_or(0),
        started = escape_html(&fmt_date(s.started_at.unwrap_or(0))),
        scan_count = s.scan_ids.as_ref().map_or(0, Vec::len),
    )
}

/// Ports `live.js`'s `renderLiveSessions(sessions)`: the "Active sessions"
/// table.
#[wasm_bindgen(js_name = renderLiveSessionsHtml)]
pub fn render_live_sessions_html(sessions_js: JsValue) -> Result<String, JsValue> {
    let sessions: Vec<LiveSessionRow> =
        serde_wasm_bindgen::from_value(sessions_js).map_err(to_js_error)?;
    if sessions.is_empty() {
        return Ok("<div class=\"empty-state\"><h3>No active sessions</h3>\
             <p>Start one above to continuously re-scan a target on an interval \u{2014} new \
             entities and correlations accrue as they appear.</p></div>"
            .to_string());
    }
    let rows: String = sessions.iter().map(live_session_row_html).collect();
    Ok(format!(
        "<div class=\"table-responsive\"><table class=\"table table-condensed table-striped\">\n    \
         <thead><tr><th>Target</th><th>Status</th><th class=\"text-right\">Iter</th>\n      \
         <th class=\"text-right\">Interval</th><th>Started</th><th>Last run</th>\n      \
         <th class=\"text-right\">Scans</th><th></th></tr></thead>\n    \
         <tbody>{rows}</tbody></table></div>"
    ))
}

/// A radar sweep's target — only `kind` is read (`renderRadarHistory` never
/// displays the sweep's target value).
#[derive(Deserialize)]
struct SweepTarget {
    kind: Option<String>,
}

/// `/api/v1/radar/history`'s per-sweep wire shape (byte-for-byte the same
/// as `/api/v1/scans`' `crate::core::scan::Scan`): only the fields
/// `renderRadarHistory` reads.
#[derive(Deserialize)]
struct SweepRow {
    id: String,
    target: Option<SweepTarget>,
    status: Option<String>,
    started_at: Option<u64>,
    finished_at: Option<u64>,
    entity_count: Option<u64>,
}

/// `renderRadarHistory`'s per-row duration cell: a raw `{n}s` suffix —
/// unlike `views::scans::fmt_duration`'s h/m/s formatting — matching the
/// original JS's own simpler `dur+'s'`.
fn sweep_duration_display(finished_at: Option<u64>, started_at: Option<u64>) -> String {
    let started = started_at.filter(|&t| t != 0);
    let finished = finished_at.filter(|&t| t != 0);
    match (finished, started) {
        (Some(f), Some(st)) => format!("{}s", f.saturating_sub(st)),
        _ => "<span class=\"text-muted\">\u{2014}</span>".to_string(),
    }
}

/// One `<tr>` of the "Radar history" table: `renderRadarHistory`'s row
/// template.
fn sweep_row_html(sw: &SweepRow) -> String {
    let seed = if sw.target.as_ref().and_then(|t| t.kind.as_deref()) == Some("mac_address") {
        "local network"
    } else {
        "ambient (GPS/RF)"
    };
    let dur = sweep_duration_display(sw.finished_at, sw.started_at);
    let id = escape_html(&sw.id);
    format!(
        "<tr>\n      \
         <td>{started}</td>\n      \
         <td>{seed}</td>\n      \
         <td>{status}</td>\n      \
         <td class=\"text-right\">{dur}</td>\n      \
         <td class=\"text-right\">{entities}</td>\n      \
         <td><a href=\"#/scaninfo?id={id}\" class=\"btn btn-default btn-xs\" title=\"Review this sweep's signals\"><i class=\"glyphicon glyphicon-eye-open\"></i>&nbsp;Review</a></td>\n    \
         </tr>",
        started = escape_html(&fmt_date(sw.started_at.unwrap_or(0))),
        status = status_pill(sw.status.as_deref()),
        entities = sw.entity_count.unwrap_or(0),
    )
}

/// Ports `live.js`'s `renderRadarHistory(sweeps)`: the "Radar history"
/// table.
#[wasm_bindgen(js_name = renderRadarHistoryHtml)]
pub fn render_radar_history_html(sweeps_js: JsValue) -> Result<String, JsValue> {
    let sweeps: Vec<SweepRow> = serde_wasm_bindgen::from_value(sweeps_js).map_err(to_js_error)?;
    if sweeps.is_empty() {
        return Ok(
            "<div class=\"empty-state\"><h3>No radar sweeps yet</h3>\
             <p>Every sweep the radar button or continuous radar ever queued is listed here, newest \
             first, once it runs \u{2014} reviewable later even after a server restart.</p></div>"
                .to_string(),
        );
    }
    let rows: String = sweeps.iter().map(sweep_row_html).collect();
    Ok(format!(
        "<div class=\"table-responsive\"><table class=\"table table-condensed table-striped\">\n    \
         <thead><tr><th>When</th><th>Seed</th><th>Status</th><th class=\"text-right\">Duration</th>\n      \
         <th class=\"text-right\">Signals</th><th></th></tr></thead>\n    \
         <tbody>{rows}</tbody></table></div>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_kind_pill_falls_back_to_unknown_not_em_dash() {
        assert_eq!(
            live_kind_pill(&None),
            "<span class=\"kind-pill k-unknown\">unknown</span>"
        );
        assert_eq!(
            live_kind_pill(&Some(LiveTarget {
                kind: None,
                value: None
            })),
            "<span class=\"kind-pill k-unknown\">unknown</span>"
        );
    }

    #[test]
    fn sweep_seed_is_local_network_only_for_mac_address() {
        let mac = SweepRow {
            id: "s1".to_string(),
            target: Some(SweepTarget {
                kind: Some("mac_address".to_string()),
            }),
            status: None,
            started_at: None,
            finished_at: None,
            entity_count: None,
        };
        let coords = SweepRow {
            target: Some(SweepTarget {
                kind: Some("coordinates".to_string()),
            }),
            ..mac_clone(&mac)
        };
        let missing = SweepRow {
            target: None,
            ..mac_clone(&mac)
        };
        assert!(sweep_row_html(&mac).contains(">local network<"));
        assert!(sweep_row_html(&coords).contains(">ambient (GPS/RF)<"));
        assert!(sweep_row_html(&missing).contains(">ambient (GPS/RF)<"));
    }

    fn mac_clone(sw: &SweepRow) -> SweepRow {
        SweepRow {
            id: sw.id.clone(),
            target: None,
            status: sw.status.clone(),
            started_at: sw.started_at,
            finished_at: sw.finished_at,
            entity_count: sw.entity_count,
        }
    }

    #[test]
    fn sweep_duration_is_a_raw_second_suffix_not_hms() {
        // Isolated from sweep_row_html: that also renders the `started_at`
        // date column through fmt_date, which calls js_sys::Date --
        // unavailable outside a real wasm/JS host for a non-zero timestamp.
        assert_eq!(sweep_duration_display(Some(4_600), Some(1_000)), "3600s");
        assert_eq!(
            sweep_duration_display(None, Some(1_000)),
            "<span class=\"text-muted\">\u{2014}</span>"
        );
        assert_eq!(
            sweep_duration_display(Some(4_600), None),
            "<span class=\"text-muted\">\u{2014}</span>"
        );
    }
}
