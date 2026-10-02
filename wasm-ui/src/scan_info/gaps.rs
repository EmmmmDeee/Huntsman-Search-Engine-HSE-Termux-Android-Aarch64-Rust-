//! Ports `src/web/js/scan_info/gaps.js`'s templating half. Fetching stays in
//! JS; this crate takes the already-parsed `/scans/{id}/gaps` response
//! (`crate::core::gap::GapReport`, plus the API handler's own
//! `corrective_modules` addition per orphan — see
//! `src/api/scan_handlers/diagnostics.rs::scan_gaps`) and builds the same
//! "Discovery gaps" panel fragment.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::escape_html;
use crate::to_js_error;

/// The subset of the handler's per-orphan JSON this view displays — mirrors
/// `crate::core::gap::OrphanSeed` plus the handler's own `corrective_modules`
/// addition (`confidence`/`reinjection_target` are part of the payload but
/// unused here).
#[derive(Deserialize)]
struct Orphan {
    uid: String,
    kind: String,
    value: String,
    /// `crate::core::gap::Isolation`, snake_case: `"unexpanded"` |
    /// `"below_expand_floor"` | `"terminal"`.
    isolation: String,
    action: String,
    corrective_modules: Vec<String>,
}

/// The subset of `crate::core::gap::GapReport`'s fields this view displays
/// (`isolated_seeds`/`isolation` counts are part of the payload but unused
/// here — the view derives its own non-terminal/terminal split from
/// `orphans` instead).
#[derive(Deserialize)]
struct GapReport {
    null_state: bool,
    total_seeds: u64,
    linked_seeds: u64,
    linked_fraction: f64,
    orphans: Vec<Orphan>,
}

fn badge_class(isolation: &str) -> &'static str {
    match isolation {
        "unexpanded" => "label-warning",
        "below_expand_floor" => "label-default",
        "terminal" => "label-info",
        _ => "label-default",
    }
}

/// Builds the "Discovery gaps" panel fragment for a `/scans/{id}/gaps`
/// response, or `""` for the explicit null state (no validated seeds at
/// all).
#[wasm_bindgen(js_name = renderGapsHtml)]
pub fn render_gaps_html(data: JsValue) -> Result<String, JsValue> {
    let data: GapReport = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.null_state {
        return Ok(String::new());
    }

    let linked_pct = (data.linked_fraction * 100.0).round() as i64;
    let mut html = format!(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-unchecked\"></i>&nbsp;Discovery gaps</h4>\n    \
         <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:8px\">{linked}/{total} seeds linked \
         ({linked_pct}%). Isolated seeds below are discovery blind spots \u{2014} each shows the corrective \
         scan that would connect it.</p>",
        linked = data.linked_seeds,
        total = data.total_seeds,
    );

    if data.orphans.is_empty() {
        html.push_str(
            "<p class=\"text-success\" style=\"font-size:12px\"><i class=\"glyphicon glyphicon-ok\"></i> \
             Every validated seed is linked into the graph.</p>",
        );
        return Ok(html);
    }

    let non_terminal_count = data
        .orphans
        .iter()
        .filter(|o| o.isolation != "terminal")
        .count();
    let terminal_count = data.orphans.len() - non_terminal_count;

    for o in data
        .orphans
        .iter()
        .filter(|o| o.isolation != "terminal")
        .take(15)
    {
        let mod_str = if o.corrective_modules.is_empty() {
            String::new()
        } else {
            let shown: Vec<String> = o
                .corrective_modules
                .iter()
                .take(6)
                .map(|m| escape_html(m))
                .collect();
            let ellipsis = if o.corrective_modules.len() > 6 {
                "\u{2026}"
            } else {
                ""
            };
            format!(
                "<span class=\"text-muted\" style=\"font-size:11px\"> \u{2192} run: {}{ellipsis}</span>",
                shown.join(", "),
            )
        };
        let value_or_uid = if o.value.is_empty() { &o.uid } else { &o.value };
        html.push_str(&format!(
            "<div style=\"margin-bottom:6px;font-size:12px\">\n      \
             <span class=\"label {badge}\">{isolation}</span>\n      \
             <code>{val}</code> <span class=\"text-muted\">({kind})</span>\n      \
             <div class=\"text-muted\" style=\"font-size:11px;margin-left:4px\">{action}{mod_str}</div>\n    \
             </div>",
            badge = badge_class(&o.isolation),
            isolation = escape_html(&o.isolation.replace('_', " ")),
            val = escape_html(value_or_uid),
            kind = escape_html(&o.kind),
            action = escape_html(&o.action),
        ));
    }
    if non_terminal_count > 15 {
        html.push_str(&format!(
            "<div class=\"text-muted\" style=\"font-size:11px\">\u{2026}and {} more actionable gaps.</div>",
            non_terminal_count - 15
        ));
    }
    if terminal_count > 0 {
        html.push_str(&format!(
            "<div class=\"text-muted\" style=\"font-size:11px\">+ {terminal_count} terminal leaf/leaves \
             (non-scannable; expected isolation).</div>"
        ));
    }
    Ok(html)
}
