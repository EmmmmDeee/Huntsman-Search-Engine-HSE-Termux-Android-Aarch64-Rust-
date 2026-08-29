//! Ports `src/web/js/scan_info/trust.js`'s templating half. Fetching, the
//! loading placeholder, and the live-error-message path all stay in JS (see
//! `crate::scan_info::communities`'s doc comment for why); this crate takes
//! the already-fetched `/scans/{id}/trust` response
//! (`crate::core::trust::TrustScore`, wrapped `{trust, count}` by
//! `api::handlers::ok_list` — see `scan_trust` in
//! `src/api/scan_handlers/intel.rs`) AND the scan's own entities (see
//! `crate::entity_lookup`) and builds the "Network trust" panel fragment,
//! including the guided empty-state message (a full block, not `""` — the
//! same non-`""`-empty-case choice `communities.rs` made, for the same
//! "run a deeper scan" guidance reason).

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::entity_lookup::EntityLookup;
use crate::html::{escape_html, kind_pill};
use crate::to_js_error;

#[derive(Deserialize)]
struct TrustScore {
    uid: String,
    /// Already clamped to `[0, 1]` server-side (`core::trust::propagate`'s
    /// own guarantee); re-clamped after rounding to a percent anyway, purely
    /// as a rendering safety net — cheap, and matches the JS original doing
    /// the same belt-and-braces `Math.max(0, Math.min(100, ...))`.
    score: f64,
}

#[derive(Deserialize)]
struct TrustResponse {
    trust: Vec<TrustScore>,
}

const EMPTY_STATE: &str = "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-stats\"></i>&nbsp;Network trust</h4>\n      <div class=\"empty-state\"><h3>No trust ranking yet</h3>\n      <p>Trust radiates across the relationship graph from high-confidence anchors.\n      It appears once the scan derives relations \u{2014} run a deeper scan to populate it.</p></div>";

/// The label for one ranked entity: a kind pill plus display value when the
/// UID resolves to a known entity, else a muted, truncated-UID placeholder.
/// Deliberately not `EntityLookup::display` for the not-found case: this
/// view's own JS original truncates to 16 characters (not 12) with its own
/// muted/smaller styling and no kind pill — a distinct look this port
/// preserves exactly rather than forcing through the shared fallback.
fn label(lookup: &EntityLookup, uid: &str) -> String {
    match lookup.get(uid) {
        Some(e) => {
            let value = if e.raw_value.is_empty() {
                &e.value
            } else {
                &e.raw_value
            };
            format!(
                "{} <code>{}</code>",
                kind_pill(&e.kind.to_string()),
                escape_html(value)
            )
        }
        None => format!(
            "<code class=\"text-muted\" style=\"font-size:10px\">{}\u{2026}</code>",
            escape_html(&uid.chars().take(16).collect::<String>())
        ),
    }
}

/// Builds the "Network trust" panel fragment for a `/scans/{id}/trust`
/// response — the guided `EMPTY_STATE` block when there are no scores, or the
/// top 12 ranked entities (the backend already sorts most-trusted first)
/// otherwise.
#[wasm_bindgen(js_name = renderTrustHtml)]
pub fn render_trust_html(data: JsValue, entities_js: JsValue) -> Result<String, JsValue> {
    let data: TrustResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.trust.is_empty() {
        return Ok(EMPTY_STATE.to_string());
    }
    let entities: Vec<hse_core::Entity> =
        serde_wasm_bindgen::from_value(entities_js).map_err(to_js_error)?;
    let lookup = EntityLookup::new(&entities);

    let n = data.trust.len().min(12);
    let mut html = format!(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-stats\"></i>&nbsp;Network trust</h4>\n    \
         <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:10px\">Top {n} entit{y} by \
         graph-corroborated trust \u{2014} how strongly the network supports each, not raw confidence.</p>",
        y = if n == 1 { "y" } else { "ies" },
    );
    for t in data.trust.iter().take(12) {
        let pct = (t.score * 100.0).round().clamp(0.0, 100.0) as i64;
        html.push_str(&format!(
            "<div style=\"display:flex;align-items:center;gap:8px;margin-bottom:5px\">\n      \
             <div style=\"flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis\">{label}</div>\n      \
             <div style=\"flex:0 0 120px;background:rgba(127,127,127,0.2);border-radius:3px;height:10px;overflow:hidden\">\n        \
             <div style=\"width:{pct}%;height:100%;background:#5cb85c\"></div></div>\n      \
             <div style=\"flex:0 0 38px;text-align:right\"><code>{score:.2}</code></div>\n    \
             </div>",
            label = label(&lookup, &t.uid),
            score = t.score,
        ));
    }
    Ok(html)
}
