//! Ports `src/web/js/scan_info/duplicates.js`'s templating half. Fetching
//! stays in JS; this crate takes the already-fetched `/scans/{id}/duplicates`
//! response (`crate::core::resolve::ResolutionGroup`, wrapped `{duplicates,
//! count}` by `api::handlers::ok_list` — see `scan_duplicates` in
//! `src/api/scan_handlers/diagnostics.rs`) AND the scan's own entities (the
//! client-side `S.entities` the JS already holds in memory, needed to resolve
//! a group member's UID to its display value) and builds the same "Likely
//! duplicates" panel fragment.
//!
//! First `scan_info` port needing a second input beyond its own API
//! response: unlike every prior view, this one also depends on
//! already-loaded client state, so `render_duplicates_html` takes `entities`
//! as a second `JsValue`, deserialized straight into real `hse_core::Entity`
//! values (the same wire format `S.entities` already holds) rather than a
//! bespoke lookup-only struct — reusing the real type instead of re-guessing
//! which of its fields this view happens to need.

use std::collections::HashMap;

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::escape_html;
use crate::to_js_error;

#[derive(Deserialize)]
struct ResolutionGroup {
    /// `crate::core::entity::EntityKind`'s `Display` string (already flat —
    /// `ResolutionGroup::kind` is `String` server-side, not the enum itself),
    /// e.g. `"email"`, `"phone"`, `"other:xyz"`.
    kind: String,
    members: Vec<String>,
    reason: String,
}

#[derive(Deserialize)]
struct DuplicatesResponse {
    duplicates: Vec<ResolutionGroup>,
}

fn kind_pill(kind: &str) -> String {
    format!(
        "<span class=\"kind-pill k-{k}\">{k}</span>",
        k = escape_html(kind)
    )
}

/// Builds the "Likely duplicates" panel fragment for a `/scans/{id}/duplicates`
/// response, or `""` when there are no suggested groups.
///
/// `entities_js` is `S.entities` as the browser already holds it (an array of
/// the same JSON `hse_core::Entity` serializes to server-side) — used only to
/// resolve a member UID to a display value; a UID absent from it (should not
/// happen in practice, but the JS original tolerated it) falls back to its
/// own first 12 characters plus an ellipsis.
#[wasm_bindgen(js_name = renderDuplicatesHtml)]
pub fn render_duplicates_html(data: JsValue, entities_js: JsValue) -> Result<String, JsValue> {
    let data: DuplicatesResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.duplicates.is_empty() {
        return Ok(String::new());
    }
    let entities: Vec<hse_core::Entity> =
        serde_wasm_bindgen::from_value(entities_js).map_err(to_js_error)?;
    let by_uid: HashMap<&str, &hse_core::Entity> =
        entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    let val = |uid: &str| -> String {
        match by_uid.get(uid) {
            Some(e) if !e.raw_value.is_empty() => escape_html(&e.raw_value),
            Some(e) => escape_html(&e.value),
            None => format!(
                "{}\u{2026}",
                escape_html(&uid.chars().take(12).collect::<String>())
            ),
        }
    };

    let n = data.duplicates.len();
    let mut html = format!(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-duplicate\"></i>&nbsp;Likely duplicates</h4>\n    \
         <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:8px\">{n} group{s} that are probably \
         one identity in different contexts \u{2014} confirm before treating as the same.</p>",
        s = if n == 1 { "" } else { "s" },
    );
    for g in &data.duplicates {
        let members: String = g
            .members
            .iter()
            .map(|u| format!("<code>{}</code>", val(u)))
            .collect::<Vec<_>>()
            .join(" ");
        html.push_str(&format!(
            "<div style=\"margin-bottom:6px;padding:6px 10px;border-left:3px solid #f0ad4e;\
             background:rgba(240,173,78,0.07)\">\n      \
             <div>{kind} {members}</div>\n      \
             <div class=\"text-muted\" style=\"font-size:11px;margin-top:2px\">{reason}</div>\n    \
             </div>",
            kind = kind_pill(&g.kind),
            reason = escape_html(&g.reason),
        ));
    }
    Ok(html)
}
