//! Ports `src/web/js/scan_info/identities.js`'s templating half. Fetching
//! stays in JS (`API.identities(id)` — async I/O is JS's job); this crate
//! only takes the already-parsed `/scans/{id}/identities` response and
//! builds the same HTML fragment the JS version built by hand, using the
//! backend's own `CoReference` wire shape (`src/core/coref/mod.rs`, not
//! reachable from this crate as a real type — `wasm-ui` depends only on
//! `hse-core`, not the main crate) instead of re-guessing its field names
//! from the JSON.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::escape_html;
use crate::to_js_error;

/// Mirrors `crate::core::coref::CoReference`'s wire shape (the fields this
/// view actually uses — `uid_a`/`uid_b`/`kind_a`/`kind_b` are part of the
/// same payload but this view never displayed them).
#[derive(Deserialize)]
struct CoReference {
    value_a: String,
    value_b: String,
    score: f64,
    signals: Vec<String>,
}

/// Mirrors the `scan_identities` handler's response envelope
/// (`src/api/scan_handlers/analysis.rs`).
#[derive(Deserialize)]
struct IdentitiesResponse {
    min_score: f64,
    coreferences: Vec<CoReference>,
}

/// Builds the "Resolved identities" panel fragment for a `/scans/{id}/identities`
/// response, or `""` when there is nothing to show (no coreferences) — the
/// caller assigns the result straight to `host.innerHTML`, exactly like the
/// JS original did.
#[wasm_bindgen(js_name = renderIdentitiesHtml)]
pub fn render_identities_html(data: JsValue) -> Result<String, JsValue> {
    let data: IdentitiesResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.coreferences.is_empty() {
        return Ok(String::new());
    }

    let n = data.coreferences.len();
    let mut html = format!(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-user\"></i>&nbsp;Resolved identities</h4>\n    \
         <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:8px\">{n} selector pair{s} \
         that score as the same individual (\u{2265} {min}).</p>",
        n = n,
        s = if n == 1 { "" } else { "s" },
        min = escape_html(&data.min_score.to_string()),
    );
    for r in &data.coreferences {
        let sig: String = r
            .signals
            .iter()
            .map(|s| {
                format!(
                    "<span class=\"label label-default\">{}</span>",
                    escape_html(s)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        html.push_str(&format!(
            "<div style=\"margin-bottom:6px;padding:6px 10px;border-left:3px solid #5bc0de;\
             background:rgba(91,192,222,0.07)\">\n      \
             <div><code>{a}</code> <span class=\"text-muted\">\u{2248}</span> <code>{b}</code>\n        \
             <span class=\"pull-right text-muted\" style=\"font-size:11px\">score {score:.2}</span></div>\n      \
             <div style=\"margin-top:2px\">{sig}</div>\n    </div>",
            a = escape_html(&r.value_a),
            b = escape_html(&r.value_b),
            score = r.score,
            sig = sig,
        ));
    }
    Ok(html)
}
