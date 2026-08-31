//! Ports `src/web/js/views/dash.js`'s `moduleHealthPanel(health)` — the only
//! pure, DOM-free piece of the dashboard's own file. `renderDash` itself
//! fetches four endpoints and assembles a static template around three
//! delegated panels from [`crate::views::scans`] plus this one local helper;
//! the fetch orchestration and DOM assignment stay in JS, like every other
//! view's outer shell.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, fmt_date};
use crate::to_js_error;

/// `/api/v1/modules/health`'s per-module entry (`module_health_json`'s wire
/// shape) — all three fields `moduleHealthPanel` reads.
#[derive(Deserialize)]
struct ModuleHealthEntry {
    name: String,
    consecutive_failures: u64,
    last_success_at: Option<u64>,
}

/// `/api/v1/modules/health`'s envelope. `count` (also part of the payload)
/// is unused: `moduleHealthPanel` recomputes it from `modules.len()` itself,
/// same as the JS original.
#[derive(Deserialize)]
struct ModuleHealthResponse {
    modules: Option<Vec<ModuleHealthEntry>>,
}

/// `moduleHealthPanel`'s per-row "Last succeeded" cell: `last_success_at` is
/// falsy-checked in the original (`m.last_success_at ? fmtDate(...) :
/// '<span>never...'`), so an explicit `Some(0)` must fall to "never this
/// process" the same as a missing/`null` value — not through `fmt_date`'s
/// own (different) zero-timestamp em-dash branch.
fn last_success_display(ts: Option<u64>) -> String {
    ts.filter(|&t| t != 0).map_or_else(
        || "<span class=\"text-muted\">never this process</span>".to_string(),
        fmt_date,
    )
}

/// Ports `dash.js`'s `moduleHealthPanel(health)`. `health` itself may be
/// absent (`renderDash`'s `Promise.allSettled` fallback for a failed
/// `/api/v1/modules/health` fetch is `null`), hence `Option` at the top
/// level rather than only on `modules`.
#[wasm_bindgen(js_name = renderModuleHealthPanelHtml)]
pub fn render_module_health_panel_html(health_js: JsValue) -> Result<String, JsValue> {
    let health: Option<ModuleHealthResponse> =
        serde_wasm_bindgen::from_value(health_js).map_err(to_js_error)?;
    let mods = health.and_then(|h| h.modules).unwrap_or_default();
    let body = if mods.is_empty() {
        "<p class=\"text-muted\" style=\"margin:0\">No modules currently show a failure streak.</p>"
            .to_string()
    } else {
        let rows: String = mods
            .iter()
            .map(|m| {
                format!(
                    "<tr>\n            \
                     <td>{name}</td>\n            \
                     <td class=\"text-right\"><span class=\"label label-warning\">{failures}</span></td>\n            \
                     <td class=\"text-right\">{last}</td>\n          \
                     </tr>",
                    name = escape_html(&m.name),
                    failures = m.consecutive_failures,
                    last = last_success_display(m.last_success_at),
                )
            })
            .collect();
        format!(
            "<table class=\"table table-condensed\" style=\"margin-bottom:0\">\n        \
             <thead><tr><th>Module</th><th class=\"text-right\">Consecutive failures</th><th class=\"text-right\">Last succeeded</th></tr></thead>\n        \
             <tbody>\n          {rows}\n        \
             </tbody>\n      \
             </table>"
        )
    };
    let count = mods.len();
    Ok(format!(
        "<div class=\"panel panel-default\" style=\"margin-top:12px\">\n    \
         <div class=\"panel-heading\"><b>Module Health</b>\n      \
         <span class=\"pull-right\" style=\"font-size:12px\">{count} with a failure streak this process</span></div>\n    \
         <div class=\"panel-body\">{body}</div>\n  \
         </div>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_missing_last_success_both_render_never() {
        // A real non-zero timestamp routes through `fmt_date`, which calls
        // `js_sys::Date` — unavailable outside a real wasm/JS host, so (like
        // `html`'s own tests) that branch isn't exercised natively here.
        assert_eq!(
            last_success_display(Some(0)),
            "<span class=\"text-muted\">never this process</span>"
        );
        assert_eq!(
            last_success_display(None),
            "<span class=\"text-muted\">never this process</span>"
        );
    }
}
