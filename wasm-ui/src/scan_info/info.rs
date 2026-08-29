//! Ports `src/web/js/scan_info/info.js`'s `renderExposure` templating half
//! only — that file's *other* export, `renderScanSettings`, reads a
//! possibly-fully-absent client-state `scan` object (`scan || S.scan || {}`)
//! and needs locale-aware date formatting (`fmtDate`'s `Date` getters are
//! browser-LOCAL-timezone-dependent, which needs `js_sys::Date` FFI this
//! crate doesn't pull in yet), so it stays in JS for a dedicated follow-up
//! port. Fetching, the null-host guard, and the "never block the surrounding
//! view" failure handling all stay in JS; this crate takes the
//! already-fetched `/scans/{id}/exposure` response
//! (`crate::core::exposure::ExposureIndex`, hand-built as `{score, band,
//! summary, components}` — see `scan_exposure` in
//! `src/api/scan_handlers/analysis.rs`) and builds the "Exposure Index"
//! panel fragment.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::escape_html;
use crate::to_js_error;

/// The subset of `crate::core::exposure::ExposureComponent`'s fields this
/// view displays — all of them; the type is serialize-only (see its own doc
/// comment) so there is nothing to omit.
#[derive(Deserialize)]
struct ExposureComponent {
    name: String,
    score: u8,
    max: u8,
    detail: String,
}

#[derive(Deserialize)]
struct ExposureResponse {
    score: u8,
    band: String,
    summary: String,
    components: Vec<ExposureComponent>,
}

/// `helpers.js`'s (well, `info.js`'s own) `BAND_CLASS` map. `band` is
/// `ExposureBand::label()`'s wire form — already upper-case (its own
/// exhaustive match never produces anything else), so unlike the JS
/// original this never needs a `.toUpperCase()` call.
fn band_class(band: &str) -> &'static str {
    match band {
        "MINIMAL" => "label-success",
        "LOW" => "label-info",
        "MODERATE" => "label-warning",
        "HIGH" | "CRITICAL" => "label-danger",
        _ => "label-default",
    }
}

/// Builds the "Exposure Index" panel fragment for a `/scans/{id}/exposure`
/// response.
#[wasm_bindgen(js_name = renderExposureHtml)]
pub fn render_exposure_html(data: JsValue) -> Result<String, JsValue> {
    let data: ExposureResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    let cls = band_class(&data.band);

    let comps: String = data
        .components
        .iter()
        .map(|c| {
            let pct = if c.max > 0 {
                ((f64::from(c.score) / f64::from(c.max)) * 100.0)
                    .round()
                    .clamp(0.0, 100.0) as i64
            } else {
                0
            };
            format!(
                "<tr>\n        <td style=\"width:190px\">{name}</td>\n        \
                 <td class=\"text-right\" style=\"width:70px\"><code>{score}/{max}</code></td>\n        \
                 <td style=\"width:120px\">\n          \
                 <div style=\"background:var(--border,#eee);height:6px;border-radius:3px;overflow:hidden\">\n            \
                 <div style=\"width:{pct}%;height:6px;background:var(--accent,#337ab7)\"></div>\n          </div>\n        </td>\n        \
                 <td style=\"font-size:12px;color:var(--text-dim)\">{detail}</td>\n      </tr>",
                name = escape_html(&c.name),
                score = c.score,
                max = c.max,
                detail = escape_html(&c.detail),
            )
        })
        .collect();

    Ok(format!(
        "<div class=\"panel panel-default\">\n      \
         <div class=\"panel-heading\"><b>Exposure Index</b>\n        \
         <span class=\"text-muted pull-right\" style=\"font-size:12px\">calibrated 0\u{2013}100 \u{b7} same assessment as the CLI dossier</span>\n      \
         </div>\n      \
         <div class=\"panel-body\">\n        \
         <div style=\"font-size:22px;margin-bottom:2px\">\n          \
         <b>{score}</b><span class=\"text-muted\" style=\"font-size:14px\">/100</span>\n          \
         &nbsp;<span class=\"label {cls}\">{band}</span>\n        \
         </div>\n        \
         {summary}\
         {comps_table}\n      \
         </div>\n    \
         </div>",
        score = data.score,
        band = escape_html(&data.band),
        summary = if data.summary.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"text-muted\" style=\"font-size:12px;margin-bottom:8px\">{}</div>\n        ",
                escape_html(&data.summary)
            )
        },
        comps_table = if comps.is_empty() {
            String::new()
        } else {
            format!(
                "<table class=\"table table-condensed\" style=\"margin-bottom:0\"><tbody>{comps}</tbody></table>"
            )
        },
    ))
}
