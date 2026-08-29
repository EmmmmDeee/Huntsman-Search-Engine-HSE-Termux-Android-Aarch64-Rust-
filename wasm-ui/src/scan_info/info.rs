//! Ports `src/web/js/scan_info/info.js`'s two templating halves.
//! `renderExposure`'s: fetching, the null-host guard, and the "never block
//! the surrounding view" failure handling all stay in JS; this crate takes
//! the already-fetched `/scans/{id}/exposure` response
//! (`crate::core::exposure::ExposureIndex`, hand-built as `{score, band,
//! summary, components}` — see `scan_exposure` in
//! `src/api/scan_handlers/analysis.rs`) and builds the "Exposure Index"
//! panel fragment. `renderScanSettings`'s: it is called with `scan ||
//! S.scan || {}` (a possibly-fully-absent client-state object, not a live
//! fetch — JS resolves that fallback chain before calling in, since a bare
//! `{}` still needs to deserialize cleanly here), and formats dates via
//! `js_sys::Date` — the browser's own `Date` object through the same FFI
//! wasm-bindgen itself is built on, so the formatted string is
//! byte-identical to `helpers.js`'s `fmtDate()` (same LOCAL timezone, same
//! everything) without reimplementing timezone logic in Rust.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, kind_pill};
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

/// A `crate::core::scan::Target`-shaped object. All-`Option` (see the module
/// doc comment): the caller's `scan` can be a bare `{}`.
#[derive(Deserialize, Default)]
struct TargetView {
    kind: Option<String>,
    value: Option<String>,
}

/// The subset of `crate::core::scan::ScanOptions`'s fields this view
/// displays. All-`Option` rather than mirroring each field's own
/// `#[serde(default = "...")]`: the JS original's own `??`/`!=null` fallback
/// values (`0`, `false`, `0.20`, "unlimited"/"module default" placeholders)
/// are display choices, not always the same as `ScanOptions::default()`'s
/// real values (e.g. `max_concurrent` defaults to `2` server-side but `0` in
/// this view) — this struct only decides presence; each row below picks its
/// own JS-matching fallback explicitly.
#[derive(Deserialize, Default)]
struct ScanOptionsView {
    modules: Option<Vec<String>>,
    exclude_modules: Option<Vec<String>>,
    throttle_ms: Option<u64>,
    module_timeout_ms: Option<u64>,
    min_confidence: Option<f64>,
    free_only: Option<bool>,
    passive_only: Option<bool>,
    max_concurrent: Option<u64>,
    depth: Option<u64>,
    min_expand_confidence: Option<f64>,
    max_entities: Option<u64>,
    max_wall_time_secs: Option<u64>,
    scan_tags: Option<Vec<String>>,
    notes: Option<String>,
}

/// A `crate::core::scan::Scan`-shaped object — all-`Option` for the same
/// "caller's `scan` can be `{}`" reason as [`TargetView`]/[`ScanOptionsView`];
/// a genuinely-fetched `Scan` has `id`/`target`/`status`/`started_at`
/// present as non-optional fields, but this view (uniquely among
/// `scan_info` ports) can be invoked before one has loaded at all.
#[derive(Deserialize, Default)]
struct ScanView {
    id: Option<String>,
    target: Option<TargetView>,
    status: Option<String>,
    started_at: Option<u64>,
    finished_at: Option<u64>,
    entity_count: Option<u64>,
    error: Option<String>,
    options: Option<ScanOptionsView>,
}

const ALL_DEFAULT: &str = "<span class=\"text-muted\">all (default)</span>";
const NONE_MUTED: &str = "<span class=\"text-muted\">none</span>";

/// `helpers.js`'s `fmtList()`.
fn fmt_list(xs: Option<&[String]>) -> String {
    match xs {
        Some(v) if !v.is_empty() => v
            .iter()
            .map(|x| format!("<code>{}</code>", escape_html(x)))
            .collect::<Vec<_>>()
            .join(" "),
        _ => ALL_DEFAULT.to_string(),
    }
}

/// `helpers.js`'s `statusPill()`. `s` is `None` when `scan.status` itself is
/// absent (a bare `{}` caller) — matching `statusPill(undefined)`'s own
/// `s-pending`/"pending" fallback exactly, distinct from `s` being present
/// but an unrecognized value (which keeps its own text, just the `s-pending`
/// class).
fn status_pill(s: Option<&str>) -> String {
    let cls = match s {
        Some("complete") => "s-complete",
        Some("running") => "s-running",
        Some("failed") => "s-failed",
        Some("pending") => "s-pending",
        Some("aborted") => "s-aborted",
        _ => "s-pending",
    };
    let text = match s {
        Some(v) if !v.is_empty() => v,
        _ => "pending",
    };
    format!(
        "<span class=\"status-pill {cls}\">{}</span>",
        escape_html(text)
    )
}

/// `helpers.js`'s `fmtDate()`. `0` (a genuinely-absent timestamp, per the
/// original's own `!ts` falsy check — true for `0` as well as
/// missing/`undefined`) renders as an em dash instead of the 1970 epoch
/// date.
fn fmt_date(ts: u64) -> String {
    if ts == 0 {
        return "\u{2014}".to_string();
    }
    #[allow(clippy::cast_precision_loss)]
    let millis = ts as f64 * 1000.0;
    let d = js_sys::Date::new(&JsValue::from_f64(millis));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        d.get_full_year(),
        d.get_month() + 1,
        d.get_date(),
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds(),
    )
}

/// Builds the "Scan settings" panel fragment. `scan_js` is the JS side's
/// already-resolved `scan || S.scan || {}` — see the module doc comment.
#[wasm_bindgen(js_name = renderScanSettingsHtml)]
pub fn render_scan_settings_html(scan_js: JsValue) -> Result<String, JsValue> {
    let scan: ScanView = serde_wasm_bindgen::from_value(scan_js).map_err(to_js_error)?;
    let target = scan.target.unwrap_or_default();
    let opts = scan.options.unwrap_or_default();

    let rows: Vec<(&str, String)> = vec![
        (
            "Scan ID",
            format!(
                "<code>{}</code>",
                escape_html(scan.id.as_deref().unwrap_or(""))
            ),
        ),
        (
            "Target type",
            target
                .kind
                .as_deref()
                .map_or_else(|| kind_pill("unknown"), kind_pill),
        ),
        (
            "Target value",
            format!(
                "<code>{}</code>",
                escape_html(target.value.as_deref().unwrap_or(""))
            ),
        ),
        ("Status", status_pill(scan.status.as_deref())),
        ("Started", fmt_date(scan.started_at.unwrap_or(0))),
        ("Finished", fmt_date(scan.finished_at.unwrap_or(0))),
        (
            "Entities recorded",
            scan.entity_count.unwrap_or(0).to_string(),
        ),
        (
            "Error",
            match scan.error.as_deref() {
                Some(e) if !e.is_empty() => {
                    format!("<span class=\"scan-error\">{}</span>", escape_html(e))
                }
                _ => NONE_MUTED.to_string(),
            },
        ),
        ("Modules (allow)", fmt_list(opts.modules.as_deref())),
        (
            "Modules (exclude)",
            fmt_list(opts.exclude_modules.as_deref()),
        ),
        ("Free-only", opts.free_only.unwrap_or(false).to_string()),
        (
            "Passive-only",
            opts.passive_only.unwrap_or(false).to_string(),
        ),
        ("Throttle (ms)", opts.throttle_ms.unwrap_or(0).to_string()),
        (
            "Module timeout (ms)",
            match opts.module_timeout_ms {
                Some(v) => v.to_string(),
                None => "<span class=\"text-muted\">module default</span>".to_string(),
            },
        ),
        (
            "Max concurrent",
            opts.max_concurrent.unwrap_or(0).to_string(),
        ),
        (
            "Min confidence",
            match opts.min_confidence {
                Some(v) => format!("{v:.2}"),
                None => "<span class=\"text-muted\">no filter</span>".to_string(),
            },
        ),
        ("Depth", opts.depth.unwrap_or(0).to_string()),
        (
            "Min expand C_eff",
            opts.min_expand_confidence.unwrap_or(0.20).to_string(),
        ),
        (
            "Max entities",
            match opts.max_entities {
                Some(v) => v.to_string(),
                None => "<span class=\"text-muted\">unlimited</span>".to_string(),
            },
        ),
        (
            "Max wall time (s)",
            match opts.max_wall_time_secs {
                Some(v) => v.to_string(),
                None => "<span class=\"text-muted\">unlimited</span>".to_string(),
            },
        ),
        (
            "Tags",
            match opts.scan_tags.as_deref() {
                Some(tags) if !tags.is_empty() => tags
                    .iter()
                    .map(|t| format!("<span class=\"tag\">{}</span>", escape_html(t)))
                    .collect::<Vec<_>>()
                    .join(" "),
                _ => NONE_MUTED.to_string(),
            },
        ),
        (
            "Notes",
            match opts.notes.as_deref() {
                Some(n) if !n.is_empty() => {
                    format!("<span style=\"font-size:12px\">{}</span>", escape_html(n))
                }
                _ => NONE_MUTED.to_string(),
            },
        ),
    ];

    let body: String = rows
        .iter()
        .map(|(k, v)| {
            format!(
                "<tr><td style=\"width:220px;color:var(--text-muted)\">{}</td><td>{v}</td></tr>",
                escape_html(k)
            )
        })
        .collect();

    Ok(format!(
        "\n    <div class=\"panel panel-default\">\n      \
         <div class=\"panel-heading\"><b>Scan settings</b></div>\n      \
         <table class=\"table table-striped table-condensed\" style=\"margin-bottom:0\">\n        \
         <tbody>{body}</tbody>\n      \
         </table>\n    \
         </div>"
    ))
}
