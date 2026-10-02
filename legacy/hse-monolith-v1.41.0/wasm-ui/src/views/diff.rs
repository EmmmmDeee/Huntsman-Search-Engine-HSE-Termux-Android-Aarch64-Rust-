//! Ports `src/web/js/views/diff.js`'s `diffRow`/`renderDiffResult` — the
//! result-rendering half of the `#/diff` temporal scan-comparison page.
//! `renderDiff` itself (the baseline/later `<select>` pickers, the
//! shareable-URL `nav()` sync, and the fetch/error handling around
//! `API.diff(a, b)`) stays in JS, like every other view's interactive shell.
//!
//! `EntityRef`/`ConfidenceShift`/`ScanDiff` are view-local response structs,
//! not `hse_core` domain types: the real `crate::core::diff::{EntityRef,
//! ConfidenceShift, ScanDiff}` live in the main `hse` binary crate, which
//! this crate deliberately does not depend on (see this crate's own
//! `Cargo.toml`). Unlike the raw entity/target kinds ported elsewhere,
//! `EntityRef::kind`/`ConfidenceShift::kind` are already flattened to a
//! plain string server-side (`EntityKind`'s own `Display` impl, e.g.
//! `"email"` or `"other:xyz"`) before serialisation, so there is no
//! `{"other":...}` wire shape to handle here.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{ext_link, kind_pill};
use crate::to_js_error;

/// `core::diff::EntityRef`'s wire shape: only `kind`/`value`/`c_effective`
/// (what `diffRow` reads) — `uid` is part of the payload but unused here.
#[derive(Deserialize)]
struct EntityRef {
    kind: String,
    value: String,
    c_effective: f64,
}

/// `core::diff::ConfidenceShift`'s wire shape: only the four fields
/// `shiftRow` reads (`uid` is, again, part of the payload but unused here).
#[derive(Deserialize)]
struct ConfidenceShift {
    kind: String,
    value: String,
    before: f64,
    after: f64,
}

/// `core::diff::ScanDiff`'s wire shape, straight off `GET
/// /api/v1/scans/{a}/diff/{b}`. `renderDiffResult` is only ever called with
/// a genuine successful response (a failed fetch is handled by `renderDiff`
/// itself, in JS, before this is reached), so — like [`crate::scan_info::browse`]
/// trusting its own top-level `Vec<hse_core::Entity>` — every field here is
/// plain, not `Option`; `helpers.js`'s own `d.added||[]`/`d.common||0`
/// fallbacks are dead for a real response.
#[derive(Deserialize)]
struct ScanDiff {
    added: Vec<EntityRef>,
    removed: Vec<EntityRef>,
    common: usize,
    confidence_shifts: Vec<ConfidenceShift>,
}

/// `diffRow`: one added/removed entity's kind, linkified value, and C_eff.
fn diff_row(e: &EntityRef) -> String {
    format!(
        "<tr><td>{kind}</td><td style=\"word-break:break-word\"><code>{value}</code></td>\n    \
         <td class=\"text-right\"><code>{ceff:.3}</code></td></tr>",
        kind = kind_pill(&e.kind),
        value = ext_link(&e.value, None),
        ceff = e.c_effective,
    )
}

/// `shiftRow`: one re-scored entity's kind, linkified value, before/after
/// C_eff, and a colored up/down triangle for the direction of the move.
fn shift_row(s: &ConfidenceShift) -> String {
    let improved = s.after >= s.before;
    let color = if improved { "#3c763d" } else { "#a94442" };
    let arrow = if improved { "\u{25b2}" } else { "\u{25bc}" };
    format!(
        "<tr><td>{kind}</td><td style=\"word-break:break-word\"><code>{value}</code></td>\n    \
         <td class=\"text-right\"><code>{before:.3} \u{2192} {after:.3}</code>\n      \
         <span style=\"color:{color}\">{arrow}</span></td></tr>",
        kind = kind_pill(&s.kind),
        value = ext_link(&s.value, None),
        before = s.before,
        after = s.after,
    )
}

/// `tbl`: a titled panel around one section's rows, or an empty string when
/// that section has none (matches the original's `rows.length ? ... : ''`).
/// `rows_html` is the already-built `<tr>...</tr>` concatenation for that
/// section — the JS original's higher-order `mk` callback has no direct
/// equivalent here since `diff_row`/`shift_row` take different row types.
fn diff_table(title: &str, color: &str, row_count: usize, rows_html: &str) -> String {
    if row_count == 0 {
        return String::new();
    }
    let value_header = if title == "Re-scored" {
        "Before \u{2192} After"
    } else {
        "C_eff"
    };
    format!(
        "<div class=\"panel panel-default\"><div class=\"panel-heading\" style=\"font-weight:600;color:{color}\">{title} <span class=\"badge\">{row_count}</span></div>\n      \
         <div class=\"table-responsive\"><table class=\"table table-condensed table-striped\">\n        \
         <thead><tr><th>Type</th><th>Value</th><th class=\"text-right\">{value_header}</th></tr></thead>\n        \
         <tbody>{rows_html}</tbody></table></div></div>"
    )
}

/// Ports `diff.js`'s `renderDiffResult(d)`: the "Identical" notice, or the
/// Added/Removed/In-common stat row plus the three (independently optional)
/// Added/Removed/Re-scored tables.
#[wasm_bindgen(js_name = renderDiffResultHtml)]
pub fn render_diff_result_html(data: JsValue) -> Result<String, JsValue> {
    let d: ScanDiff = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if d.added.is_empty() && d.removed.is_empty() && d.confidence_shifts.is_empty() {
        return Ok(format!(
            "<div class=\"empty-state\"><h3>Identical</h3><p>The two scans found the same entities at the same confidence \u{2014} {} in common.</p></div>",
            d.common
        ));
    }
    let added_rows: String = d.added.iter().map(diff_row).collect();
    let removed_rows: String = d.removed.iter().map(diff_row).collect();
    let shift_rows: String = d.confidence_shifts.iter().map(shift_row).collect();
    let added_n = d.added.len();
    let removed_n = d.removed.len();
    let common = d.common;
    let added_tbl = diff_table("Added", "#3c763d", added_n, &added_rows);
    let removed_tbl = diff_table("Removed", "#a94442", removed_n, &removed_rows);
    let shift_tbl = diff_table(
        "Re-scored",
        "#8a6d3b",
        d.confidence_shifts.len(),
        &shift_rows,
    );
    Ok(format!(
        "<div class=\"row\" style=\"margin-bottom:10px\">\n      \
         <div class=\"col-xs-4\"><div class=\"stat-card\"><div class=\"lab\">Added</div><div class=\"val\" style=\"color:var(--success)\">+{added_n}</div></div></div>\n      \
         <div class=\"col-xs-4\"><div class=\"stat-card\"><div class=\"lab\">Removed</div><div class=\"val\" style=\"color:var(--danger)\">\u{2212}{removed_n}</div></div></div>\n      \
         <div class=\"col-xs-4\"><div class=\"stat-card\"><div class=\"lab\">In common</div><div class=\"val\">{common}</div></div></div>\n    \
         </div>\n    \
         {added_tbl}\n    \
         {removed_tbl}\n    \
         {shift_tbl}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_table_omits_empty_sections() {
        assert_eq!(diff_table("Added", "#3c763d", 0, ""), "");
    }

    #[test]
    fn diff_table_re_scored_uses_before_after_header() {
        let html = diff_table("Re-scored", "#8a6d3b", 1, "<tr></tr>");
        assert!(html.contains("Before \u{2192} After"));
        assert!(!html.contains("C_eff"));
    }

    #[test]
    fn diff_table_other_titles_use_c_eff_header() {
        let html = diff_table("Added", "#3c763d", 1, "<tr></tr>");
        assert!(html.contains("C_eff"));
    }

    #[test]
    fn shift_row_picks_arrow_and_color_by_direction() {
        let up = ConfidenceShift {
            kind: "email".to_string(),
            value: "a@example.com".to_string(),
            before: 0.5,
            after: 0.8,
        };
        let down = ConfidenceShift {
            kind: "email".to_string(),
            value: "a@example.com".to_string(),
            before: 0.8,
            after: 0.5,
        };
        assert!(shift_row(&up).contains("\u{25b2}"));
        assert!(shift_row(&up).contains("#3c763d"));
        assert!(shift_row(&down).contains("\u{25bc}"));
        assert!(shift_row(&down).contains("#a94442"));
    }

    #[test]
    fn shift_row_equal_before_after_counts_as_improved() {
        // JS: `s.after>=s.before` -- equality takes the "up" branch.
        let flat = ConfidenceShift {
            kind: "email".to_string(),
            value: "a@example.com".to_string(),
            before: 0.5,
            after: 0.5,
        };
        assert!(shift_row(&flat).contains("\u{25b2}"));
    }
}
