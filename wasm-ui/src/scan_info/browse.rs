//! Ports `src/web/js/scan_info/browse.js`'s `renderBrowseTable(rows, total)`
//! — the per-row entity table builder shared by BOTH `browse.js`'s own
//! Browse tab and `views/search.js`'s global search results. `renderBrowse`
//! itself (the per-kind sidebar rollup, the search/tier/filter wiring, and
//! the delegated call into this function) stays in JS: it reads
//! `S.entities`/`S.route` directly and owns interactive DOM state
//! (debounced re-filtering, a clickable sidebar) a one-shot render doesn't
//! have — the same reasoning [`crate::scan_info::correlations`] and
//! [`crate::scan_info::path`] already established for their own JS-side
//! shells.
//!
//! Deserializes straight into [`hse_core::Entity`] (not a bespoke subset
//! struct, unlike most other ports): this row template is the one place
//! that displays nearly every field an entity has, and calling
//! `Entity::c_effective()`/`source_count()`/`Classification::from_c_eff()`
//! directly — rather than round-tripping the same values through the
//! `effC`/`sourceCount`/`classify` WASM exports once per row from JS, as
//! the original JS did — closes the same "second implementation to
//! disagree with the first" gap [`crate::confidence`] was built to close,
//! for the one caller that was still doing it by hand per row.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, ext_link, fmt_date, kind_pill};
use crate::to_js_error;

/// The optional, otherwise-unrelated pieces of client state
/// `renderBrowseTable`'s two callers pass alongside `rows`: `total` (how
/// many rows matched the current filter before the client-side render cap —
/// `browse.js`'s own second parameter), and `entities_total`/`loaded_count`
/// (`S.entitiesTotal`/`S.entities.length`, read directly as globals by the
/// original — Rust has no such global to read, so both become explicit,
/// equally-optional inputs). Both callers always pass a real object literal
/// (`{}` when a field doesn't apply, e.g. `search.js`'s call — never
/// `undefined`/`null` for the whole argument): a struct field typed
/// `Option<T>` already deserializes a MISSING key as `None` with no
/// `#[serde(default)]` needed (the same pattern this crate's own
/// [`crate::scan_info::info`] `ScanView`/`ScanOptionsView` rely on for their
/// own possibly-`{}` input), which is all three fields here need — none of
/// them are ever `None` because of an explicit JSON `null`.
#[derive(Deserialize)]
struct BrowseTableMeta {
    total: Option<usize>,
    entities_total: Option<usize>,
    loaded_count: Option<usize>,
}

/// One evidence entry's detail block: source, the non-corroborating marker,
/// recorded date, summary, and any attributes. `Evidence::attributes` is a
/// `BTreeMap<String, String>` (already sorted, and always a plain string —
/// `helpers.js`'s `attrText()`'s "stringify an object" branch was dead for
/// this call site, since the JS value it ever actually saw here was always
/// a string too).
fn evidence_detail(ev: &hse_core::Evidence) -> String {
    let attrs: String = ev
        .attributes
        .iter()
        .map(|(k, v)| {
            format!(
                "<span class=\"ev-attr\"><span class=\"ak\">{}:</span> {}</span>",
                escape_html(k),
                ext_link(v, Some(90))
            )
        })
        .collect();
    let marker = if hse_core::is_non_corroborating_source(&ev.source) {
        " <span class=\"text-muted\" style=\"font-size:10px\">(non-corroborating: enrichment/recall/cross-scan)</span>"
    } else {
        ""
    };
    let attrs_block = if attrs.is_empty() {
        String::new()
    } else {
        format!("<div class=\"ev-attrs\">{attrs}</div>")
    };
    format!(
        "<div class=\"ev-block\"><span class=\"ev-src\">{src}</span>{marker}<span class=\"text-muted pull-right\" style=\"font-size:10px\">{date}</span><div class=\"ev-sum\">{sum}</div>{attrs_block}</div>",
        src = escape_html(&ev.source),
        date = fmt_date(ev.recorded_at),
        sum = escape_html(&ev.summary),
    )
}

/// One entity's summary row plus its (initially hidden) detail row.
/// `helpers.js`'s own falsy-coalescing fallbacks (`corroboration||1`,
/// `confidence??0`, `uid||''`, `generation??0`) are all dead for a real
/// `Entity`: every one of those fields is required and always present
/// (`corroboration`'s own doc comment guarantees `>= 1`), so this reads them
/// directly.
fn browse_row(e: &hse_core::Entity, idx: usize) -> String {
    let eff = e.c_effective();
    let tier = hse_core::Classification::from_c_eff(eff).as_str();
    let src_n = e.source_count();
    let mut sources: Vec<&str> = e.evidence.iter().map(|ev| ev.source.as_str()).collect();
    sources.sort_unstable();
    sources.dedup();
    let ev_detail: String = e.evidence.iter().map(evidence_detail).collect();
    let value = if e.raw_value.is_empty() {
        &e.value
    } else {
        &e.raw_value
    };
    let tags: String = e
        .tags
        .iter()
        .map(|t| format!("<span class=\"tag\">{}</span>", escape_html(t)))
        .collect();
    let source_pills: String = sources
        .iter()
        .map(|s| format!("<span class=\"src-pill\">{}</span>", escape_html(s)))
        .collect();
    let generation = e.generation;
    let hop_s = if generation == 1 { "" } else { "s" };
    let ev_detail_or_empty = if ev_detail.is_empty() {
        "<span class=\"text-muted\">No evidence attached</span>"
    } else {
        &ev_detail
    };
    format!(
        "<tr onclick=\"toggleDetail(this)\" data-idx=\"{idx}\">\n      \
         <td>{kind_pill}</td>\n      \
         <td style=\"word-break:break-word\"><code>{value_link}</code></td>\n      \
         <td class=\"text-right\"><code>{eff:.3}</code></td>\n      \
         <td class=\"text-right\"><code>{confidence:.3}</code></td>\n      \
         <td class=\"text-right\">{corroboration}</td>\n      \
         <td class=\"text-right\" title=\"Distinct corroborating sources (excludes enrichment/recall/cross-scan)\">{src_n}</td>\n      \
         <td><span class=\"cls c-{tier}\">{tier}</span></td>\n      \
         <td>{tags}</td>\n      \
         <td>{source_pills}</td>\n      \
         <td><span class=\"text-muted\" style=\"font-family:monospace;font-size:11px\">{observed}</span></td>\n    \
         </tr>\n    \
         <tr class=\"entity-detail-row\" style=\"display:none\"><td colspan=\"10\"><div class=\"entity-detail\">\n      \
         <div style=\"margin-bottom:4px\"><b>UID:</b> <code style=\"font-size:10px\">{uid}</code>\n        \
         <span style=\"margin-left:10px\"><b>Generation:</b> {generation} hop{hop_s} from seed</span>\n        \
         <button class=\"btn btn-default btn-xs\" style=\"margin-left:8px\" data-uid=\"{uid}\" onclick=\"event.stopPropagation();entityPivot(this.dataset.uid,this)\"\n                \
         title=\"Find every scan this exact identifier appears in\"><i class=\"glyphicon glyphicon-globe\"></i>&nbsp;Seen across scans</button>\n        \
         <span class=\"pivot-out\" style=\"margin-left:8px\"></span></div>\n      \
         <div style=\"margin-bottom:6px\"><b>{ev_count} evidence entries:</b></div>\n      \
         {ev_detail_or_empty}\n    \
         </div></td></tr>",
        kind_pill = kind_pill(&e.kind.to_string()),
        value_link = ext_link(value, None),
        confidence = e.confidence,
        corroboration = e.corroboration,
        uid = escape_html(&e.uid),
        ev_count = e.evidence.len(),
        observed = fmt_date(e.observed_at),
    )
}

/// Builds the entities table for `rows` (already filtered and capped by the
/// caller), or the empty/fetch-truncation notices in its place. `meta.total`
/// is the pre-cap match count (`browse.js`'s own "Showing the top N of M"
/// note); `meta.entities_total`/`meta.loaded_count` are the scan-wide
/// "server truncated the fetch" note's inputs.
#[wasm_bindgen(js_name = renderBrowseTableHtml)]
pub fn render_browse_table_html(rows_js: JsValue, meta_js: JsValue) -> Result<String, JsValue> {
    let rows: Vec<hse_core::Entity> =
        serde_wasm_bindgen::from_value(rows_js).map_err(to_js_error)?;
    let meta: BrowseTableMeta = serde_wasm_bindgen::from_value(meta_js).map_err(to_js_error)?;

    let fetch_note = match (meta.entities_total, meta.loaded_count) {
        (Some(et), Some(lc)) if et > lc => format!(
            "<div class=\"text-warning\" style=\"font-size:11px;margin-bottom:6px\">This scan has {et} entities; the browser loaded the confidence-ranked top {lc}. Counts and filters below apply to the loaded slice \u{2014} export CSV/JSON for the complete set.</div>"
        ),
        _ => String::new(),
    };

    if rows.is_empty() {
        return Ok(format!(
            "{fetch_note}<div class=\"empty-state\"><h3>No entities match</h3><p>Adjust the filter, or check the Scan Log if the scan is still running.</p></div>"
        ));
    }

    let cap_note = match meta.total {
        Some(total) if total > rows.len() => {
            let n = rows.len();
            format!(
                "<div class=\"text-muted\" style=\"font-size:11px;margin-bottom:6px\">Showing the top {n} of {total} matching entities (confidence-ranked) \u{2014} filter by type or search to narrow, or export CSV/JSON for the full set.</div>"
            )
        }
        _ => String::new(),
    };

    let body: String = rows
        .iter()
        .enumerate()
        .map(|(idx, e)| browse_row(e, idx))
        .collect();

    Ok(format!(
        "{fetch_note}{cap_note}<div class=\"table-responsive\"><table class=\"table table-striped table-condensed tablesorter\" id=\"browse-table\">\n    \
         <thead><tr>\n      \
         <th>Type</th><th>Value</th><th class=\"text-right\">C_eff</th><th class=\"text-right\" title=\"Base confidence, before corroboration boost\">Conf</th>\n      \
         <th class=\"text-right\">Corr</th><th class=\"text-right\" title=\"Distinct corroborating sources\">Src</th><th>Tier</th>\n      \
         <th class=\"sorter-false\">Tags</th><th class=\"sorter-false\">Sources</th><th>Observed</th>\n    \
         </tr></thead><tbody>{body}</tbody></table></div>"
    ))
}
