//! Ports `src/web/js/scan_info/correlations.js`'s two pure HTML-templating
//! helpers, `cardHtml` and the member rows built lazily inside
//! `toggleCorrMembers`. Everything else in that file — pagination state
//! (`shown`/`nextPage`/`paint`), the lazy-build-on-first-expand orchestration,
//! and the inline `onclick` dispatch (`toggleCorrMembers`, `pivotToEntity`) —
//! stays in JS: unlike every other `scan_info` port, this view has no single
//! "fetch once, render once" entry point to replace (correlations already
//! live in `S.correlations`/`S.entities` client state, and a real scan can
//! have hundreds of cards with thousands of members each, which is *why*
//! it's paged and lazily built in the first place). `Correlation` is
//! `crate::core::correlator::Correlation`, `S.correlations`' element shape.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::entity_lookup::EntityLookup;
use crate::html::escape_html;
use crate::to_js_error;

/// The subset of `crate::core::correlator::Correlation`'s fields this view
/// displays (`scan_id` and `ts` are part of the payload but unused).
#[derive(Deserialize)]
struct Correlation {
    rule_id: String,
    rule_name: String,
    severity: String,
    description: String,
    entity_uids: Vec<String>,
    rank: f64,
}

/// Ports `correlations.js`'s `cardHtml(c, idx)`: one collapsed correlation
/// card (severity, rule, member count, and — once above zero, a legacy
/// pre-`rank`-field correlation reads exactly 0.0 — the rank badge). `idx`
/// is the card's position in `S.correlations` (pagination state JS alone
/// tracks), stamped onto `data-corr-idx` so `toggleCorrMembers` can look the
/// correlation back up when the card is clicked. The `.corr-members`
/// container is left empty here — see [`render_corr_members_html`].
#[wasm_bindgen(js_name = renderCorrCardHtml)]
pub fn render_corr_card_html(data: JsValue, idx: usize) -> Result<String, JsValue> {
    let c: Correlation = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    let sev = c.severity.to_lowercase();
    let n = c.entity_uids.len();
    let rank = if c.rank > 0.0 {
        format!(
            "<span class=\"pull-right\" title=\"rank = severity \u{d7} max child C_eff\">rank {:.2}</span>",
            c.rank
        )
    } else {
        String::new()
    };
    let rule_name_display = if !c.rule_name.is_empty() {
        c.rule_name.as_str()
    } else if !c.rule_id.is_empty() {
        c.rule_id.as_str()
    } else {
        "\u{2014}"
    };
    Ok(format!(
        "<div class=\"corr-card cv-{sev}\" data-corr-idx=\"{idx}\" onclick=\"toggleCorrMembers(this)\" \
         style=\"cursor:pointer\" title=\"Click to show the {n} linked entit{y}\">\n      \
         <div class=\"corr-h\"><b>{sev_upper}</b> \u{b7} {rule_id} <span class=\"badge\">{n}</span>{rank}</div>\n      \
         <div class=\"corr-name\">{rule_name_display}</div>\n      \
         <div class=\"corr-d\">{description}</div>\n      \
         <div class=\"corr-members\" style=\"display:none;margin-top:8px;border-top:1px dashed #d8d8d8;padding-top:6px\"></div>\n    \
         </div>",
        sev = escape_html(&sev),
        n = n,
        y = if n == 1 { "y" } else { "ies" },
        sev_upper = escape_html(&sev.to_uppercase()),
        rule_id = escape_html(&c.rule_id),
        rule_name_display = escape_html(rule_name_display),
        description = escape_html(&c.description),
    ))
}

/// Ports the member-row templating inside `correlations.js`'s
/// `toggleCorrMembers` — built lazily by JS on a card's first expand, from
/// that correlation's `entity_uids` and the scan's own entities (see
/// [`crate::entity_lookup`], shared with every other ranked/graph view built
/// on `S.entities`). A resolved member's inner markup is
/// [`EntityLookup::label`] (kind pill + value) wrapped in a clickable
/// `data-pivot` div (`pivotToEntity`, kept in JS, cross-references it in
/// Browse); an unresolved uid gets the same label — its own 16-char-
/// truncated fallback — without the pivot wrapper, since there is no entity
/// to pivot to.
#[wasm_bindgen(js_name = renderCorrMembersHtml)]
pub fn render_corr_members_html(uids_js: JsValue, entities_js: JsValue) -> Result<String, JsValue> {
    let uids: Vec<String> = serde_wasm_bindgen::from_value(uids_js).map_err(to_js_error)?;
    if uids.is_empty() {
        return Ok(
            "<span class=\"text-muted\">No member entities in this scan view</span>".to_string(),
        );
    }
    let entities: Vec<hse_core::Entity> =
        serde_wasm_bindgen::from_value(entities_js).map_err(to_js_error)?;
    let lookup = EntityLookup::new(&entities);
    let html: String = uids
        .iter()
        .map(|u| match lookup.get(u) {
            // The pivot/title attribute deliberately uses the entity's own
            // `value` (not `raw_value`) — the ORIGINAL JS's `attr(e.value)` —
            // distinct from the label's inner text, which prefers
            // `raw_value` (see `EntityLookup::label`). Browse's pivot filter
            // expects the normalised `value`, not the display form.
            Some(e) => format!(
                "<div class=\"corr-member\" style=\"cursor:pointer\" title=\"Show '{v}' in Browse\" \
                 data-pivot=\"{v}\" onclick=\"event.stopPropagation();pivotToEntity(this.dataset.pivot)\">{label}</div>",
                v = escape_html(&e.value),
                label = lookup.label(u),
            ),
            None => format!("<div class=\"corr-member\">{}</div>", lookup.label(u)),
        })
        .collect();
    Ok(html)
}
