//! Ports `src/web/js/scan_info/leads.js`'s templating half. Fetching, the
//! loading placeholder, and the per-lead "Scan" button's click handler all
//! stay in JS; this crate takes the already-fetched `/scans/{id}/leads`
//! response (`crate::core::leads::Lead`, wrapped `{leads, count}` by
//! `api::handlers::ok_list` — see `scan_leads` in
//! `src/api/scan_handlers/intel.rs`) AND the scan `id` itself (needed only
//! for the empty state's "Network" link) and builds the "Leads" panel
//! fragment.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, group_icon, kind_pill};
use crate::to_js_error;

/// The subset of `crate::core::leads::Lead`'s fields this view displays
/// (`uid`, `action`, `score`, `classification`, and `bridged` are part of
/// the payload but unused). `kind` is the entity's own kind (the pill);
/// `target_kind` is the *different* field the follow-up scan button seeds
/// with — see `pivot()` in `core::leads::mod` for why they diverge (e.g. a
/// `person` entity's `target_kind` is `full_name`).
#[derive(Deserialize)]
struct Lead {
    value: String,
    kind: String,
    target_kind: String,
    reason: String,
    confirmed: bool,
    discordant: bool,
    structural: bool,
    group: String,
}

#[derive(Deserialize)]
struct LeadsResponse {
    leads: Vec<Lead>,
}

/// Builds the "Leads" panel fragment for a `/scans/{id}/leads` response, or
/// the guided empty-state block (a full block, not `""` — the same
/// "run a deeper scan" guidance choice [`crate::scan_info::trust`] and
/// [`crate::scan_info::communities`] made) when there are none.
#[wasm_bindgen(js_name = renderLeadsHtml)]
pub fn render_leads_html(data: JsValue, id: &str) -> Result<String, JsValue> {
    let data: LeadsResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.leads.is_empty() {
        return Ok(format!(
            "<div class=\"empty-state\"><h3>No open leads</h3>\n      \
             <p>Leads appear when a scan surfaces people, aliases or identifiers it didn't pursue \u{2014}\n      \
             most often relatives and associates kept below the auto-pivot floor. Check the\n      \
             <a href=\"#/scaninfo?id={id}&tab=network\">Network</a>, or run a deeper scan.</p></div>",
            id = escape_html(id),
        ));
    }

    let confirmed_n = data.leads.iter().filter(|l| l.confirmed).count();
    let mut html = format!(
        "<p class=\"text-muted\" style=\"font-size:12px;margin-bottom:10px\">\n    \
         <i class=\"glyphicon glyphicon-flag\"></i>&nbsp;<b>{n}</b> recommended next step{s}\n    \
         \u{2014} untapped pivots ranked by value, the{confirmed} reliable ones first.\n    \
         Click <b>Scan</b> to launch a focused follow-up.</p>",
        n = data.leads.len(),
        s = if data.leads.len() == 1 { "" } else { "s" },
        confirmed = if confirmed_n > 0 {
            format!(" <b>{confirmed_n}</b> corroborated")
        } else {
            String::new()
        },
    );
    for l in &data.leads {
        let icon = group_icon(&l.group).unwrap_or("glyphicon-flag");
        let badge = if l.confirmed {
            "<span class=\"lead-badge\" title=\"An independent second signal corroborates this lead\">\u{2713} CONFIRMED</span>"
        } else if l.discordant {
            "<span class=\"lead-badge namesake\" title=\"Shares the surname but a whole region from the subject \u{2014} likely a different person\">\u{26a0} NAMESAKE?</span>"
        } else {
            ""
        };
        let pivot_badge = if l.structural {
            "<span class=\"lead-badge pivot\" title=\"A bridging pivot in the relationship graph \u{2014} expanding it reaches the most of the footprint for the least work\">\u{2318} PIVOT</span>"
        } else {
            ""
        };
        let cls = if l.confirmed {
            " confirmed"
        } else if l.discordant {
            " discordant"
        } else {
            ""
        };
        html.push_str(&format!(
            "<div class=\"lead-card{cls}\">\n      \
             <div class=\"lead-main\">\n        \
             <div class=\"lead-val\"><i class=\"glyphicon {icon}\"></i>&nbsp;{value} {kind_pill}{badge}{pivot_badge}</div>\n        \
             <div class=\"lead-reason\">{reason}</div>\n      \
             </div>\n      \
             <button class=\"btn btn-info btn-sm lead-scan\" data-kind=\"{kind_attr}\" data-value=\"{value_attr}\"\n        \
             title=\"Launch a focused scan seeded on this lead\">\n        \
             <i class=\"glyphicon glyphicon-search\"></i>&nbsp;Scan</button>\n    \
             </div>",
            value = escape_html(&l.value),
            kind_pill = kind_pill(&l.kind),
            reason = escape_html(&l.reason),
            kind_attr = escape_html(&l.target_kind),
            value_attr = escape_html(&l.value),
        ));
    }
    Ok(html)
}
