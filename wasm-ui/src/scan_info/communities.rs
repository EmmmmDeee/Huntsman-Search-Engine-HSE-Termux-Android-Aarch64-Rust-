//! Ports `src/web/js/scan_info/communities.js`'s templating half. Fetching,
//! the loading placeholder shown before it resolves, and the error message
//! on a failed fetch all stay in JS (synchronous DOM writes around the async
//! call are JS's job, and the error path needs the live `Error` object's
//! `message`, never available here); this crate takes the already-fetched
//! `/scans/{id}/communities` response (`crate::core::community::Community`,
//! wrapped `{communities, count}` by `api::handlers::ok_list` — see
//! `scan_communities` in `src/api/scan_handlers/intel.rs`) AND the scan's own
//! entities (see [`crate::entity_lookup`]) and builds the "Communities" panel
//! fragment, INCLUDING the guided empty-state message: unlike every other
//! `scan_info` port, "nothing to show" here is not `""` but a full
//! explanatory block, matching the JS original exactly.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::entity_lookup::EntityLookup;
use crate::html::escape_html;
use crate::to_js_error;

/// The subset of `crate::core::community::Community`'s fields this view
/// displays. `size` is omitted: its own doc comment guarantees
/// `size == uids.len()`, so `uids.len()` is used directly instead of
/// reproducing the JS original's `c.size || uids.length` fallback for a
/// value that can never actually be falsy (every community has ≥ 1 member).
#[derive(Deserialize)]
struct Community {
    uids: Vec<String>,
    label: String,
}

#[derive(Deserialize)]
struct CommunitiesResponse {
    communities: Vec<Community>,
}

const EMPTY_STATE: &str = "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-th-large\"></i>&nbsp;Communities</h4>\n      <div class=\"empty-state\"><h3>No communities yet</h3>\n      <p>Sub-clusters appear once the scan derives a connected relationship graph \u{2014}\n      run a deeper scan (<code>--depth \u{2265} 1</code>) so people, accounts and infrastructure link up.</p></div>";

/// Builds the "Communities" panel fragment for a `/scans/{id}/communities`
/// response — the guided `EMPTY_STATE` block when there are no communities,
/// or the full sub-cluster list (largest first, as the backend already
/// orders them) otherwise.
#[wasm_bindgen(js_name = renderCommunitiesHtml)]
pub fn render_communities_html(data: JsValue, entities_js: JsValue) -> Result<String, JsValue> {
    let data: CommunitiesResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.communities.is_empty() {
        return Ok(EMPTY_STATE.to_string());
    }
    let entities: Vec<hse_core::Entity> =
        serde_wasm_bindgen::from_value(entities_js).map_err(to_js_error)?;
    let lookup = EntityLookup::new(&entities);

    let n = data.communities.len();
    let mut html = format!(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-th-large\"></i>&nbsp;Communities</h4>\n    \
         <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:10px\"><b>{n}</b> sub-cluster{s} in the \
         relationship graph, largest first.</p>",
        s = if n == 1 { "" } else { "s" },
    );
    for c in &data.communities {
        let member_count = c.uids.len();
        let members: String = c
            .uids
            .iter()
            .take(8)
            .map(|u| format!("<code>{}</code>", lookup.display(u)))
            .collect::<Vec<_>>()
            .join(" ");
        let more = if member_count > 8 {
            format!(
                " <span class=\"text-muted\">+{} more</span>",
                member_count - 8
            )
        } else {
            String::new()
        };
        html.push_str(&format!(
            "<div style=\"margin-bottom:8px;padding:8px 10px;border-left:3px solid #5bc0de;\
             background:rgba(91,192,222,0.07)\">\n      \
             <div><span class=\"tag\">{label}</span> <span class=\"text-muted\">\u{b7} {member_count} \
             member{ms}</span></div>\n      \
             <div style=\"margin-top:4px;line-height:1.9\">{members}{more}</div>\n    \
             </div>",
            label = escape_html(&c.label),
            ms = if member_count == 1 { "" } else { "s" },
        ));
    }
    Ok(html)
}
