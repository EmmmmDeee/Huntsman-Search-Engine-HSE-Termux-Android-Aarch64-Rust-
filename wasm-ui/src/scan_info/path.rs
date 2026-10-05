//! Ports `src/web/js/scan_info/path.js`'s connection-path RESULT rendering:
//! the `run()` closure's body from `const paths = ...` through building
//! `html`, given the already-fetched `/scans/{id}/path` response. The static
//! form (`renderPathTool`'s own markup), its event wiring, the empty-input
//! guard, the loading placeholder, and the fetch/error handling all stay in
//! JS — like [`crate::scan_info::correlations`], this view has no single
//! fetch-once entry point to replace: `renderPathTool` sets up an
//! interactive tool the user re-runs many times against the same host.

use std::collections::HashMap;

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, kind_pill};
use crate::to_js_error;

/// One resolved node in the path graph. `scan_path`'s handler
/// (`src/api/scan_handlers/intel.rs`) already resolves each uid to its
/// raw_value-preferring display label server-side (`e.raw_value` if
/// non-empty, else `e.value`) before this ever reaches the client, so —
/// unlike [`crate::entity_lookup::EntityLookup`] — no further
/// raw_value-preference logic is needed here.
#[derive(Deserialize)]
struct PathNode {
    kind: String,
    value: String,
}

/// The subset of `crate::core::path::PathEdge`'s fields this view displays
/// (`from_uid`/`to_uid`/`confidence` are part of the payload but unused).
#[derive(Deserialize)]
struct PathEdge {
    kind: String,
}

/// `crate::core::path::ConnectionPath` — all four fields are used.
#[derive(Deserialize)]
struct ConnectionPath {
    nodes: Vec<String>,
    edges: Vec<PathEdge>,
    hops: usize,
    strength: f64,
}

#[derive(Deserialize)]
struct PathResponse {
    paths: Vec<ConnectionPath>,
    nodes: HashMap<String, PathNode>,
}

/// `path.js`'s `label(uid)`: a resolved node's kind pill plus its value, or —
/// for a uid the response's `nodes` map has no entry for — a muted,
/// 12-char-truncated uid fallback. Unlike `helpers.js`'s `trunc()`
/// ([`crate::scan_info::network`]'s copy), the ellipsis here is
/// unconditional: `String(uid).slice(0,12)` plus `…` regardless of whether
/// `uid` was actually longer than 12 characters, matching the original
/// exactly.
fn label(uid: &str, nodes: &HashMap<String, PathNode>) -> String {
    match nodes.get(uid) {
        Some(n) => format!(
            "{} <code>{}</code>",
            kind_pill(&n.kind),
            escape_html(&n.value)
        ),
        None => {
            let short = escape_html(&uid.chars().take(12).collect::<String>());
            format!("<code class=\"text-muted\" style=\"font-size:10px\">{short}\u{2026}</code>")
        }
    }
}

/// Ports the result half of `path.js`'s `run()`: given the already-fetched
/// `/scans/{id}/path` response and the two entity values the caller searched
/// for (`from`/`to`, needed only for the not-found message), builds either
/// the "no connection found" notice or the ranked list of routes.
#[wasm_bindgen(js_name = renderPathResultHtml)]
pub fn render_path_result_html(data: JsValue, from: &str, to: &str) -> Result<String, JsValue> {
    let data: PathResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.paths.is_empty() {
        let from = escape_html(from);
        let to = escape_html(to);
        return Ok(format!(
            "<div class=\"alert alert-warning\" style=\"margin-bottom:0\"><b>No connection found</b> \
             between <code>{from}</code> and <code>{to}</code> in this scan's graph (within 6 hops). \
             Run a deeper scan so the recursion draws in the linking entities.</div>"
        ));
    }

    let n = data.paths.len();
    let s = if n == 1 { "" } else { "s" };
    let mut html = format!(
        "<p class=\"text-muted\" style=\"font-size:12px;margin-bottom:8px\"><b>{n}</b> route{s} found \u{2014} shortest first.</p>"
    );
    for (i, p) in data.paths.iter().enumerate() {
        let mut chain = label(&p.nodes[0], &data.nodes);
        for (edge, next_uid) in p.edges.iter().zip(p.nodes.iter().skip(1)) {
            let kind = escape_html(&edge.kind);
            let next = label(next_uid, &data.nodes);
            chain.push_str(&format!(
                " <span class=\"text-muted\">\u{2014}<span class=\"tag\" style=\"margin:0 3px\">{kind}</span>\u{2192}</span> {next}"
            ));
        }
        let color = if i == 0 { "#5cb85c" } else { "#5bc0de" };
        let hops = p.hops;
        let hs = if hops == 1 { "" } else { "s" };
        let strength = p.strength;
        html.push_str(&format!(
            "<div style=\"margin-bottom:8px;padding:8px 10px;border-left:3px solid {color};background:rgba(127,127,127,0.06)\">\n        \
             <div style=\"margin-bottom:4px\"><span class=\"badge\">{hops} hop{hs}</span> <span class=\"text-muted\">\u{b7} strength {strength:.2}</span></div>\n        \
             <div style=\"line-height:2\">{chain}</div>\n      \
             </div>"
        ));
    }
    Ok(html)
}
