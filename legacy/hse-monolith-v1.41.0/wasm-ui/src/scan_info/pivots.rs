//! Ports `src/web/js/scan_info/pivots.js`'s templating half. Fetching stays
//! in JS; this crate takes the already-fetched `/scans/{id}/pivots` response
//! (`crate::core::pivot::PivotNode` + `BridgeEdge`, wrapped `{pivots,
//! bridges, count}` — see `scan_pivots` in
//! `src/api/scan_handlers/diagnostics.rs`) AND the scan's own entities (see
//! `crate::entity_lookup`) and builds the "Pivot nodes" panel fragment.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::entity_lookup::EntityLookup;
use crate::to_js_error;

/// The subset of `crate::core::pivot::PivotNode`'s fields this view displays
/// (`betweenness` is part of the payload but unused — `score` already folds
/// it in).
#[derive(Deserialize)]
struct PivotNode {
    uid: String,
    degree: u64,
    score: f64,
    is_cut_vertex: bool,
    coreness: u64,
}

#[derive(Deserialize)]
struct BridgeEdge {
    from_uid: String,
    to_uid: String,
}

#[derive(Deserialize)]
struct PivotsResponse {
    pivots: Vec<PivotNode>,
    bridges: Vec<BridgeEdge>,
}

/// Builds the "Pivot nodes" panel fragment for a `/scans/{id}/pivots`
/// response, or `""` when there are neither pivots nor bridges.
#[wasm_bindgen(js_name = renderPivotsHtml)]
pub fn render_pivots_html(data: JsValue, entities_js: JsValue) -> Result<String, JsValue> {
    let data: PivotsResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.pivots.is_empty() && data.bridges.is_empty() {
        return Ok(String::new());
    }
    let entities: Vec<hse_core::Entity> =
        serde_wasm_bindgen::from_value(entities_js).map_err(to_js_error)?;
    let lookup = EntityLookup::new(&entities);

    let mut html = String::from(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-screenshot\"></i>&nbsp;Pivot nodes</h4>\n    \
         <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:10px\">The high-connectivity intermediaries \
         most of the graph routes through \u{2014} the highest-leverage entities to pivot on next. A \
         <span class=\"label label-warning\">critical</span> node is a single point of failure: remove it and \
         the network fragments.</p>",
    );
    for p in data.pivots.iter().take(12) {
        let pct = (p.score * 100.0).round().clamp(0.0, 100.0) as i64;
        let cut = if p.is_cut_vertex {
            " <span class=\"label label-warning\" title=\"Cut vertex \u{2014} removing this entity fragments the \
             network into disconnected pieces\">critical</span>"
                .to_string()
        } else {
            String::new()
        };
        // coreness: k-core index. 0 = isolated periphery; higher = more deeply
        // embedded. >=2 renders as a coloured badge (robust core member); 1
        // and 0 are muted (0 shows nothing at all).
        let coreness_badge = if p.coreness >= 2 {
            format!(
                " <span class=\"label label-info\" title=\"Coreness {c} \u{2014} member of the {c}-core \
                 (redundantly corroborated; robust against single-entity removal)\">\u{2b21}{c}</span>",
                c = p.coreness
            )
        } else if p.coreness == 1 {
            " <span class=\"text-muted\" style=\"font-size:10px\" title=\"Coreness 1 \u{2014} connected but not in \
             a dense cluster\">\u{2b21}1</span>"
                .to_string()
        } else {
            String::new()
        };
        html.push_str(&format!(
            "<div style=\"display:flex;align-items:center;gap:8px;margin-bottom:5px\">\n      \
             <div style=\"flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis\">\
             {label}{cut}{coreness_badge}</div>\n      \
             <div class=\"text-muted\" style=\"flex:0 0 auto;font-size:11px\">{degree} link{s}</div>\n      \
             <div style=\"flex:0 0 110px;background:rgba(127,127,127,0.2);border-radius:3px;height:10px;overflow:hidden\">\n        \
             <div style=\"width:{pct}%;height:100%;background:#9b59b6\"></div></div>\n    \
             </div>",
            label = lookup.label(&p.uid),
            degree = p.degree,
            s = if p.degree == 1 { "" } else { "s" },
        ));
    }
    if !data.bridges.is_empty() {
        let n = data.bridges.len();
        html.push_str(&format!(
            "<h5 style=\"margin:14px 0 4px\"><i class=\"glyphicon glyphicon-resize-horizontal\"></i>&nbsp;\
             Critical links <span class=\"text-muted\" style=\"font-weight:normal;font-size:11px\">\
             ({n} bridge{s})</span></h5>\n      \
             <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:6px\">Single relationships whose removal \
             would split the graph in two \u{2014} irreplaceable connections to corroborate first.</p>",
            s = if n == 1 { "" } else { "s" },
        ));
        for br in data.bridges.iter().take(12) {
            html.push_str(&format!(
                "<div style=\"font-size:12px;margin-bottom:3px;white-space:nowrap;overflow:hidden;\
                 text-overflow:ellipsis\">{from} <span class=\"text-muted\">\u{2014}</span> {to}</div>",
                from = lookup.label(&br.from_uid),
                to = lookup.label(&br.to_uid),
            ));
        }
        if n > 12 {
            html.push_str(&format!(
                "<div class=\"text-muted\" style=\"font-size:11px\">\u{2026}and {} more.</div>",
                n - 12
            ));
        }
    }
    Ok(html)
}
