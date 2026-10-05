//! Ports `src/web/js/scan_info/metrics.js`'s templating half. Fetching stays
//! in JS; this crate takes the already-parsed `/scans/{id}/metrics` response
//! (`crate::core::metrics::ScanMetrics`) and builds the same "Scan quality"
//! stat-tile row.
//!
//! No `escape_html` calls here, unlike every other `scan_info` port: every
//! value this view displays is a count, a fraction, or a derived statistic
//! (never a raw scan-derived string), so there is no injection surface to
//! guard — the same reason the JS original never imported `esc()` either.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::to_js_error;

/// The subset of `crate::core::metrics::TierCounts`'s fields this view
/// displays (`probable`/`candidate` are part of the payload but unused).
#[derive(Deserialize)]
struct TierCounts {
    verified: u64,
}

/// The subset of `crate::core::metrics::SeedReach`'s fields this view
/// displays (`reached_at_hop`/`reachable_fraction` are part of the payload
/// but unused).
#[derive(Deserialize)]
struct SeedReach {
    anchored: bool,
    max_depth: u64,
    reachable_total: u64,
}

/// The subset of `crate::core::metrics::ScanMetrics`'s fields this view
/// displays (`entities_by_kind`/`relations_by_kind` are part of the payload
/// but unused).
#[derive(Deserialize)]
struct ScanMetrics {
    total_entities: u64,
    tier_counts: TierCounts,
    mean_confidence: f64,
    median_confidence: f64,
    corroborated_fraction: f64,
    total_relations: u64,
    linked_entity_fraction: f64,
    graph_density: f64,
    graph_degeneracy: u64,
    main_core_size: u64,
    cross_scan_bridges: u64,
    distinct_evidence_sources: u64,
    seed_reach: SeedReach,
}

fn stat(label: &str, value: &str) -> String {
    format!(
        "<div style=\"flex:0 0 auto;min-width:80px;padding:6px 10px;background:rgba(127,127,127,0.07);\
         border-radius:4px;text-align:center\"><div style=\"font-size:18px;font-weight:600;line-height:1.1\">\
         {value}</div><div class=\"text-muted\" style=\"font-size:11px\">{label}</div></div>"
    )
}

/// `Math.round(v * 100)`, for a `0.0..=1.0` fraction.
fn pct(v: f64) -> i64 {
    (v * 100.0).round() as i64
}

/// Builds the "Scan quality" stat-tile fragment for a `/scans/{id}/metrics`
/// response, or `""` for an empty scan (`total_entities == 0`).
#[wasm_bindgen(js_name = renderMetricsHtml)]
pub fn render_metrics_html(data: JsValue) -> Result<String, JsValue> {
    let data: ScanMetrics = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.total_entities == 0 {
        return Ok(String::new());
    }

    let mut html = String::from(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-dashboard\"></i>&nbsp;Scan quality</h4>\n    \
         <div style=\"display:flex;gap:6px;flex-wrap:wrap\">",
    );
    html.push_str(&stat("Entities", &data.total_entities.to_string()));
    html.push_str(&stat("Verified", &data.tier_counts.verified.to_string()));
    html.push_str(&stat("Relations", &data.total_relations.to_string()));
    html.push_str(&stat(
        "Corroborated",
        &format!("{}%", pct(data.corroborated_fraction)),
    ));
    html.push_str(&stat(
        "Linked",
        &format!("{}%", pct(data.linked_entity_fraction)),
    ));
    if data.seed_reach.anchored {
        html.push_str(&stat("Reach", &data.seed_reach.reachable_total.to_string()));
        let hops = data.seed_reach.max_depth;
        let suffix = if hops == 1 { "" } else { "s" };
        html.push_str(&stat("Max depth", &format!("{hops} hop{suffix}")));
    }
    html.push_str(&stat(
        "Graph density",
        &format!("{}%", pct(data.graph_density)),
    ));
    html.push_str(&stat("Cross-scan", &data.cross_scan_bridges.to_string()));
    html.push_str(&stat("Mean conf", &format!("{:.2}", data.mean_confidence)));
    html.push_str(&stat(
        "Median conf",
        &format!("{:.2}", data.median_confidence),
    ));
    if data.graph_degeneracy > 0 {
        html.push_str(&stat("Core (k)", &data.graph_degeneracy.to_string()));
        html.push_str(&stat("Core size", &data.main_core_size.to_string()));
    }
    html.push_str(&stat(
        "Sources",
        &data.distinct_evidence_sources.to_string(),
    ));
    html.push_str("</div>");
    Ok(html)
}
