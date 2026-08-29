//! Ports `src/web/js/scan_info/location.js`'s templating half. Fetching
//! stays in JS; this crate takes the already-parsed `/scans/{id}/location`
//! response and builds the same "Residency fix" panel fragment.
//!
//! `best_location` is a hand-built JSON object server-side
//! (`crate::app::export::extract_au_location_fix`), not a single typed
//! struct: it takes one of two structurally different shapes depending on
//! whether the AU-059 multi-source synergy fix fired (`synergy_confidence`,
//! no `locality`) or the single-signal fallback did (`confidence`,
//! `locality`, `basis`, `source`) — every field here is therefore optional,
//! mirroring the JS original's own `!= null` checks field-by-field rather
//! than assuming either shape.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::escape_html;
use crate::to_js_error;

#[derive(Deserialize)]
struct BestLocation {
    lat: Option<f64>,
    lon: Option<f64>,
    locality: Option<String>,
    state: Option<String>,
    synergy_confidence: Option<f64>,
    confidence: Option<f64>,
    classes: Option<Vec<String>>,
    radius_km: Option<f64>,
    source: Option<String>,
    rule_id: Option<String>,
    basis: Option<String>,
}

#[derive(Deserialize)]
struct LocationResponse {
    best_location: Option<BestLocation>,
}

/// `Some(s)` only for a non-empty `s` — JS's `if (loc.field)` truthiness
/// check on a string field (falsy for `null`/`undefined` **and** `""`),
/// as opposed to a bare `!= null` check.
fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// Builds the "Residency fix" panel fragment for a `/scans/{id}/location`
/// response, or `""` when there is no location to show (no `best_location`,
/// or one without both `lat` and `lon`).
#[wasm_bindgen(js_name = renderLocationHtml)]
pub fn render_location_html(data: JsValue) -> Result<String, JsValue> {
    let data: LocationResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    let Some(loc) = data.best_location else {
        return Ok(String::new());
    };
    let (Some(lat), Some(lon)) = (loc.lat, loc.lon) else {
        return Ok(String::new());
    };

    let place = [non_empty(&loc.locality), non_empty(&loc.state)]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
    let conf = loc.synergy_confidence.or(loc.confidence);
    let classes = loc.classes.unwrap_or_default();
    let osm = format!("https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}");

    let mut rows = String::new();
    if !place.is_empty() {
        rows.push_str(&format!(
            "<div style=\"font-size:14px\"><b>{}</b></div>",
            escape_html(&place)
        ));
    }
    rows.push_str("<div class=\"text-muted\" style=\"font-size:12px;margin-top:2px\">");
    rows.push_str(&format!("{lat:.4}, {lon:.4}"));
    if let Some(radius_km) = loc.radius_km {
        rows.push_str(&format!(
            " \u{b7} \u{b1}{} km",
            escape_html(&radius_km.to_string())
        ));
    }
    if let Some(conf) = conf {
        rows.push_str(&format!(" \u{b7} confidence {conf:.2}"));
    }
    if let Some(source) = non_empty(&loc.source) {
        rows.push_str(&format!(" \u{b7} {}", escape_html(source)));
    } else if let Some(rule_id) = non_empty(&loc.rule_id) {
        rows.push_str(&format!(" \u{b7} {}", escape_html(rule_id)));
    }
    rows.push_str("</div>");
    if let Some(basis) = non_empty(&loc.basis) {
        rows.push_str(&format!(
            "<div class=\"text-muted\" style=\"font-size:11px;margin-top:2px\">basis: {}</div>",
            escape_html(basis)
        ));
    }
    if !classes.is_empty() {
        let pills: String = classes
            .iter()
            .map(|c| format!("<span class=\"label label-info\">{}</span>", escape_html(c)))
            .collect::<Vec<_>>()
            .join(" ");
        rows.push_str(&format!("<div style=\"margin-top:4px\">{pills}</div>"));
    }

    Ok(format!(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-map-marker\"></i>&nbsp;Residency fix</h4>\n    \
         <div style=\"padding:8px 10px;border-left:3px solid #5cb85c;background:rgba(92,184,92,0.07)\">\n      \
         {rows}\n      \
         <div style=\"margin-top:6px\"><a href=\"{osm_href}\" target=\"_blank\" rel=\"noopener noreferrer\" \
         class=\"btn btn-default btn-xs\"><i class=\"glyphicon glyphicon-globe\"></i>&nbsp;View on OpenStreetMap</a></div>\n    \
         </div>",
        osm_href = escape_html(&osm),
    ))
}
