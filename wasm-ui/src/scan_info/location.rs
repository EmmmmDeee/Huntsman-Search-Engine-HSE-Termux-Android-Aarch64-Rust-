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
    /// The fix's fused place label (`core::place::describe_fused`
    /// server-side): offline, never finer than a locality, never a street or
    /// a point of interest. Absent from an older server's response.
    place_label: Option<PlaceLabelView>,
}

/// The fields of a `place_label` this panel uses.
#[derive(Deserialize)]
struct PlaceLabelView {
    text: Option<String>,
    label_grain: Option<String>,
}

/// The OpenStreetMap zoom that frames a place of `grain`: a doorway at 18, a
/// street 16, a suburb 14, a locality 11, a region 7, a country 4 — so the map
/// link never zooms the reader in tighter than the fix can support. `12` (the
/// panel's historical fixed zoom) when the grain is unknown.
fn osm_zoom(grain: Option<&str>) -> u8 {
    match grain {
        Some("point") => 18,
        Some("street") => 16,
        Some("suburb") => 14,
        Some("locality") => 11,
        Some("region") => 7,
        Some("country") => 4,
        _ => 12,
    }
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

    // The server's place label when it sent one (the one label every surface
    // prints), else the historical locality / state join.
    let label_text = loc
        .place_label
        .as_ref()
        .and_then(|p| non_empty(&p.text))
        .map(str::to_string);
    let place = label_text.unwrap_or_else(|| {
        [non_empty(&loc.locality), non_empty(&loc.state)]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ")
    });
    let conf = loc.synergy_confidence.or(loc.confidence);
    let classes = loc.classes.unwrap_or_default();
    let zoom = osm_zoom(
        loc.place_label
            .as_ref()
            .and_then(|p| p.label_grain.as_deref()),
    );
    let osm =
        format!("https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map={zoom}/{lat}/{lon}");

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

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ-GEOLABEL-002: the map link never zooms tighter than the fix's own
    /// grain — a city-grain fix frames the city, not a doorway — and a
    /// response without a label keeps the historical zoom.
    #[test]
    fn osm_zoom_follows_the_label_grain() {
        assert_eq!(osm_zoom(Some("point")), 18);
        assert_eq!(osm_zoom(Some("street")), 16);
        assert_eq!(osm_zoom(Some("suburb")), 14);
        assert_eq!(osm_zoom(Some("locality")), 11);
        assert_eq!(osm_zoom(Some("region")), 7);
        assert_eq!(osm_zoom(Some("country")), 4);
        assert_eq!(osm_zoom(None), 12);
        assert_eq!(osm_zoom(Some("galaxy")), 12);
    }
}
