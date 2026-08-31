//! Ports `src/web/js/scan_info/timeline.js`'s templating half. Fetching and
//! the loading placeholder stay in JS; this crate takes the already-fetched
//! `/scans/{id}/timeline` response (`crate::core::timeline::{TimelineEvent,
//! OnlineTenure, FootprintRecency, Movement}`, wrapped `{events, count,
//! tenure, recency, movement}` — see `scan_timeline` in
//! `src/api/scan_handlers/intel.rs`) and builds the "Footprint timeline" +
//! "Movement path" panel fragment.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, kind_pill};
use crate::to_js_error;

/// The subset of `crate::core::timeline::TimelineEvent`'s fields this view
/// displays (`ts`, `label`, `entity_uid`, and `confidence` are part of the
/// payload but unused).
#[derive(Deserialize)]
struct TimelineEvent {
    iso: String,
    kind: String,
    entity_value: String,
    entity_kind: String,
    source: String,
}

/// The subset of `crate::core::timeline::OnlineTenure`'s fields this view
/// displays (`earliest_ts`, `latest_ts`, `latest_iso`, and `event_count` are
/// part of the payload but unused).
#[derive(Deserialize)]
struct OnlineTenure {
    earliest_iso: String,
    span_years: u32,
    breach_count: usize,
}

/// The subset of `crate::core::timeline::FootprintRecency`'s fields this
/// view displays (`years_since_latest` is part of the payload but unused).
#[derive(Deserialize)]
struct FootprintRecency {
    status: String,
}

#[derive(Deserialize)]
struct MovementLeg {
    from_iso: String,
    from_coords: String,
    to_iso: String,
    to_coords: String,
    distance_km: f64,
}

#[derive(Deserialize)]
struct Movement {
    legs: Vec<MovementLeg>,
    total_km: f64,
    locations_visited: usize,
}

#[derive(Deserialize)]
struct TimelineResponse {
    events: Vec<TimelineEvent>,
    tenure: Option<OnlineTenure>,
    recency: Option<FootprintRecency>,
    movement: Option<Movement>,
}

/// One `TL_KIND` entry: dot/badge colour, glyphicon, and display label.
struct TlKind {
    icon: &'static str,
    color: &'static str,
    label: &'static str,
}

/// `helpers.js`'s (well, `timeline.js`'s own) `TL_KIND` map. `kind` is the
/// event's serde wire form (`TimelineEventKind`'s `#[serde(rename_all =
/// "snake_case")]`) — note this means the real wire value for
/// `TimelineEventKind::Generic` is `"generic"`, not `"event"`: the JS
/// original's own map has no `"generic"` entry either (its `event` entry
/// only ever matched a truly-unhandled kind via `TL_KIND[k] || TL_KIND.event`
/// fallback, never a direct hit — `as_str()`'s "event" is a *different*,
/// deliberately-non-serde-agreeing label used elsewhere, see its own doc
/// comment), so this match's `_` arm reproduces that fallback-only path
/// exactly rather than special-casing `"generic"` to the same values.
fn tl_kind(kind: &str) -> TlKind {
    match kind {
        "breach_exposure" => TlKind {
            icon: "glyphicon-alert",
            color: "#d9534f",
            label: "Breach",
        },
        "registered" => TlKind {
            icon: "glyphicon-globe",
            color: "#337ab7",
            label: "Registered",
        },
        "expiry" => TlKind {
            icon: "glyphicon-time",
            color: "#f0ad4e",
            label: "Expiry",
        },
        "account_created" => TlKind {
            icon: "glyphicon-user",
            color: "#5cb85c",
            label: "Account",
        },
        "incorporation" => TlKind {
            icon: "glyphicon-briefcase",
            color: "#337ab7",
            label: "Incorporated",
        },
        "dissolution" => TlKind {
            icon: "glyphicon-briefcase",
            color: "#777",
            label: "Dissolved",
        },
        "first_seen" => TlKind {
            icon: "glyphicon-eye-open",
            color: "#5bc0de",
            label: "First seen",
        },
        "last_seen" => TlKind {
            icon: "glyphicon-eye-close",
            color: "#777",
            label: "Last seen",
        },
        "date_of_birth" => TlKind {
            icon: "glyphicon-gift",
            color: "#777",
            label: "Born",
        },
        "location_visited" => TlKind {
            icon: "glyphicon-map-marker",
            color: "#8e44ad",
            label: "Location",
        },
        _ => TlKind {
            icon: "glyphicon-calendar",
            color: "#777",
            label: "Event",
        },
    }
}

/// `helpers.js`'s (well, `timeline.js`'s own) `day()`: the first 10
/// characters of an ISO date/datetime string (`YYYY-MM-DD`), escaped.
fn day(s: &str) -> String {
    escape_html(&s.chars().take(10).collect::<String>())
}

/// Builds the "Footprint timeline" (+ optional "Movement path") panel
/// fragment for a `/scans/{id}/timeline` response, or the guided empty-state
/// block (a full block, not `""` — the same choice
/// [`crate::scan_info::trust`]/[`crate::scan_info::communities`] made) when
/// there are no dated events.
#[wasm_bindgen(js_name = renderTimelineHtml)]
pub fn render_timeline_html(data: JsValue) -> Result<String, JsValue> {
    let data: TimelineResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    if data.events.is_empty() {
        return Ok(
            "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-time\"></i>&nbsp;Footprint timeline</h4>\n      \
             <div class=\"empty-state\"><h3>No dated events</h3>\n      \
             <p>The timeline appears when the scan surfaces dated facts \u{2014} a breach date, a domain\n      \
             registration, an account-created date. None were found in this scan's evidence.</p></div>"
                .to_string(),
        );
    }

    let span = if data.events.len() > 1 {
        format!(
            " \u{b7} {} \u{2192} {}",
            day(&data.events[0].iso),
            day(&data.events[data.events.len() - 1].iso)
        )
    } else {
        String::new()
    };
    let tenure_line = match &data.tenure {
        Some(tenure) => {
            let status = data.recency.as_ref().map_or("", |r| r.status.as_str());
            format!(
                "<p class=\"text-muted\" style=\"font-size:12px;margin-bottom:10px\">Online since \
                 <b>{earliest}</b> \u{2014} {span_years}y span, {breach_count} breach exposure{s}, \
                 footprint <b>{status}</b>.</p>",
                earliest = day(&tenure.earliest_iso),
                span_years = tenure.span_years,
                breach_count = tenure.breach_count,
                s = if tenure.breach_count == 1 { "" } else { "s" },
                status = escape_html(status),
            )
        }
        None => String::new(),
    };

    let mut html = format!(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-time\"></i>&nbsp;Footprint timeline</h4>\n    \
         {tenure_line}\n    \
         <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:10px\"><b>{n}</b> dated event{s}, \
         oldest first{span}.</p>\n    \
         <div class=\"tl\">",
        n = data.events.len(),
        s = if data.events.len() == 1 { "" } else { "s" },
    );
    for ev in &data.events {
        let k = tl_kind(&ev.kind);
        html.push_str(&format!(
            "<div class=\"tl-item\">\n      \
             <div class=\"tl-dot\" style=\"background:{color}\"></div>\n      \
             <div class=\"tl-date\">{date}</div>\n      \
             <div class=\"tl-body\">\n        \
             <span class=\"tl-badge\" style=\"background:{color}\"><i class=\"glyphicon {icon}\"></i>&nbsp;{label}</span>\n        \
             {value} {kind_pill}\n        \
             <div class=\"tl-src\">{source}</div>\n      \
             </div>\n    \
             </div>",
            color = k.color,
            date = day(&ev.iso),
            icon = k.icon,
            label = k.label,
            value = escape_html(&ev.entity_value),
            kind_pill = kind_pill(&ev.entity_kind),
            source = escape_html(&ev.source),
        ));
    }
    html.push_str("</div>");

    if let Some(mv) = &data.movement
        && !mv.legs.is_empty()
    {
        let location_color = tl_kind("location_visited").color;
        html.push_str(&format!(
                "<h4><i class=\"glyphicon glyphicon-road\"></i>&nbsp;Movement path</h4>\n      \
                 <p class=\"text-muted\" style=\"font-size:12px;margin-bottom:10px\"><b>{locations}</b> \
                 dated location fixes, <b>{total_km:.1} km</b> total straight-line distance.</p>\n      \
                 <div class=\"tl\">",
                locations = mv.locations_visited,
                total_km = mv.total_km,
            ));
        for leg in &mv.legs {
            html.push_str(&format!(
                    "<div class=\"tl-item\">\n        \
                     <div class=\"tl-dot\" style=\"background:{location_color}\"></div>\n        \
                     <div class=\"tl-date\">{from} \u{2192} {to}</div>\n        \
                     <div class=\"tl-body\">\n          \
                     <span class=\"tl-badge\" style=\"background:{location_color}\"><i class=\"glyphicon glyphicon-road\"></i>&nbsp;{km:.1} km</span>\n          \
                     {from_coords} \u{2192} {to_coords}\n        \
                     </div>\n      \
                     </div>",
                    from = day(&leg.from_iso),
                    to = day(&leg.to_iso),
                    km = leg.distance_km,
                    from_coords = escape_html(&leg.from_coords),
                    to_coords = escape_html(&leg.to_coords),
                ));
        }
        html.push_str("</div>");
    }
    Ok(html)
}
