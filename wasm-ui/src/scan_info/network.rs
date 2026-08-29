//! Ports `src/web/js/scan_info/network.js`'s templating half. Fetching and
//! the loading placeholder stay in JS; this crate takes the already-fetched
//! `/scans/{id}/network` response (`crate::core::network::SubjectNetwork` —
//! see `scan_network` in `src/api/scan_handlers/analysis.rs`) AND the scan
//! `id` itself (needed only for the "Browse" links in both empty states) and
//! builds the "Network" panel fragment.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, group_icon, kind_pill};
use crate::to_js_error;

/// The subset of `crate::core::network::Connection`'s fields this view
/// displays (`uid`, `relation`, and `tags` are part of the payload but
/// unused).
#[derive(Deserialize)]
struct Connection {
    value: String,
    kind: String,
    label: String,
    edge_confidence: f64,
    entity_confidence: f64,
    classification: String,
}

#[derive(Deserialize)]
struct ConnectionGroup {
    key: String,
    label: String,
    items: Vec<Connection>,
    total: usize,
}

/// The subset of `crate::core::network::SubjectCard`'s fields this view
/// displays (`uid` is part of the payload but unused).
#[derive(Deserialize)]
struct SubjectCard {
    value: String,
    kind: String,
    confidence: f64,
    classification: String,
}

#[derive(Deserialize)]
struct SubjectNetwork {
    subject: Option<SubjectCard>,
    groups: Vec<ConnectionGroup>,
    direct_count: usize,
    reachable_count: usize,
    edge_count: usize,
}

/// `helpers.js`'s `trunc()`: truncates to `n` characters (not bytes) plus an
/// ellipsis when longer, else returned as-is.
fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}\u{2026}", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

/// `helpers.js`'s `extLink()`: an external `http(s)` link wrapped in
/// `<a target="_blank">`, or just the escaped (optionally truncated) text
/// for anything else (`javascript:`/`data:` stay inert).
fn ext_link(url: &str, max_text: usize) -> String {
    let text = escape_html(&truncate(url, max_text));
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return text;
    }
    format!(
        "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{text}</a>",
        escape_html(url)
    )
}

/// Builds the "Network" panel fragment for a `/scans/{id}/network` response.
#[wasm_bindgen(js_name = renderNetworkHtml)]
pub fn render_network_html(data: JsValue, id: &str) -> Result<String, JsValue> {
    let data: SubjectNetwork = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    let browse_link = format!("#/scaninfo?id={}&tab=browse", escape_html(id));

    let Some(subject) = data.subject else {
        return Ok(format!(
            "<div class=\"empty-state\"><h3>No subject network yet</h3>\n      \
             <p>Connections appear once the scan derives relations \u{2014} people, accounts, aliases,\n      \
             organisations and locations bound to the subject. Run a deeper scan (<code>--depth \u{2265} 1</code>) \
             or open\n      <a href=\"{browse_link}\">Browse</a> for the raw entities.</p></div>"
        ));
    };

    let mut html = format!(
        "<div class=\"net-hero\">\n    \
         <div class=\"net-hero-main\">\n      \
         <div class=\"net-hero-name\">{value}</div>\n      \
         <div class=\"net-hero-meta\">{kind_pill}\n        \
         <span class=\"cls c-{cls}\">{cls_text}</span>\n        \
         <span class=\"text-muted\" style=\"font-size:11px\">C_eff {conf:.2}</span></div>\n    \
         </div>\n    \
         <div class=\"net-hero-stats\">\n      \
         <div class=\"net-stat\"><div class=\"v\">{direct}</div><div class=\"l\">direct</div></div>\n      \
         <div class=\"net-stat\"><div class=\"v\">{reachable}</div><div class=\"l\">reachable</div></div>\n      \
         <div class=\"net-stat\"><div class=\"v\">{edges}</div><div class=\"l\">edges</div></div>\n    \
         </div>\n  \
         </div>",
        value = escape_html(&subject.value),
        kind_pill = kind_pill(&subject.kind),
        cls = escape_html(&subject.classification),
        cls_text = escape_html(&subject.classification),
        conf = subject.confidence,
        direct = data.direct_count,
        reachable = data.reachable_count,
        edges = data.edge_count,
    );

    if data.groups.is_empty() {
        html.push_str(&format!(
            "<div class=\"empty-state\"><p>The subject has no derived connections yet \u{2014}\n      \
             <a href=\"{browse_link}\">Browse</a> the raw entities, or run a deeper scan to map the network.</p></div>"
        ));
    }
    for g in &data.groups {
        let more = if g.total > g.items.len() {
            format!(
                " <span class=\"text-muted\" style=\"font-weight:400;font-size:11px\">top {} of {}</span>",
                g.items.len(),
                g.total
            )
        } else {
            String::new()
        };
        html.push_str(&format!(
            "<div class=\"net-group\">\n      \
             <div class=\"net-group-head\"><i class=\"glyphicon {icon}\"></i>&nbsp;{label}\n        \
             <span class=\"badge\">{total}</span>{more}</div>",
            icon = group_icon(&g.key).unwrap_or("glyphicon-link"),
            label = escape_html(&g.label),
            total = g.total,
        ));
        for c in &g.items {
            let conf = (c.edge_confidence * 100.0).round().clamp(0.0, 100.0) as i64;
            let node_conf = (c.entity_confidence * 100.0).round() as i64;
            let tier_pill = if c.classification.is_empty() {
                String::new()
            } else {
                format!(
                    "<span class=\"cls c-{cls}\" title=\"far-end entity {tier} \u{b7} node confidence {node_conf}%\">{tier}</span>",
                    cls = escape_html(&c.classification),
                    tier = escape_html(&c.classification),
                )
            };
            html.push_str(&format!(
                "<div class=\"net-conn\">\n        \
                 <span class=\"net-rel\">{label}</span>\n        \
                 <span class=\"net-conn-val\">{link}</span>\n        \
                 {kind_pill}{tier_pill}\n        \
                 <span class=\"net-conf\" title=\"link confidence {conf}%\"><span class=\"net-conf-bar\" style=\"width:{conf}%\"></span></span>\n      \
                 </div>",
                label = escape_html(&c.label),
                link = ext_link(&c.value, 72),
                kind_pill = kind_pill(&c.kind),
            ));
        }
        html.push_str("</div>");
    }
    Ok(html)
}
