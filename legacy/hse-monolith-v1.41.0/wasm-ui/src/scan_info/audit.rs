//! Ports `src/web/js/scan_info/audit.js`'s templating half. Fetching and the
//! loading placeholder stay in JS; this crate takes the already-fetched
//! `/scans/{id}/audit` response (`crate::audit::types::AuditReport::to_json`
//! — see `scan_audit` in `src/api/scan_handlers/diagnostics.rs`) AND the
//! scan `id` itself (needed only for the closing paragraph's `hse audit
//! --scan-id <id>` example) and builds the "Audit" panel fragment.

use std::collections::BTreeMap;

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::{escape_html, kind_pill};
use crate::to_js_error;

#[derive(Deserialize)]
struct Tiers {
    verified: usize,
    probable: usize,
    candidate: usize,
}

#[derive(Deserialize)]
struct Finding {
    severity: String,
    category: String,
    message: String,
    examples: Vec<String>,
    recommendation: String,
}

/// The subset of `to_json`'s `source_health` object this view displays
/// (`module_timeouts` is part of the payload but unused here).
#[derive(Deserialize)]
struct SourceHealth {
    engine_parser_defects: Vec<String>,
    engines_down: Vec<String>,
    engines_blocked: Vec<String>,
    module_errors: BTreeMap<String, u32>,
    http_failures: u32,
    log_lines_parsed: usize,
}

#[derive(Deserialize)]
struct Expansion {
    stops: Vec<String>,
    excluded_reasons: BTreeMap<String, u32>,
}

#[derive(Deserialize)]
struct Geo {
    coord_count: usize,
    source_count: usize,
    max_spread_km: f64,
    outliers: usize,
    has_consensus: bool,
}

#[derive(Deserialize)]
struct AuditResponse {
    score: u32,
    grade: String,
    entity_total: usize,
    tiers: Tiers,
    noise_ratio: f64,
    quarantined: usize,
    by_kind: BTreeMap<String, usize>,
    findings: Vec<Finding>,
    source_health: SourceHealth,
    expansion: Expansion,
    geo: Geo,
}

/// Score-to-colour mapping shared by the top score value and the "Grade"
/// line. Written as a cascade of `>=` comparisons (not a bounded match) to
/// mirror the JS original's own semantics exactly for any input, though
/// `score` is documented 0-100 in practice.
fn audit_score_color(s: u32) -> &'static str {
    if s >= 90 {
        "#3c763d"
    } else if s >= 75 {
        "#5cb85c"
    } else if s >= 60 {
        "#8a6d3b"
    } else if s >= 40 {
        "#d9534f"
    } else {
        "#a94442"
    }
}

fn sev_badge(sev: &str) -> String {
    let c = match sev {
        "CRITICAL" => "#a94442",
        "HIGH" => "#d9534f",
        "MEDIUM" => "#8a6d3b",
        "LOW" => "#777",
        _ => "#999",
    };
    format!(
        "<span style=\"display:inline-block;min-width:64px;text-align:center;color:#fff;\
         background:{c};border-radius:3px;font-size:11px;font-weight:600;padding:1px 6px\">{sev}</span>",
        sev = escape_html(sev)
    )
}

/// Builds the "Audit" panel fragment for a `/scans/{id}/audit` response.
#[wasm_bindgen(js_name = renderAuditHtml)]
pub fn render_audit_html(data: JsValue, id: &str) -> Result<String, JsValue> {
    let data: AuditResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    let col = audit_score_color(data.score);

    let mut by_kind: Vec<(&String, &usize)> = data.by_kind.iter().collect();
    by_kind.sort_by(|a, b| b.1.cmp(a.1));
    let kinds: String = by_kind
        .iter()
        .map(|(k, n)| format!("{}&nbsp;{n}", kind_pill(k)))
        .collect::<Vec<_>>()
        .join("&nbsp; ");

    let mut sh_bits: Vec<String> = Vec::new();
    if !data.source_health.engine_parser_defects.is_empty() {
        sh_bits.push(format!(
            "parser-defect: {}",
            data.source_health
                .engine_parser_defects
                .iter()
                .map(|s| escape_html(s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !data.source_health.engines_down.is_empty() {
        sh_bits.push(format!(
            "down: {}",
            data.source_health
                .engines_down
                .iter()
                .map(|s| escape_html(s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !data.source_health.engines_blocked.is_empty() {
        sh_bits.push(format!(
            "blocked: {}",
            data.source_health
                .engines_blocked
                .iter()
                .map(|s| escape_html(s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !data.source_health.module_errors.is_empty() {
        sh_bits.push(format!(
            "module errors: {}",
            data.source_health
                .module_errors
                .iter()
                .map(|(k, v)| format!("{}\u{d7}{v}", escape_html(k)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if data.source_health.http_failures > 0 {
        sh_bits.push(format!(
            "HTTP failures: {}",
            data.source_health.http_failures
        ));
    }

    let mut ex_bits: Vec<String> = data
        .expansion
        .excluded_reasons
        .iter()
        .map(|(k, v)| format!("{}\u{d7}{v}", escape_html(k)))
        .collect();
    if !data.expansion.stops.is_empty() {
        ex_bits.push(format!(
            "stops: {}",
            data.expansion
                .stops
                .iter()
                .map(|s| escape_html(s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let findings: String = data
        .findings
        .iter()
        .map(|f| {
            let ex: String = f
                .examples
                .iter()
                .map(|x| format!("<li><code>{}</code></li>", escape_html(x)))
                .collect();
            let border_color = if f.severity == "CRITICAL" || f.severity == "HIGH" {
                "#d9534f"
            } else {
                "#8a6d3b"
            };
            format!(
                "<div style=\"border-left:4px solid #ddd;border-left-color:{border_color};\
                 background:#fafafa;padding:10px 12px;margin-bottom:10px;border-radius:3px\">\n      \
                 <div>{badge}&nbsp;<b>{category}</b></div>\n      \
                 <div style=\"margin:6px 0\">{message}</div>\n      \
                 {ex_list}\
                 <div style=\"color:var(--success)\"><i class=\"glyphicon glyphicon-arrow-right\"></i>&nbsp;{rec}</div>\n    \
                 </div>",
                badge = sev_badge(&f.severity),
                category = escape_html(&f.category),
                message = escape_html(&f.message),
                ex_list = if ex.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<ul style=\"margin:4px 0 6px 18px;color:var(--text-muted)\">{ex}</ul>\n      "
                    )
                },
                rec = escape_html(&f.recommendation),
            )
        })
        .collect();

    let quarantined = if data.quarantined > 0 {
        format!(
            " \u{b7} <span style=\"color:var(--warning)\">{} quarantined</span>",
            data.quarantined
        )
    } else {
        String::new()
    };
    let geo = if data.geo.coord_count > 0 {
        let outliers = if data.geo.outliers > 0 {
            format!(
                " \u{b7} <span style=\"color:var(--danger)\">{} outlier(s)</span>",
                data.geo.outliers
            )
        } else {
            String::new()
        };
        format!(
            "<div class=\"text-muted\" style=\"margin-top:2px\">geo: {} fix(es) / {} source(s) \u{b7} \
             spread {} km \u{b7} {}{outliers}</div>",
            data.geo.coord_count,
            data.geo.source_count,
            data.geo.max_spread_km.round(),
            if data.geo.has_consensus {
                "consensus"
            } else {
                "no consensus"
            },
        )
    } else {
        String::new()
    };

    Ok(format!(
        "<div class=\"row\">\n      \
         <div class=\"col-sm-3 col-xs-6\"><div class=\"stat-card\"><div class=\"lab\">Quality score</div>\n        \
         <div class=\"val\" style=\"color:{col}\">{score}<span style=\"font-size:14px;color:var(--text-dim)\">/100</span></div></div></div>\n      \
         <div class=\"col-sm-9 col-xs-6\"><div class=\"stat-card\" style=\"text-align:left\">\n        \
         <div class=\"lab\">Grade</div><div style=\"font-size:15px;color:{col};font-weight:600\">{grade}</div>\n        \
         <div class=\"text-muted\" style=\"margin-top:4px\">{entity_total} entities \u{b7} {verified} verified \u{b7} \
         {probable} probable \u{b7} {candidate} candidate \u{b7} {noise}% noise{quarantined}</div>\n        \
         {geo}\n      \
         </div></div>\n    \
         </div>\n    \
         {kinds_p}\
         {sh_alert}\
         {ex_alert}\
         <h4 style=\"margin-top:6px\">Findings {badge}</h4>\n    \
         {findings_or_empty}\n    \
         <p class=\"text-muted\" style=\"font-size:12px;margin-top:10px\">{log_line}Source-health signals here come \
         from this scan's own stored events and live engine status automatically \u{2014} a bare \
         <code>hse audit --scan-id {id}</code> needs <code>--log &lt;debug-log-file&gt;</code> for the same \
         signals, so a CLI re-run without it will show a cleaner (less complete) report. Re-run after fixes to \
         confirm the score improves.</p>",
        score = data.score,
        grade = escape_html(&data.grade),
        entity_total = data.entity_total,
        verified = data.tiers.verified,
        probable = data.tiers.probable,
        candidate = data.tiers.candidate,
        noise = (data.noise_ratio * 100.0).round(),
        kinds_p = if kinds.is_empty() {
            String::new()
        } else {
            format!("<p class=\"text-muted\" style=\"margin:6px 0 12px\">{kinds}</p>\n    ")
        },
        sh_alert = if sh_bits.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"alert alert-warning\" style=\"padding:8px 12px\"><b>Source health:</b> {}</div>\n    ",
                sh_bits.join(" \u{b7} ")
            )
        },
        ex_alert = if ex_bits.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"alert alert-info\" style=\"padding:8px 12px\"><b>Expansion ledger:</b> {}</div>\n    ",
                ex_bits.join(" \u{b7} ")
            )
        },
        badge = if data.findings.is_empty() {
            String::new()
        } else {
            format!("<span class=\"badge\">{}</span>", data.findings.len())
        },
        findings_or_empty = if findings.is_empty() {
            "<div class=\"alert alert-success\">\u{2713} No weaknesses detected \u{2014} results are individualised \
             and verifiable.</div>"
                .to_string()
        } else {
            findings
        },
        log_line = if data.source_health.log_lines_parsed > 0 {
            format!(
                "Audited {} scan-log line(s). ",
                data.source_health.log_lines_parsed
            )
        } else {
            String::new()
        },
        id = escape_html(id),
    ))
}
