//! Ports the provider-coverage panel of `src/web/js/scan_info/info.js`.
//!
//! Fetching stays in JS (the `/scans/{id}/coverage` call and its
//! never-block-the-view failure handling); this crate takes the already-fetched
//! response and builds the panel fragment, the same split every other
//! `scan_info` view uses.
//!
//! # Why the console needs this panel
//!
//! Every other view in the console shows what the scan FOUND. None of them show
//! what it managed to ASK, and without that a thin result is ambiguous: a sweep
//! that queried everything and found little is a real negative, while a sweep
//! where a third of its providers broke or were never configured is not, and
//! the two render identically everywhere else. On a Termux/Android device the
//! console is the primary interface — there is no second terminal to run
//! `hse export` in — so the distinction has to be visible here.
//!
//! The rows come from the same
//! `core::intelligence::provider_coverage_from_events` derivation that
//! `report.json` and the CLI dossier carry, so the three surfaces cannot
//! disagree about what was covered.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::escape_html;
use crate::to_js_error;

/// One provider's aggregate outcome, as
/// `core::intelligence::ProviderOutcome` serialises it: an internally-tagged
/// `kind`, with `reason` present only on the two unresolved variants.
#[derive(Deserialize)]
struct Outcome {
    kind: String,
    #[serde(default)]
    reason: Option<String>,
}

/// One row of `core::intelligence::ProviderCoverage`.
#[derive(Deserialize)]
struct Row {
    provider_id: String,
    outcome: Outcome,
    #[serde(default)]
    dispatches: u32,
    #[serde(default)]
    findings: u32,
    /// `"unavailable"` or `"scoped"` on an unresolved row; absent otherwise.
    #[serde(default)]
    skip_class: Option<String>,
}

/// The `/scans/{id}/coverage` response.
#[derive(Deserialize)]
struct CoverageResponse {
    /// Nothing broke. `None` when coverage is unknown — see
    /// [`render_coverage_html`].
    #[serde(default)]
    all_available_providers_answered: Option<bool>,
    /// Nothing broke AND nothing was out of scope.
    #[serde(default)]
    exhaustive: Option<bool>,
    /// Providers that could not be used — the actionable gaps.
    #[serde(default)]
    unavailable_count: u32,
    /// Providers the scan's own options put out of reach.
    #[serde(default)]
    out_of_scope_count: u32,
    #[serde(default)]
    provider_count: u32,
    /// `None`, never `[]`, when no dispatch events are retained.
    #[serde(default)]
    providers: Option<Vec<Row>>,
}

/// Bootstrap label class per outcome. The two unresolved outcomes are warned
/// on, never styled as ordinary results.
fn outcome_class(kind: &str) -> &'static str {
    match kind {
        "observed" => "label-success",
        "clean_negative" => "label-info",
        "failed" => "label-danger",
        "not_attempted" => "label-warning",
        _ => "label-default",
    }
}

/// Operator-facing wording for an outcome, spelling out what it licenses.
fn outcome_label(kind: &str) -> &'static str {
    match kind {
        "observed" => "answered, found something",
        "clean_negative" => "answered, holds nothing",
        "failed" => "failed",
        "not_attempted" => "never queried",
        _ => "unknown",
    }
}

/// Builds the "Provider Coverage" panel fragment for a `/scans/{id}/coverage`
/// response.
///
/// Four distinct states, deliberately not collapsed:
///
/// * **Unknown** (`providers` is `null`) — no dispatch events are retained, so
///   nothing at all can be said about coverage. Rendered as an explicit
///   "not known", never as a clean bill of health.
/// * **Exhaustive** — every provider answered and none was out of scope, so a
///   thin result here IS evidence of absence, and the panel says so.
/// * **Narrowed** — nothing broke, but the scan's own options put providers out
///   of reach. Reported calmly: this is the ordinary case, and styling it as a
///   fault on every scan is how a warning stops being read.
/// * **Degraded** — providers that could not be used. The only state that
///   demands action, so it is the only one styled as a fault.
#[wasm_bindgen(js_name = renderProviderCoverageHtml)]
pub fn render_coverage_html(data: JsValue) -> Result<String, JsValue> {
    let data: CoverageResponse = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    let Some(rows) = data.providers else {
        return Ok(panel(
            "label-default",
            "coverage not known",
            "No dispatch events are retained for this scan, so which providers answered \
             cannot be established. A thin result here is not evidence of absence.",
            String::new(),
        ));
    };

    // Unusable first, then out of scope, then the providers that answered —
    // most actionable at the top; provider id within each group, matching the
    // server's own ordering.
    let mut ordered: Vec<&Row> = rows.iter().collect();
    ordered.sort_by_key(|row| {
        let rank = match row.skip_class.as_deref() {
            Some("unavailable") => 0,
            Some("scoped") => 1,
            _ => 2,
        };
        (rank, row.provider_id.clone())
    });

    let body: String = ordered
        .iter()
        .map(|row| {
            format!(
                "<tr>\n        <td style=\"width:200px\"><code>{provider}</code></td>\n        \
                 <td style=\"width:190px\"><span class=\"label {cls}\">{label}</span></td>\n        \
                 <td class=\"text-right\" style=\"width:110px\"><span class=\"text-muted\" \
                 style=\"font-size:12px\">{dispatches} dispatch(es), {findings} found</span></td>\n        \
                 <td style=\"font-size:12px;color:var(--text-dim)\">{reason}</td>\n      </tr>",
                provider = escape_html(&row.provider_id),
                cls = outcome_class(&row.outcome.kind),
                label = outcome_label(&row.outcome.kind),
                dispatches = row.dispatches,
                findings = row.findings,
                reason = escape_html(row.outcome.reason.as_deref().unwrap_or("")),
            )
        })
        .collect();
    let table = format!(
        "<table class=\"table table-condensed\" style=\"margin-top:8px\">\n      <tbody>{body}</tbody>\n    </table>"
    );

    if data.exhaustive == Some(true) {
        return Ok(panel(
            "label-success",
            "exhaustive",
            &format!(
                "All {} provider(s) answered \u{2014} a thin result here is a real negative.",
                data.provider_count
            ),
            table,
        ));
    }
    if data.all_available_providers_answered == Some(true) {
        // Nothing broke. Reported calmly: narrowing the sweep is the ordinary
        // case, and styling it as a fault on every scan is how a warning stops
        // being read.
        return Ok(panel(
            "label-info",
            "narrowed",
            &format!(
                "Every available provider answered. {} of {} were out of scope for this scan \u{2014} \
                 silence about what THOSE cover is not evidence of absence.",
                data.out_of_scope_count, data.provider_count
            ),
            table,
        ));
    }
    Ok(panel(
        "label-danger",
        "degraded",
        &format!(
            "{} of {} provider(s) could not be used ({} more were out of scope). This scan's \
             silence about what they cover is NOT evidence of absence.",
            data.unavailable_count, data.provider_count, data.out_of_scope_count
        ),
        table,
    ))
}

/// The shared panel chrome: heading, verdict badge, one-line summary, body.
fn panel(badge_class: &str, badge: &str, summary: &str, body: String) -> String {
    format!(
        "<div class=\"panel panel-default\">\n      \
         <div class=\"panel-heading\"><b>Provider Coverage</b>\n        \
         <span class=\"text-muted pull-right\" style=\"font-size:12px\">what the scan managed to ask \u{b7} same derivation as the CLI dossier</span>\n      \
         </div>\n      \
         <div class=\"panel-body\">\n        \
         <div style=\"margin-bottom:6px\"><span class=\"label {badge_class}\">{badge}</span></div>\n        \
         <div class=\"text-muted\" style=\"font-size:12px\">{summary}</div>\n        \
         {body}\n      \
         </div>\n    \
         </div>",
        badge_class = badge_class,
        badge = escape_html(badge),
        summary = escape_html(summary),
        body = body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_narrowed_scan_is_not_styled_as_a_fault() {
        // Every real scan narrows the sweep, so styling that as a fault would
        // make the panel alarming on every scan and therefore read on none.
        let narrowed = panel(
            "label-info",
            "narrowed",
            "Every available provider answered. 40 of 120 were out of scope for this scan.",
            String::new(),
        );
        assert!(narrowed.contains("label-info"));
        assert!(!narrowed.contains("label-danger"));
        // A provider that could not be used is the one state that IS a fault.
        let degraded = panel(
            "label-danger",
            "degraded",
            "3 of 120 provider(s) could not be used.",
            String::new(),
        );
        assert!(degraded.contains("label-danger"));
        assert_ne!(
            narrowed, degraded,
            "the two states must not render alike: only one needs acting on"
        );
    }

    #[test]
    fn an_unknown_coverage_never_renders_as_a_clean_bill_of_health() {
        let html = panel(
            "label-default",
            "coverage not known",
            "No dispatch events are retained for this scan, so which providers answered \
             cannot be established. A thin result here is not evidence of absence.",
            String::new(),
        );
        assert!(html.contains("coverage not known"));
        assert!(!html.contains("exhaustive"));
        assert!(!html.contains("narrowed"));
        assert!(html.contains("not evidence of absence"));
    }

    #[test]
    fn an_unresolved_outcome_is_warned_on_not_styled_as_a_result() {
        assert_eq!(outcome_class("failed"), "label-danger");
        assert_eq!(outcome_class("not_attempted"), "label-warning");
        assert_eq!(outcome_class("observed"), "label-success");
        assert_eq!(outcome_class("clean_negative"), "label-info");
        // A clean negative and a failure must never share wording: only the
        // first licenses reading the silence as a negative.
        assert_ne!(
            outcome_label("clean_negative"),
            outcome_label("failed"),
            "the two must not be presented alike"
        );
        assert!(outcome_label("not_attempted").contains("never queried"));
    }

    #[test]
    fn a_provider_name_from_the_wire_is_escaped() {
        let html = panel("label-danger", "incomplete", "<b>x</b>", String::new());
        assert!(!html.contains("<b>x</b>"));
        assert!(html.contains("&lt;b&gt;x&lt;/b&gt;"));
    }
}
