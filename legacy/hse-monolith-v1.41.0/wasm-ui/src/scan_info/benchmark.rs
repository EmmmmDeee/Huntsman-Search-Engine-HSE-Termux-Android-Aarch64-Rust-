//! Ports `src/web/js/scan_info/benchmark.js`'s templating half. Fetching
//! stays in JS; this crate takes the already-parsed `/scans/{id}/benchmark`
//! response (`crate::core::benchmark::BenchmarkReport` server-side, not
//! reachable from this crate as a real type — see the `scan_info::identities`
//! doc comment) and builds the same scorecard table fragment.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::html::escape_html;
use crate::to_js_error;

/// The subset of `crate::core::benchmark::Scorecard`'s fields this view
/// displays. `usize` server-side; deserialized as `u64` here since this
/// crate's `usize` is wasm32's 32-bit one, not the server's 64-bit one.
#[derive(Deserialize)]
struct Scorecard {
    total_entities: u64,
    total_relations: u64,
    multi_hop_depth: u64,
    graph_coverage: f64,
    corroborated_fraction: f64,
}

/// The subset of `crate::core::benchmark::BenchmarkReport`'s fields this
/// view displays.
#[derive(Deserialize)]
struct BenchmarkReport {
    entities_per_sec: f64,
    modules_run: u64,
    modules_errored: u64,
    modules_timed_out: u64,
    pivot_count: u64,
    scorecard: Scorecard,
    /// Why this scorecard is not straightforwardly comparable to another run's
    /// — see `crate::core::benchmark::BenchmarkReport::comparability_caveat`
    /// server-side. Absent when the run asked everything.
    #[serde(default)]
    comparability_caveat: Option<String>,
}

fn row(k: &str, v: &str) -> String {
    format!(
        "<tr><td>{}</td><td class=\"text-right\">{}</td></tr>",
        escape_html(k),
        escape_html(v)
    )
}

/// `Math.round(v * 100) + '%'`, for a `0.0..=1.0` fraction.
fn pct(v: f64) -> String {
    format!("{}%", (v * 100.0).round() as i64)
}

/// Builds the "Benchmark scorecard" panel fragment for a
/// `/scans/{id}/benchmark` response — unlike `scan_info::identities`, this
/// view has no "nothing to show" case (a scan always has a scorecard).
#[wasm_bindgen(js_name = renderBenchmarkHtml)]
pub fn render_benchmark_html(data: JsValue) -> Result<String, JsValue> {
    let data: BenchmarkReport = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
    let sc = &data.scorecard;
    Ok(format!(
        "<h4 style=\"margin-top:0\"><i class=\"glyphicon glyphicon-dashboard\"></i>&nbsp;Benchmark scorecard</h4>\n    \
         {caveat}\
         <div class=\"table-responsive\"><table class=\"table table-condensed\"><tbody>\n      \
         {r1}\n      {r2}\n      {r3}\n      {r4}\n      {r5}\n      {r6}\n      {r7}\n      {r8}\n      {r9}\n      {r10}\n    \
         </tbody></table></div>",
        r1 = row("Entities", &sc.total_entities.to_string()),
        r2 = row("Relations", &sc.total_relations.to_string()),
        r3 = row("Modules run", &data.modules_run.to_string()),
        r4 = row("Modules errored", &data.modules_errored.to_string()),
        r5 = row("Modules timed out", &data.modules_timed_out.to_string()),
        r6 = row("Pivot count", &data.pivot_count.to_string()),
        r7 = row("Entities/sec", &format!("{:.2}", data.entities_per_sec)),
        r8 = row("Multi-hop depth", &sc.multi_hop_depth.to_string()),
        r9 = row("Graph coverage", &pct(sc.graph_coverage)),
        r10 = row("Corroborated fraction", &pct(sc.corroborated_fraction)),
        // Above the numbers, not below them: this scorecard exists to be set
        // against another run's, and a reader who has already absorbed the
        // figures has drawn the comparison the caveat exists to qualify.
        caveat = caveat_banner(data.comparability_caveat.as_deref()),
    ))
}

/// The comparability banner, or nothing when the run asked everything.
///
/// Silence is the claim that the comparison is sound, so the banner is only
/// omitted when there is genuinely no caveat — never merely because the field
/// was missing from an older response, which deserialises to `None` and would
/// then read as a clean run. That is why the server always sends the field.
fn caveat_banner(caveat: Option<&str>) -> String {
    match caveat {
        Some(text) => format!(
            "<div class=\"alert alert-warning\" style=\"padding:8px;font-size:12px\">\n      \
             <b>Not directly comparable:</b> {}\n    </div>\n    ",
            escape_html(text)
        ),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scorecard_without_a_caveat_shows_no_banner() {
        // The absence of a banner is itself the claim that the comparison is
        // sound, so it must appear only when the run really asked everything.
        assert!(caveat_banner(None).is_empty());
        let banner = caveat_banner(Some("3 of 40 provider(s) could not be used"));
        assert!(banner.contains("Not directly comparable"));
        assert!(banner.contains("alert-warning"));
        assert!(banner.contains("3 of 40"));
    }

    #[test]
    fn a_caveat_from_the_wire_is_escaped() {
        let banner = caveat_banner(Some("<img src=x onerror=1>"));
        assert!(!banner.contains("<img"));
        assert!(banner.contains("&lt;img"));
    }
}
