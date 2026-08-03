//! Doc-vs-code drift guards: documentation claims that assert a NUMBER the code
//! also defines must be checked against the code, not maintained by hand.
//!
//! Motivating regression: PR #326 corrected `see_know`'s `ENDPOINT_COSTS` after
//! the table was found to over-bill three endpoints against the SeekNow
//! contract (`/search/deep` 3→1, `/username/social` 2→1, `/username/history`
//! 2→1). Nothing pointed at the operator docs, so `ENTERPRISE_GUIDE.md` and
//! `HIGH_VALUE_QUERY_SYSTEM.md` kept quoting the OLD prices — and, worse, kept
//! ROI worked examples computed from them. A reader budgeting a scan would have
//! planned around a 3× overstatement of `/search/deep`.
//!
//! These guards make that class of drift impossible: the docs' credit claims
//! are parsed and compared to `get_endpoint_cost`, so changing a price in code
//! fails CI until the docs follow.

use huntsman_search_engine::util::see_know::config::get_endpoint_cost;
use std::fs;
use std::path::{Path, PathBuf};

/// Docs that quote SeekNow per-endpoint credit prices.
const COST_QUOTING_DOCS: &[&str] = &[
    "docs/ENTERPRISE_GUIDE.md",
    "docs/HIGH_VALUE_QUERY_SYSTEM.md",
];

fn doc_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Reads the leading numeric run: `"3 credits (only on fast miss)"` → `3.0`,
/// `"95, Cost=3.0"` → `95.0`. `None` when the text does not start with a
/// number. Takes the numeric PREFIX rather than a whitespace token, so a
/// trailing delimiter (`95,`) still parses.
fn leading_number(s: &str) -> Option<f32> {
    let s = s.trim_start();
    let end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .unwrap_or(s.len());
    s[..end].parse::<f32>().ok()
}

/// The real cost(s) `path` refers to, or an empty vec when it names nothing the
/// cost table knows about.
///
/// Resolving to the ACTUAL entries (rather than calling `get_endpoint_cost`
/// directly) matters because that function returns a 1.0 DEFAULT for anything
/// unrecognised — so a typo'd or invented path would silently "agree" with any
/// doc line that happens to say 1 credit.
///
/// A trailing `/*` is honoured as the prefix shorthand the docs legitimately use
/// (`/enterprise/discord/*: 5 credits each`). It expands to every matching
/// endpoint, all of which must charge the quoted price — so the shorthand is
/// verified, not waved through.
fn resolved_costs(path: &str) -> Vec<(&'static str, f32)> {
    let table = huntsman_search_engine::util::see_know::config::ENDPOINT_COSTS;
    if let Some(prefix) = path.strip_suffix('*') {
        return table
            .iter()
            .filter(|(name, _)| name.starts_with(prefix))
            .copied()
            .collect();
    }
    table
        .iter()
        .filter(|(name, _)| *name == path)
        .copied()
        .collect()
}

#[test]
fn doc_credit_tables_match_the_endpoint_cost_table() {
    // Canonical cost-table form, e.g. `/search/deep: 3 credits (only on fast miss)`.
    let mut checked = 0usize;
    let mut drift: Vec<String> = Vec::new();

    for rel in COST_QUOTING_DOCS {
        let text = fs::read_to_string(doc_path(rel)).unwrap();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if !line.starts_with('/') {
                continue;
            }
            let Some((path, rest)) = line.split_once(": ") else {
                continue;
            };
            // Only the `N credit(s)` form here; `Value=…, Cost=…` is checked by
            // the sibling test below.
            if !rest.contains("credit") {
                continue;
            }
            let Some(claimed) = leading_number(rest) else {
                continue;
            };
            let resolved = resolved_costs(path);
            if resolved.is_empty() {
                drift.push(format!(
                    "{rel}:{} quotes a price for `{path}`, which is not in ENDPOINT_COSTS",
                    i + 1
                ));
                continue;
            }
            checked += 1;
            for (name, actual) in resolved {
                if (claimed - actual).abs() > f32::EPSILON {
                    drift.push(format!(
                        "{rel}:{} says `{path}` costs {claimed} credit(s), but \
                         ENDPOINT_COSTS bills {actual} for `{name}`",
                        i + 1
                    ));
                }
            }
        }
    }

    assert!(
        checked >= 10,
        "sanity: expected 10+ parseable `<path>: N credits` claims across {COST_QUOTING_DOCS:?}, \
         found {checked} — the docs were restructured and this guard silently stopped checking"
    );
    drift.sort();
    assert!(
        drift.is_empty(),
        "operator docs quote credit prices the code does not charge \
         (a reader would budget a scan wrongly):\n  {}",
        drift.join("\n  ")
    );
}

#[test]
fn doc_roi_examples_use_the_real_credit_costs() {
    // Worked-example form, e.g. `/search/deep: Value=95, Cost=3.0, ROI=31.7`.
    // Both the Cost (vs the code) and the ROI arithmetic (Value/Cost, the
    // formula the surrounding prose states) are checked, so a corrected price
    // cannot leave a stale ROI ranking behind — the ranking is the whole point
    // of those examples.
    let mut checked = 0usize;
    let mut drift: Vec<String> = Vec::new();

    for rel in COST_QUOTING_DOCS {
        let text = fs::read_to_string(doc_path(rel)).unwrap();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if !line.starts_with('/') || !line.contains("Cost=") {
                continue;
            }
            let Some((path, rest)) = line.split_once(": ") else {
                continue;
            };
            let field = |key: &str| -> Option<f32> {
                let at = rest.find(key)?;
                leading_number(
                    rest[at + key.len()..]
                        .trim_start()
                        .trim_start_matches(|c: char| !c.is_ascii_digit() && c != '.' && c != '-'),
                )
            };
            let (Some(value), Some(cost)) = (field("Value="), field("Cost=")) else {
                continue;
            };
            if resolved_costs(path).is_empty() {
                drift.push(format!(
                    "{rel}:{} scores `{path}`, which is not in ENDPOINT_COSTS",
                    i + 1
                ));
                continue;
            }
            checked += 1;
            let actual = get_endpoint_cost(path);
            if (cost - actual).abs() > f32::EPSILON {
                drift.push(format!(
                    "{rel}:{} scores `{path}` at Cost={cost}, but ENDPOINT_COSTS \
                     bills {actual}",
                    i + 1
                ));
            }
            // ROI is Value/Cost; the docs round to 1dp, so allow a little slack.
            if let Some(roi) = field("ROI=")
                && cost > 0.0
                && (roi - value / cost).abs() > 0.1
            {
                drift.push(format!(
                    "{rel}:{} scores `{path}` ROI={roi}, but Value/Cost = {}",
                    i + 1,
                    value / cost
                ));
            }
        }
    }

    assert!(
        checked >= 5,
        "sanity: expected 5+ parseable `Value=…, Cost=…` ROI examples, found {checked} \
         — the docs were restructured and this guard silently stopped checking"
    );
    drift.sort();
    assert!(
        drift.is_empty(),
        "operator docs rank endpoints by stale credit costs \
         (the ROI ordering they teach is wrong):\n  {}",
        drift.join("\n  ")
    );
}
