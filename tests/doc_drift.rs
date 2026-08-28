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

/// `ci.yml`'s MSRV job must pin exactly the version `Cargo.toml` declares.
///
/// The MSRV floor lives in four places at once: `Cargo.toml`'s `rust-version`,
/// and three independent literals in `ci.yml` — the job NAME operators read in
/// the checks list, the `RUSTUP_TOOLCHAIN` env var that actually decides which
/// compiler runs, and the `dtolnay/rust-toolchain@<ver>` ref that installs it.
/// Nothing tied them together, so raising `rust-version` while leaving the
/// workflow alone left a green "MSRV (1.88)" check that was, in fact, no longer
/// testing the crate's real floor — a gate that passes while measuring the
/// wrong thing, which is worse than no gate.
///
/// #350 identified this and deliberately left it, because the obvious fix —
/// `dtolnay/rust-toolchain@master` plus a `toolchain:` input read from the
/// manifest — trades a pinned action for a floating one, which is the exact
/// drift class every other workflow here is pinned to avoid.
///
/// This resolves it the other way round. The action stays pinned; the guard
/// moves into the test suite, where this repo already keeps its no-silent-drift
/// ratchets. `Cargo.toml` becomes the single source of truth in the only sense
/// that matters — divergence fails a required check — and the workflow gains no
/// new moving parts.
///
/// If the three literals ever need to differ from `rust-version` on purpose,
/// that is a real decision and this test is the right place to argue with.
#[test]
fn ci_msrv_job_pins_the_version_cargo_toml_declares() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml must exist");
    let msrv = manifest
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == "rust-version").then(|| v.trim().trim_matches('"').to_string())
        })
        .expect("Cargo.toml must declare rust-version");

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect(".github/workflows/ci.yml must exist");

    // Each expected literal, paired with what it controls, so a failure names
    // the one that drifted rather than just "something is wrong".
    let required = [
        (
            format!("name: MSRV ({msrv})"),
            "the job name shown in the checks list",
        ),
        (
            format!("RUSTUP_TOOLCHAIN: \"{msrv}\""),
            "the env var that actually selects the compiler (highest rustup precedence)",
        ),
        (
            // The toolchain selector moved out of the action REF and into an
            // explicit input when third-party actions were pinned to commit
            // SHAs: `dtolnay/rust-toolchain@1.88` named a mutable branch, so the
            // version and the pin could not both live in the ref. The action is
            // now pinned by SHA and told which toolchain to install here.
            format!("toolchain: {msrv}"),
            "the `toolchain:` input that installs the compiler",
        ),
    ];

    let missing: Vec<String> = required
        .iter()
        .filter(|(needle, _)| !ci.contains(needle.as_str()))
        .map(|(needle, what)| format!("`{needle}`  — {what}"))
        .collect();

    assert!(
        missing.is_empty(),
        "Cargo.toml declares rust-version = \"{msrv}\", but ci.yml's MSRV job does not \
         pin it everywhere. Missing:\n  {}\n\
         Update .github/workflows/ci.yml so all three agree, or change rust-version.",
        missing.join("\n  ")
    );

    // A stale literal elsewhere in the file is the same defect wearing a
    // different hat: the job would install `msrv` and then be described, or
    // overridden, by a different version. Catch any OTHER `1.NN` toolchain
    // reference inside the msrv job block.
    // Line-based, because a YAML job block is defined by indentation: the job
    // key sits at two spaces, and its body is everything more deeply indented
    // (blank lines included) until the next two-space key.
    let mut in_job = false;
    let msrv_block: Vec<&str> = ci
        .lines()
        .filter(|line| {
            if line.trim_end() == "  msrv:" {
                in_job = true;
                return false;
            }
            if in_job && !line.trim().is_empty() && !line.starts_with("   ") {
                in_job = false;
            }
            in_job
        })
        .collect();
    assert!(
        !msrv_block.is_empty(),
        "ci.yml no longer has an `msrv:` job whose body this guard can read — \
         it silently stopped checking"
    );
    for (i, line) in msrv_block.iter().enumerate() {
        // Comments are prose, not configuration. This job's header comment
        // explains the rustup precedence rule by NAMING the 1.97.1 pin it has
        // to override, so scanning comments would flag the very explanation
        // that documents why the override is correct.
        if line.trim_start().starts_with('#') {
            continue;
        }
        // The action is pinned by commit SHA now, so `dtolnay/rust-toolchain@…`
        // no longer names a version — the `toolchain:` input does. Watching the
        // ref would flag the pin itself; watching the input catches the drift
        // the guard is actually for.
        let is_toolchain_ref = line.contains("RUSTUP_TOOLCHAIN")
            || line.trim_start().starts_with("toolchain:")
            || line.contains("name: MSRV");
        assert!(
            !is_toolchain_ref || line.contains(&msrv),
            "ci.yml msrv job line {} pins a toolchain other than rust-version = \"{msrv}\": {}",
            i + 1,
            line.trim()
        );
    }
}
