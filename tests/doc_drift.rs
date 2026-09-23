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

/// The operator-facing sections of `RULE.md` (the project's top-level,
/// "binding" operational doc) must send a new operator to the live SeekNow
/// host, not the dead `.eu` alias.
///
/// Regression: `src/util/keys/tests.rs`'s
/// `seeknow_signup_hint_names_the_live_ru_host_not_the_dead_eu_alias` already
/// guards `hse doctor`'s own signup hint against this class of drift — its
/// doc comment records that `see-know.eu` is a dead host
/// (`docs/SEEKNOW_WEB_AUTOMATION.md` logs it "Not responding | 000") and that
/// `see_know::client::DEFAULT_BASE` (the actual live API base) is
/// `see-know.ru`. `RULE.md`'s "Setup & Configuration: SeekNow API" and "OSINT
/// API Reference" sections independently told operators to sign up and find
/// their dashboard at `see-know.eu` — the same defect class, in the doc a
/// fresh reader hits first, just never caught because that guard only reads
/// `hse doctor`'s in-process hint string, not the markdown. `DEFAULT_BASE` is
/// a private `const` this integration test cannot import, so the literal
/// host names are asserted directly here, same as the unit test does.
///
/// Scoped to the two sections that actually point an operator at a signup
/// URL, endpoint, or provider table, rather than banning the substring
/// `see-know.eu` across the whole file: `RULE.md` legitimately covers many
/// other topics (the three RULEs, installation, troubleshooting, security
/// policy) where a *future, accurate* explanatory note naming the dead alias
/// — e.g. warning readers not to use it — would be exactly the kind of
/// content this guard exists to encourage, not forbid.
fn seeknow_section<'a>(rule: &'a str, heading: &str) -> &'a str {
    let start = rule
        .find(heading)
        .unwrap_or_else(|| panic!("RULE.md must still have a {heading:?} section"));
    let after = &rule[start..];
    let end = after[heading.len()..]
        .find("\n## ")
        .map_or(after.len(), |i| i + heading.len());
    &after[..end]
}

#[test]
fn rule_md_names_the_live_seeknow_host_not_the_dead_eu_alias() {
    let rule = fs::read_to_string(doc_path("RULE.md")).expect("RULE.md must exist");
    for heading in [
        "## Setup & Configuration: SeekNow API",
        "## OSINT API Reference",
    ] {
        let section = seeknow_section(&rule, heading);
        assert!(
            section.contains("see-know.ru"),
            "RULE.md's {heading:?} section should name the live .ru host"
        );
        assert!(
            !section.contains("see-know.eu"),
            "RULE.md's {heading:?} section must not point an operator at the dead \
             .eu host (docs/SEEKNOW_WEB_AUTOMATION.md logs it \"Not responding | 000\")"
        );
    }
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

// ---------------------------------------------------------------------------
// The organising documents: ledger ⇄ map ⇄ changelog
// ---------------------------------------------------------------------------
//
// The same defect as the credit tables above, one level up. Three documents
// make claims about each other's contents and nothing checked them:
//
//   * `docs/REQUIREMENTS_LEDGER.md` is the authority — the transcript of what
//     each requirement IS and what happened to it.
//   * `docs/ROADMAP.md` is the living map. `CLAUDE.md` requires it to be
//     "re-assessed and realigned on each iteration", and its own header says a
//     claim it makes that the code does not honour is a defect in it.
//   * `CHANGELOG.md` is the per-release record a reader consults to find out
//     what happened to a given fix.
//
// Realignment was a remembered procedure, so it drifted. On `0a09c336` the map
// still named REQ-ZOOMEYE-001, REQ-LEAKCHECK-001 and REQ-HUDSONROCK-001 as the
// "still-open siblings" of the REQ-AUGEO-001 fail-open family — all three had
// shipped (`1c2b7447`, `0fb6c2ac`, `444a8f3b`) and none had a ledger entry at
// all — while the changelog was silent on 51 recorded requirements.
//
// A repeated manual procedure standing in for a structural property is exactly
// what these guards replace: the ledger defines the vocabulary, the map may not
// cite outside it, and the changelog must account for every entry it holds.

const LEDGER_DOC: &str = "docs/REQUIREMENTS_LEDGER.md";
const ROADMAP_DOC: &str = "docs/ROADMAP.md";
const CHANGELOG_DOC: &str = "CHANGELOG.md";

fn read_doc(rel: &str) -> String {
    fs::read_to_string(doc_path(rel)).unwrap_or_else(|e| panic!("{rel} must be readable: {e}"))
}

/// Every `REQ-<AREA>-<NNN>` identifier in `text`.
///
/// Hand-scanned rather than regex-matched, like the rest of this file. The
/// shapes the documents actually use are the constraint: `AREA` is itself
/// hyphenated in places (`REQ-AU-UNCLAIMED-001`, `REQ-DEVICE-CELL-001`) and may
/// carry digits, ids sit against punctuation (`REQ-CI-008.`, `A / B`), and the
/// suffix is always exactly three digits. Anything not ending in `-NNN` is not
/// an identifier — `REQ-` on its own, or a trailing hyphen, yields nothing.
fn req_ids(text: &str) -> std::collections::BTreeSet<String> {
    const PREFIX: &str = "REQ-";
    let bytes = text.as_bytes();
    let mut out = std::collections::BTreeSet::new();
    let mut cursor = 0usize;

    while let Some(offset) = text[cursor..].find(PREFIX) {
        let start = cursor + offset;
        // `XREQ-CI-001` is not an identifier: the prefix must start a token.
        let joined_to_a_word = start > 0
            && (bytes[start - 1].is_ascii_alphanumeric()
                || bytes[start - 1] == b'_'
                || bytes[start - 1] == b'-');
        if joined_to_a_word {
            cursor = start + PREFIX.len();
            continue;
        }

        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_uppercase()
                || bytes[end].is_ascii_digit()
                || bytes[end] == b'-')
        {
            end += 1;
        }
        // A trailing hyphen is punctuation ("the REQ-CI- family"), not part of
        // the identifier.
        let mut trimmed = end;
        while trimmed > start && bytes[trimmed - 1] == b'-' {
            trimmed -= 1;
        }

        let candidate = &text[start..trimmed];
        let suffix = candidate.rsplit('-').next().unwrap_or_default();
        let well_formed = candidate.matches('-').count() >= 2
            && suffix.len() == 3
            && suffix.bytes().all(|b| b.is_ascii_digit());
        if well_formed {
            out.insert(candidate.to_string());
        }
        cursor = end.max(start + PREFIX.len());
    }
    out
}

/// The identifiers the ledger *defines* — those introduced by one of its own
/// section headings. An id that appears only in another entry's prose is a
/// cross-reference, not a record: REQ-ZOOMEYE-001 was cited four times in the
/// ledger and defined nowhere, which is precisely the hole the first guard
/// below now refuses.
fn ledger_defined_ids(ledger: &str) -> std::collections::BTreeSet<String> {
    ledger
        .lines()
        .filter(|line| line.starts_with('#'))
        .flat_map(req_ids)
        .collect()
}

/// Vacuity guard for the two guards below: a scanner that silently stopped
/// matching would make both of them pass on any pair of documents. Pins the
/// exact shapes the corpus contains, and the near-misses it must reject.
#[test]
fn the_requirement_id_scanner_reads_the_shapes_the_documents_use() {
    let found = req_ids(
        "### REQ-CORRELATOR-002 / REQ-AU-UNCLAIMED-001 (fixed), REQ-CI-008. \
         `REQ-DEVICE-CELL-001` and REQ-IP2LOCATION-002's sibling.",
    );
    assert_eq!(
        found.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "REQ-AU-UNCLAIMED-001",
            "REQ-CI-008",
            "REQ-CORRELATOR-002",
            "REQ-DEVICE-CELL-001",
            "REQ-IP2LOCATION-002",
        ],
        "the scanner must read hyphenated and digit-bearing areas, ids against \
         punctuation, and several ids on one line"
    );

    // Near-misses that must NOT be admitted, each for its own reason.
    for not_an_id in [
        "REQ-",               // the bare prefix
        "the REQ-CI- family", // trailing hyphen is punctuation
        "REQ-CI-05",          // two-digit suffix
        "REQ-CI-0051",        // four-digit suffix
        "PREQ-CI-001",        // prefix joined to a preceding word
        "REQ-ci-001",         // lowercase area
    ] {
        assert!(
            req_ids(not_an_id).is_empty(),
            "`{not_an_id}` is not a requirement id, but the scanner read one"
        );
    }
}

/// **The map may not cite a requirement the ledger does not record.**
///
/// A citation outside the ledger is a claim with no transcript behind it —
/// which is how the roadmap came to describe three shipped fixes as still open.
/// Either the requirement earns a ledger entry or the map stops naming it.
#[test]
fn the_map_never_cites_a_requirement_the_ledger_does_not_record() {
    let ledger = read_doc(LEDGER_DOC);
    let defined = ledger_defined_ids(&ledger);
    assert!(
        defined.len() > 100,
        "the ledger defines only {} requirement ids — the heading scan broke, \
         and this guard would pass vacuously",
        defined.len()
    );

    // Both documents are scanned before anything is asserted. Asserting per
    // document reports only the first one's dangling citations and hides the
    // other's behind the panic — the same "collect the survivors" discipline
    // the falsification passes use, for the same reason: one run should name
    // every instance, not the first.
    let dangling: Vec<String> = [ROADMAP_DOC, CHANGELOG_DOC]
        .iter()
        .flat_map(|doc| {
            let cited = req_ids(&read_doc(doc));
            cited
                .into_iter()
                .filter(|id| !defined.contains(id))
                .map(|id| format!("{id}  (cited in {doc})"))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        dangling.is_empty(),
        "{} requirement citation(s) have no entry of their own in {LEDGER_DOC}:\n  {}\n\
         Give each one a ledger entry (it is the authority for what a \
         requirement is), or stop citing it.",
        dangling.len(),
        dangling.join("\n  ")
    );
}

/// **The changelog must account for every requirement the ledger records.**
///
/// The ledger holds the transcript; the changelog is where a reader looks to
/// find out whether a given requirement shipped. One line per requirement is
/// the whole cost, and it makes the changelog impossible to leave behind: a new
/// ledger entry fails the suite until the changelog names it. Refuted and
/// measured-but-unchanged requirements count too — "we looked and changed
/// nothing" is an answer the reader needs, not an omission.
#[test]
fn every_requirement_the_ledger_records_is_accounted_for_in_the_changelog() {
    let ledger = read_doc(LEDGER_DOC);
    let defined = ledger_defined_ids(&ledger);
    let changelog = read_doc(CHANGELOG_DOC);
    let logged = req_ids(&changelog);

    // Vacuity guard on the LEDGER scan, not on the changelog: an empty
    // `defined` makes `missing` empty and this guard silently toothless. The
    // changelog's own count is the quantity under test, so it must not gate the
    // assertion — the first cut asserted `logged.len() > 100` and tripped on the
    // very 62-of-113 shortfall it was meant to report.
    assert!(
        defined.len() > 100,
        "{LEDGER_DOC} defines only {} requirement ids — the heading scan broke, \
         and this guard would pass vacuously",
        defined.len()
    );

    let missing: Vec<&str> = defined
        .iter()
        .filter(|id| !logged.contains(*id))
        .map(String::as_str)
        .collect();
    assert!(
        missing.is_empty(),
        "{LEDGER_DOC} records {} requirement(s) {CHANGELOG_DOC} never mentions:\n  {}\n\
         Add one line per requirement under the matching heading — `Fixed` for a \
         shipped correction, `Added` for new capability, `Investigated (no code \
         change)` for a refuted or measured-only lead — naming the defect and \
         pointing at the ledger for the transcript.",
        missing.len(),
        missing.join("\n  ")
    );
}

/// **The map's module count is the registry's.** The Layer 3 heading states how
/// many provider modules HSE registers. It is the same hand-maintained figure
/// the README carries, and the README's copy has long been locked
/// (`readme_module_overview_count_matches_registry`, `tests/architecture_parts`)
/// — while this copy was not, and the three layer headings around it had all
/// drifted from the tree (`src/util` 213 vs 215 files, `src/core` 203 vs 207,
/// `src/modules` 516 vs 518) by the time `api_discovery` became module 194.
/// A figure with a guard in one document and none in the other is the
/// "guard applied to one consumer but not its neighbour" shape the map itself
/// names; the module count is the one that means something, so it is the one
/// locked.
#[test]
fn the_map_states_the_live_registry_size() {
    let map = read_doc(ROADMAP_DOC);
    let n = huntsman_search_engine::modules::registry().len();
    let heading = map
        .lines()
        .find(|l| l.starts_with("### Layer 3 "))
        .unwrap_or_else(|| panic!("{ROADMAP_DOC} must keep its `### Layer 3` modules heading"));
    assert!(
        heading.contains(&format!(", {n} provider modules)")),
        "{ROADMAP_DOC}'s Layer 3 heading must state the live registry size ({n}); \
         update it after adding or removing a module. Found: {heading}"
    );
}
