//! Differential test against M D's legacy stolen.tax output.
//!
//! `tests/fixtures/legacy_764ce8e/stolen_tax_expected.json` was recorded by running
//! the old-tree implementation (restore commit `1dfb5c9d` merged onto `98c77fd`,
//! *without* the uncommitted guard) on `stolen_tax_cases.json`, through the same
//! decode → normalise → build → dedup → partial-marking steps its `process` runs.
//!
//! The port must reproduce every legacy record (same kind, identity, spelling,
//! confidence, tags and evidence source) with one documented exception, the
//! blank-name/host guard:
//! - a legacy `breach:osintcat` marker (osintcat row with no corpus name) and a
//!   legacy `stealer:unknown` marker (stealer hit with no host) are placeholders
//!   and are not emitted;
//! - a legacy evidence fact rendered as `unknown` (absent date / OS / IP) is
//!   omitted from the sentence; every supplied fact is kept, in the same order.
//!
//! The port emits nothing the legacy output lacks.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::http::{Response, TransportFailure};

const CASES: &str = include_str!("../../tests/fixtures/legacy_764ce8e/stolen_tax_cases.json");
const EXPECTED: &str = include_str!("../../tests/fixtures/legacy_764ce8e/stolen_tax_expected.json");

/// Serves each case's recorded v2 envelope for its path.
struct Envelopes(BTreeMap<String, Vec<u8>>);

impl Transport for Envelopes {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let path = request.url.rsplit_once("path=").map(|(_, p)| p).unwrap();
        let body = self
            .0
            .get(path)
            .cloned()
            .unwrap_or_else(|| br#"{"success":true,"data":null}"#.to_vec());
        Ok(Response {
            status: 200,
            headers: Vec::new(),
            body,
            truncated: false,
        })
    }
}

fn kind_of(debug_name: &str) -> EntityKind {
    serde_json::from_value(Value::String(debug_name.to_ascii_lowercase())).unwrap()
}

/// A legacy placeholder marker the guard intentionally no longer mints.
fn guard_dropped(e: &Value) -> bool {
    let value = e["value"].as_str().unwrap();
    let summaries: Vec<&str> = e["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|ev| ev["summary"].as_str().unwrap())
        .collect();
    e["kind"] == "Credential"
        && (value == "stealer:unknown"
            || (value == "breach:osintcat"
                && summaries.iter().all(|s| s.contains("path=osintcat"))))
}

/// `Head (a, b; c; d)` → (`Head`, [a, b, c, d]).
fn facts(summary: &str) -> (String, Vec<String>) {
    match summary.strip_suffix(')').and_then(|s| s.split_once(" (")) {
        Some((head, inner)) => (
            head.to_owned(),
            inner
                .split("; ")
                .flat_map(|part| part.split(", "))
                .map(str::to_owned)
                .collect(),
        ),
        None => (summary.to_owned(), Vec::new()),
    }
}

/// What the guard makes of a legacy evidence sentence: `unknown` stand-ins gone.
fn guarded_facts(summary: &str) -> (String, Vec<String>) {
    let (head, list) = facts(summary);
    (
        head,
        list.into_iter()
            .filter(|f| !f.ends_with(": unknown") && !f.ends_with("=unknown"))
            .collect(),
    )
}

fn sorted(
    mut v: Vec<(String, (String, Vec<String>), Value)>,
) -> Vec<(String, (String, Vec<String>), Value)> {
    v.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    v
}

#[test]
#[allow(clippy::too_many_lines)] // one walk over the recorded cases, assertion by assertion
fn port_matches_the_legacy_stolen_tax_output_modulo_the_guard() {
    let cases: Vec<Value> = serde_json::from_str(CASES).unwrap();
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    let expected_cases = expected["cases"].as_array().unwrap();
    assert_eq!(cases.len(), expected_cases.len());
    let keys = Keys::parse(&format!("{KEY_SLOT}=st-fixture-key-0123456789\n")).unwrap();
    let mut guard_drops = 0;

    for (case, want) in cases.iter().zip(expected_cases) {
        let name = case["name"].as_str().unwrap();
        assert_eq!(want["name"], case["name"]);
        let query = case["query"].as_str().unwrap();
        let transport = Envelopes(
            case["paths"]
                .as_array()
                .unwrap()
                .iter()
                .map(|step| {
                    (
                        step[0].as_str().unwrap().to_owned(),
                        serde_json::to_vec(&step[1]).unwrap(),
                    )
                })
                .collect(),
        );
        let legacy_failed: Vec<&str> = want["failed_paths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();

        let report = match lookup(&transport, &keys, query, "fixture-scan", 0) {
            Ok(report) => {
                assert!(
                    want["error"].is_null(),
                    "{name}: legacy failed, port did not"
                );
                report
            }
            Err(StolenTaxError::Failed(first)) => {
                let legacy_error = want["error"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{name}: port failed ({first:?}), legacy did not"));
                assert_eq!(Some(&first.path), legacy_failed.first(), "{name}");
                let provider_words = legacy_error
                    .split_once("success=false: ")
                    .map_or(legacy_error, |(_, w)| w);
                assert!(
                    first.reason.contains(provider_words),
                    "{name}: {first:?} vs {legacy_error}"
                );
                assert_eq!(want["entities"].as_array().unwrap().len(), 0);
                continue;
            }
            Err(other) => panic!("{name}: {other}"),
        };

        let failed: Vec<&str> = report.failed_paths.iter().map(|f| f.path).collect();
        assert_eq!(failed, legacy_failed, "{name}: failed paths");

        let mut legacy_kept = Vec::new();
        for e in want["entities"].as_array().unwrap() {
            if guard_dropped(e) {
                guard_drops += 1;
                continue;
            }
            let kind = kind_of(e["kind"].as_str().unwrap());
            let value = normalise(&kind, e["value"].as_str().unwrap());
            for ev in e["evidence"].as_array().unwrap() {
                legacy_kept.push((
                    format!("{kind:?}|{value}|{}|{}", e["raw_value"], e["confidence"]),
                    guarded_facts(ev["summary"].as_str().unwrap()),
                    json!({"source": ev["source"], "attributes": ev["attributes"], "tags": e["tags"]}),
                ));
            }
        }
        let mut ported = Vec::new();
        for e in &report.entities {
            let mut tags = e.tags.clone();
            tags.sort();
            for ev in &e.evidence {
                ported.push((
                    format!(
                        "{:?}|{}|{}|{}",
                        e.kind,
                        e.value,
                        Value::String(e.raw_value.clone()),
                        json!(e.confidence)
                    ),
                    facts(&ev.summary),
                    json!({"source": ev.provenance.source, "attributes": ev.attributes, "tags": tags}),
                ));
            }
        }
        assert_eq!(
            sorted(ported),
            sorted(legacy_kept),
            "{name}: every legacy record kept (modulo the guard), nothing extra"
        );

        let legacy_n = want["entities"].as_array().unwrap().len();
        match want["truncation"].as_str() {
            Some(legacy_note) => {
                let note = report.truncation.as_deref().expect("partial is declared");
                assert_eq!(
                    note,
                    legacy_note.replacen(
                        &format!("{legacy_n} retrieved"),
                        &format!("{} retrieved", report.entities.len()),
                        1
                    ),
                    "{name}: partial note"
                );
            }
            None => assert!(report.truncation.is_none(), "{name}: not partial"),
        }
    }
    // The guard fired on the fixtures that exercise it, and only there.
    assert_eq!(guard_drops, 4, "legacy placeholder markers in the fixtures");
}

#[test]
fn port_keeps_the_legacy_endpoints_and_budget() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    let urls: Vec<String> = PATHS.iter().map(|p| format!("{API_BASE}{p}")).collect();
    let legacy: Vec<&str> = expected["api_urls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap())
        .collect();
    assert_eq!(urls, legacy);
    // The monolith's module budget bounded the whole cascade; so does LOOKUP_BUDGET.
    assert_eq!(
        u128::from(expected["max_timeout_ms"].as_u64().unwrap()),
        LOOKUP_BUDGET.as_millis()
    );
}

#[test]
fn guard_rewrite_only_removes_unknown_facts() {
    assert_eq!(
        guarded_facts("Breach: DB_A (records: 2, date: unknown)"),
        ("Breach: DB_A".to_owned(), vec!["records: 2".to_owned()])
    );
    assert_eq!(
        guarded_facts(
            "Stealer hit: stealer:H (date: unknown; path=hudsonrock; os=unknown; ip=unknown)"
        ),
        (
            "Stealer hit: stealer:H".to_owned(),
            vec!["path=hudsonrock".to_owned()]
        )
    );
    assert_eq!(
        facts("Breach: Bare"),
        ("Breach: Bare".to_owned(), Vec::new())
    );
}

const SINGLE_KEY: &str =
    include_str!("../../tests/fixtures/legacy_764ce8e/stolen_tax_single_key_expected.json");

/// Every request gets the scenario's one-key answer; logs (path, status) and checks
/// each attempt carried the one configured key.
struct OneKey {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    bearer: String,
    log: std::cell::RefCell<Vec<(String, u16)>>,
}

impl Transport for OneKey {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let path = request.url.rsplit_once("path=").map(|(_, p)| p).unwrap();
        assert_eq!(
            request.header_value("authorization"),
            Some(self.bearer.as_str()),
            "every attempt is on the one key"
        );
        self.log.borrow_mut().push((path.to_owned(), self.status));
        Ok(Response {
            status: self.status,
            headers: self.headers.clone(),
            body: self.body.clone(),
            truncated: false,
        })
    }
}

/// The monolith with a one-key pool (derived from the two-key rotation capture, see
/// `CAPTURE.md`): a `429` gets three attempts on the key, everything else one, and
/// then the path fails; with every path failing the lookup fails on the first.
#[test]
fn single_key_attempts_match_the_legacy_cascade_with_one_key() {
    let fixture: Value = serde_json::from_str(SINGLE_KEY).unwrap();
    let key = "st-fixture-key-0123456789";
    let keys = Keys::parse(&format!("{KEY_SLOT}={key}\n")).unwrap();
    let scenarios = fixture["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 9);
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let answer = &scenario["first_key_answer"];
        let status = u16::try_from(answer["status"].as_u64().unwrap()).unwrap();
        let transport = OneKey {
            status,
            headers: answer["headers"]
                .as_object()
                .map(|h| {
                    h.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
                        .collect()
                })
                .unwrap_or_default(),
            body: answer["body"].as_str().unwrap().as_bytes().to_vec(),
            bearer: format!("Bearer {key}"),
            log: std::cell::RefCell::new(Vec::new()),
        };
        let clock = crate::deadline::FakeClock::new();
        let err = lookup_with_clock(&transport, &clock, &keys, "user@example.com", "s", 0)
            .expect_err(name);

        // Same attempts, path by path, in cascade order.
        let mut legacy = Vec::new();
        for path in PATHS {
            for s in scenario["attempts"][path].as_array().unwrap() {
                legacy.push((path.to_owned(), u16::try_from(s.as_u64().unwrap()).unwrap()));
            }
        }
        assert_eq!(*transport.log.borrow(), legacy, "{name}: attempts");
        // Retry-After: 0 in the capture, so no pause was taken.
        assert_eq!(clock.elapsed(), Duration::ZERO, "{name}");

        let StolenTaxError::Failed(first) = &err else {
            panic!("{name}: {err:?}");
        };
        assert_eq!(first.path, "snusbase", "{name}");
        let reason = &first.reason;
        assert!(!err.to_string().contains(key), "{name}: key in {err}");
        if (200..300).contains(&status) {
            let words: Value = serde_json::from_str(answer["body"].as_str().unwrap()).unwrap();
            let words = words["error"].as_str().unwrap();
            assert!(reason.contains(words), "{name}: {reason}");
        } else {
            assert!(
                reason.starts_with(&format!("HTTP {status} ")),
                "{name}: {reason}"
            );
        }
        if status == 429 {
            assert!(reason.ends_with("after 3 attempts"), "{name}: {reason}");
        }
        // Where legacy's own error was captured, the port names the same status or
        // the provider's own words (it never carries a raw response body).
        if let Some(legacy_error) = scenario["legacy_error"].as_str() {
            let shared = if (200..300).contains(&status) {
                legacy_error.rsplit_once(": ").unwrap().1.to_owned()
            } else {
                format!("HTTP {status}")
            };
            assert!(
                legacy_error.contains(&shared) && reason.contains(&shared),
                "{name}"
            );
        }
    }
}
