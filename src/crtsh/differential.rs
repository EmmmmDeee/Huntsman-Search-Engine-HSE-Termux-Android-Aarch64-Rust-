//! Differential test against M D's legacy crt.sh output.
//!
//! `tests/fixtures/legacy_764ce8e/crtsh_expected.json` was recorded by running the
//! old-tree implementation (restore commit `1dfb5c9d` merged onto `98c77fd`) on
//! `crtsh_cases.json`. This port must reproduce it: same records, same values,
//! confidence, tags and evidence, nothing dropped, nothing capped. The one
//! deliberate difference is ordering *within* a confidence tie, which follows each
//! crate's own uid derivation; the confidence order itself is identical.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::entity::normalise;
use crate::http::{Response, TransportFailure};

const CASES: &str = include_str!("../../tests/fixtures/legacy_764ce8e/crtsh_cases.json");
const EXPECTED: &str = include_str!("../../tests/fixtures/legacy_764ce8e/crtsh_expected.json");

struct Fixed {
    replies: RefCell<Vec<Response>>,
    sent: Cell<u32>,
}

impl Fixed {
    fn new(mut replies: Vec<Response>) -> Self {
        replies.reverse();
        Self {
            replies: RefCell::new(replies),
            sent: Cell::new(0),
        }
    }
}

impl Transport for Fixed {
    fn send(&self, _: &Request) -> Result<Response, TransportFailure> {
        self.sent.set(self.sent.get() + 1);
        Ok(self.replies.borrow_mut().pop().expect("unscripted request"))
    }
}

fn reply(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body,
        truncated: false,
    }
}

fn seed_kind(s: &str) -> ReconTargetKind {
    serde_json::from_value(Value::String(s.into())).unwrap()
}

fn kind_of(debug_name: &str) -> EntityKind {
    serde_json::from_value(Value::String(debug_name.to_ascii_lowercase())).unwrap()
}

/// The comparable view of one entity, keyed by its identity in the new crate.
fn view(e: &Entity) -> Value {
    let mut tags = e.tags.clone();
    tags.sort();
    let evidence: Vec<Value> = e
        .evidence
        .iter()
        .map(|ev| json!({"source": ev.provenance.source, "summary": ev.summary, "attributes": ev.attributes}))
        .collect();
    json!({
        "raw_value": e.raw_value,
        "confidence": e.confidence,
        "tags": tags,
        "evidence": evidence,
    })
}

fn legacy_view(e: &Value) -> Value {
    json!({
        "raw_value": e["raw_value"],
        "confidence": e["confidence"],
        "tags": e["tags"],
        "evidence": e["evidence"],
    })
}

#[test]
fn port_reproduces_the_legacy_crtsh_output() {
    let cases: Vec<Value> = serde_json::from_str(CASES).unwrap();
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    let expected_cases = expected["cases"].as_array().unwrap();
    assert_eq!(cases.len(), expected_cases.len());

    for (case, want) in cases.iter().zip(expected_cases) {
        let name = case["name"].as_str().unwrap();
        assert_eq!(want["name"], case["name"]);
        let kind = seed_kind(case["seed_kind"].as_str().unwrap());
        let seed = case["seed"].as_str().unwrap();

        let mut entries = case["entries"].as_array().cloned().unwrap_or_default();
        if let Some(n) = case["generate_unrelated"].as_u64() {
            let names: Vec<String> = (0..n).map(|i| format!("host{i}.other-{i}.net")).collect();
            entries.push(json!({"name_value": names.join("\n")}));
        }
        let transport = Fixed::new(vec![reply(
            200,
            serde_json::to_vec(&Value::Array(entries)).unwrap(),
        )]);
        let report = lookup_with_pause(&transport, kind, seed, "fixture-scan", &|_| {
            panic!("{name}: no retry on a 200")
        })
        .unwrap();

        assert_eq!(
            report.query.as_deref(),
            want["query"].as_str(),
            "{name}: query"
        );
        assert_eq!(
            apex_base(kind, seed),
            want["apex_base"].as_str().unwrap(),
            "{name}: apex"
        );
        let count = usize::try_from(want["emitted_count"].as_u64().unwrap()).unwrap();
        assert_eq!(
            report.entities.len(),
            count,
            "{name}: nothing dropped, nothing capped"
        );
        assert!(
            report
                .entities
                .windows(2)
                .all(|w| w[0].confidence >= w[1].confidence),
            "{name}: confidence order"
        );
        assert_eq!(want["confidence_non_increasing"], true);

        let legacy: BTreeMap<(EntityKind, String), Value> = want["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let k = kind_of(e["kind"].as_str().unwrap());
                let v = normalise(&k, e["value"].as_str().unwrap());
                ((k, v), legacy_view(e))
            })
            .collect();
        let ported: BTreeMap<(EntityKind, String), Value> = report
            .entities
            .iter()
            .map(|e| ((e.kind.clone(), e.value.clone()), view(e)))
            .collect();
        assert_eq!(
            ported.len(),
            report.entities.len(),
            "{name}: no uid collisions"
        );
        assert_eq!(
            ported.keys().collect::<Vec<_>>(),
            legacy.keys().collect::<Vec<_>>(),
            "{name}: same records, no extras, no misattribution"
        );
        for (key, legacy_entity) in &legacy {
            assert_eq!(&ported[key], legacy_entity, "{name}: {key:?}");
        }

        // The legacy head of the list is in the new head's confidence tier.
        if let Some(first) = want["first_value"].as_str() {
            let top = report.entities[0].confidence;
            assert!(
                report
                    .entities
                    .iter()
                    .any(|e| e.value == normalise(&e.kind, first)
                        && (e.confidence - top).abs() < f64::EPSILON),
                "{name}: legacy first {first} is not in the top tier"
            );
        }
    }
}

#[test]
fn port_keeps_the_legacy_timeout_and_retry_contract() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    assert_eq!(
        u128::from(expected["max_timeout_ms"].as_u64().unwrap()),
        TIMEOUT.as_millis()
    );
    assert_eq!(
        expected["transient_attempts"].as_u64().unwrap(),
        u64::from(TRANSIENT_ATTEMPTS)
    );
    assert_eq!(
        u128::from(expected["transient_pause_ms"].as_u64().unwrap()),
        TRANSIENT_PAUSE.as_millis()
    );
    for row in expected["retry_by_status"].as_array().unwrap() {
        let status = u16::try_from(row["status"].as_u64().unwrap()).unwrap();
        let retry = row["retry"].as_bool().unwrap();
        assert_eq!(is_transient_crt_status(status), retry, "{status}");
        // End to end: the status every attempt, then count what was sent.
        let transport = Fixed::new(
            (0..TRANSIENT_ATTEMPTS)
                .map(|_| reply(status, Vec::new()))
                .collect(),
        );
        let err = lookup_with_pause(
            &transport,
            ReconTargetKind::Domain,
            "example.com",
            "s",
            &|_| {},
        )
        .unwrap_err();
        let attempts = if retry { TRANSIENT_ATTEMPTS } else { 1 };
        assert_eq!(err, CrtShError::Status { status, attempts }, "{status}");
        assert_eq!(transport.sent.get(), attempts, "{status}");
    }
}
