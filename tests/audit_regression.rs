//! Golden regression benchmark for the scored self-audit (`hse audit`).
//!
//! A fixed, representative scan fixture is audited and its score + the exact set
//! of findings are pinned. The point is to make any *unintended* change to the
//! scoring model, a detector's severity, or a detector silently ceasing to fire
//! trip a test — rather than being noticed later through a degraded live scan.
//!
//! When a scoring change is deliberate, re-bless the expected values below in the
//! same commit: the diff then documents exactly how the audit's judgement moved.

use huntsman_search_engine::audit::{AuditEntity, LogSignals, Severity, audit};
use std::collections::BTreeMap;

/// Build an `AuditEntity` the way the engine's normaliser would, but with the
/// fields a regression fixture needs to control directly.
fn ent(kind: &str, value: &str, c_eff: f64, corroboration: u32, tags: &[&str]) -> AuditEntity {
    AuditEntity {
        kind: kind.into(),
        value: value.into(),
        confidence: c_eff,
        c_effective: c_eff,
        corroboration,
        sources: vec!["fixture".into()],
        tags: tags.iter().map(|s| (*s).to_string()).collect(),
    }
}

/// A representative scan: an individualised, mostly-verified identity core, plus
/// three *deliberate* weaknesses the auditor must keep catching — a Cloudflare
/// edge IP (infrastructure pollution), a `@gmail` fragment email (truncated,
/// unverifiable value), and a wrong-identity gate that suppressed many aliases
/// (recall blind spot) — alongside benign dedup exclusions that stay INFO-only.
fn fixture() -> (Vec<AuditEntity>, LogSignals) {
    let entities = vec![
        ent("email", "matthewdiegmann@gmail.com", 1.0, 4, &[]),
        ent("person", "Matthew Diegmann", 0.80, 2, &[]),
        ent("username", "matthewdiegmann", 1.0, 3, &[]),
        ent("url", "https://github.com/matthewdiegmann", 0.70, 1, &[]),
        ent("coordinates", "-27.470000,153.020000", 0.70, 2, &["geoint"]),
        // Weakness 1: a Cloudflare anycast edge IP (104.16.0.0/13).
        ent("ip_address", "104.16.1.1", 0.50, 1, &[]),
        // Weakness 2: a domain-less `@gmail` fragment.
        ent("email", "@gmail", 0.50, 1, &[]),
    ];

    let mut excluded_reasons = BTreeMap::new();
    // Weakness 3: the wrong-identity gate dominated (12 suppressed vs 7 kept).
    excluded_reasons.insert("identity_mismatch".to_string(), 12);
    // Benign hygiene exclusions — must NOT be penalised.
    excluded_reasons.insert("already_dispatched_this_scan".to_string(), 5);

    let log = LogSignals {
        excluded_reasons,
        expansion_stops: vec!["maximum expansion depth reached".into()],
        lines_parsed: 100,
        ..Default::default()
    };
    (entities, log)
}

#[test]
fn golden_audit_score_and_findings_are_stable() {
    let (entities, log) = fixture();
    let r = audit(&entities, log);

    // The findings the fixture must always surface, in the auditor's stable sort
    // order (most-severe first, then category). If a detector stops firing or its
    // severity changes, this vector diverges.
    let got: Vec<(&str, Severity)> =
        r.findings.iter().map(|f| (f.category, f.severity)).collect();
    let expected: Vec<(&str, Severity)> = vec![
        ("fragment-values", Severity::High),
        ("infrastructure-pollution", Severity::High),
        ("recursion-recall", Severity::Medium),
        ("expansion-ledger", Severity::Info),
    ];
    assert_eq!(got, expected, "audit finding set/order regressed");

    // Pinned score: 100 − (High 15 + High 15 + Medium 8 + Info 0) = 62.
    assert_eq!(r.score, 62, "audit score regressed (re-bless if intentional)");

    // The recall finding must carry the actionable remedy that ties it to the
    // wrong-identity gate override.
    let recall = r
        .findings
        .iter()
        .find(|f| f.category == "recursion-recall")
        .unwrap();
    assert!(recall.recommendation.contains("--expand-all-identities"));
}

#[test]
fn golden_audit_json_exposes_the_expansion_ledger() {
    let (entities, log) = fixture();
    let j = audit(&entities, log).to_json();

    let exp = &j["expansion"];
    assert_eq!(exp["excluded_reasons"]["identity_mismatch"], 12);
    assert_eq!(exp["excluded_reasons"]["already_dispatched_this_scan"], 5);
    assert_eq!(
        exp["stops"][0],
        serde_json::Value::String("maximum expansion depth reached".into())
    );
}
