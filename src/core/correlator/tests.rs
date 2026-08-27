use std::collections::HashSet;

use super::*;
use crate::core::entity::{Entity, EntityKind, Evidence};

// ── Candidate quarantine ────────────────────────────────────────────

fn ent(kind: EntityKind, value: &str, conf: f64, src: &str, candidate: bool) -> Entity {
    let mut e = Entity::new(kind, value, conf, "scan");
    e.add_evidence(Evidence::new(src, "x".to_string()));
    if candidate {
        e.tag(crate::core::tags::CANDIDATE);
    }
    e
}

#[test]
fn rule_context_by_uid_indexes_every_entity_and_caches() {
    // Contract for the shared uid→entity cache the fourteen relation rules
    // switched to (from a private per-rule rebuild). It must index every entity
    // by its uid and return the same entity a private rebuild would have, so the
    // switch is behaviour-neutral; a second call returns the cached view.
    let ents = vec![
        ent(EntityKind::Email, "a@example.com", 0.9, "src-a", false),
        ent(EntityKind::Username, "alice", 0.8, "src-b", false),
        ent(EntityKind::Domain, "example.com", 0.7, "src-c", false),
    ];
    let ctx = RuleContext::new(&ents);

    let by_uid = ctx.by_uid();
    assert_eq!(
        by_uid.len(),
        ents.len(),
        "every entity is indexed exactly once"
    );
    for e in &ents {
        let got = by_uid
            .get(e.uid.as_str())
            .expect("each entity is reachable by its own uid");
        assert_eq!(got.uid, e.uid);
        assert_eq!(got.value, e.value);
    }
    drop(by_uid);

    // Cached: a second call yields the identical mapping.
    let again = ctx.by_uid();
    assert_eq!(again.len(), ents.len());
    assert!(again.contains_key(ents[0].uid.as_str()));
}

#[test]
fn temporal_breach_cluster_survives_non_ascii_breach_date() {
    // Regression: a `breach_date` taken verbatim from an upstream API whose
    // byte index 10 falls inside a multi-byte UTF-8 char must NOT panic the
    // rule's date slice. rule_au_019 runs OUTSIDE the per-module
    // catch_unwind, so a panic here previously killed the whole scan/live
    // task (lost finalization; live session stuck Running forever).
    let mk = |value: &str, date: &str| {
        let mut e = Entity::new(EntityKind::Email, value, 0.8, "scan");
        e.tag("breach");
        e.add_evidence(Evidence::new("hibp", "breach").with_attr("breach_date", date));
        e
    };
    let ents = vec![
        // '€' (3 bytes) begins at byte 9, so byte 10 is mid-codepoint.
        mk("a@x.com", "2024-01-0€9"),
        mk("b@x.com", "2024-01-15"),
        mk("c@x.com", "2024-02-10"),
    ];
    // Must not panic; the malformed-date row is simply skipped.
    let _ = rule_au_019_temporal_breach_cluster(&RuleContext::new(&ents), "scan", 0);
}

#[test]
fn temporal_breach_cluster_window_is_anchored_not_rolling() {
    let mk = |value: &str, date: &str| {
        let mut e = Entity::new(EntityKind::Email, value, 0.8, "scan");
        e.tag("breach");
        e.add_evidence(Evidence::new("hibp", "breach").with_attr("breach_date", date));
        e
    };
    // Three breaches genuinely within a 30-day window → one cluster fires.
    let tight = vec![
        mk("a@x.com", "2024-01-01"),
        mk("b@x.com", "2024-01-10"),
        mk("c@x.com", "2024-01-20"),
    ];
    let r = rule_au_019_temporal_breach_cluster(&RuleContext::new(&tight), "scan", 0);
    assert_eq!(r.len(), 1, "a real ≤30-day cluster must fire");
    assert_eq!(r[0].entity_uids.len(), 3);

    // Rolling chain: each consecutive pair is ≤30 days apart but the span is ~88
    // days. The anchored window must NOT fuse these into a "within 30 days"
    // cluster (the old rolling-gap logic did, an over-claim).
    let chained = vec![
        mk("a@x.com", "2024-01-01"),
        mk("b@x.com", "2024-01-30"),
        mk("c@x.com", "2024-02-28"),
        mk("d@x.com", "2024-03-30"),
    ];
    assert!(
        rule_au_019_temporal_breach_cluster(&RuleContext::new(&chained), "scan", 0).is_empty(),
        "a chained >30-day span must not be reported as a 30-day cluster"
    );
}

#[test]
fn candidates_are_excluded_from_correlation() {
    // A breach-dump-style set: one confirmed identity plus many quarantined
    // `candidate` strangers (the AU-002/AU-003 mega-fusion scenario). The
    // correlator must ignore the candidates entirely — no critical identity
    // cluster fused from strangers, no high-corroboration firings on them.
    let mut ents = vec![
        ent(EntityKind::Email, "me@real.com", 0.85, "oathnet_pro", false),
        ent(EntityKind::Username, "me", 0.70, "oathnet_pro", false),
        ent(EntityKind::Phone, "15551112222", 0.70, "oathnet_pro", false),
    ];
    for i in 0..40 {
        ents.push(ent(
            EntityKind::Email,
            &format!("stranger{i}@bank.com"),
            0.25,
            "oathnet_pro",
            true,
        ));
    }
    let firings = evaluate_rules(&ents, "scan");
    // No correlation may reference a candidate entity.
    let candidate_uids: HashSet<&str> = ents
        .iter()
        .filter(|e| e.has_tag(crate::core::tags::CANDIDATE))
        .map(|e| e.uid.as_str())
        .collect();
    for c in &firings {
        for uid in &c.entity_uids {
            assert!(
                !candidate_uids.contains(uid.as_str()),
                "rule {} leaked a candidate entity into a correlation",
                c.rule_id
            );
        }
    }
    // AU-002 may still fire on the 3 confirmed (1 email/1 user/1 phone) —
    // but its email bucket must be the single confirmed one, never 41.
    if let Some(au002) = firings.iter().find(|c| c.rule_id == "AU-002") {
        assert!(
            au002.description.contains("1 email(s)"),
            "AU-002 must cluster only the confirmed identity: {}",
            au002.description
        );
    }
}

#[test]
fn confirmed_only_drops_candidate_tagged() {
    let ents = vec![
        ent(EntityKind::Email, "a@b.com", 0.8, "s", false),
        ent(EntityKind::Email, "c@d.com", 0.25, "s", true),
    ];
    let kept = confirmed_only(&ents);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].value, "a@b.com");
}

#[test]
fn au002_refuses_to_fuse_an_implausible_identity_dump() {
    // Backstop: even if a bulk source emitted many NON-candidate emails,
    // AU-002 must not declare 30 distinct emails one "critical identity".
    let mut big = vec![
        ent(EntityKind::Username, "u", 0.7, "s", false),
        ent(EntityKind::Phone, "15551112222", 0.7, "s", false),
    ];
    for i in 0..30 {
        big.push(ent(
            EntityKind::Email,
            &format!("e{i}@x.com"),
            0.7,
            "s",
            false,
        ));
    }
    assert!(
        rule_au_002_identity_cluster(&RuleContext::new(&big), "scan", 0).is_empty(),
        "30 distinct emails is a dump, not an identity cluster"
    );

    // A plausible identity (a handful each) still fires.
    let small = vec![
        ent(EntityKind::Email, "me@x.com", 0.85, "s", false),
        ent(EntityKind::Username, "me", 0.7, "s", false),
        ent(EntityKind::Phone, "15551112222", 0.7, "s", false),
    ];
    assert_eq!(
        rule_au_002_identity_cluster(&RuleContext::new(&small), "scan", 0).len(),
        1,
        "a small corroborated identity must still cluster"
    );

    // Low-confidence entities are below the floor → no fire.
    let weak = vec![
        ent(EntityKind::Email, "me@x.com", 0.3, "s", false),
        ent(EntityKind::Username, "me", 0.3, "s", false),
        ent(EntityKind::Phone, "15551112222", 0.3, "s", false),
    ];
    assert!(
        rule_au_002_identity_cluster(&RuleContext::new(&weak), "scan", 0).is_empty(),
        "sub-floor confidence must not fuse an identity"
    );
}

// ── Severity::as_canonical ──────────────────────────────────────────

#[test]
fn as_canonical_returns_lowercase() {
    assert_eq!(Severity::Low.as_canonical(), "low");
    assert_eq!(Severity::Medium.as_canonical(), "medium");
    assert_eq!(Severity::High.as_canonical(), "high");
    assert_eq!(Severity::Critical.as_canonical(), "critical");
}

// ── Severity::weight + rank ordering ────────────────────────────────

#[test]
fn severity_weight_is_monotonic() {
    assert!(Severity::Low.weight() < Severity::Medium.weight());
    assert!(Severity::Medium.weight() < Severity::High.weight());
    assert!(Severity::High.weight() < Severity::Critical.weight());
}

#[test]
fn run_ranks_by_severity_times_max_child_ceff() {
    use crate::core::test_support::InMemoryStore;
    use std::sync::Arc;

    // Build a scan where:
    //  - a HIGH-severity rule will fire over a strongly-corroborated entity
    //    (high C_eff), and
    //  - a CRITICAL-severity rule will fire over a weakly-corroborated one
    //    (low C_eff),
    // so that severity-alone ordering (critical first) and
    // severity×C_eff ordering disagree — proving the rank is C_eff-scaled.
    //
    // AU-021 (API key exposure) is Critical and fires on any ApiKey entity.
    // AU-003 (cross-source corroboration) is Medium and fires on an entity
    // with >=2 distinct sources. We give the ApiKey a LOW C_eff (single
    // source, low base confidence) and the corroborated email a HIGH C_eff
    // (3 distinct sources, high base confidence). The Medium hit on the
    // high-C_eff entity must outrank the Critical hit on the low-C_eff one
    // once C_eff dominates the severity gap.
    let store: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
    let sid = "rank-test";

    let mut weak_key = Entity::new(EntityKind::ApiKey, "AKIAWEAK", 0.20, sid);
    weak_key.add_evidence(Evidence::new("key_harvest", "found once"));

    let mut strong_email = Entity::new(EntityKind::Email, "a@b.com", 0.95, sid);
    for src in ["hibp", "dehashed", "search_engines"] {
        strong_email.add_evidence(Evidence::new(src, "seen"));
    }

    store.upsert_entity(&weak_key).expect("should succeed");
    store.upsert_entity(&strong_email).expect("should succeed");

    let corr = Correlator::new(Arc::clone(&store));
    let hits = corr.run(sid).expect("should succeed");

    // Both rules fired.
    let key_hit = hits
        .iter()
        .find(|c| c.rule_id == "AU-021")
        .expect("should succeed");
    let email_hit = hits
        .iter()
        .find(|c| c.rule_id == "AU-003")
        .expect("should succeed");

    // Critical×low-C_eff vs Medium×high-C_eff: 4×~0.20 = 0.8 vs 2×~0.99 ≈ 1.98.
    assert!(
        email_hit.rank > key_hit.rank,
        "C_eff-scaled rank must put the strongly-corroborated Medium hit \
         (rank {:.3}) above the weak Critical hit (rank {:.3})",
        email_hit.rank,
        key_hit.rank,
    );
    // And the returned Vec is sorted by rank desc.
    assert!(
        hits.windows(2).all(|w| w[0].rank >= w[1].rank),
        "correlations must be returned in rank-descending order"
    );
    // Rank is severity.weight × max child C_eff (sanity on the key hit).
    let expected_key_rank = Severity::Critical.weight() * weak_key.c_effective();
    assert!((key_hit.rank - expected_key_rank).abs() < 1e-9);
}

// ── Ranking determinism ─────────────────────────────────────────────

#[test]
fn rank_and_sort_is_deterministic_for_same_rule_ties() {
    // DETERMINISM REQUIREMENT (evidence): when one rule fires for several entity
    // groups (same rule_id, same rank), the final order must be fixed by the
    // (sorted) entity_uids — not by the order the groups were generated in.
    use std::collections::HashMap;
    let ceff: HashMap<String, f64> = [("u1".to_string(), 0.5), ("u2".to_string(), 0.5)]
        .into_iter()
        .collect();
    let mk = |uids: Vec<&str>| {
        Correlation::new(
            "AU-034",
            "handle reuse",
            Severity::Medium,
            "x".into(),
            uids.into_iter().map(String::from).collect(),
            "scan",
            0,
        )
    };
    // Same rule, same rank — distinguished only by entity_uids. Feed both orders.
    let mut a = vec![mk(vec!["u2"]), mk(vec!["u1"])];
    let mut b = vec![mk(vec!["u1"]), mk(vec!["u2"])];
    super::rank_and_sort(&mut a, &ceff);
    super::rank_and_sort(&mut b, &ceff);
    let uids = |c: &[Correlation]| c.iter().map(|x| x.entity_uids.clone()).collect::<Vec<_>>();
    assert_eq!(
        uids(&a),
        uids(&b),
        "same-rule ranking depended on input order"
    );
    // And the fixed order is by entity_uids ascending.
    assert_eq!(a[0].entity_uids, vec!["u1".to_string()]);
}

// ── Severity Display ────────────────────────────────────────────────

#[test]
fn display_returns_uppercase() {
    assert_eq!(Severity::Low.to_string(), "LOW");
    assert_eq!(Severity::Medium.to_string(), "MEDIUM");
    assert_eq!(Severity::High.to_string(), "HIGH");
    assert_eq!(Severity::Critical.to_string(), "CRITICAL");
}

// ── Severity ordering ───────────────────────────────────────────────

#[test]
fn severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

// ── Severity serde ──────────────────────────────────────────────────

#[test]
fn severity_json_round_trip() {
    for (variant, expected_str) in [
        (Severity::Low, "\"low\""),
        (Severity::Medium, "\"medium\""),
        (Severity::High, "\"high\""),
        (Severity::Critical, "\"critical\""),
    ] {
        let json = serde_json::to_string(&variant).expect("should succeed");
        assert_eq!(json, expected_str);
        let back: Severity = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(back, variant);
    }
}

