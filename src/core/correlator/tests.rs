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

// ── Correlation::new ────────────────────────────────────────────────

#[test]
fn correlation_new_sets_all_fields() {
    let uids = vec!["uid-a".to_string(), "uid-b".to_string()];
    let c = Correlation::new(
        "R001",
        "test rule",
        Severity::High,
        "something suspicious".to_string(),
        uids.clone(),
        "scan-1",
        1700000000,
    );

    assert_eq!(c.rule_id, "R001");
    assert_eq!(c.rule_name, "test rule");
    assert_eq!(c.severity, Severity::High);
    assert_eq!(c.description, "something suspicious");
    assert_eq!(c.entity_uids, uids);
    assert_eq!(c.scan_id, "scan-1");
    assert_eq!(c.ts, 1700000000);
}

// ── Correlation serde round-trip ────────────────────────────────────

#[test]
fn correlation_json_round_trip() {
    let original = Correlation::new(
        "R002",
        "exposed creds",
        Severity::Critical,
        "credentials found in breach db".to_string(),
        vec!["uid-x".to_string()],
        "scan-99",
        1700000001,
    );

    let json = serde_json::to_string(&original).expect("should succeed");
    let back: Correlation = serde_json::from_str(&json).expect("should succeed");

    assert_eq!(back.rule_id, original.rule_id);
    assert_eq!(back.rule_name, original.rule_name);
    assert_eq!(back.severity, original.severity);
    assert_eq!(back.description, original.description);
    assert_eq!(back.entity_uids, original.entity_uids);
    assert_eq!(back.scan_id, original.scan_id);
    assert_eq!(back.ts, original.ts);
}

// ── Rule test helpers ───────────────────────────────────────────────

fn email(value: &str, sources: &[&str]) -> Entity {
    let mut e = Entity::new(EntityKind::Email, value, 0.9, "scan-test");
    for src in sources {
        e.add_evidence(Evidence::new(*src, "test"));
    }
    e
}

fn domain(value: &str, sources: &[&str]) -> Entity {
    let mut e = Entity::new(EntityKind::Domain, value, 0.9, "scan-test");
    for src in sources {
        e.add_evidence(Evidence::new(*src, "test"));
    }
    e
}

fn username(value: &str, sources: &[&str]) -> Entity {
    let mut e = Entity::new(EntityKind::Username, value, 0.9, "scan-test");
    for src in sources {
        e.add_evidence(Evidence::new(*src, "test"));
    }
    e
}

#[test]
fn au033_links_abn_to_registry_organisation() {
    let entities = vec![
        tagged(EntityKind::AbnAcn, "51824753556", &["abr"]),
        tagged(
            EntityKind::Organisation,
            "Example Pty Ltd",
            &["abr", "australian"],
        ),
    ];
    let r = rule_au_033_abn_organisation_link(&RuleContext::new(&entities), "scan-test", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-033");
    assert_eq!(r[0].entity_uids.len(), 2);
}

#[test]
fn au033_no_fire_without_registry_org_or_abn() {
    // ABN + a non-registry Organisation (e.g. a search_engines org name)
    // must NOT link — avoids joining unrelated company names.
    let mixed = vec![
        tagged(EntityKind::AbnAcn, "51824753556", &["abr"]),
        Entity::new(EntityKind::Organisation, "Some Other Co", 0.9, "scan-test"),
    ];
    assert!(
        rule_au_033_abn_organisation_link(&RuleContext::new(&mixed), "scan-test", 0).is_empty()
    );
    // A registry org with no ABN present also does not fire.
    let only_org = vec![tagged(
        EntityKind::Organisation,
        "Example Pty Ltd",
        &["opencorporates"],
    )];
    assert!(
        rule_au_033_abn_organisation_link(&RuleContext::new(&only_org), "scan-test", 0).is_empty()
    );
}

#[test]
fn au033_links_abn_to_acnc_and_gleif_registry_orgs() {
    // Integration regression: the ACNC charities register and GLEIF LEI index
    // both emit an ABN/ACN plus the registered Organisation, so AU-033 must
    // link them exactly as it does for abr/opencorporates. Before the gate was
    // widened, an acnc/gleif-tagged org silently failed to correlate.
    for tag in ["acnc", "gleif"] {
        let entities = vec![
            tagged(EntityKind::AbnAcn, "51824753556", &[tag]),
            tagged(
                EntityKind::Organisation,
                "Example Org",
                &[tag, "country:AU"],
            ),
        ];
        let r = rule_au_033_abn_organisation_link(&RuleContext::new(&entities), "scan-test", 0);
        assert_eq!(
            r.len(),
            1,
            "AU-033 must fire for a {tag}-tagged registry org"
        );
        assert_eq!(r[0].rule_id, "AU-033");
        assert_eq!(r[0].entity_uids.len(), 2);
    }
}

// ── AU-048 ──────────────────────────────────────────────────────────
fn shared_key(tag: &str, emails: &[&str]) -> Entity {
    let mut e = Entity::new(EntityKind::Credential, "AAAAB3NzaC1shared", 0.9, "scan");
    e.tag(tag);
    for em in emails {
        e.add_evidence(Evidence::new("key_harvest", "reused public key").with_attr("email", *em));
    }
    e
}

#[test]
fn au048_fires_for_same_local_part_across_different_domains() {
    // Regression: a target publishing the SAME key from john@gmail.com and
    // john@acme.com is exactly the rotated/burner seam AU-048 exists to expose.
    // The previous local-part-only fold collapsed both to "john" and silently
    // dropped this Critical link (cryptographic proof of common control).
    let entities = vec![
        shared_key("ssh-key", &["john@gmail.com", "john@acme.com"]),
        email("john@gmail.com", &["github_user"]),
        email("john@acme.com", &["hunter_io"]),
    ];
    let r = rule_au_048_shared_public_key(&RuleContext::new(&entities), "scan-test", 0);
    assert_eq!(r.len(), 1, "two accounts sharing one key must fire");
    assert_eq!(r[0].rule_id, "AU-048");
    assert_eq!(r[0].severity, Severity::Critical);
    assert_eq!(r[0].entity_uids.len(), 3, "links the key + both emails");
    assert!(
        r[0].description.contains("2 accounts"),
        "counts 2 distinct controllers: {}",
        r[0].description
    );
}

#[test]
fn au048_does_not_fire_for_a_login_plus_its_own_email() {
    // A single account whose key evidence carries BOTH its login and its email
    // ("alice" + "alice@x.com") is ONE controller, not two — must not fire.
    let mut key = Entity::new(EntityKind::Credential, "AAAAB3NzaC1solo", 0.9, "scan");
    key.tag("ssh-key");
    key.add_evidence(Evidence::new("github_user", "k").with_attr("github_login", "alice"));
    key.add_evidence(Evidence::new("key_harvest", "k").with_attr("email", "alice@x.com"));
    let entities = vec![
        key,
        email("alice@x.com", &["hunter_io"]),
        username("alice", &["github_user"]),
    ];
    let r = rule_au_048_shared_public_key(&RuleContext::new(&entities), "scan-test", 0);
    assert!(
        r.is_empty(),
        "a login and its own email are one account, not two"
    );
}

// ── AU-034 ──────────────────────────────────────────────────────────
#[test]
fn au034_links_username_to_email_by_shared_handle() {
    // Username from one source, matching email from another INDEPENDENT
    // observation → ≥2 distinct corroborating sources → fires, linking both uids.
    // (Both sources must be genuine sightings: a `name_intel`-derived email is a
    // derivation of the seed, not independent — see ENRICHMENT_ONLY_SOURCES.)
    let entities = vec![
        username("jmeyers", &["github_user"]),
        email("jmeyers@gmail.com", &["hudsonrock"]),
    ];
    let r = rule_au_034_handle_reuse_identity(&RuleContext::new(&entities), "scan-test", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-034");
    assert_eq!(r[0].severity, Severity::Medium);
    assert_eq!(r[0].entity_uids.len(), 2);
    assert!(r[0].description.contains("jmeyers@gmail.com"));
}

#[test]
fn au034_and_au076_byte_vs_char_handle_floor_does_not_bridge_a_short_cjk_name() {
    // Regression (critical audit): MIN_HANDLE_LEN's floor (rule_au_034) and the
    // matching AU-076 checks were compared against str::len() -- UTF-8 BYTES --
    // not chars(). "李明" is 2 characters but 6 bytes, so it cleared the ">= 4"
    // gate meant to exclude short/common handles. Two unrelated people who
    // both happen to share this common Chinese name (like "John Smith") would
    // otherwise be bridged into one identity by a coincidental short-name
    // match -- the exact false-positive the length floor exists to prevent,
    // and the identical bug class already fixed for the sibling AU-123 rule
    // (see au123_silent_on_a_short_non_latin_stem_that_would_clear_a_byte_length_check)
    // but never propagated here.
    use super::rules::rule_au_076_email_username_localpart_bridge;
    assert_eq!("李明".chars().count(), 2);
    assert_eq!("李明".len(), 6); // bytes -- would clear a ">= 4" byte check

    let entities = vec![
        username("李明", &["github_user"]),
        email("李明@gmail.com", &["hibp"]),
    ];
    let r = rule_au_034_handle_reuse_identity(&RuleContext::new(&entities), "scan-test", 0);
    assert!(
        r.is_empty(),
        "a 2-character handle must not bridge identities, AU-034 fired: {r:?}"
    );

    let mut email_e = Entity::new(EntityKind::Email, "李明@gmail.com", 0.9, "s");
    email_e.add_evidence(Evidence::new("hibp", "breach hit".to_string()));
    let mut uname_e = Entity::new(EntityKind::Username, "李明", 0.8, "s");
    uname_e.add_evidence(Evidence::new("github_user", "profile".to_string()));
    let r2 =
        rule_au_076_email_username_localpart_bridge(&RuleContext::new(&[email_e, uname_e]), "s", 0);
    assert!(
        r2.is_empty(),
        "a 2-character local-part must not bridge identities, AU-076 fired: {r2:?}"
    );
}

#[test]
fn au034_handle_match_is_separator_insensitive_and_strips_plus_tag() {
    // `jordanmeyers` ↔ `jordan.meyers+news@x.com`: dots removed and the
    // Gmail `+tag` stripped, so the canonical handles match.
    let entities = vec![
        username("jordanmeyers", &["search_engines"]),
        email("jordan.meyers+news@x.com", &["hunter_io"]),
    ];
    let r = rule_au_034_handle_reuse_identity(&RuleContext::new(&entities), "scan-test", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au034_groups_multiple_emails_under_one_correlation() {
    // One username matching the same handle across two providers →
    // a single correlation linking the username + both emails (3 uids).
    let entities = vec![
        username("jmeyers", &["github_user"]),
        email("jmeyers@gmail.com", &["name_intel"]),
        email("j.meyers@outlook.com", &["hunter_io"]),
    ];
    let r = rule_au_034_handle_reuse_identity(&RuleContext::new(&entities), "scan-test", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].entity_uids.len(), 3);
}

#[test]
fn au034_no_fire_on_single_source_self_correlation() {
    // Both candidates minted by the SAME single module (e.g. name_intel
    // derives both a username and an email from one name) → only one
    // distinct source → suppressed, so the rule can't self-correlate.
    let entities = vec![
        username("jmeyers", &["name_intel"]),
        email("jmeyers@gmail.com", &["name_intel"]),
    ];
    assert!(
        rule_au_034_handle_reuse_identity(&RuleContext::new(&entities), "scan-test", 0).is_empty()
    );
}

#[test]
fn au034_no_fire_on_role_or_placeholder_handle() {
    // Role mailbox (`info`) and placeholder (`admin`) link organisation
    // functions, not people — excluded even across distinct sources.
    let role = vec![
        username("info", &["github_user"]),
        email("info@company.com", &["hunter_io"]),
    ];
    assert!(rule_au_034_handle_reuse_identity(&RuleContext::new(&role), "scan-test", 0).is_empty());
    let placeholder = vec![
        username("admin", &["github_user"]),
        email("admin@company.com", &["hunter_io"]),
    ];
    assert!(
        rule_au_034_handle_reuse_identity(&RuleContext::new(&placeholder), "scan-test", 0)
            .is_empty()
    );
}

#[test]
fn au034_no_fire_on_short_handle_or_no_match() {
    // A handle < 4 chars is too weak to identify; distinct handles never
    // match.
    let short = vec![
        username("abc", &["github_user"]),
        email("abc@x.com", &["hunter_io"]),
    ];
    assert!(
        rule_au_034_handle_reuse_identity(&RuleContext::new(&short), "scan-test", 0).is_empty()
    );
    let nomatch = vec![
        username("alice", &["github_user"]),
        email("bob@x.com", &["hunter_io"]),
    ];
    assert!(
        rule_au_034_handle_reuse_identity(&RuleContext::new(&nomatch), "scan-test", 0).is_empty()
    );
}

// ── AU-035 ──────────────────────────────────────────────────────────

#[test]
fn au035_fires_when_inferred_then_confirmed() {
    // Derived by name_intel, then observed live by username_search →
    // a guessed handle confirmed real.
    let e = username("jdoe", &["name_intel", "username_search"]);
    let r = rule_au_035_confirmed_derived_handle(&RuleContext::new(&[e]), "scan-test", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-035");
    assert_eq!(r[0].entity_uids.len(), 1);
    assert!(r[0].description.contains("name_intel"));
    assert!(r[0].description.contains("username_search"));
}

#[test]
fn au035_fires_for_email_parse_plus_github() {
    let e = username("jdoe", &["email_parse", "github_user"]);
    let r = rule_au_035_confirmed_derived_handle(&RuleContext::new(&[e]), "scan-test", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au035_no_fire_when_only_inferred_or_only_discovered() {
    // Guessed but never confirmed → unconfirmed candidate, no fire.
    let only_inferred = username("jdoe", &["username_variants"]);
    assert!(
        rule_au_035_confirmed_derived_handle(&RuleContext::new(&[only_inferred]), "scan-test", 0)
            .is_empty()
    );
    // Observed but never inferred → an ordinary find, no fire.
    let only_discovered = username("jdoe", &["github_user", "keybase"]);
    assert!(
        rule_au_035_confirmed_derived_handle(&RuleContext::new(&[only_discovered]), "scan-test", 0)
            .is_empty()
    );
}

#[test]
fn au035_no_fire_when_confirmation_is_status_only() {
    // Derived by name_intel, but the "discovery" source is a status-only guess
    // (no body verification) — must NOT count as independent confirmation,
    // mirroring the discount AU-077 already applies for the identical merge.
    let mut e = Entity::new(EntityKind::Username, "jdoe", 0.9, "scan-test");
    e.add_evidence(Evidence::new("name_intel", "test"));
    e.add_evidence(Evidence::new("username_search", "test").with_attr("detection", "status-only"));
    assert!(
        rule_au_035_confirmed_derived_handle(&RuleContext::new(&[e]), "scan-test", 0).is_empty()
    );
}

#[test]
fn au035_no_fire_on_all_guess_summary_with_zero_verified_hits() {
    let mut e = Entity::new(EntityKind::Username, "jdoe", 0.9, "scan-test");
    e.add_evidence(Evidence::new("name_intel", "test"));
    e.add_evidence(Evidence::new("username_search", "test").with_attr("hits_verified", "0"));
    assert!(
        rule_au_035_confirmed_derived_handle(&RuleContext::new(&[e]), "scan-test", 0).is_empty(),
        "an all-guess summary with zero verified hits must not confirm"
    );
}

#[test]
fn au035_no_fire_on_social_probe_all_status_only_summary() {
    // Same shared `is_verified_discovery` guard as AU-077 (OD-17): `social_probe`
    // is also in USERNAME_DISCOVERY_SOURCES, and its Username-kind summary used
    // to have no `hits_verified` attribute at all, which the guard treated as
    // vacuously verified rather than unconfirmed.
    let mut e = Entity::new(EntityKind::Username, "jdoe", 0.9, "scan-test");
    e.add_evidence(Evidence::new("name_intel", "test"));
    e.add_evidence(
        Evidence::new("social_probe", "test")
            .with_attr("hits_verified", "0")
            .with_attr("hits_status_only", "2"),
    );
    assert!(
        rule_au_035_confirmed_derived_handle(&RuleContext::new(&[e]), "scan-test", 0).is_empty(),
        "an all-status-only social_probe summary must not confirm AU-035"
    );
}

// ── AU-036 ──────────────────────────────────────────────────────────

/// Build a canonical Email entity carrying one `email_canonical` evidence
/// record per source address it was folded from (mirroring how the merge
/// accumulates them — distinct per-source summaries survive the dedup).
fn canonical_email(value: &str, source_emails: &[&str]) -> Entity {
    let mut e = Entity::new(EntityKind::Email, value, 0.8, "scan-test");
    e.tag("canonical");
    for src in source_emails {
        e.add_evidence(
            Evidence::new("email_canonical", format!("Canonical mailbox of {src}"))
                .with_attr("source_email", *src),
        );
    }
    e
}

#[test]
fn au036_fires_when_two_addresses_converge() {
    let e = canonical_email(
        "jdoe@gmail.com",
        &["j.doe@gmail.com", "jdoe+news@gmail.com"],
    );
    let r = rule_au_036_email_alias_convergence(&RuleContext::new(&[e]), "scan-test", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-036");
    assert!(r[0].description.contains("jdoe@gmail.com"));
    assert!(r[0].description.contains("j.doe@gmail.com"));
    assert!(r[0].description.contains("jdoe+news@gmail.com"));
}

#[test]
fn au036_no_fire_on_single_alias() {
    // Only one address folded in → nothing converged, no finding.
    let e = canonical_email("jdoe@gmail.com", &["j.doe@gmail.com"]);
    assert!(
        rule_au_036_email_alias_convergence(&RuleContext::new(&[e]), "scan-test", 0).is_empty()
    );
}

#[test]
fn au036_ignores_non_canonical_evidence() {
    // Two evidence records, but not from email_canonical → not alias
    // convergence (could be two breach sources for one address).
    let e = email("jdoe@gmail.com", &["hibp", "hudsonrock"]);
    assert!(
        rule_au_036_email_alias_convergence(&RuleContext::new(&[e]), "scan-test", 0).is_empty()
    );
}

fn tagged(kind: EntityKind, value: &str, tags: &[&str]) -> Entity {
    let mut e = Entity::new(kind, value, 0.9, "scan-test");
    for t in tags {
        e.tag(*t);
    }
    e
}

fn username_summary(value: &str, count: u64, platforms: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Username, value, 0.95, "scan-test");
    e.tag("multi-platform");
    e.add_evidence(
        Evidence::new("username_search", "summary")
            .with_attr("platforms_count", count.to_string())
            .with_attr("platforms", platforms),
    );
    e
}

// ── AU-001 ──────────────────────────────────────────────────────────

#[test]
fn au001_fires_at_two_breach_sources() {
    let e = email("x@y.com", &["hudsonrock", "breach_directory"]);
    let r = rule_au_001_multi_breach(&RuleContext::new(&[e]), "s1", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-001");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au001_no_fire_at_one_source() {
    let e = email("x@y.com", &["hudsonrock"]);
    assert!(rule_au_001_multi_breach(&RuleContext::new(&[e]), "s1", 0).is_empty());
}

#[test]
fn au001_ignores_non_breach_sources() {
    let e = email("x@y.com", &["crtsh", "dns_resolver"]);
    assert!(rule_au_001_multi_breach(&RuleContext::new(&[e]), "s1", 0).is_empty());
}

#[test]
fn au001_does_not_count_generic_search_as_a_breach_source() {
    // A web-search hit alongside ONE real breach source is a single breach
    // source — `search_engines` must never count toward the Critical multi-breach
    // finding (guards against re-adding it to BREACH_SOURCES).
    let one = email("x@y.com", &["hibp", "search_engines"]);
    assert!(rule_au_001_multi_breach(&RuleContext::new(&[one]), "s1", 0).is_empty());
    // Two genuine breach sources still fire.
    let two = email("x@y.com", &["hibp", "dehashed"]);
    assert_eq!(
        rule_au_001_multi_breach(&RuleContext::new(&[two]), "s1", 0).len(),
        1
    );
}

#[test]
fn au001_recognises_real_breach_modules_the_allow_list_had_missed() {
    // BREACH_SOURCES was a hand-maintained allow-list that never grew to cover
    // several real breach-category modules -- confirmed against
    // source_family_covers_every_breach_category_module (rules/tests.rs),
    // which pins all of them as family "breach". Two of the previously-missed
    // modules together must still fire AU-001, exactly as two listed ones do.
    let e = email("x@y.com", &["intelx", "psbdmp"]);
    let r = rule_au_001_multi_breach(&RuleContext::new(&[e]), "s1", 0);
    assert_eq!(
        r.len(),
        1,
        "intelx + psbdmp is two genuinely independent breach corpora: {r:?}"
    );
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au001_does_not_raise_critical_on_a_role_mailbox() {
    // Live person-scan false positive: `abuse@godaddy.com` (a registrar desk) is in
    // HIBP + XposedOrNot as a matter of course — that is NOT the subject's breach
    // exposure and must not fire a Critical.
    let role = email("abuse@godaddy.com", &["hibp", "xposed_or_not"]);
    assert!(rule_au_001_multi_breach(&RuleContext::new(&[role]), "s1", 0).is_empty());
    // A genuine personal mailbox in the same two sources still fires.
    let real = email("matthew@example.com", &["hibp", "xposed_or_not"]);
    assert_eq!(
        rule_au_001_multi_breach(&RuleContext::new(&[real]), "s1", 0).len(),
        1
    );
}

// ── AU-002 ──────────────────────────────────────────────────────────

#[test]
fn au002_fires_with_all_three_kinds() {
    let entities = vec![
        Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
        Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
        Entity::new(EntityKind::Phone, "+61400000000", 0.8, "s"),
    ];
    let r = rule_au_002_identity_cluster(&RuleContext::new(&entities), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-002");
    assert_eq!(r[0].entity_uids.len(), 3);
}

#[test]
fn au002_no_fire_missing_kind() {
    let entities = vec![
        Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
        Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
    ];
    assert!(rule_au_002_identity_cluster(&RuleContext::new(&entities), "s", 0).is_empty());
}

// ── AU-003 ──────────────────────────────────────────────────────────

#[test]
fn au003_fires_at_kind_specific_thresholds() {
    // Thresholds are now on DISTINCT sources: identity (email) >= 2,
    // infra (domain) >= 3. These fixtures set corroboration with no
    // evidence, so source_count() falls back to the field value.
    let mut email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    email.corroboration = 2;
    let r = rule_au_003_high_corroboration(&RuleContext::new(&[email]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-003");
    assert!(
        r[0].description.contains("2 independent source"),
        "description must report the true distinct-source count: {}",
        r[0].description
    );

    let mut domain = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
    domain.corroboration = 3;
    let r = rule_au_003_high_corroboration(&RuleContext::new(&[domain]), "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au003_no_fire_below_threshold() {
    // Email below 2 distinct sources, domain below 3 → no fire.
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    e.corroboration = 1;
    assert!(rule_au_003_high_corroboration(&RuleContext::new(&[e]), "s", 0).is_empty());

    let mut d = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
    d.corroboration = 2;
    assert!(rule_au_003_high_corroboration(&RuleContext::new(&[d]), "s", 0).is_empty());
}

#[test]
fn au003_uses_distinct_sources_not_summed_corroboration() {
    // THE FIX in correlator terms: an email with summed corroboration=8
    // but only 1 distinct evidence source must NOT fire AU-003 (it is not
    // cross-corroborated), and an email with 2 distinct sources must fire
    // regardless of the summed field.
    let mut single = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
    single.corroboration = 8;
    single.add_evidence(crate::core::entity::Evidence::new("oathnet_pro", "8 rows"));
    assert!(
        rule_au_003_high_corroboration(&RuleContext::new(&[single]), "s", 0).is_empty(),
        "single-source entity must not fire AU-003 despite inflated corroboration"
    );

    let mut multi = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
    multi.corroboration = 2;
    multi.add_evidence(crate::core::entity::Evidence::new("hibp", "breach"));
    multi.add_evidence(crate::core::entity::Evidence::new("dehashed", "breach"));
    assert_eq!(
        rule_au_003_high_corroboration(&RuleContext::new(&[multi]), "s", 0).len(),
        1,
        "two distinct sources must fire AU-003"
    );
}

#[test]
fn au003_excludes_weak_detection_only_entities() {
    // Regression: a real scan against a guessed username handle showed a
    // `Url` entity (a guessed profile page) reach `source_count() = 6` and a
    // reported `C_eff=1.000` purely from status-only guesses (username_search,
    // streaming_probe) plus `webserver_banner`'s domain-root check
    // mis-attributed to the guessed path (fixed separately) — "high
    // cross-source corroboration" for a handle that was never confirmed to
    // exist. An entity tagged `weak-detection` with no accompanying
    // `verified-detection` must not fire AU-003 no matter how many distinct
    // modules ran the same shallow check.
    let mut weak = Entity::new(
        EntityKind::Url,
        "https://onlyfans.com/rob_dorito",
        0.74,
        "s",
    );
    weak.tag("weak-detection");
    weak.add_evidence(crate::core::entity::Evidence::new(
        "username_search",
        "status 200",
    ));
    weak.add_evidence(crate::core::entity::Evidence::new(
        "streaming_probe",
        "status 200",
    ));
    weak.add_evidence(crate::core::entity::Evidence::new("web_crawler", "linked"));
    assert!(
        rule_au_003_high_corroboration(&RuleContext::new(&[weak]), "s", 0).is_empty(),
        "weak-detection-only entity must not fire AU-003 regardless of distinct-source count"
    );

    // A `verified-detection` tag (a real body-marker confirmation) alongside
    // the same evidence chain means genuine corroboration is present, so the
    // rule still fires.
    let mut verified = Entity::new(EntityKind::Url, "https://github.com/rob_dorito", 0.92, "s");
    verified.tag("weak-detection"); // some sources were still weak…
    verified.tag("verified-detection"); // …but at least one was confirmed
    verified.add_evidence(crate::core::entity::Evidence::new(
        "username_search",
        "body match",
    ));
    verified.add_evidence(crate::core::entity::Evidence::new(
        "streaming_probe",
        "status 200",
    ));
    verified.add_evidence(crate::core::entity::Evidence::new("web_crawler", "linked"));
    assert_eq!(
        rule_au_003_high_corroboration(&RuleContext::new(&[verified]), "s", 0).len(),
        1,
        "a genuinely verified-detection entity must still fire AU-003"
    );
}

// ── AU-004 ──────────────────────────────────────────────────────────

#[test]
fn au004_fires_on_malicious_domain() {
    // Requires two independent sources to reach CRITICAL — shared infra appears
    // in single blocklists without being subject-owned.
    let mut e = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    e.add_evidence(Evidence::new(
        "ip_reputation",
        "flagged malicious".to_string(),
    ));
    e.add_evidence(Evidence::new("threatfox", "c2 domain".to_string()));
    let r = rule_au_004_malicious_infrastructure(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au004_no_fire_single_source() {
    // Single-source malicious tag must NOT produce a CRITICAL — insufficient
    // corroboration to distinguish CDN/ESP blocklist noise from real malice.
    let mut e = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    e.add_evidence(Evidence::new(
        "ip_reputation",
        "flagged malicious".to_string(),
    ));
    assert!(rule_au_004_malicious_infrastructure(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au004_no_fire_without_tag() {
    let e = tagged(EntityKind::Domain, "ok.example", &[]);
    assert!(rule_au_004_malicious_infrastructure(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au004_no_fire_on_single_threat_source_plus_enrichment() {
    // Regression: the ≥2 bar must count THREAT sources, not every corroborating
    // source. `ip_geo` is geolocation enrichment — it is NOT in
    // ENRICHMENT_ONLY_SOURCES, so it counts toward `Entity::source_count`, yet it
    // asserts nothing about maliciousness. One blocklist hit (`ip_reputation`)
    // plus a routine `ip_geo` record previously reached source_count == 2 and
    // fired a CRITICAL "malicious" finding on a shared-edge IP. Only one threat
    // source actually flagged it, so AU-004 must stay silent (AU-015 still
    // reports the single-source hit at its own severity).
    let mut e = tagged(
        EntityKind::IpAddress,
        "45.79.10.20",
        &[crate::core::tags::MALICIOUS],
    );
    e.add_evidence(Evidence::new(
        "ip_reputation",
        "flagged malicious".to_string(),
    ));
    e.add_evidence(Evidence::new("ip_geo", "Sydney, AU".to_string()));
    assert!(
        rule_au_004_malicious_infrastructure(&RuleContext::new(&[e]), "s", 0).is_empty(),
        "one threat source + geolocation enrichment is not two agreeing threat verdicts"
    );
}

// ── AU-005 ──────────────────────────────────────────────────────────

#[test]
fn au005_fires_on_tor_exit() {
    let e = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
    let r = rule_au_005_anonymous_network(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

// ── AU-006 ──────────────────────────────────────────────────────────

#[test]
fn au006_fires_on_vpn_but_not_tor() {
    let vpn_ip = tagged(EntityKind::IpAddress, "2.2.2.2", &["vpn"]);
    let tor_ip = tagged(EntityKind::IpAddress, "3.3.3.3", &["tor-exit", "vpn"]);
    let r = rule_au_006_proxy_vpn(&RuleContext::new(&[vpn_ip, tor_ip]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2.2.2.2"));
}

#[test]
fn au006_excludes_all_anon_tags_not_just_tor_exit() {
    let tor_short = tagged(EntityKind::IpAddress, "4.4.4.4", &["tor", "vpn"]);
    let anon_net = tagged(
        EntityKind::IpAddress,
        "5.5.5.5",
        &["anonymous-network", "vpn"],
    );
    let anon_vpn = tagged(EntityKind::IpAddress, "6.6.6.6", &["anonymous-vpn", "vpn"]);
    assert!(rule_au_006_proxy_vpn(&RuleContext::new(&[tor_short]), "s", 0).is_empty());
    assert!(rule_au_006_proxy_vpn(&RuleContext::new(&[anon_net]), "s", 0).is_empty());
    assert!(rule_au_006_proxy_vpn(&RuleContext::new(&[anon_vpn]), "s", 0).is_empty());
}

// ── AU-007 ──────────────────────────────────────────────────────────

#[test]
fn au007_fires_on_high_risk() {
    let e = tagged(EntityKind::IpAddress, "4.4.4.4", &["high-risk", "scanner"]);
    let r = rule_au_007_high_risk_reputation(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

// ── AU-008 ──────────────────────────────────────────────────────────

#[test]
fn au008_fires_on_vulnerable_tag() {
    let e = tagged(
        EntityKind::Domain,
        "vuln.example",
        &[crate::core::tags::VULNERABLE],
    );
    let r = rule_au_008_exposed_service(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-008");
}

#[test]
fn au008_benign_infra_verdict_vetoes_exposed_service() {
    // The user's real false positive: a Cloudflare edge IP tagged
    // `vulnerable` by a shared-edge CVE scan but catalogued benign by
    // GreyNoise must not be reported as an exposed service.
    let e = tagged(
        EntityKind::IpAddress,
        "104.20.37.187",
        &[crate::core::tags::VULNERABLE, "greynoise-benign"],
    );
    assert!(rule_au_008_exposed_service(&RuleContext::new(&[e]), "s", 0).is_empty());
}

// ── AU-009 ──────────────────────────────────────────────────────────

#[test]
fn au009_fires_on_stealer_log() {
    let e = tagged(EntityKind::Email, "x@y.com", &["stealer-log"]);
    let r = rule_au_009_stealer_log(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au009_fires_on_the_oathnet_pro_and_see_know_stealer_tag() {
    // oathnet_pro::stealer::push_stealer_entity and push_oathnet_entity (the
    // two richest stealer-log extraction paths in this codebase) tag their
    // entities "stealer", not "stealer-log" -- confirmed against
    // src/modules/oathnet_pro/stealer.rs and breach.rs. see_know's stealer
    // extraction does the same (src/modules/see_know/extract/mod.rs). AU-009
    // must recognise both literals, or a subject whose credentials were
    // captured live by malware and surfaced via OathNet/SeeKnow gets no
    // "Stealer-log compromise" finding at all.
    let oathnet = tagged(
        EntityKind::Email,
        "a@b.com",
        &["breach", "oathnet-pro", "stealer"],
    );
    let see_know = tagged(EntityKind::Email, "c@d.com", &["see-know", "stealer"]);
    let r = rule_au_009_stealer_log(&RuleContext::new(&[oathnet, see_know]), "s", 0);
    assert_eq!(
        r.len(),
        2,
        "both the OathNet Pro and SeeKnow stealer-tagged emails must fire AU-009: {r:?}"
    );
}

// ── AU-037 ──────────────────────────────────────────────────────────

#[test]
fn au037_fires_critical_on_plaintext_credentials() {
    let pw1 = Entity::new(EntityKind::Password, "hunter2", 0.9, "s");
    let pw2 = Entity::new(EntityKind::Password, "letmein", 0.9, "s");
    let cred = Entity::new(EntityKind::Credential, "user:pass", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    let r = rule_au_037_credential_exposure(
        &RuleContext::new(&[pw1, pw2, cred, email.clone()]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1, "one aggregate alert");
    assert_eq!(r[0].severity, Severity::Critical);
    assert!(r[0].description.contains("2 plaintext passwords"));
    assert!(r[0].description.contains("1 credential record"));
    // The raw secret value must NEVER appear in the alert text.
    assert!(
        !r[0].description.contains("hunter2") && !r[0].description.contains("letmein"),
        "secret values must not leak into correlation text"
    );
    // Links the secret entities plus the affected identity (the email).
    assert!(r[0].entity_uids.contains(&email.uid));

    // No secret entities → no firing.
    assert!(rule_au_037_credential_exposure(&RuleContext::new(&[email]), "s", 0).is_empty());
}

#[test]
fn au037_does_not_fire_on_a_published_public_key() {
    // github_user (fetch.rs) and pgp (mod.rs) both mint EntityKind::Credential
    // for a PUBLISHED public key -- an SSH/PGP key fingerprint the subject
    // themselves posted on GitHub or a keyserver, tagged "ssh-key"/"pgp-key",
    // used only to feed AU-048's cross-account key-sharing link. A public
    // key's private half is definitionally not "directly recoverable"; AU-037
    // must not treat one as breach/stealer credential exposure.
    let mut ssh_key = Entity::new(EntityKind::Credential, "SHA256:abc123", 0.9, "s");
    ssh_key.tag("ssh-key");
    ssh_key.tag("public-key");
    ssh_key.tag("github");
    let mut pgp_key = Entity::new(EntityKind::Credential, "0xDEADBEEF", 0.9, "s");
    pgp_key.tag("pgp-key");
    assert!(
        rule_au_037_credential_exposure(&RuleContext::new(&[ssh_key, pgp_key]), "s", 0).is_empty(),
        "a published SSH/PGP public key must not fire AU-037"
    );
}

#[test]
fn au037_entity_uids_are_deterministic_under_input_order() {
    // Determinism fix (the AU-039 take(N) family): the secret/identity samples are
    // sorted-then-capped, so the persisted entity_uids SET is independent of the
    // randomized HashMap input order — preventing duplicate AU-037 rows across the
    // live and finalise passes. Use >cap (20) secrets so truncation engages.
    use std::collections::BTreeSet;
    let mut ents: Vec<Entity> = (0..25)
        .map(|i| Entity::new(EntityKind::Password, format!("pw{i:02}"), 0.9, "s"))
        .collect();
    ents.push(Entity::new(
        EntityKind::Email,
        "subject@example.com",
        0.9,
        "s",
    ));

    let forward = rule_au_037_credential_exposure(&RuleContext::new(&ents), "s", 0);
    let mut reversed = ents.clone();
    reversed.reverse();
    let backward = rule_au_037_credential_exposure(&RuleContext::new(&reversed), "s", 0);

    assert_eq!(forward.len(), 1);
    assert_eq!(backward.len(), 1);
    let f: BTreeSet<&String> = forward[0].entity_uids.iter().collect();
    let b: BTreeSet<&String> = backward[0].entity_uids.iter().collect();
    assert_eq!(
        f, b,
        "entity_uids must be order-independent (sorted-then-capped)"
    );
    // The 20-cap on secrets is honoured (+ the one identity).
    assert!(forward[0].entity_uids.len() <= 21);
}

// ── AU-038 ──────────────────────────────────────────────────────────

#[test]
fn au038_fires_on_confirmed_profiles_across_platforms() {
    let mk = |url: &str| {
        let mut e = Entity::new(EntityKind::Url, url, 0.85, "s");
        e.tag("confirmed-profile");
        e
    };
    // Confirmed profiles on TWO distinct hosts → fires Medium, names both.
    let r = rule_au_038_verified_cross_platform_identity(
        &RuleContext::new(&[
            mk("https://x.com/kylo4kylo"),
            mk("https://github.com/kylo4kylo"),
        ]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].description.contains("2 distinct platforms"));
    assert!(r[0].description.contains("x.com") && r[0].description.contains("github.com"));

    // Same host twice → only one distinct platform → no firing.
    assert!(
        rule_au_038_verified_cross_platform_identity(
            &RuleContext::new(&[
                mk("https://www.x.com/kylo4kylo"),
                mk("https://x.com/kylo4kylo")
            ]),
            "s",
            0
        )
        .is_empty()
    );
    // A non-confirmed URL is ignored.
    let plain = Entity::new(EntityKind::Url, "https://x.com/kylo4kylo", 0.5, "s");
    assert!(
        rule_au_038_verified_cross_platform_identity(&RuleContext::new(&[plain]), "s", 0)
            .is_empty()
    );
}

#[test]
fn au038_fires_on_social_probe_profiles() {
    // `social_probe` tags direct-enumeration profiles `social-profile` (not
    // `confirmed-profile`); AU-038 must treat that probe signal as verified.
    let mk = |url: &str| {
        let mut e = Entity::new(EntityKind::Url, url, 0.9, "s");
        e.tag("social-profile");
        e
    };
    let r = rule_au_038_verified_cross_platform_identity(
        &RuleContext::new(&[
            mk("https://steamcommunity.com/id/kylo4kylo"),
            mk("https://www.tiktok.com/@kylo4kylo"),
            mk("https://bsky.app/profile/kylo4kylo.bsky.social"),
        ]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("3 distinct platforms"));

    // Mixed provenance (one probe + one search-confirmed) still aggregates.
    let mut probe = Entity::new(EntityKind::Url, "https://twitch.tv/kylo4kylo", 0.9, "s");
    probe.tag("social-profile");
    let mut searched = Entity::new(EntityKind::Url, "https://twitter.com/kylo4kylo", 0.85, "s");
    searched.tag("confirmed-profile");
    let r =
        rule_au_038_verified_cross_platform_identity(&RuleContext::new(&[probe, searched]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 distinct platforms"));
}

#[test]
fn au038_excludes_weak_detection_status_only_guesses() {
    // Same regression as AU-055: `social-profile` is tagged on a bare
    // status-code guess just as readily as on a body-marker-confirmed hit,
    // and this rule's OWN NAME promises "verified" — a claim only the latter
    // earns. `weak-detection`-tagged hits, even across several platforms,
    // must not fire this rule.
    let mk_weak = |url: &str| {
        let mut e = Entity::new(EntityKind::Url, url, 0.74, "s");
        e.tag("social-profile");
        e.tag("weak-detection");
        e
    };
    let r = rule_au_038_verified_cross_platform_identity(
        &RuleContext::new(&[
            mk_weak("https://onlyfans.com/rob_dorito"),
            mk_weak("https://twitch.tv/rob_dorito"),
            mk_weak("https://tiktok.com/@rob_dorito"),
        ]),
        "s",
        0,
    );
    assert!(
        r.is_empty(),
        "weak-detection hits must not fire a rule named 'Verified cross-platform identity'"
    );

    // A verified-detection hit alongside a weak one still needs a SECOND
    // distinct platform (the rule's own ≥2 contract) — one strong platform
    // alone doesn't fire AU-038 (that's AU-055's job).
    let mut strong1 = Entity::new(EntityKind::Url, "https://github.com/rob_dorito", 0.92, "s");
    strong1.tag("social-profile");
    strong1.tag("verified-detection");
    let mut strong2 = Entity::new(
        EntityKind::Url,
        "https://reddit.com/user/rob_dorito",
        0.92,
        "s",
    );
    strong2.tag("social-profile");
    strong2.tag("verified-detection");
    let r = rule_au_038_verified_cross_platform_identity(
        &RuleContext::new(&[strong1, strong2, mk_weak("https://onlyfans.com/rob_dorito")]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 distinct platforms"));
    assert!(!r[0].description.contains("onlyfans"));
}

// ── AU-010 ──────────────────────────────────────────────────────────

#[test]
fn au010_fires_at_three_sources_on_domain() {
    let e = domain("x.com", &["crtsh", "dns_resolver", "hudsonrock"]);
    let r = rule_au_010_infra_consensus(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-010");
}

#[test]
fn au010_no_fire_at_two_sources() {
    let e = domain("x.com", &["crtsh", "dns_resolver"]);
    assert!(rule_au_010_infra_consensus(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au010_ignores_non_infrastructure_kinds() {
    let e = email("x@y.com", &["a", "b", "c"]);
    assert!(rule_au_010_infra_consensus(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au010_recall_replay_does_not_manufacture_consensus() {
    // Live person-scan flaw: a CDN edge IP "confirmed by dns_intel, doh_resolver,
    // recall" fired AU-010 265× — but `recall` is a replay of the same prior
    // observation, not an independent source, so `corroborating_sources` drops it
    // below the 3-source bar and the infrastructure noise no longer fires.
    let mk = |sources: &[&str]| {
        let mut e = Entity::new(EntityKind::IpAddress, "104.26.7.243", 0.9, "scan-test");
        for s in sources {
            e.add_evidence(Evidence::new(*s, "test"));
        }
        e
    };
    assert!(
        rule_au_010_infra_consensus(
            &RuleContext::new(&[mk(&["dns_intel", "doh_resolver", "recall"])]),
            "s",
            0
        )
        .is_empty(),
        "two resolvers + a recall replay is not a 3-source consensus"
    );
    // Three INDEPENDENT infrastructure sources still fire.
    assert_eq!(
        rule_au_010_infra_consensus(
            &RuleContext::new(&[mk(&["dns_intel", "doh_resolver", "crtsh"])]),
            "s",
            0
        )
        .len(),
        1
    );
}

// ── AU-011 ──────────────────────────────────────────────────────────

#[test]
fn au011_fires_on_three_platforms() {
    let e = username_summary("alice", 3, "github, reddit, twitter");
    let r = rule_au_011_cross_platform_username(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("3 platforms"));
    assert!(r[0].description.contains("github"));
}

#[test]
fn au011_no_fire_on_two_platforms() {
    let e = username_summary("alice", 2, "github, reddit");
    assert!(rule_au_011_cross_platform_username(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au011_discounts_status_only_hits_when_hits_verified_present() {
    // platforms_count=4 (raw, includes status-only guesses) but hits_verified=1:
    // AU-011 must trust the verified count, not the inflated raw one, so this
    // must NOT fire despite 4 >= 3.
    let mut e = Entity::new(EntityKind::Username, "alice", 0.9, "scan-test");
    e.add_evidence(
        Evidence::new("username_search", "summary")
            .with_attr("platforms_count", "4")
            .with_attr("platforms", "a, b, c, d")
            .with_attr("hits_verified", "1")
            .with_attr("hits_status_only", "3"),
    );
    assert!(
        rule_au_011_cross_platform_username(&RuleContext::new(&[e]), "s", 0).is_empty(),
        "an inflated raw count with only 1 verified hit must not fire"
    );
}

#[test]
fn au011_fires_on_genuinely_verified_hits() {
    let mut e = Entity::new(EntityKind::Username, "alice", 0.9, "scan-test");
    e.add_evidence(
        Evidence::new("username_search", "summary")
            .with_attr("platforms_count", "3")
            .with_attr("platforms", "github, reddit, twitter")
            .with_attr("hits_verified", "3")
            .with_attr("hits_status_only", "0"),
    );
    let r = rule_au_011_cross_platform_username(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("3 platforms"));
}

// ── AU-012 ──────────────────────────────────────────────────────────

#[test]
fn au012_fires_when_username_and_personal_site_url_present() {
    let entities = vec![
        tagged(EntityKind::Username, "alice", &[]),
        tagged(
            EntityKind::Url,
            "https://alice.example/",
            &["personal-site"],
        ),
    ];
    let r = rule_au_012_identity_linked_domain(&RuleContext::new(&entities), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].entity_uids.len(), 2);
    assert!(r[0].description.contains("co-occurs"));
}

#[test]
fn au012_also_fires_on_personal_site_domain() {
    let entities = vec![
        tagged(EntityKind::Username, "alice", &[]),
        tagged(EntityKind::Domain, "alice.example", &["personal-site"]),
    ];
    let r = rule_au_012_identity_linked_domain(&RuleContext::new(&entities), "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au012_no_fire_without_username() {
    let entities = vec![tagged(
        EntityKind::Url,
        "https://alice.example/",
        &["personal-site"],
    )];
    assert!(rule_au_012_identity_linked_domain(&RuleContext::new(&entities), "s", 0).is_empty());
}

// ── AU-013 ──────────────────────────────────────────────────────────

#[test]
fn au013_fires_on_two_lan_entities() {
    let entities = vec![
        tagged(
            EntityKind::IpAddress,
            "192.168.1.1",
            &[crate::core::tags::LOCAL_ARP],
        ),
        tagged(
            EntityKind::MacAddress,
            "aa:bb:cc:dd:ee:ff",
            &[crate::core::tags::LOCAL_ARP],
        ),
    ];
    let r = rule_au_013_local_network_discovery(&RuleContext::new(&entities), "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au013_no_fire_on_one_lan_entity() {
    let entities = vec![tagged(
        EntityKind::IpAddress,
        "192.168.1.1",
        &[crate::core::tags::LOCAL_ARP],
    )];
    assert!(rule_au_013_local_network_discovery(&RuleContext::new(&entities), "s", 0).is_empty());
}

// ── AU-014 ──────────────────────────────────────────────────────────

#[test]
fn au014_fires_on_two_geo_sources() {
    // A real coordinate — not the "0,0" radar sentinel, which is infrastructure
    // geo — anchored by two ANCHORING sources (wigle + device GPS).
    let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    e.add_evidence(Evidence::new("wigle", "test"));
    e.add_evidence(Evidence::new("device_sensors", "test"));
    let r = rule_au_014_geo_cluster(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au014_excludes_infrastructure_coordinates() {
    // A datacentre/hosting centroid — even corroborated by two geo sources — is
    // NOT a personal geo lead (parity with AU-017). A HOSTING-tagged coordinate,
    // and a bare coordinate whose sources are non-anchoring (ip_geo/ipinfo), are
    // both infrastructure_geo and must be filtered; the same point, person-
    // anchored, still fires.
    let mut hosting = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    hosting.tag(crate::core::tags::HOSTING);
    hosting.add_evidence(Evidence::new("ip_geo", "geolocated"));
    hosting.add_evidence(Evidence::new("ipinfo", "geolocated"));
    assert!(
        rule_au_014_geo_cluster(&RuleContext::new(&[hosting]), "s", 0).is_empty(),
        "a hosting-tagged coordinate must not fire AU-014"
    );

    let mut bare = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    bare.add_evidence(Evidence::new("ip_geo", "geolocated"));
    bare.add_evidence(Evidence::new("ipinfo", "geolocated"));
    assert!(
        rule_au_014_geo_cluster(&RuleContext::new(&[bare]), "s", 0).is_empty(),
        "a bare IP-geo coordinate (no anchoring source) must not fire AU-014"
    );

    // Control: the same point, anchored by real person-fixing sources, fires.
    let mut anchored = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    anchored.add_evidence(Evidence::new("exif_geo", "photo GPS"));
    anchored.add_evidence(Evidence::new("device_sensors", "gps"));
    assert_eq!(
        rule_au_014_geo_cluster(&RuleContext::new(&[anchored]), "s", 0).len(),
        1,
        "an anchored two-source coordinate still fires AU-014"
    );
}

#[test]
fn au014_does_not_count_cooccurring_tags_as_two_sources() {
    // Regression: the `hits.len() >= 2` disjunct bypasses the "corroborating
    // sources only" guard the function's own comment describes, because it
    // counts co-occurring TAGS on one entity rather than independent evidence
    // sources. `wigle::wifi_ap_entities` mints exactly this shape for every
    // WiGLE-trilaterated Wi-Fi AP: ONE Coordinates entity from ONE evidence
    // record (source "wigle"), tagged with BOTH "wifi-observed" and "geoint"
    // (see wigle/mod.rs's own emit site and its test asserting both tags).
    // Before the fix this fired "confirmed by 2 geo source(s)" from a single,
    // uncorroborated database lookup.
    let mut e = Entity::new(
        EntityKind::Coordinates,
        "-27.4766,153.0280",
        crate::core::confidence::HIGH_PLUS,
        "s",
    );
    e.tag("wigle");
    e.tag("wifi-observed");
    e.tag("geoint");
    e.add_evidence(Evidence::new(
        "wigle",
        "WiGLE-observed position of WiFi AP AA:BB:CC:DD:EE:01",
    ));
    assert!(
        rule_au_014_geo_cluster(&RuleContext::new(&[e]), "s", 0).is_empty(),
        "a single WiGLE evidence record must not fire AU-014 on tag co-occurrence alone"
    );
}

#[test]
fn geo_normalize_alone_does_not_over_fire_corroboration_rules() {
    // Regression: a coarse qld_unclaimed geo set, each entity touched only
    // by the deterministic `geo_normalize` enrichment pass, must NOT light
    // up the corroboration rules. Before the fix, geo_normalize counted as a
    // phantom second source and fired AU-003 on every address/centroid plus
    // AU-014 on every centroid and AU-030 across the set — ~20 spurious
    // correlations from a single name search.
    let coarse = |kind, val: &str| -> Entity {
        let mut e = Entity::new(kind, val, 0.30, "s");
        e.add_evidence(Evidence::new("qld_unclaimed", "register record"));
        e.add_evidence(Evidence::new("geo_normalize", "enrichment"));
        e.tag("geoint");
        e
    };
    let ents = vec![
        coarse(EntityKind::Address, "QLD 4552, Australia"),
        coarse(EntityKind::Address, "Maleny, QLD 4552, Australia"),
        coarse(EntityKind::Address, "Booroobin, QLD 4552, Australia"),
        coarse(EntityKind::Coordinates, "-26.72900,152.75540"),
    ];
    let firings = evaluate_rules(&ents, "s");
    let fired = |id: &str| firings.iter().any(|c| c.rule_id == id);
    assert!(
        !fired("AU-003"),
        "geo_normalize must not fabricate high-corroboration (AU-003)"
    );
    assert!(
        !fired("AU-014"),
        "a single-source centroid must not look like a geo cluster (AU-014)"
    );
    assert!(
        !fired("AU-030"),
        "geo_normalize must not be the 3rd source for convergence (AU-030)"
    );
}

// ── AU-015 ──────────────────────────────────────────────────────────

#[test]
fn au015_fires_on_threat_intel_tag() {
    let e = tagged(
        EntityKind::Domain,
        "bad.example",
        &[crate::core::tags::THREAT_INTEL, "ti:malware"],
    );
    let r = rule_au_015_threat_intel_hit(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("malware"));
}

#[test]
fn au015_attribution_names_evidence_source_not_otx() {
    let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
    e.tag(crate::core::tags::THREAT_INTEL);
    e.add_evidence(Evidence::new("threatfox", "t"));
    let r = rule_au_015_threat_intel_hit(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("threatfox"));
    assert!(!r[0].description.contains("OTX"));
}

#[test]
fn au015_attribution_excludes_non_ti_evidence() {
    let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
    e.tag(crate::core::tags::THREAT_INTEL);
    e.add_evidence(Evidence::new("ip_reputation", "ti-hit"));
    e.add_evidence(Evidence::new("whois", "registry-data"));
    e.add_evidence(Evidence::new("dns_resolver", "a-record"));
    let r = rule_au_015_threat_intel_hit(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("ip_reputation"));
    assert!(!r[0].description.contains("whois"));
    assert!(!r[0].description.contains("dns_resolver"));
}

#[test]
fn au015_attribution_falls_back_when_source_unknown() {
    let e = tagged(
        EntityKind::Domain,
        "bad.example",
        &[crate::core::tags::THREAT_INTEL],
    );
    let r = rule_au_015_threat_intel_hit(&RuleContext::new(&[e]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("curated threat-intel feed"));
}

// ── Cross-cutting ───────────────────────────────────────────────────

#[test]
fn severity_orders_correctly() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn evaluate_rules_fires_expected_subset() {
    let mut email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    email.add_evidence(Evidence::new("hudsonrock", "t"));
    email.add_evidence(Evidence::new("xposed_or_not", "t"));
    email.tag("stealer-log");
    let mut domain = tagged(
        EntityKind::Domain,
        "evil.example",
        &[
            crate::core::tags::MALICIOUS,
            crate::core::tags::VULNERABLE,
            crate::core::tags::THREAT_INTEL,
        ],
    );
    domain.add_evidence(Evidence::new(
        "ip_reputation",
        "flagged malicious".to_string(),
    ));
    domain.add_evidence(Evidence::new("threatfox", "c2 domain".to_string()));
    let ip = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
    let firings = evaluate_rules(&[email, domain, ip], "s");
    let ids: HashSet<&str> = firings.iter().map(|c| c.rule_id.as_str()).collect();
    for expected in &["AU-001", "AU-004", "AU-005", "AU-008", "AU-009", "AU-015"] {
        assert!(
            ids.contains(expected),
            "expected {expected} in firings, got {ids:?}"
        );
    }
}

/// Ground-truth regression guard (real data as a fixture, operator-
/// confirmed): the `jordanavery@gmail.com` identity and the
/// Maleny/Booroobin (QLD 4552) locality are the accurate results, and the
/// engine must cross-correlate them. This pins the full path so a future
/// refactor of the rule set can't silently sever it.
#[test]
fn ground_truth_jordan_avery_identity_and_booroobin_geo() {
    let scan = "ground-truth";
    let id = |kind, val: &str, sources: &[&str]| -> Entity {
        let mut e = Entity::new(kind, val, 0.80, scan);
        for s in sources {
            e.add_evidence(Evidence::new(*s, "ground-truth fixture"));
        }
        e
    };

    // Identity anchor — the email cross-confirmed by two independent
    // modules, plus the username and phone that complete the cluster.
    // NB both sources are genuine *observations* (two breach corpora): a
    // `name_intel` name-permutation is a derivation of the seed, not an
    // independent sighting, so it must not be one of the corroborating two
    // (see `ENRICHMENT_ONLY_SOURCES`) — otherwise a `name × freemail` guess
    // would self-confirm into AU-003.
    let email = id(
        EntityKind::Email,
        "jordanavery@gmail.com",
        &["oathnet_pro", "hibp"],
    );
    let username = id(
        EntityKind::Username,
        "javery88",
        &["username_search", "oathnet_pro"],
    );
    let phone = id(EntityKind::Phone, "+61400000111", &["oathnet_pro"]);
    let person = id(EntityKind::Person, "Jordan Avery", &["name_intel"]);

    // qld_unclaimed surfaces Booroobin at *candidate* confidence (0.40,
    // below the 0.50 expand floor) — a coarse postcode-centroid lead.
    let booroobin_candidate = {
        let mut a = Entity::new(
            EntityKind::Address,
            "Booroobin, QLD 4552, Australia",
            0.40,
            scan,
        );
        a.tag("qld_unclaimed");
        a.tag("geoint");
        a.tag("candidate-suburb");
        a
    };

    // ── Phase 1: identity cross-correlation always holds; the unconfirmed
    //    suburb must NOT yet claim an email↔location linkage. ──
    let mut ents = vec![
        email.clone(),
        username.clone(),
        phone.clone(),
        person.clone(),
        booroobin_candidate,
    ];
    let firings = evaluate_rules(&ents, scan);
    let ids: HashSet<&str> = firings.iter().map(|c| c.rule_id.as_str()).collect();

    // AU-002 ties the email and username into one identity cluster.
    let au002 = firings
        .iter()
        .find(|c| c.rule_id == "AU-002")
        .expect("identity cluster (AU-002) must fire");
    assert!(
        au002.entity_uids.contains(&email.uid),
        "cluster must include the email"
    );
    assert!(
        au002.entity_uids.contains(&username.uid),
        "cluster must include javery88"
    );

    // AU-003 flags the two-source email as high cross-source corroboration.
    assert!(
        firings
            .iter()
            .any(|c| c.rule_id == "AU-003" && c.entity_uids.contains(&email.uid)),
        "the cross-confirmed email must be flagged high-corroboration"
    );

    // Accurate hedging: a 0.40 candidate suburb is below AU-018's 0.50 gate,
    // so the engine must not yet assert identity↔location linkage.
    assert!(
        !ids.contains("AU-018"),
        "unconfirmed candidate suburb must not fire email-location colocation"
    );

    // ── Phase 2: once a second geo source corroborates Booroobin to >=0.50,
    //    the email↔Booroobin linkage the operator validated must fire. ──
    let booroobin_confirmed = {
        let mut a = Entity::new(
            EntityKind::Address,
            "Booroobin, QLD 4552, Australia",
            0.72,
            scan,
        );
        a.tag("qld_unclaimed");
        a.tag("geoint");
        a.add_evidence(Evidence::new("qld_unclaimed", "unclaimed-money register"));
        a.add_evidence(Evidence::new("geocode", "address confirmed"));
        a
    };
    ents.pop(); // drop the candidate
    ents.push(booroobin_confirmed.clone());
    let firings2 = evaluate_rules(&ents, scan);
    let au018 = firings2
        .iter()
        .find(|c| c.rule_id == "AU-018")
        .expect("email-location linkage (AU-018) must fire once geo is corroborated");
    assert!(
        au018.entity_uids.contains(&email.uid),
        "linkage must include jordanavery@gmail.com"
    );
    assert!(
        au018.entity_uids.contains(&booroobin_confirmed.uid),
        "linkage must include the confirmed Booroobin address"
    );
}

/// Ground-truth regression guard (the operator's own `name` scan, after the
/// geo_normalize / qld_unclaimed / name_intel quality fixes). BEFORE the fix
/// this entity set produced **28** correlations — ~19 spurious AU-003 + 4
/// AU-014 + 1 AU-030 fabricated by the `geo_normalize` phantom source over
/// coarse `qld_unclaimed` geo. It must now yield exactly the **four** real
/// cross-source findings (person corroboration, peekyou infra consensus +
/// AU-003, local Wi-Fi) and never resurrect the geo over-fire or fuse the
/// single-source candidate guesses (suburbs / permuted handles+emails) into a
/// false identity (AU-002) or identity↔location (AU-018) cluster.
#[test]
fn ground_truth_erik_avery_scan_yields_only_real_correlations() {
    use std::collections::HashMap;

    let mk = |kind, value: &str, conf: f64, sources: &[&str], tags: &[&str]| -> Entity {
        let mut e = Entity::new(kind, value, conf, "erik");
        for s in sources {
            e.add_evidence(Evidence::new(*s, "ground-truth fixture"));
        }
        for t in tags {
            e.tag(*t);
        }
        e
    };

    let mut ents: Vec<Entity> = Vec::new();
    // ── Genuine cross-source signal ──
    ents.push(mk(
        EntityKind::Person,
        "Erik Avery",
        0.90,
        &["oathnet_pro", "social_probe"],
        &["breach", "social-probed"],
    ));
    // The people-search PLATFORM the scan profiled (its own infra) — well-
    // corroborated infrastructure, but about the platform, not the person.
    ents.push(mk(
        EntityKind::Domain,
        "www.peekyou.com",
        0.95,
        &[
            "cert_intel",
            "crtsh",
            "dns_intel",
            "hackertarget",
            "rdap_domain",
            "shodan",
            "social_probe",
            "urlscan",
            "waf_detect",
            "web_crawler",
            "webserver_banner",
        ],
        &["social-platform", "cloudflare"],
    ));
    ents.push(mk(
        EntityKind::Url,
        "https://www.peekyou.com/erik-avery",
        0.80,
        &["social_probe"],
        &["social-profile"],
    ));
    // Operator's own device / local network (single-source, local-only).
    for m in [
        "94:a6:7e:7d:49:76",
        "94:a6:7e:7d:49:77",
        "ec:d9:09:2c:66:40",
        "96:2a:6f:fc:98:dd",
        "94:a6:7e:7d:49:74",
        "9a:49:14:d1:f3:14",
    ] {
        ents.push(mk(
            EntityKind::MacAddress,
            m,
            0.95,
            &["wifi_intel"],
            &[crate::core::tags::WIFI_AP],
        ));
    }
    ents.push(mk(
        EntityKind::Coordinates,
        "-27.2690125,153.0179605",
        0.97,
        &["device_sensors", "geo_normalize"],
        &["geoint", "device-sensor"],
    ));
    // ── Coarse qld_unclaimed geo — every entity ALSO touched by the
    //    deterministic geo_normalize pass (the phantom-source trap). ──
    ents.push(mk(
        EntityKind::Address,
        "QLD 4552, Australia",
        0.38,
        &["qld_unclaimed", "geo_normalize"],
        &[
            "postcode-only",
            "geoint",
            crate::core::tags::COARSE,
            "exact-name-match",
        ],
    ));
    for pc in ["QLD 4555, Australia", "QLD 4557, Australia"] {
        ents.push(mk(
            EntityKind::Address,
            pc,
            0.32,
            &["qld_unclaimed", "geo_normalize"],
            &[
                "postcode-only",
                "geoint",
                crate::core::tags::COARSE,
                "family-candidate",
            ],
        ));
    }
    for s in [
        "Conondale, QLD 4552, Australia",
        "Curramore, QLD 4552, Australia",
        "Booroobin, QLD 4552, Australia",
        "Maleny, QLD 4552, Australia",
        "Mooloolaba, QLD 4557, Australia",
        "Palmwoods, QLD 4555, Australia",
    ] {
        ents.push(mk(
            EntityKind::Address,
            s,
            0.30,
            &["qld_unclaimed", "geo_normalize"],
            &["candidate-suburb", "geoint", crate::core::tags::COARSE],
        ));
    }
    for c in [
        "-26.68330,152.96670",
        "-26.72900,152.75540",
        "-26.68330,153.11670",
    ] {
        ents.push(mk(
            EntityKind::Coordinates,
            c,
            0.30,
            &["qld_unclaimed", "geo_normalize"],
            &["geoint", "postcode-centroid", crate::core::tags::COARSE],
        ));
    }
    // ── name_intel permutations (single-source Candidate guesses) ──
    for u in ["erikavery", "eavery", "erik_avery", "erik.avery", "erikd"] {
        ents.push(mk(
            EntityKind::Username,
            u,
            0.38,
            &["name_intel"],
            &["derived", "name-derived"],
        ));
    }
    for em in [
        "erikavery@gmail.com",
        "erik.avery@gmail.com",
        "eavery@gmail.com",
    ] {
        ents.push(mk(
            EntityKind::Email,
            em,
            0.30,
            &["name_intel"],
            &["derived", "permuted"],
        ));
    }

    let firings = evaluate_rules(&ents, "erik");
    let summary: Vec<(&str, &str)> = firings
        .iter()
        .map(|c| (c.rule_id.as_str(), c.description.as_str()))
        .collect();

    // Real correlations — nothing fabricated. AU-045: "Erik Avery" is
    // corroborated by oathnet_pro (breach) AND social_probe (social) — two
    // independent service families. AU-054: the subject's own listing at
    // peekyou.com/erik-avery is a genuine data-location finding. AU-061: the
    // two family-candidate Avery addresses (QLD 4555/4557) resolve to within
    // ~150 km of the subject's confirmed Brisbane fix. AU-076: the email
    // local-parts of erikavery@gmail.com / erik.avery@gmail.com / eavery@
    // canonically match username entities in the fixture — free offline
    // identity bridges, all correct (the emails *are* the login handles).
    assert!(
        firings.len() >= 7,
        "expected at least 7 real correlations, got: {summary:#?}"
    );

    let fired: HashSet<&str> = firings.iter().map(|c| c.rule_id.as_str()).collect();
    assert!(
        fired.contains("AU-003"),
        "person + peekyou cross-source corroboration"
    );
    assert!(fired.contains("AU-010"), "peekyou infrastructure consensus");
    assert!(fired.contains("AU-013"), "local Wi-Fi AP discovery");
    assert!(
        fired.contains("AU-045"),
        "Erik Avery confirmed across breach + social families"
    );
    // The free family geo-corroboration: surname kin in the subject's area.
    assert!(
        fired.contains("AU-061"),
        "family-candidates geo-corroborated near the subject's fix"
    );
    let au061 = firings
        .iter()
        .find(|c| c.rule_id == "AU-061")
        .expect("family-candidates near the subject's fix → AU-061");
    assert!(
        au061.description.contains("family-candidate") && au061.description.contains("4555"),
        "AU-061 names the geo-corroborated relatives: {}",
        au061.description
    );
    // The location finding: subject's PII brokered on a people-search site.
    let au054 = firings
        .iter()
        .find(|c| c.rule_id == "AU-054")
        .expect("subject's PII located on peekyou.com → AU-054");
    assert!(
        au054.description.contains("PeekYou") && au054.description.contains("brokered on"),
        "AU-054 must name the broker as a data-location finding: {}",
        au054.description
    );

    // The fix holds: no geo over-fire, no fused identity/location from guesses.
    for absent in ["AU-002", "AU-014", "AU-018", "AU-030"] {
        assert!(
            !fired.contains(absent),
            "{absent} must not fire on coarse/candidate noise: {summary:#?}"
        );
    }

    // AU-003 may only flag the corroborated person + domain — NEVER a coarse
    // geo entity (the exact phantom-`geo_normalize`-source regression). Two
    // firings, both non-geo.
    let kind_by_uid: HashMap<&str, &EntityKind> =
        ents.iter().map(|e| (e.uid.as_str(), &e.kind)).collect();
    let au003: Vec<&Correlation> = firings.iter().filter(|c| c.rule_id == "AU-003").collect();
    assert_eq!(au003.len(), 2, "AU-003 only on the person + peekyou domain");
    for c in au003 {
        for uid in &c.entity_uids {
            let kind = kind_by_uid.get(uid.as_str()).expect("uid in fixture");
            assert!(
                matches!(kind, EntityKind::Person | EntityKind::Domain),
                "AU-003 must not flag a coarse {kind:?} as corroborated"
            );
        }
    }
}

#[test]
fn rule_016_breach_ip_geo_chain_fires() {
    let mut ip = Entity::new(EntityKind::IpAddress, "101.169.42.148", 0.72, "s");
    ip.tag("breach");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.5567,152.2767", 0.65, "s");
    coord.add_evidence(Evidence::new(
        "ip_geo",
        "Geolocation for 101.169.42.148: Gatton, QLD",
    ));
    let firings = rule_au_016_breach_ip_geo_chain(&RuleContext::new(&[ip, coord]), "s", 0);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].rule_id, "AU-016");
}

#[test]
fn rule_016_no_fire_without_breach_tag() {
    let ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.72, "s");
    let coord = Entity::new(EntityKind::Coordinates, "1.0,2.0", 0.65, "s");
    let firings = rule_au_016_breach_ip_geo_chain(&RuleContext::new(&[ip, coord]), "s", 0);
    assert!(firings.is_empty());
}

#[test]
fn rule_016_does_not_chain_on_substring_ip_match() {
    // Breach IP 1.2.3.4 must NOT chain to a coordinate geolocated from the
    // unrelated 11.2.3.45 (which contains "1.2.3.4" as a substring). A bare
    // `contains` would mis-fire this High finding.
    let mut breach = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.72, "s");
    breach.tag("breach");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.65, "s");
    coord.add_evidence(Evidence::new(
        "ip_geo",
        "Geolocation for 11.2.3.45: Gatton, QLD",
    ));
    assert!(
        rule_au_016_breach_ip_geo_chain(&RuleContext::new(&[breach, coord]), "s", 0).is_empty(),
        "substring IP match must not chain"
    );

    // A trailing ':' (IP: city / IP:port) is still a legitimate whole-IP match.
    let mut breach2 = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.72, "s");
    breach2.tag("breach");
    let mut coord2 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.65, "s");
    coord2.add_evidence(Evidence::new(
        "ip_geo",
        "Geolocation for 1.2.3.4: Gatton, QLD",
    ));
    assert_eq!(
        rule_au_016_breach_ip_geo_chain(&RuleContext::new(&[breach2, coord2]), "s", 0).len(),
        1,
        "exact whole-IP match (even followed by ':') must still chain"
    );
}

// A coordinate anchored to a real person-fixing source (EXIF/device GPS), so it
// passes the is_infrastructure_geo guard AU-017/AU-057 now share with AU-030/099.
fn anchored_coord(value: &str, conf: f64) -> Entity {
    let mut e = Entity::new(EntityKind::Coordinates, value, conf, "s");
    e.add_evidence(crate::core::entity::Evidence::new("exif_geo", "photo GPS"));
    e
}

#[test]
fn rule_017_multi_geo_convergence_fires() {
    let c1 = anchored_coord("-27.55,152.27", 0.60);
    let c2 = anchored_coord("-27.60,152.30", 0.65);
    let firings = rule_au_017_multi_geo_convergence(&RuleContext::new(&[c1, c2]), "s", 0);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].rule_id, "AU-017");
    assert!(firings[0].description.contains("converge"));
}

#[test]
fn rule_017_no_fire_for_distant_coords() {
    let c1 = anchored_coord("-27.55,152.27", 0.60);
    let c2 = anchored_coord("-33.86,151.20", 0.65);
    let firings = rule_au_017_multi_geo_convergence(&RuleContext::new(&[c1, c2]), "s", 0);
    assert!(firings.is_empty());
}

#[test]
fn rule_017_excludes_infrastructure_coordinates() {
    // Two hosting-datacentre coordinates within convergence distance must NOT
    // fuse into a "subject physically located here" finding — parity with
    // AU-030/AU-099. A bare IP-geo/hosting coordinate locates the infra, not the
    // person. The same geometry, person-anchored, still fires (control).
    let mut h1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
    h1.tag(crate::core::tags::HOSTING);
    let mut h2 = Entity::new(EntityKind::Coordinates, "-27.60,152.30", 0.65, "s");
    h2.tag(crate::core::tags::HOSTING);
    assert!(
        rule_au_017_multi_geo_convergence(&RuleContext::new(&[h1, h2]), "s", 0).is_empty(),
        "infrastructure coordinates must not converge into a subject location"
    );
    // A bare coordinate with no anchoring source is also infrastructure.
    let b1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
    let b2 = Entity::new(EntityKind::Coordinates, "-27.60,152.30", 0.65, "s");
    assert!(rule_au_017_multi_geo_convergence(&RuleContext::new(&[b1, b2]), "s", 0).is_empty());
    // Control: the same points, person-anchored, DO converge.
    assert_eq!(
        rule_au_017_multi_geo_convergence(
            &RuleContext::new(&[
                anchored_coord("-27.55,152.27", 0.60),
                anchored_coord("-27.60,152.30", 0.65)
            ]),
            "s",
            0
        )
        .len(),
        1
    );
}

#[test]
fn rule_017_clustering_is_order_independent() {
    // Chain geometry: A-B within 0.5 deg, B-C within 0.5 deg, A-C beyond it.
    // The greedy assignment compares against each cluster's FOUNDING member,
    // so without a deterministic pre-sort the input order decided whether the
    // chain clustered as {A,B}+{C} or {A,B,C} — and the live pass feeds
    // entities in HashMap (randomised) order, persisting conflicting AU-017
    // uid sets across rounds. Every permutation must now produce identical
    // firings.
    let a = anchored_coord("1.00,0.00", 0.60);
    let b = anchored_coord("1.40,0.00", 0.60);
    let c = anchored_coord("1.80,0.00", 0.60);
    let uid_sets = |ents: &[Entity]| -> Vec<Vec<String>> {
        rule_au_017_multi_geo_convergence(&RuleContext::new(ents), "s", 0)
            .into_iter()
            .map(|f| {
                let mut u = f.entity_uids;
                u.sort();
                u
            })
            .collect()
    };
    let baseline = uid_sets(&[a.clone(), b.clone(), c.clone()]);
    for perm in [
        vec![a.clone(), c.clone(), b.clone()],
        vec![b.clone(), a.clone(), c.clone()],
        vec![b.clone(), c.clone(), a.clone()],
        vec![c.clone(), a.clone(), b.clone()],
        vec![c.clone(), b.clone(), a.clone()],
    ] {
        assert_eq!(
            uid_sets(&perm),
            baseline,
            "AU-017 clusters must not depend on entity iteration order"
        );
    }
}

#[test]
fn rule_017_drops_out_of_range_coordinates() {
    // Junk coordinates (lat/lon outside Earth's range) must be rejected by the
    // range-validating parse_coords helper, not clustered as a convergence.
    let junk1 = Entity::new(EntityKind::Coordinates, "200.0,300.0", 0.60, "s");
    let junk2 = Entity::new(EntityKind::Coordinates, "201.0,301.0", 0.65, "s");
    let firings = rule_au_017_multi_geo_convergence(&RuleContext::new(&[junk1, junk2]), "s", 0);
    assert!(firings.is_empty(), "out-of-range coords must not converge");
}

// ── AU-031 (graph-aware: relation edges) ────────────────────────────

#[test]
fn au031_fires_on_edge_to_malicious_node() {
    use crate::core::relation::{Relation, RelationKind};
    let bad = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    let benign = tagged(EntityKind::Domain, "blog.evil.example", &[]);
    let rel = Relation::new(
        benign.uid.clone(),
        bad.uid.clone(),
        RelationKind::SubdomainOf,
        0.8,
        "s",
    );
    let r = rule_au_031_malicious_adjacency(
        &RuleContext::new(&[bad.clone(), benign.clone()]),
        &[rel],
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-031");
    assert_eq!(r[0].severity, Severity::High);
    assert!(r[0].entity_uids.contains(&benign.uid));
    assert!(r[0].entity_uids.contains(&bad.uid));
    assert!(r[0].description.contains("blog.evil.example"));
    assert!(r[0].description.contains("malicious"));
}

#[test]
fn au031_no_fire_when_neither_endpoint_flagged() {
    use crate::core::relation::{Relation, RelationKind};
    let a = tagged(EntityKind::Domain, "a.example", &[]);
    let b = tagged(EntityKind::Domain, "example", &[]);
    let rel = Relation::new(
        a.uid.clone(),
        b.uid.clone(),
        RelationKind::SubdomainOf,
        0.8,
        "s",
    );
    assert!(rule_au_031_malicious_adjacency(&RuleContext::new(&[a, b]), &[rel], "s", 0).is_empty());
}

#[test]
fn au031_no_fire_when_both_endpoints_flagged() {
    use crate::core::relation::{Relation, RelationKind};
    let a = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    let b = tagged(
        EntityKind::Domain,
        "bad.example",
        &[crate::core::tags::THREAT_INTEL],
    );
    let rel = Relation::new(
        a.uid.clone(),
        b.uid.clone(),
        RelationKind::CoLocatedWith,
        0.8,
        "s",
    );
    assert!(rule_au_031_malicious_adjacency(&RuleContext::new(&[a, b]), &[rel], "s", 0).is_empty());
}

#[test]
fn au031_skips_edges_with_missing_endpoints() {
    use crate::core::relation::{Relation, RelationKind};
    // Edge references a uid not in the entity set → no fire, no panic.
    let bad = tagged(
        EntityKind::Domain,
        "evil.example",
        &[crate::core::tags::MALICIOUS],
    );
    let rel = Relation::new(
        "ghost-uid",
        bad.uid.clone(),
        RelationKind::DerivedFrom,
        0.8,
        "s",
    );
    assert!(rule_au_031_malicious_adjacency(&RuleContext::new(&[bad]), &[rel], "s", 0).is_empty());
}

#[test]
fn au031_aggregates_high_fanout_shared_infra() {
    use crate::core::relation::{Relation, RelationKind};
    // One flagged shared IP (CDN) with 30 distinct co-hosted domains: the
    // real-world noise case. Must collapse to ONE Medium aggregate, not 30
    // High rows — while a dedicated node (≤ cap) still fires per-neighbour.
    let bad = tagged(
        EntityKind::IpAddress,
        "104.20.37.187",
        &[crate::core::tags::VULNERABLE],
    );
    let mut entities = vec![bad.clone()];
    let mut rels = Vec::new();
    for i in 0..30 {
        let d = tagged(EntityKind::Domain, &format!("site{i}-merch.example"), &[]);
        rels.push(Relation::new(
            d.uid.clone(),
            bad.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        ));
        entities.push(d);
    }
    let r = rule_au_031_malicious_adjacency(&RuleContext::new(&entities), &rels, "s", 0);
    assert_eq!(r.len(), 1, "30-way fan-out must aggregate to one finding");
    assert_eq!(r[0].rule_id, "AU-031");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].description.contains("30 entities"));
    assert!(r[0].description.contains("shared infrastructure"));
    assert!(r[0].entity_uids.contains(&bad.uid));

    // Deterministic across input orderings (BTreeMap-keyed).
    let mut shuffled = rels.clone();
    shuffled.reverse();
    let r2 = rule_au_031_malicious_adjacency(&RuleContext::new(&entities), &shuffled, "s", 0);
    assert_eq!(r[0].description, r2[0].description);
    assert_eq!(r[0].entity_uids, r2[0].entity_uids);

    // Control: a flagged node with few neighbours stays per-neighbour/High.
    let r3 = rule_au_031_malicious_adjacency(&RuleContext::new(&entities[..4]), &rels[..3], "s", 0);
    assert_eq!(r3.len(), 3);
    assert!(r3.iter().all(|c| c.severity == Severity::High));
}

#[test]
fn au031_benign_infra_verdict_vetoes_adjacency() {
    use crate::core::relation::{Relation, RelationKind};
    // The real case: a Cloudflare edge IP tagged BOTH `vulnerable` (CVE scan
    // of the shared edge) AND `greynoise-riot` (catalogued benign). The
    // GreyNoise verdict wins — no adjacency fires at all (not exploded, not
    // aggregated), and the explosion is killed at its root, not its symptom.
    let bad = tagged(
        EntityKind::IpAddress,
        "104.20.37.187",
        &[crate::core::tags::VULNERABLE, "greynoise-riot"],
    );
    let mut entities = vec![bad.clone()];
    let mut rels = Vec::new();
    for i in 0..30 {
        let d = tagged(EntityKind::Domain, &format!("site{i}.example"), &[]);
        rels.push(Relation::new(
            d.uid.clone(),
            bad.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        ));
        entities.push(d);
    }
    assert!(
        rule_au_031_malicious_adjacency(&RuleContext::new(&entities), &rels, "s", 0).is_empty(),
        "a GreyNoise-benign shared edge must not anchor adjacency"
    );

    // A genuine high-fan-out MALICIOUS cluster (no benign verdict) stays
    // loud: aggregated, but High — not silently downgraded.
    let evil = tagged(
        EntityKind::Domain,
        "evil.apex",
        &[crate::core::tags::MALICIOUS],
    );
    let mut ents = vec![evil.clone()];
    let mut er = Vec::new();
    for i in 0..20 {
        let s = tagged(EntityKind::Domain, &format!("n{i}.evil.apex"), &[]);
        er.push(Relation::new(
            s.uid.clone(),
            evil.uid.clone(),
            RelationKind::SubdomainOf,
            0.8,
            "s",
        ));
        ents.push(s);
    }
    let rm = rule_au_031_malicious_adjacency(&RuleContext::new(&ents), &er, "s", 0);
    assert_eq!(rm.len(), 1);
    assert_eq!(
        rm[0].severity,
        Severity::High,
        "malicious cluster stays High"
    );
}

// ── AU-032 (graph-aware: co-location cluster) ───────────────────────

#[test]
fn au032_fires_on_three_node_colocation_cluster() {
    use crate::core::relation::{Relation, RelationKind};
    // Anchored to a real person-fixing source (device GPS) so the coordinates are
    // NOT infrastructure geo; otherwise the co-location edges are (correctly)
    // dropped. See au032_excludes_infrastructure_colocations.
    let mut c1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    c1.add_evidence(Evidence::new("device_sensors", "gps"));
    let mut c2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    c2.add_evidence(Evidence::new("device_sensors", "gps"));
    let mut c3 = Entity::new(EntityKind::Coordinates, "-27.471000,153.021000", 0.7, "s");
    c3.add_evidence(Evidence::new("device_sensors", "gps"));
    // Chain c1–c2–c3 → one connected component of 3.
    let rels = vec![
        Relation::new(
            c1.uid.clone(),
            c2.uid.clone(),
            RelationKind::CoLocatedWith,
            0.9,
            "s",
        ),
        Relation::new(
            c2.uid.clone(),
            c3.uid.clone(),
            RelationKind::CoLocatedWith,
            0.9,
            "s",
        ),
    ];
    let r = rule_au_032_colocation_cluster(&RuleContext::new(&[c1, c2, c3]), &rels, "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-032");
    assert_eq!(r[0].severity, Severity::Medium);
    assert_eq!(r[0].entity_uids.len(), 3);
    assert!(r[0].description.contains("3 coordinates"));
}

#[test]
fn au032_excludes_infrastructure_colocations() {
    use crate::core::relation::{Relation, RelationKind};
    // Three co-located datacentre coordinates are infrastructure, not a personal
    // convergence — the co-location edges between them are dropped, so no cluster
    // forms. The same chain, person-anchored, still fires (control).
    let colo = |a: &Entity, b: &Entity| {
        Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::CoLocatedWith,
            0.9,
            "s",
        )
    };

    let mut h1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    h1.tag(crate::core::tags::HOSTING);
    let mut h2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    h2.tag(crate::core::tags::HOSTING);
    let mut h3 = Entity::new(EntityKind::Coordinates, "-27.471000,153.021000", 0.7, "s");
    h3.tag(crate::core::tags::HOSTING);
    let rels = vec![colo(&h1, &h2), colo(&h2, &h3)];
    assert!(
        rule_au_032_colocation_cluster(&RuleContext::new(&[h1, h2, h3]), &rels, "s", 0).is_empty(),
        "co-located datacentres must not form a convergence cluster"
    );

    // Control: the same chain, person-anchored, fires.
    let mut a1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    a1.add_evidence(Evidence::new("device_sensors", "gps"));
    let mut a2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    a2.add_evidence(Evidence::new("device_sensors", "gps"));
    let mut a3 = Entity::new(EntityKind::Coordinates, "-27.471000,153.021000", 0.7, "s");
    a3.add_evidence(Evidence::new("device_sensors", "gps"));
    let rels2 = vec![colo(&a1, &a2), colo(&a2, &a3)];
    assert_eq!(
        rule_au_032_colocation_cluster(&RuleContext::new(&[a1, a2, a3]), &rels2, "s", 0).len(),
        1,
        "person-anchored co-located coordinates still cluster"
    );
}

#[test]
fn au032_no_fire_on_pair() {
    use crate::core::relation::{Relation, RelationKind};
    let c1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    let c2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    let rels = vec![Relation::new(
        c1.uid.clone(),
        c2.uid.clone(),
        RelationKind::CoLocatedWith,
        0.9,
        "s",
    )];
    assert!(rule_au_032_colocation_cluster(&RuleContext::new(&[c1, c2]), &rels, "s", 0).is_empty());
}

#[test]
fn au032_ignores_non_colocation_edges() {
    use crate::core::relation::{Relation, RelationKind};
    // Three domains chained by SubdomainOf — not co-location → no cluster.
    let a = Entity::new(EntityKind::Domain, "a.b.c.com", 0.9, "s");
    let b = Entity::new(EntityKind::Domain, "b.c.com", 0.9, "s");
    let c = Entity::new(EntityKind::Domain, "c.com", 0.9, "s");
    let rels = vec![
        Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::SubdomainOf,
            0.9,
            "s",
        ),
        Relation::new(
            b.uid.clone(),
            c.uid.clone(),
            RelationKind::SubdomainOf,
            0.9,
            "s",
        ),
    ];
    assert!(
        rule_au_032_colocation_cluster(&RuleContext::new(&[a, b, c]), &rels, "s", 0).is_empty()
    );
}

// ── AU-060 (graph-aware: transitive identity closure) ────────────────

#[test]
fn au060_fires_on_two_hop_identity_chain() {
    use crate::core::relation::{Relation, RelationKind};
    // email → domain → person: 2 hops, 1 intermediate node
    let email = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "s");
    let domain = Entity::new(EntityKind::Domain, "example.com", 0.7, "s");
    let person = Entity::new(EntityKind::Person, "Alice Doe", 0.9, "s");
    let rels = [
        Relation::new(
            email.uid.clone(),
            domain.uid.clone(),
            RelationKind::BelongsToDomain,
            0.8,
            "s",
        ),
        Relation::new(
            domain.uid.clone(),
            person.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
    ];
    let r = rule_au_060_transitive_identity_closure(
        &RuleContext::new(&[email.clone(), domain.clone(), person.clone()]),
        &rels,
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-060");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].entity_uids.contains(&email.uid));
    assert!(r[0].entity_uids.contains(&person.uid));
    assert!(r[0].entity_uids.contains(&domain.uid));
    assert!(r[0].description.contains("1 intermediate node"));
}

#[test]
fn au060_no_fire_when_identity_pair_directly_connected() {
    use crate::core::relation::{Relation, RelationKind};
    let email = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "s");
    let person = Entity::new(EntityKind::Person, "Alice Doe", 0.9, "s");
    let rels = [Relation::new(
        email.uid.clone(),
        person.uid.clone(),
        RelationKind::DerivedFrom,
        0.8,
        "s",
    )];
    assert!(
        rule_au_060_transitive_identity_closure(&RuleContext::new(&[email, person]), &rels, "s", 0)
            .is_empty()
    );
}

// ── Crypto / identity / exposure rules (AU-039 … AU-043) ─────────────

/// Build an entity with tags + a single evidence record (with optional attrs).
fn mk_tagged(kind: EntityKind, value: &str, src: &str, tags: &[&str]) -> Entity {
    let mut e = Entity::new(kind, value, 0.8, "scan");
    e.add_evidence(Evidence::new(src, "x".to_string()));
    for t in tags {
        e.tag(*t);
    }
    e
}

#[test]
fn au_039_links_wallet_to_source_related_identity() {
    // Genuine co-location: one stealer log ("hudsonrock") surfaced BOTH the wallet
    // and the account owner, so the same source is stamped on each entity — a real
    // attribution lead the rule reports.
    let ents = vec![
        mk_tagged(
            EntityKind::CryptoAddress,
            "1A1zP1eP...",
            "hudsonrock",
            &["crypto-address"],
        ),
        mk_tagged(EntityKind::Person, "Jordan Avery", "hudsonrock", &[]),
    ];
    let out = rule_au_039_wallet_identity(&RuleContext::new(&ents), "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-039");
    assert_eq!(out[0].severity, Severity::High);
    assert_eq!(out[0].entity_uids.len(), 2);

    // No identity present ⇒ no firing.
    let only_wallet = vec![mk_tagged(
        EntityKind::CryptoAddress,
        "x",
        "chain_intel",
        &[],
    )];
    assert!(rule_au_039_wallet_identity(&RuleContext::new(&only_wallet), "scan", 0).is_empty());

    // Co-existence WITHOUT a shared source is not attribution (T2.39): a wallet
    // from a chain module and a person from a disjoint presence module co-occur in
    // the same scan but were never surfaced together, so no link is fabricated.
    let disjoint = vec![
        mk_tagged(
            EntityKind::CryptoAddress,
            "1A1zP1eP...",
            "chain_intel",
            &["crypto-address"],
        ),
        mk_tagged(EntityKind::Person, "Jordan Avery", "see_know", &[]),
    ];
    assert!(rule_au_039_wallet_identity(&RuleContext::new(&disjoint), "scan", 0).is_empty());
}

#[test]
fn au_039_does_not_attribute_wallet_to_source_unrelated_identity() {
    // T2.39 regression — the core defect: the pre-fix rule anchored every wallet to
    // the single smallest-UID Person across the whole scan, so an unrelated
    // bystander was reported as the wallet's owner purely by UID sort order. Here
    // the wallet + one person come from the same stealer log ("hudsonrock"); a
    // second, unrelated person comes from a disjoint source. We deliberately give
    // the UNRELATED person the smaller UID, so the buggy min-UID pick would name
    // them — the fix must instead pick the source-related person and never the
    // bystander.
    let a = Entity::new(EntityKind::Person, "Aaron Avery", 0.8, "scan");
    let z = Entity::new(EntityKind::Person, "Zoe Zimmer", 0.8, "scan");
    let (small_uid_name, large_uid_name) = if a.uid <= z.uid {
        (a.raw_value.clone(), z.raw_value.clone())
