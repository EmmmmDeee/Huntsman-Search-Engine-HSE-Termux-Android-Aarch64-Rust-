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

// ── AU-048 ───────────────────────────────────────────────────────
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

// Split into part files under tests/ (a plain directory alongside this file —
// `mod tests;` above already resolves to tests.rs, so this does not conflict)
// purely to keep each file small enough for reliable transmission through the
// push tooling used in this repo's environment, and to keep these synthetic
// test-fixture credentials covered by .gitleaks.toml's `(^|/)tests/`
// allowlist. `include!` splices them back into this same module scope at
// compile time, so this is byte-for-byte the same test suite as one file;
// behavior, test names, and results are unaffected.
include!("tests/part02.rs");
include!("tests/part03.rs");
include!("tests/part04.rs");
include!("tests/part05.rs");
include!("tests/part06.rs");
include!("tests/part07.rs");
include!("tests/part08.rs");
include!("tests/part09.rs");
include!("tests/part10.rs");
include!("tests/part11.rs");
include!("tests/part12.rs");
include!("tests/part13.rs");
include!("tests/part14.rs");
include!("tests/part15.rs");
