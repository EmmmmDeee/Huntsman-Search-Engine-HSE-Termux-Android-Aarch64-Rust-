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
fn temporal_breach_cluster_survives_non_ascii_breach_date() {
    // Regression: a `breach_date` taken verbatim from an upstream API whose
    // byte index 10 falls inside a multi-byte UTF-8 char must NOT panic the
    // rule's date slice. rule_au_019 runs OUTSIDE the per-module
    // catch_unwind, so a panic here previously killed the whole scan/live
    // task (lost finalization; live session stuck Running forever).
    let mk = |value: &str, date: &str| {
        let mut e = Entity::new(EntityKind::Email, value, 0.8, "scan");
        e.tag("breach");
        e.add_evidence(Evidence::new("test", "breach").with_attr("breach_date", date));
        e
    };
    let ents = vec![
        // '€' (3 bytes) begins at byte 9, so byte 10 is mid-codepoint.
        mk("a@x.com", "2024-01-0€9"),
        mk("b@x.com", "2024-01-15"),
        mk("c@x.com", "2024-02-10"),
    ];
    // Must not panic; the malformed-date row is simply skipped.
    let _ = rule_au_019_temporal_breach_cluster(&ents, "scan", 0);
}

#[test]
fn temporal_breach_cluster_window_is_anchored_not_rolling() {
    let mk = |value: &str, date: &str| {
        let mut e = Entity::new(EntityKind::Email, value, 0.8, "scan");
        e.tag("breach");
        e.add_evidence(Evidence::new("test", "breach").with_attr("breach_date", date));
        e
    };
    // Three breaches genuinely within a 30-day window → one cluster fires.
    let tight = vec![
        mk("a@x.com", "2024-01-01"),
        mk("b@x.com", "2024-01-10"),
        mk("c@x.com", "2024-01-20"),
    ];
    let r = rule_au_019_temporal_breach_cluster(&tight, "scan", 0);
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
        rule_au_019_temporal_breach_cluster(&chained, "scan", 0).is_empty(),
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
        rule_au_002_identity_cluster(&big, "scan", 0).is_empty(),
        "30 distinct emails is a dump, not an identity cluster"
    );

    // A plausible identity (a handful each) still fires.
    let small = vec![
        ent(EntityKind::Email, "me@x.com", 0.85, "s", false),
        ent(EntityKind::Username, "me", 0.7, "s", false),
        ent(EntityKind::Phone, "15551112222", 0.7, "s", false),
    ];
    assert_eq!(
        rule_au_002_identity_cluster(&small, "scan", 0).len(),
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
        rule_au_002_identity_cluster(&weak, "scan", 0).is_empty(),
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

    store.upsert_entity(&weak_key).unwrap();
    store.upsert_entity(&strong_email).unwrap();

    let corr = Correlator::new(Arc::clone(&store));
    let hits = corr.run(sid).unwrap();

    // Both rules fired.
    let key_hit = hits.iter().find(|c| c.rule_id == "AU-021").unwrap();
    let email_hit = hits.iter().find(|c| c.rule_id == "AU-003").unwrap();

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
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, expected_str);
        let back: Severity = serde_json::from_str(&json).unwrap();
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

    let json = serde_json::to_string(&original).unwrap();
    let back: Correlation = serde_json::from_str(&json).unwrap();

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
    let r = rule_au_033_abn_organisation_link(&entities, "scan-test", 0);
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
    assert!(rule_au_033_abn_organisation_link(&mixed, "scan-test", 0).is_empty());
    // A registry org with no ABN present also does not fire.
    let only_org = vec![tagged(
        EntityKind::Organisation,
        "Example Pty Ltd",
        &["opencorporates"],
    )];
    assert!(rule_au_033_abn_organisation_link(&only_org, "scan-test", 0).is_empty());
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
        let r = rule_au_033_abn_organisation_link(&entities, "scan-test", 0);
        assert_eq!(
            r.len(),
            1,
            "AU-033 must fire for a {tag}-tagged registry org"
        );
        assert_eq!(r[0].rule_id, "AU-033");
        assert_eq!(r[0].entity_uids.len(), 2);
    }
}

// ── AU-034 ──────────────────────────────────────────────────────────
#[test]
fn au034_links_username_to_email_by_shared_handle() {
    // Username from one source, matching email from another → ≥2 distinct
    // sources → fires, linking both uids.
    let entities = vec![
        username("jmeyers", &["github_user"]),
        email("jmeyers@gmail.com", &["name_intel"]),
    ];
    let r = rule_au_034_handle_reuse_identity(&entities, "scan-test", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-034");
    assert_eq!(r[0].severity, Severity::Medium);
    assert_eq!(r[0].entity_uids.len(), 2);
    assert!(r[0].description.contains("jmeyers@gmail.com"));
}

#[test]
fn au034_handle_match_is_separator_insensitive_and_strips_plus_tag() {
    // `jordanmeyers` ↔ `jordan.meyers+news@x.com`: dots removed and the
    // Gmail `+tag` stripped, so the canonical handles match.
    let entities = vec![
        username("jordanmeyers", &["search_engines"]),
        email("jordan.meyers+news@x.com", &["hunter_io"]),
    ];
    let r = rule_au_034_handle_reuse_identity(&entities, "scan-test", 0);
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
    let r = rule_au_034_handle_reuse_identity(&entities, "scan-test", 0);
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
    assert!(rule_au_034_handle_reuse_identity(&entities, "scan-test", 0).is_empty());
}

#[test]
fn au034_no_fire_on_role_or_placeholder_handle() {
    // Role mailbox (`info`) and placeholder (`admin`) link organisation
    // functions, not people — excluded even across distinct sources.
    let role = vec![
        username("info", &["github_user"]),
        email("info@company.com", &["hunter_io"]),
    ];
    assert!(rule_au_034_handle_reuse_identity(&role, "scan-test", 0).is_empty());
    let placeholder = vec![
        username("admin", &["github_user"]),
        email("admin@company.com", &["hunter_io"]),
    ];
    assert!(rule_au_034_handle_reuse_identity(&placeholder, "scan-test", 0).is_empty());
}

#[test]
fn au034_no_fire_on_short_handle_or_no_match() {
    // A handle < 4 chars is too weak to identify; distinct handles never
    // match.
    let short = vec![
        username("abc", &["github_user"]),
        email("abc@x.com", &["hunter_io"]),
    ];
    assert!(rule_au_034_handle_reuse_identity(&short, "scan-test", 0).is_empty());
    let nomatch = vec![
        username("alice", &["github_user"]),
        email("bob@x.com", &["hunter_io"]),
    ];
    assert!(rule_au_034_handle_reuse_identity(&nomatch, "scan-test", 0).is_empty());
}

// ── AU-035 ──────────────────────────────────────────────────────────

#[test]
fn au035_fires_when_inferred_then_confirmed() {
    // Derived by name_intel, then observed live by username_search →
    // a guessed handle confirmed real.
    let e = username("jdoe", &["name_intel", "username_search"]);
    let r = rule_au_035_confirmed_derived_handle(&[e], "scan-test", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-035");
    assert_eq!(r[0].entity_uids.len(), 1);
    assert!(r[0].description.contains("name_intel"));
    assert!(r[0].description.contains("username_search"));
}

#[test]
fn au035_fires_for_email_parse_plus_github() {
    let e = username("jdoe", &["email_parse", "github_user"]);
    let r = rule_au_035_confirmed_derived_handle(&[e], "scan-test", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au035_no_fire_when_only_inferred_or_only_discovered() {
    // Guessed but never confirmed → unconfirmed candidate, no fire.
    let only_inferred = username("jdoe", &["username_variants"]);
    assert!(rule_au_035_confirmed_derived_handle(&[only_inferred], "scan-test", 0).is_empty());
    // Observed but never inferred → an ordinary find, no fire.
    let only_discovered = username("jdoe", &["github_user", "keybase"]);
    assert!(rule_au_035_confirmed_derived_handle(&[only_discovered], "scan-test", 0).is_empty());
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
    let r = rule_au_036_email_alias_convergence(&[e], "scan-test", 0);
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
    assert!(rule_au_036_email_alias_convergence(&[e], "scan-test", 0).is_empty());
}

#[test]
fn au036_ignores_non_canonical_evidence() {
    // Two evidence records, but not from email_canonical → not alias
    // convergence (could be two breach sources for one address).
    let e = email("jdoe@gmail.com", &["hibp", "hudsonrock"]);
    assert!(rule_au_036_email_alias_convergence(&[e], "scan-test", 0).is_empty());
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
    let r = rule_au_001_multi_breach(&[e], "s1", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-001");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au001_no_fire_at_one_source() {
    let e = email("x@y.com", &["hudsonrock"]);
    assert!(rule_au_001_multi_breach(&[e], "s1", 0).is_empty());
}

#[test]
fn au001_ignores_non_breach_sources() {
    let e = email("x@y.com", &["crtsh", "dns_resolver"]);
    assert!(rule_au_001_multi_breach(&[e], "s1", 0).is_empty());
}

#[test]
fn au001_does_not_count_generic_search_as_a_breach_source() {
    // A web-search hit alongside ONE real breach source is a single breach
    // source — `search_engines` must never count toward the Critical multi-breach
    // finding (guards against re-adding it to BREACH_SOURCES).
    let one = email("x@y.com", &["hibp", "search_engines"]);
    assert!(rule_au_001_multi_breach(&[one], "s1", 0).is_empty());
    // Two genuine breach sources still fire.
    let two = email("x@y.com", &["hibp", "dehashed"]);
    assert_eq!(rule_au_001_multi_breach(&[two], "s1", 0).len(), 1);
}

// ── AU-002 ──────────────────────────────────────────────────────────

#[test]
fn au002_fires_with_all_three_kinds() {
    let entities = vec![
        Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
        Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
        Entity::new(EntityKind::Phone, "+61400000000", 0.8, "s"),
    ];
    let r = rule_au_002_identity_cluster(&entities, "s", 0);
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
    assert!(rule_au_002_identity_cluster(&entities, "s", 0).is_empty());
}

// ── AU-003 ──────────────────────────────────────────────────────────

#[test]
fn au003_fires_at_kind_specific_thresholds() {
    // Thresholds are now on DISTINCT sources: identity (email) >= 2,
    // infra (domain) >= 3. These fixtures set corroboration with no
    // evidence, so source_count() falls back to the field value.
    let mut email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    email.corroboration = 2;
    let r = rule_au_003_high_corroboration(&[email], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-003");
    assert!(
        r[0].description.contains("2 independent source"),
        "description must report the true distinct-source count: {}",
        r[0].description
    );

    let mut domain = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
    domain.corroboration = 3;
    let r = rule_au_003_high_corroboration(&[domain], "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au003_no_fire_below_threshold() {
    // Email below 2 distinct sources, domain below 3 → no fire.
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    e.corroboration = 1;
    assert!(rule_au_003_high_corroboration(&[e], "s", 0).is_empty());

    let mut d = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
    d.corroboration = 2;
    assert!(rule_au_003_high_corroboration(&[d], "s", 0).is_empty());
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
        rule_au_003_high_corroboration(&[single], "s", 0).is_empty(),
        "single-source entity must not fire AU-003 despite inflated corroboration"
    );

    let mut multi = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
    multi.corroboration = 2;
    multi.add_evidence(crate::core::entity::Evidence::new("hibp", "breach"));
    multi.add_evidence(crate::core::entity::Evidence::new("dehashed", "breach"));
    assert_eq!(
        rule_au_003_high_corroboration(&[multi], "s", 0).len(),
        1,
        "two distinct sources must fire AU-003"
    );
}

// ── AU-004 ──────────────────────────────────────────────────────────

#[test]
fn au004_fires_on_malicious_domain() {
    let e = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
    let r = rule_au_004_malicious_infrastructure(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au004_no_fire_without_tag() {
    let e = tagged(EntityKind::Domain, "ok.example", &[]);
    assert!(rule_au_004_malicious_infrastructure(&[e], "s", 0).is_empty());
}

// ── AU-005 ──────────────────────────────────────────────────────────

#[test]
fn au005_fires_on_tor_exit() {
    let e = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
    let r = rule_au_005_anonymous_network(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

// ── AU-006 ──────────────────────────────────────────────────────────

#[test]
fn au006_fires_on_vpn_but_not_tor() {
    let vpn_ip = tagged(EntityKind::IpAddress, "2.2.2.2", &["vpn"]);
    let tor_ip = tagged(EntityKind::IpAddress, "3.3.3.3", &["tor-exit", "vpn"]);
    let r = rule_au_006_proxy_vpn(&[vpn_ip, tor_ip], "s", 0);
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
    assert!(rule_au_006_proxy_vpn(&[tor_short], "s", 0).is_empty());
    assert!(rule_au_006_proxy_vpn(&[anon_net], "s", 0).is_empty());
    assert!(rule_au_006_proxy_vpn(&[anon_vpn], "s", 0).is_empty());
}

// ── AU-007 ──────────────────────────────────────────────────────────

#[test]
fn au007_fires_on_high_risk() {
    let e = tagged(EntityKind::IpAddress, "4.4.4.4", &["high-risk", "scanner"]);
    let r = rule_au_007_high_risk_reputation(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

// ── AU-008 ──────────────────────────────────────────────────────────

#[test]
fn au008_fires_on_vulnerable_tag() {
    let e = tagged(EntityKind::Domain, "vuln.example", &["vulnerable"]);
    let r = rule_au_008_exposed_service(&[e], "s", 0);
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
        &["vulnerable", "greynoise-benign"],
    );
    assert!(rule_au_008_exposed_service(&[e], "s", 0).is_empty());
}

// ── AU-009 ──────────────────────────────────────────────────────────

#[test]
fn au009_fires_on_stealer_log() {
    let e = tagged(EntityKind::Email, "x@y.com", &["stealer-log"]);
    let r = rule_au_009_stealer_log(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::High);
}

// ── AU-037 ──────────────────────────────────────────────────────────

#[test]
fn au037_fires_critical_on_plaintext_credentials() {
    let pw1 = Entity::new(EntityKind::Password, "hunter2", 0.9, "s");
    let pw2 = Entity::new(EntityKind::Password, "letmein", 0.9, "s");
    let cred = Entity::new(EntityKind::Credential, "user:pass", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
    let r = rule_au_037_credential_exposure(&[pw1, pw2, cred, email.clone()], "s", 0);
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
    assert!(rule_au_037_credential_exposure(&[email], "s", 0).is_empty());
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
        &[
            mk("https://x.com/kylo4kylo"),
            mk("https://github.com/kylo4kylo"),
        ],
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
            &[
                mk("https://www.x.com/kylo4kylo"),
                mk("https://x.com/kylo4kylo")
            ],
            "s",
            0
        )
        .is_empty()
    );
    // A non-confirmed URL is ignored.
    let plain = Entity::new(EntityKind::Url, "https://x.com/kylo4kylo", 0.5, "s");
    assert!(rule_au_038_verified_cross_platform_identity(&[plain], "s", 0).is_empty());
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
        &[
            mk("https://steamcommunity.com/id/kylo4kylo"),
            mk("https://www.tiktok.com/@kylo4kylo"),
            mk("https://bsky.app/profile/kylo4kylo.bsky.social"),
        ],
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
    let r = rule_au_038_verified_cross_platform_identity(&[probe, searched], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 distinct platforms"));
}

// ── AU-010 ──────────────────────────────────────────────────────────

#[test]
fn au010_fires_at_three_sources_on_domain() {
    let e = domain("x.com", &["crtsh", "dns_resolver", "hudsonrock"]);
    let r = rule_au_010_infra_consensus(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-010");
}

#[test]
fn au010_no_fire_at_two_sources() {
    let e = domain("x.com", &["crtsh", "dns_resolver"]);
    assert!(rule_au_010_infra_consensus(&[e], "s", 0).is_empty());
}

#[test]
fn au010_ignores_non_infrastructure_kinds() {
    let e = email("x@y.com", &["a", "b", "c"]);
    assert!(rule_au_010_infra_consensus(&[e], "s", 0).is_empty());
}

// ── AU-011 ──────────────────────────────────────────────────────────

#[test]
fn au011_fires_on_three_platforms() {
    let e = username_summary("alice", 3, "github, reddit, twitter");
    let r = rule_au_011_cross_platform_username(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("3 platforms"));
    assert!(r[0].description.contains("github"));
}

#[test]
fn au011_no_fire_on_two_platforms() {
    let e = username_summary("alice", 2, "github, reddit");
    assert!(rule_au_011_cross_platform_username(&[e], "s", 0).is_empty());
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
    let r = rule_au_012_identity_linked_domain(&entities, "s", 0);
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
    let r = rule_au_012_identity_linked_domain(&entities, "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au012_no_fire_without_username() {
    let entities = vec![tagged(
        EntityKind::Url,
        "https://alice.example/",
        &["personal-site"],
    )];
    assert!(rule_au_012_identity_linked_domain(&entities, "s", 0).is_empty());
}

// ── AU-013 ──────────────────────────────────────────────────────────

#[test]
fn au013_fires_on_two_lan_entities() {
    let entities = vec![
        tagged(EntityKind::IpAddress, "192.168.1.1", &["local-arp"]),
        tagged(EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff", &["local-arp"]),
    ];
    let r = rule_au_013_local_network_discovery(&entities, "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au013_no_fire_on_one_lan_entity() {
    let entities = vec![tagged(EntityKind::IpAddress, "192.168.1.1", &["local-arp"])];
    assert!(rule_au_013_local_network_discovery(&entities, "s", 0).is_empty());
}

// ── AU-014 ──────────────────────────────────────────────────────────

#[test]
fn au014_fires_on_two_geo_sources() {
    let mut e = Entity::new(EntityKind::Coordinates, "0,0", 0.9, "s");
    e.add_evidence(Evidence::new("wigle", "test"));
    e.add_evidence(Evidence::new("device_sensors", "test"));
    let r = rule_au_014_geo_cluster(&[e], "s", 0);
    assert_eq!(r.len(), 1);
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
        &["threat-intel", "ti:malware"],
    );
    let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("malware"));
}

#[test]
fn au015_attribution_names_evidence_source_not_otx() {
    let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
    e.tag("threat-intel");
    e.add_evidence(Evidence::new("threatfox", "t"));
    let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("threatfox"));
    assert!(!r[0].description.contains("OTX"));
}

#[test]
fn au015_attribution_excludes_non_ti_evidence() {
    let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
    e.tag("threat-intel");
    e.add_evidence(Evidence::new("ip_reputation", "ti-hit"));
    e.add_evidence(Evidence::new("whois", "registry-data"));
    e.add_evidence(Evidence::new("dns_resolver", "a-record"));
    let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("ip_reputation"));
    assert!(!r[0].description.contains("whois"));
    assert!(!r[0].description.contains("dns_resolver"));
}

#[test]
fn au015_attribution_falls_back_when_source_unknown() {
    let e = tagged(EntityKind::Domain, "bad.example", &["threat-intel"]);
    let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
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
    let domain = tagged(
        EntityKind::Domain,
        "evil.example",
        &["malicious", "vulnerable", "threat-intel"],
    );
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
/// confirmed): the `matthewdiegmann@gmail.com` identity and the
/// Maleny/Booroobin (QLD 4552) locality are the accurate results, and the
/// engine must cross-correlate them. This pins the full path so a future
/// refactor of the rule set can't silently sever it.
#[test]
fn ground_truth_matthew_diegmann_identity_and_booroobin_geo() {
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
    let email = id(
        EntityKind::Email,
        "matthewdiegmann@gmail.com",
        &["oathnet_pro", "name_intel"],
    );
    let username = id(
        EntityKind::Username,
        "mdieg123",
        &["username_search", "oathnet_pro"],
    );
    let phone = id(EntityKind::Phone, "+61400000111", &["oathnet_pro"]);
    let person = id(EntityKind::Person, "Matthew Diegmann", &["name_intel"]);

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
        "cluster must include mdieg123"
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
        "linkage must include matthewdiegmann@gmail.com"
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
fn ground_truth_erik_diegmann_scan_yields_only_real_correlations() {
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
        "Erik Diegmann",
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
        "https://www.peekyou.com/erik-diegmann",
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
            &["wifi-ap"],
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
        &["postcode-only", "geoint", "coarse", "exact-name-match"],
    ));
    for pc in ["QLD 4555, Australia", "QLD 4557, Australia"] {
        ents.push(mk(
            EntityKind::Address,
            pc,
            0.32,
            &["qld_unclaimed", "geo_normalize"],
            &["postcode-only", "geoint", "coarse", "family-candidate"],
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
            &["candidate-suburb", "geoint", "coarse"],
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
            &["geoint", "postcode-centroid", "coarse"],
        ));
    }
    // ── name_intel permutations (single-source Candidate guesses) ──
    for u in [
        "erikdiegmann",
        "ediegmann",
        "erik_diegmann",
        "erik.diegmann",
        "erikd",
    ] {
        ents.push(mk(
            EntityKind::Username,
            u,
            0.38,
            &["name_intel"],
            &["derived", "name-derived"],
        ));
    }
    for em in [
        "erikdiegmann@gmail.com",
        "erik.diegmann@gmail.com",
        "ediegmann@gmail.com",
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

    // Exactly five real correlations — nothing fabricated. The fifth is AU-045:
    // "Erik Diegmann" is corroborated by oathnet_pro (breach) AND social_probe
    // (social) — two independent service families — which is precisely the
    // cross-service identity confirmation the correlation upgrade surfaces.
    assert_eq!(
        firings.len(),
        5,
        "expected 5 real correlations, got: {summary:#?}"
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
        "Erik Diegmann confirmed across breach + social families"
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
    let firings = rule_au_016_breach_ip_geo_chain(&[ip, coord], "s", 0);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].rule_id, "AU-016");
}

#[test]
fn rule_016_no_fire_without_breach_tag() {
    let ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.72, "s");
    let coord = Entity::new(EntityKind::Coordinates, "1.0,2.0", 0.65, "s");
    let firings = rule_au_016_breach_ip_geo_chain(&[ip, coord], "s", 0);
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
        rule_au_016_breach_ip_geo_chain(&[breach, coord], "s", 0).is_empty(),
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
        rule_au_016_breach_ip_geo_chain(&[breach2, coord2], "s", 0).len(),
        1,
        "exact whole-IP match (even followed by ':') must still chain"
    );
}

#[test]
fn rule_017_multi_geo_convergence_fires() {
    let c1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
    let c2 = Entity::new(EntityKind::Coordinates, "-27.60,152.30", 0.65, "s");
    let firings = rule_au_017_multi_geo_convergence(&[c1, c2], "s", 0);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].rule_id, "AU-017");
    assert!(firings[0].description.contains("converge"));
}

#[test]
fn rule_017_no_fire_for_distant_coords() {
    let c1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
    let c2 = Entity::new(EntityKind::Coordinates, "-33.86,151.20", 0.65, "s");
    let firings = rule_au_017_multi_geo_convergence(&[c1, c2], "s", 0);
    assert!(firings.is_empty());
}

#[test]
fn rule_017_drops_out_of_range_coordinates() {
    // Junk coordinates (lat/lon outside Earth's range) must be rejected by the
    // range-validating parse_coords helper, not clustered as a convergence.
    let junk1 = Entity::new(EntityKind::Coordinates, "200.0,300.0", 0.60, "s");
    let junk2 = Entity::new(EntityKind::Coordinates, "201.0,301.0", 0.65, "s");
    let firings = rule_au_017_multi_geo_convergence(&[junk1, junk2], "s", 0);
    assert!(firings.is_empty(), "out-of-range coords must not converge");
}

// ── AU-031 (graph-aware: relation edges) ────────────────────────────

#[test]
fn au031_fires_on_edge_to_malicious_node() {
    use crate::core::relation::{Relation, RelationKind};
    let bad = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
    let benign = tagged(EntityKind::Domain, "blog.evil.example", &[]);
    let rel = Relation::new(
        benign.uid.clone(),
        bad.uid.clone(),
        RelationKind::SubdomainOf,
        0.8,
        "s",
    );
    let r = rule_au_031_malicious_adjacency(&[bad.clone(), benign.clone()], &[rel], "s", 0);
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
    assert!(rule_au_031_malicious_adjacency(&[a, b], &[rel], "s", 0).is_empty());
}

#[test]
fn au031_no_fire_when_both_endpoints_flagged() {
    use crate::core::relation::{Relation, RelationKind};
    let a = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
    let b = tagged(EntityKind::Domain, "bad.example", &["threat-intel"]);
    let rel = Relation::new(
        a.uid.clone(),
        b.uid.clone(),
        RelationKind::CoLocatedWith,
        0.8,
        "s",
    );
    assert!(rule_au_031_malicious_adjacency(&[a, b], &[rel], "s", 0).is_empty());
}

#[test]
fn au031_skips_edges_with_missing_endpoints() {
    use crate::core::relation::{Relation, RelationKind};
    // Edge references a uid not in the entity set → no fire, no panic.
    let bad = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
    let rel = Relation::new(
        "ghost-uid",
        bad.uid.clone(),
        RelationKind::DerivedFrom,
        0.8,
        "s",
    );
    assert!(rule_au_031_malicious_adjacency(&[bad], &[rel], "s", 0).is_empty());
}

#[test]
fn au031_aggregates_high_fanout_shared_infra() {
    use crate::core::relation::{Relation, RelationKind};
    // One flagged shared IP (CDN) with 30 distinct co-hosted domains: the
    // real-world noise case. Must collapse to ONE Medium aggregate, not 30
    // High rows — while a dedicated node (≤ cap) still fires per-neighbour.
    let bad = tagged(EntityKind::IpAddress, "104.20.37.187", &["vulnerable"]);
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
    let r = rule_au_031_malicious_adjacency(&entities, &rels, "s", 0);
    assert_eq!(r.len(), 1, "30-way fan-out must aggregate to one finding");
    assert_eq!(r[0].rule_id, "AU-031");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].description.contains("30 entities"));
    assert!(r[0].description.contains("shared infrastructure"));
    assert!(r[0].entity_uids.contains(&bad.uid));

    // Deterministic across input orderings (BTreeMap-keyed).
    let mut shuffled = rels.clone();
    shuffled.reverse();
    let r2 = rule_au_031_malicious_adjacency(&entities, &shuffled, "s", 0);
    assert_eq!(r[0].description, r2[0].description);
    assert_eq!(r[0].entity_uids, r2[0].entity_uids);

    // Control: a flagged node with few neighbours stays per-neighbour/High.
    let r3 = rule_au_031_malicious_adjacency(&entities[..4], &rels[..3], "s", 0);
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
        &["vulnerable", "greynoise-riot"],
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
        rule_au_031_malicious_adjacency(&entities, &rels, "s", 0).is_empty(),
        "a GreyNoise-benign shared edge must not anchor adjacency"
    );

    // A genuine high-fan-out MALICIOUS cluster (no benign verdict) stays
    // loud: aggregated, but High — not silently downgraded.
    let evil = tagged(EntityKind::Domain, "evil.apex", &["malicious"]);
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
    let rm = rule_au_031_malicious_adjacency(&ents, &er, "s", 0);
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
    let c1 = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s");
    let c2 = Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s");
    let c3 = Entity::new(EntityKind::Coordinates, "-27.471000,153.021000", 0.7, "s");
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
    let r = rule_au_032_colocation_cluster(&[c1, c2, c3], &rels, "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-032");
    assert_eq!(r[0].severity, Severity::Medium);
    assert_eq!(r[0].entity_uids.len(), 3);
    assert!(r[0].description.contains("3 coordinates"));
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
    assert!(rule_au_032_colocation_cluster(&[c1, c2], &rels, "s", 0).is_empty());
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
    assert!(rule_au_032_colocation_cluster(&[a, b, c], &rels, "s", 0).is_empty());
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
fn au_039_links_wallet_to_identity() {
    let ents = vec![
        mk_tagged(
            EntityKind::CryptoAddress,
            "1A1zP1eP...",
            "chain_intel",
            &["crypto-address"],
        ),
        mk_tagged(EntityKind::Person, "Matthew Diegmann", "see_know", &[]),
    ];
    let out = rule_au_039_wallet_identity(&ents, "scan", 0);
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
    assert!(rule_au_039_wallet_identity(&only_wallet, "scan", 0).is_empty());
}

#[test]
fn au_040_fires_only_on_breach_harvested_wallets() {
    let found_keys_from = |value: &str, provider: &str| {
        let mut e = Entity::new(EntityKind::CryptoAddress, value, 0.8, "scan");
        e.tag("retrieved");
        e.add_evidence(Evidence::new("found_keys", "x").with_attr("source_provider", provider));
        e
    };
    let ents = vec![
        // found_keys harvest from an actual breach pool → genuine exposure.
        found_keys_from("0xleaked", "see-know"),
        // found_keys harvest from chain_intel's OWN explorer response → an
        // explorer artifact, NOT a breach leak (the precision case).
        found_keys_from("0xexplorer", "chain_intel"),
        // Breach-record-field harvest via the shared key-harvest path.
        mk_tagged(
            EntityKind::CryptoAddress,
            "0xfield",
            "oathnet_pro",
            &["crypto-address"],
        ),
        // Pure chain_intel enrichment of a pasted seed — not an exposure.
        mk_tagged(
            EntityKind::CryptoAddress,
            "0xseed",
            "chain_intel",
            &["crypto-address"],
        ),
    ];
    let out = rule_au_040_wallet_breach_exposure(&ents, "scan", 0);
    let fired: HashSet<&String> = out.iter().flat_map(|c| c.entity_uids.iter()).collect();
    let uid = |v: &str| ents.iter().find(|e| e.value == v).unwrap().uid.clone();
    assert_eq!(out.len(), 2, "only genuine breach exposures fire: {out:?}");
    assert!(fired.contains(&uid("0xleaked")) && fired.contains(&uid("0xfield")));
    assert!(!fired.contains(&uid("0xexplorer")) && !fired.contains(&uid("0xseed")));
    assert!(out.iter().all(|c| c.severity == Severity::High));
}

#[test]
fn au_041_fires_on_ens_handle() {
    let mut ens = Entity::new(EntityKind::Username, "vitalik", 0.7, "scan");
    ens.tag("ens");
    ens.add_evidence(Evidence::new("chain_intel", "x").with_attr("ens_name", "vitalik.eth"));
    let out = rule_au_041_ens_identity(&[ens], "scan", 0);
    assert_eq!(out.len(), 1);
    assert!(out[0].description.contains("vitalik.eth"));
    // A plain username (no ens tag) must not fire.
    let plain = mk_tagged(EntityKind::Username, "bob", "username_search", &[]);
    assert!(rule_au_041_ens_identity(&[plain], "scan", 0).is_empty());
}

#[test]
fn au_042_groups_pgp_linked_emails() {
    let ents = vec![
        mk_tagged(EntityKind::Email, "alt@work.com", "pgp", &["pgp-linked"]),
        mk_tagged(EntityKind::Email, "other@home.com", "pgp", &["pgp-linked"]),
        mk_tagged(EntityKind::Email, "unrelated@x.com", "hibp", &[]),
    ];
    let out = rule_au_042_pgp_email_identity(&ents, "scan", 0);
    assert_eq!(out.len(), 1, "one grouped firing");
    assert_eq!(out[0].entity_uids.len(), 2, "only the pgp-linked emails");
    assert_eq!(out[0].severity, Severity::High);
}

#[test]
fn au_043_fires_on_paste_exposure() {
    let ents = vec![
        mk_tagged(
            EntityKind::Url,
            "https://pastebin.com/abc",
            "psbdmp",
            &[crate::core::tags::PASTE_EXPOSED],
        ),
        mk_tagged(EntityKind::Url, "https://example.com", "web_crawler", &[]),
    ];
    let out = rule_au_043_paste_exposure(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].entity_uids.len(), 1, "only the paste url");
    assert!(out[0].description.contains("1 public paste"));
}

#[test]
fn shared_tracking_id_fires_only_across_multiple_sites() {
    // A TrackingId carrying source_domain evidence for two distinct sites is the
    // affiliate signal: same analytics id ⇒ common ownership.
    let mut shared = Entity::new(EntityKind::TrackingId, "UA-123456-1", 0.80, "scan");
    shared.add_evidence(
        Evidence::new("web_crawler", "ga id on a.com".to_string())
            .with_attr("source_domain", "a.com"),
    );
    shared.add_evidence(
        Evidence::new("web_crawler", "ga id on b.com".to_string())
            .with_attr("source_domain", "b.com"),
    );

    let out = rule_au_044_shared_tracking_id(std::slice::from_ref(&shared), "scan", 0);
    assert_eq!(out.len(), 1, "shared id across 2 sites must fire");
    assert_eq!(out[0].rule_id, "AU-044");
    assert!(out[0].description.contains("a.com") && out[0].description.contains("b.com"));

    // A tracking id on a single site is not a correlation.
    let mut single = Entity::new(EntityKind::TrackingId, "G-ABCDE12345", 0.80, "scan");
    single.add_evidence(
        Evidence::new("web_crawler", "ga4 on a.com".to_string())
            .with_attr("source_domain", "a.com"),
    );
    assert!(
        rule_au_044_shared_tracking_id(std::slice::from_ref(&single), "scan", 0).is_empty(),
        "single-site id must not fire"
    );
}

#[test]
fn au045_multi_service_identity_requires_cross_family_agreement() {
    use super::rules::source_family;
    // Classifier maps real module names to the expected families. Code-hosting,
    // forums and social media are distinct independent families.
    assert_eq!(source_family("github_user"), "code");
    assert_eq!(source_family("reddit_user"), "forum");
    assert_eq!(source_family("hacker_news"), "forum");
    assert_eq!(source_family("social_probe"), "social");
    assert_eq!(source_family("hibp"), "breach");
    assert_eq!(source_family("username_search"), "presence");
    assert_eq!(source_family("dns_intel"), "infra");
    assert_eq!(source_family("totally_unknown_src"), "other");

    // The payoff: an alias confirmed on GitHub (code) + Reddit (forum) — two
    // independent provider families — now fires AU-045, where before the three
    // social modules were one family and never did.
    let mut handle = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        handle.add_evidence(Evidence::new(s, "confirmed"));
    }
    assert_eq!(
        super::rules::rule_au_045_multi_service_identity(&[handle], "scan", 0).len(),
        1,
        "code + forum are independent families and must fire AU-045"
    );

    // A username confirmed by breach + social + presence → 3 families → fires.
    let mut u = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["hibp", "github_user", "username_search"] {
        u.add_evidence(Evidence::new(s, "found"));
    }
    let hits = super::rules::rule_au_045_multi_service_identity(&[u], "scan", 0);
    assert_eq!(hits.len(), 1, "cross-family identity must fire AU-045");
    assert_eq!(hits[0].rule_id, "AU-045");
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(
        hits[0].description.contains("3 service families"),
        "got: {}",
        hits[0].description
    );

    // Same family only (two breach DBs) → not independent → must NOT fire.
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.6, "scan");
    for s in ["hibp", "dehashed"] {
        e.add_evidence(Evidence::new(s, "found"));
    }
    assert!(
        super::rules::rule_au_045_multi_service_identity(&[e], "scan", 0).is_empty(),
        "same-family corroboration must not count as multi-service"
    );

    // An unclassified source can't fabricate diversity on its own.
    let mut p = Entity::new(EntityKind::Person, "Kylo Ren", 0.6, "scan");
    for s in ["hibp", "totally_unknown_src"] {
        p.add_evidence(Evidence::new(s, "x"));
    }
    assert!(
        super::rules::rule_au_045_multi_service_identity(&[p], "scan", 0).is_empty(),
        "the 'other' bucket is excluded from family diversity"
    );

    // Non-identity kinds are ignored even when cross-family.
    let mut d = Entity::new(EntityKind::Domain, "acme.com", 0.6, "scan");
    for s in ["dns_intel", "github_user"] {
        d.add_evidence(Evidence::new(s, "x"));
    }
    assert!(
        super::rules::rule_au_045_multi_service_identity(&[d], "scan", 0).is_empty(),
        "AU-045 binds identity kinds only"
    );
}

#[test]
fn au011_counts_independent_platform_module_confirmations() {
    // Three independent username-keyed modules (github_user + reddit_user +
    // hacker_news) confirming one handle is a 3-platform footprint even though no
    // single module reported a `platforms_count` — the cross-service signal the
    // keyless social modules produce must light up AU-011.
    let mut u = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user", "hacker_news"] {
        u.add_evidence(Evidence::new(s, "confirmed account"));
    }
    let hits = super::rules::rule_au_011_cross_platform_username(&[u], "scan", 0);
    assert_eq!(
        hits.len(),
        1,
        "3 independent platform modules must fire AU-011"
    );
    assert_eq!(hits[0].rule_id, "AU-011");
    assert!(
        hits[0].description.contains("3 platforms"),
        "got: {}",
        hits[0].description
    );

    // Two platform modules is below the threshold.
    let mut u2 = Entity::new(EntityKind::Username, "lonely", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        u2.add_evidence(Evidence::new(s, "x"));
    }
    assert!(
        super::rules::rule_au_011_cross_platform_username(&[u2], "scan", 0).is_empty(),
        "two platforms must not fire"
    );
}

#[test]
fn au046_resolves_an_alias_to_platform_exposed_identifiers() {
    // The alias confirmed across two platform families (npm=code, reddit=forum),
    // plus an email its npm account exposed → AU-046 links handle to identity.
    let mut handle = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["npm_author", "reddit_user"] {
        handle.add_evidence(Evidence::new(s, "confirmed account"));
    }
    let mut email = Entity::new(EntityKind::Email, "k@example.com", 0.7, "scan");
    email.add_evidence(Evidence::new("npm_author", "maintainer email"));

    let hits = super::rules::rule_au_046_cross_platform_identity_resolution(
        &[handle.clone(), email.clone()],
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "alias + platform-exposed email must resolve");
    assert_eq!(hits[0].rule_id, "AU-046");
    assert_eq!(hits[0].severity, super::Severity::High);
    // The correlation links the alias AND the resolved identifier.
    assert!(hits[0].entity_uids.contains(&handle.uid));
    assert!(hits[0].entity_uids.contains(&email.uid));

    // Single-family handle (only npm) does NOT resolve — needs ≥2 platforms.
    let mut one = Entity::new(EntityKind::Username, "solo", 0.6, "scan");
    one.add_evidence(Evidence::new("npm_author", "x"));
    assert!(
        super::rules::rule_au_046_cross_platform_identity_resolution(&[one, email], "scan", 0)
            .is_empty(),
        "one platform family is not cross-platform resolution"
    );
}

#[test]
fn au047_links_identities_by_a_reused_unique_secret_only() {
    // The unmasking rule, and its precision gate. A salted hash carried against
    // two emails links them (same controller); an UNSALTED digest must NOT —
    // md5("123456") is shared by millions and would manufacture false identities.
    let cred = |hash: &str, emails: &[&str]| {
        let mut c = Entity::new(EntityKind::Credential, hash, 0.6, "scan");
        for em in emails {
            c.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("email", *em));
        }
        c
    };
    let a = Entity::new(EntityKind::Email, "burner1@proton.me", 0.6, "scan");
    let b = Entity::new(EntityKind::Email, "real.name@gmail.com", 0.6, "scan");

    // Salted bcrypt hash seen against both identities → Critical link.
    let bcrypt = cred("$2a$10$id3HAw6TcOjKvPH/RK7MS.abcdef", &[&a.value, &b.value]);
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &[bcrypt.clone(), a.clone(), b.clone()],
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "salted hash across 2 identities must link them"
    );
    assert_eq!(hits[0].rule_id, "AU-047");
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].entity_uids.contains(&bcrypt.uid));
    assert!(hits[0].entity_uids.contains(&a.uid) && hits[0].entity_uids.contains(&b.uid));

    // PRECISION GATE: an unsalted hex digest across the same two identities must
    // NOT fire — it could be a common password shared by unrelated people.
    let unsalted = cred(
        "00346d91dd87c74089f3bfa88e13de8101000000dcb6",
        &[&a.value, &b.value],
    );
    assert!(
        super::rules::rule_au_047_reused_secret_identity(
            &[unsalted, a.clone(), b.clone()],
            "scan",
            0
        )
        .is_empty(),
        "an unsalted digest must NOT link people (weak-password collision risk)"
    );

    // A unique secret seen against only ONE identity is not a link.
    let single = cred("$2b$12$onlyoneidentityhasthisxx", &[&a.value]);
    assert!(
        super::rules::rule_au_047_reused_secret_identity(&[single, a], "scan", 0).is_empty(),
        "one identity is not a cross-account link"
    );
}

#[test]
fn au048_links_accounts_sharing_a_public_key() {
    // A public key published by two accounts → cryptographic proof of one
    // controller (same private key). Single account → no link.
    let key = |fp: &str, logins: &[&str]| {
        let mut e = Entity::new(EntityKind::Credential, fp, 0.85, "scan");
        e.tag("ssh-key");
        for l in logins {
            e.add_evidence(
                Evidence::new("github_user", format!("SSH key published by @{l}"))
                    .with_attr("github_login", *l),
            );
        }
        e
    };
    let a = Entity::new(EntityKind::Username, "ghost91", 0.6, "scan");
    let b = Entity::new(EntityKind::Username, "jsmith_work", 0.6, "scan");

    let shared = key("ssh:deadbeefcafef00d", &["ghost91", "jsmith_work"]);
    let hits = super::rules::rule_au_048_shared_public_key(
        &[shared.clone(), a.clone(), b.clone()],
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "a key on two accounts must link them");
    assert_eq!(hits[0].rule_id, "AU-048");
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].entity_uids.contains(&a.uid) && hits[0].entity_uids.contains(&b.uid));

    // A key on a single account is not a link; a non-key Credential is ignored.
    let solo = key("ssh:only0neacct", &["ghost91"]);
    assert!(super::rules::rule_au_048_shared_public_key(&[solo, a.clone()], "scan", 0).is_empty());
    let mut pw = Entity::new(EntityKind::Credential, "$2a$10$x", 0.6, "scan");
    pw.add_evidence(Evidence::new("import", "x").with_attr("github_login", "a"));
    pw.add_evidence(Evidence::new("import", "y").with_attr("github_login", "b"));
    assert!(
        super::rules::rule_au_048_shared_public_key(&[pw], "scan", 0).is_empty(),
        "AU-048 only fires on key-tagged credentials"
    );
}

// ─── Associates / household family (AU-049 … AU-051) ─────────────────────────

#[cfg(test)]
fn person_at(name: &str, addr: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Person, name, 0.62, "s");
    e.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("address", addr));
    e
}

#[cfg(test)]
fn person_with_phone(name: &str, phone: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Person, name, 0.62, "s");
    e.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("phone", phone));
    e
}

#[test]
fn au049_fires_on_two_people_one_residence() {
    // Two distinct people whose breach records carry the same specific residence
    // (in inconsistent formatting) form one household cluster.
    let ents = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield, IL"),
        person_at("Dana Meyers", "123 Main St Springfield IL"),
    ];
    let hits = super::rules::rule_au_049_shared_address_association(&ents, "s", 0);
    assert_eq!(hits.len(), 1, "one household cluster expected");
    assert_eq!(hits[0].rule_id, "AU-049");
    assert!(hits[0].description.contains("2 people"));
}

#[test]
fn au049_single_person_and_region_only_do_not_fire() {
    let one = vec![person_at("Jordan Meyers", "123 Main St, Springfield, IL")];
    assert!(super::rules::rule_au_049_shared_address_association(&one, "s", 0).is_empty());
    // A bare region shared by strangers must never fuse a household.
    let region = vec![
        person_at("Jordan Meyers", "California"),
        person_at("Unrelated Stranger", "California"),
    ];
    assert!(super::rules::rule_au_049_shared_address_association(&region, "s", 0).is_empty());
}

#[test]
fn au049_one_persons_two_emails_is_not_a_household() {
    // Two emails + one named person at an address is the SAME person's handles,
    // not an association — must not fire.
    let mut e1 = Entity::new(EntityKind::Email, "jordan@gmail.com", 0.72, "s");
    e1.add_evidence(
        Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
    );
    let mut e2 = Entity::new(EntityKind::Email, "j.meyers@work.com", 0.72, "s");
    e2.add_evidence(
        Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
    );
    let ents = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        e1,
        e2,
    ];
    assert!(super::rules::rule_au_049_shared_address_association(&ents, "s", 0).is_empty());
}

#[test]
fn au049_references_address_node_and_reachable_handles() {
    let mut email = Entity::new(EntityKind::Email, "dana@gmail.com", 0.72, "s");
    email.add_evidence(
        Evidence::new("import:dossier", "e").with_attr("address", "123 Main St, Springfield"),
    );
    let addr = Entity::new(EntityKind::Address, "123 Main St, Springfield", 0.58, "s");
    let addr_uid = addr.uid.clone();
    let email_uid = email.uid.clone();
    let ents = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        person_at("Dana Meyers", "123 Main St, Springfield"),
        email,
        addr,
    ];
    let hits = super::rules::rule_au_049_shared_address_association(&ents, "s", 0);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0].entity_uids.contains(&addr_uid),
        "address node referenced"
    );
    assert!(
        hits[0].entity_uids.contains(&email_uid),
        "reachable handle referenced"
    );
}

#[test]
fn au050_shared_phone_links_two_people_and_rejects_placeholders() {
    // Formatting variants of the same line collapse to one association.
    let ents = vec![
        person_with_phone("Jordan Meyers", "+1 (415) 555-0100"),
        person_with_phone("Casey Lin", "14155550100"),
    ];
    let hits = super::rules::rule_au_050_shared_phone_association(&ents, "s", 0);
    assert_eq!(
        hits.len(),
        1,
        "formatting variants must collapse to one line"
    );
    assert_eq!(hits[0].rule_id, "AU-050");
    assert!(hits[0].description.contains("0100"), "masked tail shown");

    // All-same-digit placeholder is not a subscriber line.
    let placeholder = vec![
        person_with_phone("Jordan Meyers", "+00000000000"),
        person_with_phone("Casey Lin", "+00000000000"),
    ];
    assert!(super::rules::rule_au_050_shared_phone_association(&placeholder, "s", 0).is_empty());
}

#[test]
fn au051_shared_surname_at_residence_is_kin() {
    let ents = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        person_at("Dana Meyers", "123 Main St, Springfield"),
    ];
    let hits = super::rules::rule_au_051_shared_surname_kin(&ents, "s", 0);
    assert_eq!(hits.len(), 1, "shared surname + residence = kin");
    assert_eq!(hits[0].rule_id, "AU-051");
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].description.contains("meyers"));
}

#[test]
fn au051_requires_shared_residence_and_distinguishes_roommates() {
    // Same surname, different homes: two unrelated people must NOT link.
    let apart = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        person_at("Dana Meyers", "987 Oak Ave, Portland"),
    ];
    assert!(super::rules::rule_au_051_shared_surname_kin(&apart, "s", 0).is_empty());

    // Same residence, different families: AU-049 fires (household) but AU-051
    // (kin) does not.
    let roommates = vec![
        person_at("Jordan Meyers", "123 Main St, Springfield"),
        person_at("Casey Lin", "123 Main St, Springfield"),
    ];
    assert_eq!(
        super::rules::rule_au_049_shared_address_association(&roommates, "s", 0).len(),
        1
    );
    assert!(super::rules::rule_au_051_shared_surname_kin(&roommates, "s", 0).is_empty());
}

// ─── Geo convex footprint (AU-052) ───────────────────────────────────────────

#[cfg(test)]
fn coord_from(value: &str, source: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Coordinates, value, 0.70, "s");
    e.add_evidence(Evidence::new(source, "geo sighting"));
    e
}

/// A coordinate tagged `hosting` (a CDN/datacenter edge) — infrastructure, not a
/// person, even if it carries several sources.
#[cfg(test)]
fn hosting_coord(value: &str, source: &str) -> Entity {
    let mut e = coord_from(value, source);
    e.tag(crate::core::tags::HOSTING);
    e
}

#[test]
fn au052_tight_multisource_footprint_is_a_high_location_fix() {
    // Three person-anchored sightings around one suburb (photo EXIF, Wi-Fi,
    // geocoded address) → a tight, High-severity fix with a centroid.
    let ents = vec![
        coord_from("-33.8700,151.2100", "geocode"),
        coord_from("-33.8720,151.2150", "exif_geo"),
        coord_from("-33.8680,151.2080", "wigle"),
    ];
    let hits = super::rules::rule_au_052_geographic_area_of_operation(&ents, "s", 0);
    assert_eq!(hits.len(), 1, "three multi-source coords bound an area");
    assert_eq!(hits[0].rule_id, "AU-052");
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(hits[0].description.contains("centroid"));
    assert!(hits[0].description.contains("tight"));
    // The headline fix is the outlier-robust geometric median; the Chebyshev
    // centre is retained as the bounding circle with its uncertainty radius.
    assert!(hits[0].description.contains("geometric median"));
    assert!(hits[0].description.contains("Chebyshev centre"));
    assert!(hits[0].description.contains("±"));
}

#[test]
fn au052_requires_three_points_and_two_sources() {
    // Two points: no area.
    let two = vec![
        coord_from("-33.8700,151.2100", "geocode"),
        coord_from("-33.8720,151.2150", "exif_geo"),
    ];
    assert!(super::rules::rule_au_052_geographic_area_of_operation(&two, "s", 0).is_empty());

    // Three points but all from ONE source (a single device's track) → not
    // multi-source convergence, must not assert a footprint.
    let one_source = vec![
        coord_from("-33.8700,151.2100", "exif_geo"),
        coord_from("-33.8720,151.2150", "exif_geo"),
        coord_from("-33.8680,151.2080", "exif_geo"),
    ];
    assert!(super::rules::rule_au_052_geographic_area_of_operation(&one_source, "s", 0).is_empty());
}

#[test]
fn au052_dispersed_footprint_is_medium_travel_pattern() {
    // Person-anchored sightings hundreds of km apart → a dispersed,
    // Medium-severity travel footprint (not a single-residence fix).
    let ents = vec![
        coord_from("-33.8700,151.2100", "geocode"),  // Sydney
        coord_from("-37.8100,144.9600", "exif_geo"), // Melbourne
        coord_from("-27.4700,153.0200", "wigle"),    // Brisbane
    ];
    let hits = super::rules::rule_au_052_geographic_area_of_operation(&ents, "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, super::Severity::Medium);
    assert!(hits[0].description.contains("dispersed"));
}

#[test]
fn au052_excludes_infrastructure_geo_live_peekyou_case() {
    // Regression from a real peekyou.com-pivoted scan: every coordinate
    // geolocated the target's web HOST, not the target. A Cloudflare edge
    // (hosting-tagged) plus two IP/WHOIS-only datacenter coords must NOT form a
    // person's footprint — otherwise the hull spans four continents of CDN.
    let ents = vec![
        hosting_coord("43.6532,-79.3832", "ip_geo"), // Toronto CF edge (hosting)
        coord_from("37.7621,-122.3971", "ipinfo"),   // SF — IP-geo only
        coord_from("36.0345,-89.3856", "ip_whois_geo"), // Tennessee — WHOIS-geo only
    ];
    assert!(
        super::rules::rule_au_052_geographic_area_of_operation(&ents, "s", 0).is_empty(),
        "infrastructure coordinates must not form a person's area of operation"
    );

    // But a real person-anchored coordinate mixed in is kept: if the same scan
    // ALSO held three EXIF/Wi-Fi/geocode sightings in one suburb, those — and
    // only those — would fix the location.
    let mixed = vec![
        hosting_coord("43.6532,-79.3832", "ip_geo"),
        coord_from("-33.8700,151.2100", "exif_geo"),
        coord_from("-33.8720,151.2150", "wigle"),
        coord_from("-33.8680,151.2080", "geocode"),
    ];
    let hits = super::rules::rule_au_052_geographic_area_of_operation(&mixed, "s", 0);
    assert_eq!(hits.len(), 1, "the three real sightings fix the location");
    assert!(hits[0].description.contains("tight"));
}

// ─── Geo out-of-area anomaly (AU-053) ────────────────────────────────────────

#[test]
fn au053_flags_a_sighting_outside_the_established_area() {
    // Three tight Sydney sightings (the established area) + one Perth sighting
    // ~3300 km away. AU-053 flags Perth as out-of-area; the Sydney points, being
    // the dominant cluster, are never themselves flagged.
    let ents = vec![
        coord_from("-33.8700,151.2100", "geocode"),
        coord_from("-33.8720,151.2150", "exif_geo"),
        coord_from("-33.8680,151.2080", "wigle"),
        coord_from("-31.9520,115.8570", "exif_geo"), // Perth
    ];
    let hits = super::rules::rule_au_053_out_of_area_location(&ents, "s", 0);
    assert_eq!(hits.len(), 1, "the Perth sighting is out of area");
    assert_eq!(hits[0].rule_id, "AU-053");
    assert_eq!(hits[0].severity, super::Severity::Medium);
    assert!(hits[0].description.contains("outside"));
}

#[test]
fn au053_does_not_fire_on_a_single_coherent_area() {
    // Four tight sightings in one suburb — no outlier, no anomaly.
    let ents = vec![
        coord_from("-33.8700,151.2100", "geocode"),
        coord_from("-33.8720,151.2150", "exif_geo"),
        coord_from("-33.8680,151.2080", "wigle"),
        coord_from("-33.8710,151.2120", "geocode"),
    ];
    assert!(super::rules::rule_au_053_out_of_area_location(&ents, "s", 0).is_empty());
}

#[test]
fn au053_ignores_infrastructure_and_needs_an_established_area() {
    // The live peekyou.com case: infra coords are excluded, leaving too few
    // person-anchored points to form an established area → no anomaly fires.
    let ents = vec![
        hosting_coord("43.6532,-79.3832", "ip_geo"),
        coord_from("37.7621,-122.3971", "ipinfo"),
        coord_from("36.0345,-89.3856", "ip_whois_geo"),
        coord_from("-33.8700,151.2100", "exif_geo"), // one real point
    ];
    assert!(super::rules::rule_au_053_out_of_area_location(&ents, "s", 0).is_empty());
}
