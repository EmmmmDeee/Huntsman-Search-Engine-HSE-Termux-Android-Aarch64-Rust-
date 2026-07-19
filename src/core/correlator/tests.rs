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
    // Username from one source, matching email from another INDEPENDENT
    // observation → ≥2 distinct corroborating sources → fires, linking both uids.
    // (Both sources must be genuine sightings: a `name_intel`-derived email is a
    // derivation of the seed, not independent — see ENRICHMENT_ONLY_SOURCES.)
    let entities = vec![
        username("jmeyers", &["github_user"]),
        email("jmeyers@gmail.com", &["hudsonrock"]),
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

#[test]
fn au001_does_not_raise_critical_on_a_role_mailbox() {
    // Live person-scan false positive: `abuse@godaddy.com` (a registrar desk) is in
    // HIBP + XposedOrNot as a matter of course — that is NOT the subject's breach
    // exposure and must not fire a Critical.
    let role = email("abuse@godaddy.com", &["hibp", "xposed_or_not"]);
    assert!(rule_au_001_multi_breach(&[role], "s1", 0).is_empty());
    // A genuine personal mailbox in the same two sources still fires.
    let real = email("matthew@example.com", &["hibp", "xposed_or_not"]);
    assert_eq!(rule_au_001_multi_breach(&[real], "s1", 0).len(), 1);
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
        rule_au_003_high_corroboration(&[weak], "s", 0).is_empty(),
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
        rule_au_003_high_corroboration(&[verified], "s", 0).len(),
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
    let r = rule_au_004_malicious_infrastructure(&[e], "s", 0);
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
    assert!(rule_au_004_malicious_infrastructure(&[e], "s", 0).is_empty());
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
    let e = tagged(
        EntityKind::Domain,
        "vuln.example",
        &[crate::core::tags::VULNERABLE],
    );
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
        &[crate::core::tags::VULNERABLE, "greynoise-benign"],
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

    let forward = rule_au_037_credential_exposure(&ents, "s", 0);
    let mut reversed = ents.clone();
    reversed.reverse();
    let backward = rule_au_037_credential_exposure(&reversed, "s", 0);

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
        &[
            mk_weak("https://onlyfans.com/rob_dorito"),
            mk_weak("https://twitch.tv/rob_dorito"),
            mk_weak("https://tiktok.com/@rob_dorito"),
        ],
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
        &[strong1, strong2, mk_weak("https://onlyfans.com/rob_dorito")],
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
        rule_au_010_infra_consensus(&[mk(&["dns_intel", "doh_resolver", "recall"])], "s", 0)
            .is_empty(),
        "two resolvers + a recall replay is not a 3-source consensus"
    );
    // Three INDEPENDENT infrastructure sources still fire.
    assert_eq!(
        rule_au_010_infra_consensus(&[mk(&["dns_intel", "doh_resolver", "crtsh"])], "s", 0).len(),
        1
    );
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
    let r = rule_au_013_local_network_discovery(&entities, "s", 0);
    assert_eq!(r.len(), 1);
}

#[test]
fn au013_no_fire_on_one_lan_entity() {
    let entities = vec![tagged(
        EntityKind::IpAddress,
        "192.168.1.1",
        &[crate::core::tags::LOCAL_ARP],
    )];
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
        &[crate::core::tags::THREAT_INTEL, "ti:malware"],
    );
    let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("malware"));
}

#[test]
fn au015_attribution_names_evidence_source_not_otx() {
    let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
    e.tag(crate::core::tags::THREAT_INTEL);
    e.add_evidence(Evidence::new("threatfox", "t"));
    let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
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
    let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
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
    let firings = rule_au_017_multi_geo_convergence(&[c1, c2], "s", 0);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].rule_id, "AU-017");
    assert!(firings[0].description.contains("converge"));
}

#[test]
fn rule_017_no_fire_for_distant_coords() {
    let c1 = anchored_coord("-27.55,152.27", 0.60);
    let c2 = anchored_coord("-33.86,151.20", 0.65);
    let firings = rule_au_017_multi_geo_convergence(&[c1, c2], "s", 0);
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
        rule_au_017_multi_geo_convergence(&[h1, h2], "s", 0).is_empty(),
        "infrastructure coordinates must not converge into a subject location"
    );
    // A bare coordinate with no anchoring source is also infrastructure.
    let b1 = Entity::new(EntityKind::Coordinates, "-27.55,152.27", 0.60, "s");
    let b2 = Entity::new(EntityKind::Coordinates, "-27.60,152.30", 0.65, "s");
    assert!(rule_au_017_multi_geo_convergence(&[b1, b2], "s", 0).is_empty());
    // Control: the same points, person-anchored, DO converge.
    assert_eq!(
        rule_au_017_multi_geo_convergence(
            &[
                anchored_coord("-27.55,152.27", 0.60),
                anchored_coord("-27.60,152.30", 0.65)
            ],
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
        rule_au_017_multi_geo_convergence(ents, "s", 0)
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
    let firings = rule_au_017_multi_geo_convergence(&[junk1, junk2], "s", 0);
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
    assert!(rule_au_031_malicious_adjacency(&[a, b], &[rel], "s", 0).is_empty());
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
    assert!(rule_au_031_malicious_adjacency(&[bad], &[rel], "s", 0).is_empty());
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
        rule_au_031_malicious_adjacency(&entities, &rels, "s", 0).is_empty(),
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
        &[email.clone(), domain.clone(), person.clone()],
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
    assert!(rule_au_060_transitive_identity_closure(&[email, person], &rels, "s", 0).is_empty());
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
    assert!(rule_au_039_wallet_identity(&disjoint, "scan", 0).is_empty());
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
    } else {
        (z.raw_value.clone(), a.raw_value.clone())
    };
    let wallet = mk_tagged(
        EntityKind::CryptoAddress,
        "1A1zP1eP...",
        "hudsonrock",
        &["crypto-address"],
    );
    // Smaller-UID person: UNRELATED (disjoint source, would win the buggy pick).
    let unrelated = mk_tagged(EntityKind::Person, &small_uid_name, "see_know", &[]);
    // Larger-UID person: shares the wallet's source ⇒ the genuine attribution.
    let related = mk_tagged(EntityKind::Person, &large_uid_name, "hudsonrock", &[]);

    let out = rule_au_039_wallet_identity(
        &[wallet.clone(), unrelated.clone(), related.clone()],
        "scan",
        0,
    );
    assert_eq!(
        out.len(),
        1,
        "only the source-related identity is attributed"
    );
    assert!(out[0].entity_uids.contains(&wallet.uid));
    assert!(
        out[0].entity_uids.contains(&related.uid),
        "attributed to the shared-source person"
    );
    assert!(
        !out[0].entity_uids.contains(&unrelated.uid),
        "never the min-UID bystander"
    );
    // Order-independent: same result whichever order the entities arrive in (the
    // live HashMap-ordered pass and the finalise pass must agree).
    let rev = rule_au_039_wallet_identity(
        &[wallet.clone(), related.clone(), unrelated.clone()],
        "scan",
        0,
    );
    assert_eq!(out[0].entity_uids, rev[0].entity_uids);
}

#[test]
fn au_039_prefers_tied_person_over_email_and_reports_each_tie() {
    // One stealer log surfaced the wallet, two people, and an email — all sharing
    // the "hudsonrock" source. Person is the more specific identity, so both tied
    // people are reported (each an independent, genuine lead) and the redundant
    // email is suppressed.
    let src = "hudsonrock";
    let wallet = mk_tagged(
        EntityKind::CryptoAddress,
        "1A1zP1eP...",
        src,
        &["crypto-address"],
    );
    let p1 = mk_tagged(EntityKind::Person, "Aaron Avery", src, &[]);
    let p2 = mk_tagged(EntityKind::Person, "Zoe Zimmer", src, &[]);
    let em = mk_tagged(EntityKind::Email, "z@example.com", src, &[]);
    let out = rule_au_039_wallet_identity(
        &[wallet.clone(), p1.clone(), p2.clone(), em.clone()],
        "scan",
        0,
    );
    assert_eq!(out.len(), 2, "both tied people reported");
    let uids: std::collections::HashSet<_> = out
        .iter()
        .flat_map(|c| c.entity_uids.iter().cloned())
        .collect();
    assert!(uids.contains(&p1.uid) && uids.contains(&p2.uid));
    assert!(
        !uids.contains(&em.uid),
        "email not emitted when a person is tied"
    );

    // Falls back to an email anchor only when NO person is tied.
    let out2 = rule_au_039_wallet_identity(&[wallet.clone(), em.clone()], "scan", 0);
    assert_eq!(out2.len(), 1);
    assert!(out2[0].entity_uids.contains(&em.uid));
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

// A pgp-linked email carrying the `key_fingerprint` evidence attribute the real
// `pgp` module attaches — the fingerprint AU-042 now partitions on.
fn pgp_email(addr: &str, fpr: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Email, addr, 0.8, "scan");
    e.tag("pgp-linked");
    e.add_evidence(Evidence::new("pgp", "PGP keyserver User ID").with_attr("key_fingerprint", fpr));
    e
}

#[test]
fn au_042_groups_pgp_linked_emails() {
    // Two emails bound to the SAME PGP key group into one same-owner finding.
    let ents = vec![
        pgp_email("alt@work.com", "AAAA1111BBBB2222"),
        pgp_email("other@home.com", "AAAA1111BBBB2222"),
        mk_tagged(EntityKind::Email, "unrelated@x.com", "hibp", &[]),
    ];
    let out = rule_au_042_pgp_email_identity(&ents, "scan", 0);
    assert_eq!(out.len(), 1, "one grouped firing for the shared key");
    assert_eq!(
        out[0].entity_uids.len(),
        2,
        "only the two same-key pgp-linked emails"
    );
    assert_eq!(out[0].severity, Severity::High);
    assert!(out[0].description.contains("AAAA1111BBBB2222"));
}

#[test]
fn au042_does_not_fuse_emails_from_two_distinct_keys() {
    // Key A binds two emails; key B binds two others — potentially two different
    // people. They must NOT be fused into a single four-email "one owner"; each key
    // fires its own finding over only its own emails.
    let ents = vec![
        pgp_email("a1@x.com", "KEYAAAA00000000"),
        pgp_email("a2@x.com", "KEYAAAA00000000"),
        pgp_email("b1@y.com", "KEYBBBB11111111"),
        pgp_email("b2@y.com", "KEYBBBB11111111"),
    ];
    let out = rule_au_042_pgp_email_identity(&ents, "scan", 0);
    assert_eq!(
        out.len(),
        2,
        "one finding per key, not a single fused owner"
    );
    assert!(
        out.iter().all(|c| c.entity_uids.len() == 2),
        "each key binds exactly its own two emails, never all four"
    );
    let key_a = out
        .iter()
        .find(|c| c.description.contains("KEYAAAA00000000"))
        .expect("a finding for key A");
    assert!(
        key_a.description.contains("a1@x.com") && key_a.description.contains("a2@x.com"),
        "key A's finding lists its own two emails: {}",
        key_a.description
    );
    assert!(
        !key_a.description.contains("b1@y.com") && !key_a.description.contains("b2@y.com"),
        "key A's finding must not carry key B's emails: {}",
        key_a.description
    );
}

#[test]
fn au_054_locates_pii_corroboration_scaled_never_high() {
    use super::rules::rule_au_054_data_broker_exposure;

    // Subject across TWO distinct brokers (2 Spokeo URLs + 1 Whitepages) plus an
    // unrelated public URL that must NOT count. One grouped finding.
    let multi = vec![
        mk_tagged(
            EntityKind::Url,
            "https://www.spokeo.com/John-Doe",
            "search_engines",
            &[],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://www.spokeo.com/John-Doe/2",
            "search_engines",
            &[],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://www.whitepages.com/name/John-Doe",
            "search_engines",
            &[],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://github.com/jdoe",
            "github_user",
            &[],
        ),
    ];
    let out = rule_au_054_data_broker_exposure(&multi, "scan", 0);
    assert_eq!(out.len(), 1, "one grouped finding, not one per broker");
    assert_eq!(out[0].rule_id, "AU-054");
    // ≥2 independent brokers → Medium (corroborated), but NEVER High/Critical —
    // brokers are not preferenced over other OSINT.
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].description.contains("Spokeo") && out[0].description.contains("Whitepages"));
    assert!(out[0].description.contains("brokered on"));
    assert!(
        out[0].description.contains("not confirmation"),
        "must caveat broker data as a lead, not confirmation"
    );
    assert!(
        !out[0].description.contains("http"),
        "location finding only — no opt-out/takedown surface"
    );
    assert_eq!(
        out[0].entity_uids.len(),
        3,
        "all broker URLs (2 Spokeo + 1 Whitepages) under one finding"
    );

    // A LONE broker is weak/uncorroborated → Low, so it never outranks real
    // OSINT and is never treated as credible in isolation.
    let single = vec![mk_tagged(
        EntityKind::Url,
        "https://www.spokeo.com/John-Doe",
        "search_engines",
        &[],
    )];
    let out = rule_au_054_data_broker_exposure(&single, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].severity,
        super::Severity::Low,
        "a single broker listing is low-credibility, never preferenced"
    );

    // No broker exposure → no finding.
    let clean = vec![mk_tagged(
        EntityKind::Url,
        "https://github.com/jdoe",
        "github_user",
        &[],
    )];
    assert!(rule_au_054_data_broker_exposure(&clean, "scan", 0).is_empty());
}

#[test]
fn au_055_flags_owned_primary_accounts_excluding_brokers() {
    use super::rules::rule_au_055_primary_source_accounts;

    // A single confirmed primary-source profile fires (AU-038 needs ≥2 platforms,
    // so a lone owned account was previously invisible) — High, outranking the
    // Low/Medium broker findings of AU-054.
    let single = vec![mk_tagged(
        EntityKind::Url,
        "https://github.com/jdoe",
        "github_user",
        &["public-profile"],
    )];
    let out = rule_au_055_primary_source_accounts(&single, "scan", 0);
    assert_eq!(out.len(), 1, "one grouped finding");
    assert_eq!(out[0].rule_id, "AU-055");
    assert_eq!(out[0].severity, super::Severity::High);
    assert!(out[0].description.contains("github.com"));
    assert!(out[0].description.contains("primary source"));
    assert_eq!(out[0].entity_uids.len(), 1);

    // ≥3 distinct platforms → Critical.
    let many = vec![
        mk_tagged(
            EntityKind::Url,
            "https://github.com/jdoe",
            "github_user",
            &["public-profile"],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://twitter.com/jdoe",
            "search_engines",
            &["social-profile"],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://jdoe.dev/",
            "web_crawler",
            &["personal-site"],
        ),
    ];
    let out = rule_au_055_primary_source_accounts(&many, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Critical);
    assert_eq!(out[0].entity_uids.len(), 3);

    // A broker listing tagged as a profile is NOT an owned account — excluded.
    let broker = vec![mk_tagged(
        EntityKind::Url,
        "https://www.spokeo.com/John-Doe",
        "search_engines",
        &["social-profile"],
    )];
    assert!(
        rule_au_055_primary_source_accounts(&broker, "scan", 0).is_empty(),
        "broker host must not count as a subject-controlled account"
    );

    // No owned-account URL → no finding.
    let none = vec![mk_tagged(
        EntityKind::Url,
        "https://github.com/jdoe",
        "github_user",
        &[],
    )];
    assert!(rule_au_055_primary_source_accounts(&none, "scan", 0).is_empty());
}

#[test]
fn au_055_excludes_weak_detection_status_only_guesses() {
    // Regression: a real scan against a guessed username handle produced a
    // CRITICAL "primary-source accounts... the subject controls" finding
    // across 60+ platforms where nearly every hit was `username_search`'s
    // bare-status-code guess (`weak-detection`) — a soft-404/SPA-shell can
    // return HTTP 200 for almost any handle, so this is not a confirmed
    // account. `weak-detection`-tagged hits, even 3+ of them, must not fire
    // this rule at all — a pile of unverified guesses is not a primary
    // source, confirmed or otherwise.
    use super::rules::rule_au_055_primary_source_accounts;

    let all_weak = vec![
        mk_tagged(
            EntityKind::Url,
            "https://onlyfans.com/rob_dorito",
            "streaming_probe",
            &["fans-profile", "weak-detection"],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://twitch.tv/rob_dorito",
            "username_search",
            &["social-profile", "weak-detection"],
        ),
        mk_tagged(
            EntityKind::Url,
            "https://tiktok.com/@rob_dorito",
            "username_search",
            &["social-profile", "weak-detection"],
        ),
    ];
    assert!(
        rule_au_055_primary_source_accounts(&all_weak, "scan", 0).is_empty(),
        "weak-detection (status-only) hits must never count as confirmed primary-source accounts"
    );

    // A single body-marker-verified hit alongside the weak guesses still
    // fires — only the unverified ones are excluded, not the whole rule.
    let mut mixed = all_weak.clone();
    mixed.push(mk_tagged(
        EntityKind::Url,
        "https://github.com/rob_dorito",
        "username_search",
        &["social-profile", "verified-detection"],
    ));
    let out = rule_au_055_primary_source_accounts(&mixed, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].entity_uids.len(),
        1,
        "only the verified-detection hit counts, none of the weak-detection ones"
    );
    assert!(out[0].description.contains("github.com"));
    assert_eq!(
        out[0].severity,
        super::Severity::High,
        "one confirmed platform is High, not Critical"
    );
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
fn au045_excludes_status_only_hits_even_across_distinct_families() {
    // Regression: a real scan against a guessed handle showed `username_search`
    // (family "presence") and `social_probe` (family "social") both hit the
    // SAME unverified handle via a bare status-code check — and because they
    // classify into two DIFFERENT families purely by platform category, not
    // by detection rigour, that satisfied AU-045's "two distinct service
    // families" bar despite neither one being an actual confirmation. A
    // status-only hit must not contribute its family to the diversity count.
    let mut weak = Entity::new(EntityKind::Username, "rob_dorito", 0.6, "scan");
    weak.add_evidence(
        Evidence::new("username_search", "status 200").with_attr("detection", "status-only"),
    );
    weak.add_evidence(
        Evidence::new("social_probe", "status 200").with_attr("detection", "status-only"),
    );
    assert!(
        super::rules::rule_au_045_multi_service_identity(&[weak], "scan", 0).is_empty(),
        "two status-only hits in different families must not satisfy the cross-family bar"
    );

    // The same two sources, but at least one with a real body-marker
    // confirmation, DOES count — the fix discounts the *hit*, not the module.
    let mut strong = Entity::new(EntityKind::Username, "rob_dorito", 0.6, "scan");
    strong.add_evidence(
        Evidence::new("username_search", "body match").with_attr("detection", "body-marker"),
    );
    strong.add_evidence(
        Evidence::new("social_probe", "status 200").with_attr("detection", "status-only"),
    );
    assert_eq!(
        super::rules::rule_au_045_multi_service_identity(&[strong], "scan", 0).len(),
        0,
        "one verified source alone is still only ONE family (presence) — needs a second"
    );

    // Two genuinely verified sources in distinct families fire normally.
    let mut both_strong = Entity::new(EntityKind::Username, "rob_dorito", 0.6, "scan");
    both_strong.add_evidence(
        Evidence::new("username_search", "body match").with_attr("detection", "body-marker"),
    );
    both_strong.add_evidence(Evidence::new("hibp", "breach row"));
    assert_eq!(
        super::rules::rule_au_045_multi_service_identity(&[both_strong], "scan", 0).len(),
        1,
        "a verified presence hit + a breach hit are two real independent families"
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
fn au072_payid_surface_fires_on_multiple_payids_and_links_them() {
    // Two PayID handles (email + phone) → the consolidated payment-identity
    // surface fires, lists both channels, and links both uids in sorted order.
    let mut email = Entity::new(EntityKind::Email, "a@contoso.com", 0.8, "s");
    email.tag("payid");
    email.tag("payid:email");
    let mut phone = Entity::new(EntityKind::Phone, "+61410959140", 0.8, "s");
    phone.tag("payid");
    phone.tag("payid:phone");

    // Deliberately unsorted input to exercise the determinism of entity_uids.
    let r =
        super::rules::rule_au_072_payid_payment_surface(&[phone.clone(), email.clone()], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-072");
    assert_eq!(
        r[0].severity,
        Severity::Medium,
        "no register-resolvable ABN → Medium"
    );
    assert!(r[0].description.contains("2 PayID"));
    assert!(r[0].description.contains("email") && r[0].description.contains("phone"));
    let mut expect = vec![email.uid.clone(), phone.uid.clone()];
    expect.sort();
    assert_eq!(r[0].entity_uids, expect, "full member set, sorted");

    // A single PayID handle is not a surface.
    assert!(super::rules::rule_au_072_payid_payment_surface(&[email], "s", 0).is_empty());
}

#[test]
fn au072_register_resolvable_abn_raises_severity() {
    let mut email = Entity::new(EntityKind::Email, "a@contoso.com", 0.8, "s");
    email.tag("payid");
    email.tag("payid:email");
    let mut abn = Entity::new(EntityKind::AbnAcn, "51824753556", 0.9, "s");
    abn.tag("payid");
    abn.tag("payid:abn");
    abn.tag("payid:registry-resolvable");

    let r = super::rules::rule_au_072_payid_payment_surface(&[email, abn], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].severity,
        Severity::High,
        "a register-resolvable ABN PayID lifts the severity"
    );
    assert!(r[0].description.contains("public register"));
}

#[test]
fn au073_dob_corroborated_across_sources_disambiguates_namesakes() {
    // Two independent sources assert the same DOB (one as an ISO datetime that
    // must normalise) → High. A namesake's DOB from a single source is a
    // separate Medium finding — visible, not silently merged.
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(
        Evidence::new("oathnet_pro", "breach").with_attr("date_of_birth", "1980-11-08T00:00:00"),
    );
    let mut e = Entity::new(EntityKind::Email, "c@contoso.com", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("dob", "1980-11-08"));
    let mut ns = Entity::new(EntityKind::Email, "d@contoso.com", 0.9, "s");
    ns.add_evidence(Evidence::new("hibp", "breach").with_attr("date_of_birth", "1975-01-01"));

    let r = super::rules::rule_au_073_subject_date_of_birth(&[p, e, ns], "s", 0);
    let main = r
        .iter()
        .find(|c| c.description.contains("1980-11-08"))
        .expect("the corroborated DOB fires");
    assert_eq!(main.rule_id, "AU-073");
    assert_eq!(main.severity, Severity::High, "two agreeing sources → High");
    let minor = r
        .iter()
        .find(|c| c.description.contains("1975-01-01"))
        .expect("the namesake DOB is surfaced separately");
    assert_eq!(minor.severity, Severity::Medium, "single source → Medium");
}

#[test]
fn au073_derives_subject_age_from_dob() {
    // ts = 2026-01-01 00:00 UTC; DOB 1992-07-01 → age 33 (July birthday not yet
    // passed). Also exercises the new `date_birth` key (OathNet's field).
    const TS_2026_01_01: u64 = 1_767_225_600;
    let mut p = Entity::new(EntityKind::Person, "Jerome Despal", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("date_birth", "1992-07-01"));
    let mut e = Entity::new(EntityKind::Email, "j@x.com", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("dob", "1992-07-01"));

    let r = super::rules::rule_au_073_subject_date_of_birth(&[p, e], "s", TS_2026_01_01);
    let f = r
        .iter()
        .find(|c| c.description.contains("1992-07-01"))
        .expect("the DOB fires (incl. via the date_birth key)");
    assert_eq!(f.severity, Severity::High, "date_birth + dob = two sources");
    assert!(
        f.description.contains("age 33"),
        "derived age present: {}",
        f.description
    );
}

#[test]
fn au073_tolerates_a_multibyte_dob_without_panicking() {
    // Regression: a breach DOB whose first 8 bytes look ISO ("YYYY-MM-", with
    // ASCII dashes at indices 4 and 7) but whose 9th byte begins a MULTIBYTE
    // UTF-8 char (here `€`, three bytes at indices 8..11) passed `normalise_dob`
    // verbatim via its non-ISO else-branch and then reached `age_from_dob`, whose
    // guard only checked the two dashes and the length — so `dob[8..10]` sliced
    // through the middle of the `€` and panicked. The correlator runs OUTSIDE the
    // engine's per-module `catch_unwind`, so that panic crashed the whole scan on
    // adversarial breach input. It must degrade to "no derived age", never panic.
    const TS: u64 = 1_767_225_600; // 2026-01-01
    let mut p = Entity::new(EntityKind::Person, "Jerome Despal", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("dob", "1980-11-€X"));
    let mut e = Entity::new(EntityKind::Email, "j@x.com", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("dob", "1980-11-€X"));
    let r = super::rules::rule_au_073_subject_date_of_birth(&[p, e], "s", TS);
    let f = r
        .iter()
        .find(|c| c.description.contains("1980-11-€X"))
        .expect("the non-ISO DOB still fires as a (no-age) correlation");
    assert!(
        !f.description.contains("age "),
        "no age is derived from a non-ISO DOB: {}",
        f.description
    );
}

#[test]
fn au073_never_panics_on_a_multibyte_dob_at_any_byte_position() {
    // Generalises the regression above: slide a 3-byte char (`€`) through every
    // byte position of an otherwise-ISO date so it straddles each of the
    // `dob[0..4]`/`dob[5..7]`/`dob[8..10]` slice boundaries in turn, then add a
    // 4-byte emoji, all-multibyte, control, short and empty forms. The rule must
    // tolerate every one (no panic) — proving the byte-slice DOB parser is
    // boundary-safe on arbitrary breach input, not just the one captured shrink.
    const TS: u64 = 1_767_225_600;
    let base = "1980-11-08";
    let mut inputs: Vec<String> = (0..=base.len())
        .map(|i| format!("{}€{}", &base[..i], &base[i..]))
        .collect();
    for s in [
        "",
        "€",
        "--------",
        "1980-11-",
        "1980-€1-08",
        "1980-11-0😀",
        "😀😀😀😀-11-08",
        "19\u{0}0-11-08",
    ] {
        inputs.push(s.to_string());
    }
    for dob in inputs {
        let mut p = Entity::new(EntityKind::Person, "X Y", 0.9, "s");
        p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("dob", dob.as_str()));
        // The assertion is simply that this returns without panicking.
        let _ = super::rules::rule_au_073_subject_date_of_birth(&[p], "s", TS);
    }
}

#[test]
fn au073_age_advances_after_the_birthday() {
    // Same DOB, ts = 2026-12-01 (after the July birthday) → age 34.
    const TS_2026_12_01: u64 = 1_796_083_200;
    let mut p = Entity::new(EntityKind::Person, "Jerome Despal", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("dob", "1992-07-01"));
    let r = super::rules::rule_au_073_subject_date_of_birth(&[p], "s", TS_2026_12_01);
    let f = r
        .iter()
        .find(|c| c.description.contains("1992-07-01"))
        .unwrap();
    assert!(f.description.contains("age 34"), "{}", f.description);
}

#[test]
fn au073_omits_age_for_a_non_iso_dob() {
    // A non-ISO DOB is surfaced verbatim but yields no (mis-parsed) age.
    let mut p = Entity::new(EntityKind::Person, "Jane Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("dob", "08/11/1980"));
    let r = super::rules::rule_au_073_subject_date_of_birth(&[p], "s", 1_767_225_600);
    let f = r
        .iter()
        .find(|c| c.description.contains("08/11/1980"))
        .unwrap();
    assert!(
        !f.description.contains("age "),
        "no age for a non-ISO DOB: {}",
        f.description
    );
}

#[test]
fn au074_government_id_exposure_validates_checksum_and_masks() {
    // A checksum-valid TFN (ATO example 123456782) + a valid Medicare under their
    // breach keys → CRITICAL, value masked. A bad-checksum TFN is rejected.
    let mut e = Entity::new(EntityKind::Credential, "leak", 0.9, "s");
    e.add_evidence(
        Evidence::new("dehashed", "breach")
            .with_attr("tfn", "123456782")
            .with_attr("medicare", "2123456701"),
    );
    let mut bad = Entity::new(EntityKind::Credential, "leak2", 0.9, "s");
    bad.add_evidence(Evidence::new("dehashed", "breach").with_attr("tfn", "123456789"));

    let r = super::rules::rule_au_074_au_government_id_exposure(&[e, bad], "s", 0);
    assert!(!r.is_empty(), "a valid gov-ID exposure must fire");
    let crit = r
        .iter()
        .find(|c| c.rule_id == "AU-074")
        .expect("AU-074 fires");
    assert_eq!(crit.rule_id, "AU-074");
    assert_eq!(crit.severity, Severity::Critical);
    assert!(r.iter().any(|c| c.description.contains("Tax File Number")));
    assert!(r.iter().any(|c| c.description.contains("Medicare")));
    assert!(
        r.iter().all(|c| !c.description.contains("123456782")),
        "the raw value must be masked, never shown in the finding"
    );
    assert_eq!(
        r.iter()
            .filter(|c| c.description.contains("Tax File Number"))
            .count(),
        1,
        "the bad-checksum TFN produced no finding"
    );
}

#[test]
fn au075_named_associate_from_breach_record() {
    let mut e = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    e.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("spouse", "Thomas Haynes")
            .with_attr("emergency_contact", "self"),
    );
    let r = super::rules::rule_au_075_named_associate(&[e], "s", 0);
    let hit = r
        .iter()
        .find(|c| c.description.contains("Thomas Haynes"))
        .expect("the named spouse is surfaced");
    assert_eq!(hit.rule_id, "AU-075");
    assert!(hit.description.contains("spouse"));
    assert!(
        r.iter()
            .all(|c| !c.description.contains("emergency contact")),
        "a placeholder 'self' contact must be filtered out"
    );
}

#[test]
fn au090_jurisdiction_two_sources_agree_is_high() {
    let mut e = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    e.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("state", "QLD"));
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("address_state", "Queensland"));
    let r = super::rules::rule_au_090_au_jurisdiction(&[e], "s", 0);
    assert_eq!(r.len(), 1, "QLD and Queensland resolve to one jurisdiction");
    assert_eq!(r[0].rule_id, "AU-090");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("QLD"));
    assert!(r[0].description.contains("2 breach record source"));
}

#[test]
fn au090_single_source_is_medium() {
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("licence_state", "VIC"));
    let r = super::rules::rule_au_090_au_jurisdiction(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("VIC"));
}

#[test]
fn au090_conflicting_states_each_surface_with_move_note() {
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "NSW"));
    e.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("licence_state", "VIC"));
    let r = super::rules::rule_au_090_au_jurisdiction(&[e], "s", 0);
    assert_eq!(r.len(), 2, "each distinct state surfaces independently");
    assert!(r.iter().all(|c| c.rule_id == "AU-090"));
    assert!(r.iter().any(|c| c.description.contains("NSW")));
    assert!(r.iter().any(|c| c.description.contains("VIC")));
    assert!(
        r.iter().all(|c| c.description.contains("interstate move")),
        "multiple state claims must carry the move/namesake note"
    );
}

#[test]
fn au090_non_au_or_missing_state_yields_nothing() {
    let mut e = Entity::new(EntityKind::Person, "John Doe", 0.9, "s");
    // A US state and a status-style value — neither resolves to an AU jurisdiction.
    e.add_evidence(Evidence::new("dehashed", "breach").with_attr("state", "California"));
    e.add_evidence(Evidence::new("dehashed", "breach").with_attr("state", "active"));
    assert!(super::rules::rule_au_090_au_jurisdiction(&[e], "s", 0).is_empty());
}

#[test]
fn au091_postcode_resolves_to_state_and_offline_coord() {
    let mut e = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    e.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "4000"));
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("post_code", "4000"));
    let r = super::rules::rule_au_091_au_postcode_locality(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-091");
    assert_eq!(r[0].severity, super::Severity::High); // two independent sources
    assert!(r[0].description.contains("4000"));
    assert!(
        r[0].description.contains("QLD"),
        "4000 is a Brisbane (QLD) postcode"
    );
    assert!(
        r[0].description.contains("offline"),
        "an offline coordinate is attached"
    );
}

#[test]
fn au091_single_source_is_medium_and_handles_leading_zero() {
    // NT postcode 0800 (Darwin) — 4-digit with a leading zero must still resolve.
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("postal_code", "0800"));
    let r = super::rules::rule_au_091_au_postcode_locality(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("0800"));
    assert!(r[0].description.contains("NT"));
}

#[test]
fn au091_two_postcodes_surface_separately_with_note() {
    let mut e = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    e.add_evidence(Evidence::new("see_know", "breach").with_attr("postcode", "4000")); // QLD
    e.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "3000")); // VIC
    let r = super::rules::rule_au_091_au_postcode_locality(&[e], "s", 0);
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|c| c.rule_id == "AU-091"));
    assert!(
        r.iter()
            .any(|c| c.description.contains("4000") && c.description.contains("QLD"))
    );
    assert!(
        r.iter()
            .any(|c| c.description.contains("3000") && c.description.contains("VIC"))
    );
    assert!(r.iter().all(|c| c.description.contains("second residence")));
}

#[test]
fn au091_non_au_and_noise_yield_nothing() {
    let mut e = Entity::new(EntityKind::Person, "John Doe", 0.9, "s");
    // A US 5-digit zip in a postal_code field, and a non-postcode 4-digit (year).
    e.add_evidence(Evidence::new("dehashed", "breach").with_attr("postal_code", "90210"));
    e.add_evidence(Evidence::new("dehashed", "breach").with_attr("postcode", "0001")); // unassigned
    assert!(super::rules::rule_au_091_au_postcode_locality(&[e], "s", 0).is_empty());
}

#[test]
fn au092_breach_state_agrees_with_geocoded_footprint() {
    // Breach says QLD; an independent Brisbane coordinate also resolves to QLD.
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("state", "QLD"));
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s"); // Brisbane
    coord.add_evidence(Evidence::new("geocode", "geocoded subject fix")); // person-anchored, not infra
    let r = super::rules::rule_au_092_breach_locality_footprint_crosscheck(&[p, coord], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-092");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].rule_name.contains("corroborated"));
    assert!(r[0].description.contains("QLD"));
}

#[test]
fn au092_breach_postcode_conflicts_with_footprint() {
    // Breach postcode 3000 (VIC) vs a Brisbane (QLD) coordinate → conflict.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("see_know", "breach").with_attr("postcode", "3000"));
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s");
    coord.add_evidence(Evidence::new("geocode", "geocoded subject fix")); // person-anchored, not infra
    let r = super::rules::rule_au_092_breach_locality_footprint_crosscheck(&[p, coord], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].rule_name.contains("conflict"));
    assert!(r[0].description.contains("VIC") && r[0].description.contains("QLD"));
}

#[test]
fn au092_agrees_with_address_entity_footprint() {
    // Footprint can also come from a confident Address entity, not just a coord.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "New South Wales"));
    let addr = Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.7, "s");
    let r = super::rules::rule_au_092_breach_locality_footprint_crosscheck(&[p, addr], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].rule_name.contains("corroborated"));
    assert!(r[0].description.contains("NSW"));
}

#[test]
fn au092_requires_both_sides() {
    // Only a breach field, no footprint → nothing.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "QLD"));
    assert!(
        super::rules::rule_au_092_breach_locality_footprint_crosscheck(&[p.clone()], "s", 0)
            .is_empty()
    );
    // Only a footprint, no breach field → nothing.
    let coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s");
    assert!(
        super::rules::rule_au_092_breach_locality_footprint_crosscheck(&[coord], "s", 0).is_empty()
    );
}

#[test]
fn au093_full_street_address_is_high_and_geocoded() {
    // Street + suburb + state + postcode in ONE record → dwelling-grade address.
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(
        Evidence::new("oathnet_pro", "breach")
            .with_attr("street", "12 Smith St")
            .with_attr("suburb", "Maleny")
            .with_attr("state", "QLD")
            .with_attr("postcode", "4552"),
    );
    let r = super::rules::rule_au_093_au_address_from_breach(&[p], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-093");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].rule_name.contains("residential address"));
    assert!(r[0].description.contains("12 Smith St"));
    assert!(r[0].description.contains("Maleny"));
    assert!(r[0].description.contains("QLD 4552"));
    assert!(
        r[0].description.contains("offline"),
        "postcode 4552 geocodes offline"
    );
}

#[test]
fn au093_suburb_only_is_medium_with_postcode_derived_state() {
    // No street; suburb + postcode (state derived from the postcode).
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("city", "Brisbane")
            .with_attr("postcode", "4000"),
    );
    let r = super::rules::rule_au_093_au_address_from_breach(&[p], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].rule_name.contains("suburb"));
    assert!(r[0].description.contains("Brisbane"));
    assert!(r[0].description.contains("QLD 4000"));
}

#[test]
fn au093_requires_suburb_plus_state_or_postcode() {
    // A suburb with no state/postcode anywhere in the record → nothing (that is
    // AU-090/091 territory, not an assembled locality).
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("see_know", "breach").with_attr("suburb", "Maleny"));
    assert!(super::rules::rule_au_093_au_address_from_breach(&[p], "s", 0).is_empty());
    // A state with no suburb → nothing (AU-090 already covers a bare state).
    let mut q = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    q.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "QLD"));
    assert!(super::rules::rule_au_093_au_address_from_breach(&[q], "s", 0).is_empty());
}

#[test]
fn au093_dedups_same_address_across_sources() {
    // Two sources naming the same dwelling collapse to one finding (2 sources).
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(
        Evidence::new("oathnet_pro", "breach")
            .with_attr("street", "12 Smith St")
            .with_attr("suburb", "Maleny")
            .with_attr("state", "QLD")
            .with_attr("postcode", "4552"),
    );
    p.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("street", "12 Smith St")
            .with_attr("suburb", "Maleny")
            .with_attr("state", "QLD")
            .with_attr("postcode", "4552"),
    );
    let r = super::rules::rule_au_093_au_address_from_breach(&[p], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 breach record source"));
}

#[test]
fn au098_three_classes_agree_is_high_consensus() {
    // Brisbane coordinate (QLD) + a QLD address + a breach state=QLD → 3 classes.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored, not infra
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let mut person = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    person.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "Queensland"));
    let r = super::rules::rule_au_098_residency_consensus(&[coord, addr, person], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-098");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("QLD"));
    assert!(r[0].description.contains("3 of 3"));
    assert!(r[0].description.contains("no dissenting signal"));
    // The Brisbane coordinate sharpens the state verdict to a locality.
    assert!(
        r[0].description.contains("near Brisbane"),
        "consensus sharpened to locality: {}",
        r[0].description
    );
}

#[test]
fn au098_two_classes_medium_and_surfaces_dissent() {
    // A QLD coordinate + a QLD phone (07) agree; a lone VIC address dissents.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored, not infra
    let phone = Entity::new(EntityKind::Phone, "+61731234567", 0.7, "s"); // 07 → QLD
    let addr = Entity::new(EntityKind::Address, "Melbourne VIC 3000", 0.7, "s");
    let r = super::rules::rule_au_098_residency_consensus(&[coord, phone, addr], "s", 0);
    assert_eq!(r.len(), 1);
    // QLD is supported by 2 classes (coordinate + phone) → Medium; the lone VIC
    // address is the dissenting minority.
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("2 of 3"));
    assert!(r[0].description.contains("QLD"));
    assert!(r[0].description.contains("dissenting minority: VIC"));
}

#[test]
fn au098_single_class_does_not_fire() {
    // Only a coordinate — one class — is the single-signal rules' job, not AU-098.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored: a real 1-class case
    assert!(super::rules::rule_au_098_residency_consensus(&[coord], "s", 0).is_empty());
}

#[test]
fn au098_appends_australian_isp_network_corroboration() {
    // Coordinate + address agree on QLD (2 classes); an IP on Telstra adds a
    // domestic-connection corroboration to the verdict.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored, not infra
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "s");
    ip.add_evidence(Evidence::new("ip_geo", "geo").with_attr("isp", "Telstra"));
    let r = super::rules::rule_au_098_residency_consensus(&[coord, addr, ip], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("QLD"));
    assert!(
        r[0].description.contains("Australian ISP (Telstra)"),
        "network corroboration appended: {}",
        r[0].description
    );
}

#[test]
fn au101_five_identity_facets_is_high_resolution() {
    // Name + email + phone + username + address → 5 distinct facet classes.
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "h@example.com", 0.8, "s");
    let phone = Entity::new(EntityKind::Phone, "+61731234567", 0.8, "s");
    let user = Entity::new(EntityKind::Username, "haigenb", 0.8, "s");
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let r =
        super::rules::rule_au_101_identity_resolution(&[person, email, phone, user, addr], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-101");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("5 independent identity facets"));
    assert!(r[0].description.contains("legal name"));
    assert!(r[0].description.contains("physical address"));
}

#[test]
fn au101_four_facets_is_medium_resolution() {
    // Exactly four facet classes → Medium (n == 4).
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "h@example.com", 0.8, "s");
    let phone = Entity::new(EntityKind::Phone, "+61731234567", 0.8, "s");
    let user = Entity::new(EntityKind::Username, "haigenb", 0.8, "s");
    let r = super::rules::rule_au_101_identity_resolution(&[person, email, phone, user], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("4 independent identity facets"));
}

#[test]
fn au101_counts_phone_and_email_facets_from_breach_evidence_attributes() {
    // A breach record carries the subject's phone + DOB as evidence ATTRIBUTES (no
    // standalone Phone entity). With the legal name and a physical address that is
    // four resolved facets — but the phone facet only counts via the new
    // evidence-attribute path; without it the footprint stays at 3 and is silent.
    let mut person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    person.add_evidence(
        Evidence::new("oathnet", "breach")
            .with_attr("phone", "+61 7 3123 4567")
            .with_attr("date_of_birth", "1990-01-01"),
    );
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let r = super::rules::rule_au_101_identity_resolution(&[person, addr.clone()], "s", 0);
    assert_eq!(
        r.len(),
        1,
        "name + address + DOB-attr + phone-attr = 4 facets must fire"
    );
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("phone"));

    // Control: WITHOUT the phone attribute only 3 facets (name, address, DOB) →
    // below the n>=4 floor → silent, proving the phone facet is what tips it over.
    let mut person_no_phone = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    person_no_phone
        .add_evidence(Evidence::new("oathnet", "breach").with_attr("date_of_birth", "1990-01-01"));
    assert!(
        super::rules::rule_au_101_identity_resolution(&[person_no_phone, addr], "s", 0).is_empty(),
        "without the phone facet the footprint is only 3 facets"
    );
}

#[test]
fn au101_thin_footprint_and_low_confidence_do_not_fire() {
    // Three facets is below the threshold — the single-facet rules' job.
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "h@example.com", 0.8, "s");
    let phone = Entity::new(EntityKind::Phone, "+61731234567", 0.8, "s");
    // A low-confidence Person and Address are not counted as resolved facets, so
    // adding them does not push a 3-facet footprint over the line.
    let weak_name = Entity::new(EntityKind::Person, "J Bloggs", 0.30, "s");
    let weak_addr = Entity::new(EntityKind::Address, "somewhere", 0.30, "s");
    assert!(
        super::rules::rule_au_101_identity_resolution(
            &[person, email, phone, weak_name, weak_addr],
            "s",
            0
        )
        .is_empty()
    );
}

#[test]
fn au101_breach_dob_and_gov_id_count_as_facets() {
    // Name + email are two entity facets; a breach DOB field and a checksum-valid
    // TFN add the "date of birth" and "government ID" facets → 4 classes, Medium.
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let mut email = Entity::new(EntityKind::Email, "h@example.com", 0.8, "s");
    email.add_evidence(
        Evidence::new("oathnet_pro", "breach")
            .with_attr("date_of_birth", "1990-04-12")
            .with_attr("tfn", "123456782"), // checksum-valid TFN
    );
    let r = super::rules::rule_au_101_identity_resolution(&[person, email], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("date of birth"));
    assert!(r[0].description.contains("government ID"));
}

// ─── AU-104 tests (Australian bank account / institution exposure) ────────────

#[test]
fn au104_resolves_bsb_to_institution_medium() {
    // A CBA BSB in a breach record, no account number → Medium attribution.
    let mut person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    person.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("bsb", "062-000"));
    let r = super::rules::rule_au_104_bank_account_exposure(&[person], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-104");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("Commonwealth Bank"));
    assert!(r[0].description.contains("BSB only"));
}

#[test]
fn au104_escalates_to_high_when_account_number_co_occurs() {
    // BSB + account number = a full, directly-abusable account credential → High.
    let mut person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    person.add_evidence(
        Evidence::new("stealer_log", "stealer")
            .with_attr("bank_state_branch", "012003") // ANZ
            .with_attr("account_number", "123456789"),
    );
    let r = super::rules::rule_au_104_bank_account_exposure(&[person], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("ANZ"));
    assert!(r[0].description.contains("account number"));
}

#[test]
fn au104_silent_for_unresolvable_or_absent_bsb() {
    // An unallocated BSB resolves to no bank → no (potentially wrong) finding.
    let mut p1 = Entity::new(EntityKind::Person, "X", 0.9, "s");
    p1.add_evidence(Evidence::new("src", "breach").with_attr("bsb", "999-999"));
    assert!(super::rules::rule_au_104_bank_account_exposure(&[p1], "s", 0).is_empty());
    // No BSB field at all → nothing fires.
    let p2 = Entity::new(EntityKind::Person, "Y", 0.9, "s");
    assert!(super::rules::rule_au_104_bank_account_exposure(&[p2], "s", 0).is_empty());
}

#[test]
fn au105_flags_plaintext_password_reused_across_breaches() {
    // The same plaintext password across three distinct breaches → High, and the
    // finding NEVER echoes the secret.
    let mut email = Entity::new(EntityKind::Email, "j@x.com", 0.9, "s");
    for db in ["pemiblanc.com", "gamigo.com", "2844databases"] {
        email.add_evidence(
            Evidence::new("see_know", "breach")
                .with_attr("dbname", db)
                .with_attr("password", "mnimp316895007"),
        );
    }
    let r = super::rules::rule_au_105_credential_reuse(&[email], "s", 0);
    assert_eq!(r.len(), 1, "one reuse finding");
    assert_eq!(r[0].rule_id, "AU-105");
    assert_eq!(r[0].severity, Severity::High, "plaintext reuse is High");
    assert!(r[0].description.contains("3 distinct breaches"));
    assert!(
        !r[0].description.contains("mnimp316895007"),
        "the secret value must never be echoed"
    );
}

#[test]
fn au105_reads_the_see_know_source_db_breach_name() {
    // SeekNow (`see_know`) records carry the breach DB name in a raw `source`
    // field, which the extractor renames to `source_db` (so it can't clobber the
    // provenance `source` attr). Before the fix, `breach_of` read only `dbname`/
    // `breach`, so every SeekNow breach collapsed to the bare module name
    // "see_know": a genuine cross-breach password reuse counted as ONE breach and
    // AU-105 stayed silent. Reading `source_db` recovers the two distinct breaches.
    let mut email = Entity::new(EntityKind::Email, "j@x.com", 0.9, "s");
    for db in ["linkedin.com", "adobe.com"] {
        email.add_evidence(
            Evidence::new("see_know", "SeekNow record")
                .with_attr("source_db", db)
                .with_attr("password", "reused-pw-9931"),
        );
    }
    let r = super::rules::rule_au_105_credential_reuse(&[email], "s", 0);
    assert_eq!(r.len(), 1, "cross-breach reuse via source_db must fire");
    assert_eq!(r[0].rule_id, "AU-105");
    assert_eq!(r[0].severity, Severity::High, "plaintext reuse is High");
    assert!(r[0].description.contains("2 distinct breaches"));
    assert!(
        r[0].description.contains("linkedin.com") && r[0].description.contains("adobe.com"),
        "both recovered breach names must appear: {}",
        r[0].description
    );
}

#[test]
fn au105_groups_a_hash_case_insensitively_across_sources() {
    // The same hash dumped UPPER-case by one source and lower-case by another is
    // ONE reused secret (Medium) — case must not split it.
    let mut a = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
    a.add_evidence(
        Evidence::new("snusbase", "breach")
            .with_attr("dbname", "teg.com.au")
            .with_attr("password_hash", "00346D91DD87"),
    );
    let mut b = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
    b.add_evidence(
        Evidence::new("oathnet", "breach")
            .with_attr("dbname", "ticketek.com.au")
            .with_attr("password_hash", "00346d91dd87"),
    );
    let r = super::rules::rule_au_105_credential_reuse(&[a, b], "s", 0);
    assert_eq!(r.len(), 1, "case variants of one hash = one reuse");
    assert_eq!(r[0].severity, Severity::Medium, "hash reuse is Medium");
}

#[test]
fn au105_does_not_link_on_a_common_password_hash_collision() {
    // A hash whose plaintext is a COMMON password (here md5("password")) recurs
    // for countless unrelated people, so sharing it across breaches is a
    // collision, NOT a reuse link — AU-105 must not fire. A genuinely unique hash
    // of the same length still does, proving the gate keys on the collision, not
    // the shape.
    let common = "5f4dcc3b5aa765d61d8327deb882cf99"; // md5("password")
    let uniq = "00112233445566778899aabbccddeeff"; // not a common-password digest
    let mk = |db: &str, hash: &str| {
        let mut e = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
        e.add_evidence(
            Evidence::new("breach", "rec")
                .with_attr("dbname", db)
                .with_attr("password_hash", hash),
        );
        e
    };
    assert!(
        super::rules::rule_au_105_credential_reuse(&[mk("db1", common), mk("db2", common)], "s", 0)
            .is_empty(),
        "a common-password hash is a collision, not a reuse link"
    );
    let r = super::rules::rule_au_105_credential_reuse(&[mk("db1", uniq), mk("db2", uniq)], "s", 0);
    assert_eq!(r.len(), 1, "a unique hash IS a real reuse link");
}

#[test]
fn au105_bridges_a_plaintext_to_the_same_password_leaked_as_a_hash() {
    // The synergy: account A leaked the PLAINTEXT in one breach; account B leaked a
    // HASH of the SAME (uncommon) password in another. Recomputing the plaintext's
    // digests offline bridges them into ONE reuse finding spanning both breaches —
    // High, because the plaintext is known. No brute force, no network query.
    let pw = "Tr0ub4dor&3xY-uncommon";
    let digs = crate::util::hashcat::digests_of(pw);
    let mut a = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
    a.add_evidence(
        Evidence::new("b", "rec")
            .with_attr("dbname", "breach1")
            .with_attr("password", pw),
    );
    let mut b = Entity::new(EntityKind::Username, "alias", 0.9, "s");
    b.add_evidence(
        Evidence::new("b", "rec")
            .with_attr("dbname", "breach2")
            .with_attr("password_hash", digs[1].as_str()), // sha1(pw)
    );
    let r = super::rules::rule_au_105_credential_reuse(&[a, b], "s", 0);
    assert_eq!(
        r.len(),
        1,
        "plaintext + its hash across two breaches = one reuse"
    );
    assert_eq!(
        r[0].severity,
        Severity::High,
        "the plaintext is known → High"
    );
}

#[test]
fn au105_silent_for_a_single_use_secret() {
    // A password seen in only ONE breach is not reuse → no finding.
    let mut e = Entity::new(EntityKind::Email, "s@x.com", 0.9, "s");
    e.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("dbname", "onlyone.com")
            .with_attr("password", "uniquepass1"),
    );
    assert!(super::rules::rule_au_105_credential_reuse(&[e], "s", 0).is_empty());
}

#[test]
fn au106_links_accounts_sharing_a_unique_device_fingerprint() {
    // A stealer/breach device fingerprint (hwid) carried against two DISTINCT
    // accounts means both were used on the same physical machine — one controller.
    let mut dev = Entity::new(EntityKind::DeviceId, "HWID-7f3a9c2e1b8d4056", 0.55, "scan");
    dev.tag("stealer");
    dev.add_evidence(Evidence::new("oathnet", "rec1").with_attr("username", "ghost_91"));
    dev.add_evidence(Evidence::new("oathnet", "rec2").with_attr("username", "nightcrawler"));
    let u1 = Entity::new(EntityKind::Username, "ghost_91", 0.6, "scan");
    let u2 = Entity::new(EntityKind::Username, "nightcrawler", 0.6, "scan");
    let hits = super::rules::rule_au_106_shared_device_identity(
        &[dev.clone(), u1.clone(), u2.clone()],
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a shared device fingerprint across 2 distinct accounts must link them"
    );
    assert_eq!(hits[0].rule_id, "AU-106");
    assert_eq!(hits[0].severity, Severity::High);
    assert!(hits[0].entity_uids.contains(&dev.uid));
    assert!(hits[0].entity_uids.contains(&u1.uid) && hits[0].entity_uids.contains(&u2.uid));

    // SAFETY: a short/generic hostname (`USER-PC`) is not a hardware fingerprint
    // and must NOT link people, even across two distinct accounts.
    let mut generic = Entity::new(EntityKind::DeviceId, "USER-PC", 0.55, "scan");
    generic.add_evidence(Evidence::new("oathnet", "r").with_attr("username", "ghost_91"));
    generic.add_evidence(Evidence::new("oathnet", "r").with_attr("username", "nightcrawler"));
    assert!(
        super::rules::rule_au_106_shared_device_identity(&[generic], "scan", 0).is_empty(),
        "a short/generic hostname must not link people"
    );

    // SAFETY: an email and its MATCHING username from ONE record are one account
    // (the canonical-handle fold), so a single device record cannot self-fire.
    let mut one = Entity::new(EntityKind::DeviceId, "HWID-aaaa1111bbbb2222", 0.55, "scan");
    one.add_evidence(
        Evidence::new("oathnet", "r")
            .with_attr("email", "alice@example.com")
            .with_attr("username", "alice"),
    );
    assert!(
        super::rules::rule_au_106_shared_device_identity(&[one], "scan", 0).is_empty(),
        "one account described two ways from one record is not a link"
    );
}

#[test]
fn au106_discloses_when_the_identifier_list_is_truncated() {
    // Same "(+N more)" disclosure convention as AU-047/AU-048/AU-076 — a device
    // genuinely shared across MANY accounts must say so, not silently cut the
    // enumerated list at 6 with no indication.
    let mut dev = Entity::new(
        EntityKind::DeviceId,
        "HWID-widelysharedmachine01",
        0.55,
        "scan",
    );
    dev.tag("stealer");
    for i in 0..9 {
        dev.add_evidence(
            Evidence::new("oathnet", format!("rec{i}"))
                .with_attr("username", format!("user_account_{i}")),
        );
    }
    let hits = super::rules::rule_au_106_shared_device_identity(&[dev], "scan", 0);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0]
            .description
            .contains("9 otherwise-separate accounts"),
        "the true total must still be stated: {}",
        hits[0].description
    );
    assert!(
        hits[0].description.contains("(+3 more)"),
        "the enumerated (top-6) identifier list must disclose the 3 it omitted: {}",
        hits[0].description
    );
}

#[test]
fn au106_links_accounts_sharing_a_breach_router_bssid_or_imei() {
    // A stealer-logged router BSSID (a `device`-tagged MacAddress) shared across
    // two DISTINCT accounts is the same single-device co-location proof as a hwid.
    let mut mac = Entity::new(EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff", 0.60, "scan");
    mac.tag("device");
    mac.add_evidence(Evidence::new("oathnet", "r1").with_attr("username", "ghost_91"));
    mac.add_evidence(Evidence::new("oathnet", "r2").with_attr("username", "nightcrawler"));
    let u1 = Entity::new(EntityKind::Username, "ghost_91", 0.6, "scan");
    let u2 = Entity::new(EntityKind::Username, "nightcrawler", 0.6, "scan");
    let hits = super::rules::rule_au_106_shared_device_identity(
        &[mac.clone(), u1.clone(), u2.clone()],
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a shared BSSID across 2 accounts must link them"
    );
    assert_eq!(hits[0].rule_id, "AU-106");
    assert!(hits[0].entity_uids.contains(&mac.uid));

    // SAFETY: a LAN/Wi-Fi MAC surfaced by local_net/wifi_intel is NOT tagged
    // `device`, so the same address with the same accounts must not link people.
    let mut lan = Entity::new(EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff", 0.60, "scan");
    lan.tag(crate::core::tags::WIFI_AP);
    lan.add_evidence(Evidence::new("wifi_intel", "r1").with_attr("username", "ghost_91"));
    lan.add_evidence(Evidence::new("wifi_intel", "r2").with_attr("username", "nightcrawler"));
    assert!(
        super::rules::rule_au_106_shared_device_identity(&[lan], "scan", 0).is_empty(),
        "a non-`device` Wi-Fi MAC must never link identities"
    );

    // A shared 15-digit IMEI (typed DeviceId) across two accounts also fires.
    let mut imei = Entity::new(EntityKind::DeviceId, "359881234567890", 0.55, "scan");
    imei.tag("device");
    imei.add_evidence(Evidence::new("see-know", "r1").with_attr("username", "ghost_91"));
    imei.add_evidence(Evidence::new("see-know", "r2").with_attr("username", "nightcrawler"));
    assert!(
        !super::rules::rule_au_106_shared_device_identity(&[imei, u1, u2], "scan", 0).is_empty(),
        "a shared IMEI across 2 accounts must link them"
    );
}

#[test]
fn au107_names_the_breach_stated_employer() {
    // A breach-tagged Organisation (0.50) — the employer field of a breach record —
    // is named as the subject's affiliation; one source is Medium.
    let mut org = Entity::new(EntityKind::Organisation, "Globex Pty Ltd", 0.50, "scan");
    org.tag("breach");
    org.add_evidence(Evidence::new("oathnet", "breach record"));
    let r = super::rules::rule_au_107_breach_employer_affiliation(&[org], "scan", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-107");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("Globex Pty Ltd"));

    // Two INDEPENDENT breach sources naming the same employer → High.
    let mut org2 = Entity::new(EntityKind::Organisation, "Globex Pty Ltd", 0.50, "scan");
    org2.tag("breach");
    org2.add_evidence(Evidence::new("oathnet", "rec"));
    org2.add_evidence(Evidence::new("dehashed", "rec"));
    let r2 = super::rules::rule_au_107_breach_employer_affiliation(&[org2], "scan", 0);
    assert_eq!(r2[0].severity, super::Severity::High);

    // A registry Organisation (no `breach` tag) does NOT fire AU-107.
    let mut reg = Entity::new(EntityKind::Organisation, "Acme Ltd", 0.65, "scan");
    reg.tag("abr");
    assert!(
        super::rules::rule_au_107_breach_employer_affiliation(&[reg], "scan", 0).is_empty(),
        "a registry org is not a breach-stated employer"
    );
}

#[test]
fn au108_reports_breach_cross_platform_footprint() {
    let mk = |val: &str| {
        let mut e = Entity::new(EntityKind::Username, val, 0.55, "scan");
        e.tag("breach");
        e
    };
    let r = super::rules::rule_au_108_breach_social_footprint(
        &[mk("twitter:alice"), mk("telegram:alice_b")],
        "scan",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-108");
    assert!(r[0].description.contains("twitter") && r[0].description.contains("telegram"));

    // A single platform never fires.
    assert!(
        super::rules::rule_au_108_breach_social_footprint(&[mk("twitter:alice")], "scan", 0)
            .is_empty(),
        "one platform is not a cross-platform footprint"
    );
    // Two handles on the SAME platform don't inflate to a footprint.
    assert!(
        super::rules::rule_au_108_breach_social_footprint(
            &[mk("twitter:alice"), mk("twitter:bob")],
            "scan",
            0
        )
        .is_empty(),
        "two handles on one platform are still one platform"
    );
    // A non-allow-list prefix (an epieos `google:<id>`) is ignored, so it can't
    // combine with a single real platform to reach the ≥2 gate.
    assert!(
        super::rules::rule_au_108_breach_social_footprint(
            &[mk("google:123456"), mk("twitter:alice")],
            "scan",
            0
        )
        .is_empty(),
        "a non-social prefix must not count toward the footprint"
    );
}

// ─── best_au_location_estimate (single-signal headline geolocation) ──────────

#[test]
fn best_location_uses_a_single_confirmed_coordinate() {
    use super::best_au_location_estimate;
    // One person-anchored AU coordinate (geocode source makes it person-anchored).
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.7, "s");
    coord.add_evidence(Evidence::new("geocode", "Brisbane fix"));
    let est = best_au_location_estimate(&[coord]).expect("a single AU coord yields a fix");
    assert_eq!(est.basis, "confirmed coordinate");
    assert_eq!(est.state, "QLD");
    assert_eq!(est.locality.as_deref(), Some("Brisbane"));
    assert!(est.radius_km <= 2.0);
}

#[test]
fn best_location_falls_back_to_name_matched_address_postcode() {
    use super::best_au_location_estimate;
    let mut addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    addr.tag("exact-name-match");
    let est = best_au_location_estimate(&[addr]).expect("postcode 4000 resolves");
    assert_eq!(est.basis, "name-matched address (postcode grain)");
    assert_eq!(est.state, "QLD");
    assert!((est.radius_km - 8.0).abs() < 1e-9, "postcode grain");
}

#[test]
fn best_location_uses_a_breach_postcode_when_nothing_finer() {
    use super::best_au_location_estimate;
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.6, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "4000"));
    let est = best_au_location_estimate(&[p]).expect("breach postcode resolves");
    assert_eq!(est.basis, "breach/register postcode");
    assert_eq!(est.state, "QLD");
}

#[test]
fn best_location_prefers_a_coordinate_over_an_address() {
    use super::best_au_location_estimate;
    // A Brisbane coordinate AND a Perth name-matched address: the finer coordinate
    // wins (precedence), so the headline is the coordinate, not the postcode.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.7, "s");
    coord.add_evidence(Evidence::new("geocode", "Brisbane fix"));
    let mut addr = Entity::new(EntityKind::Address, "Perth WA 6000", 0.7, "s");
    addr.tag("exact-name-match");
    let est = best_au_location_estimate(&[coord, addr]).unwrap();
    assert_eq!(est.basis, "confirmed coordinate");
    assert_eq!(est.state, "QLD");
}

#[test]
fn best_location_is_none_without_any_location_signal() {
    use super::best_au_location_estimate;
    let e = Entity::new(EntityKind::Email, "x@y.com", 0.8, "s");
    assert!(best_au_location_estimate(&[e]).is_none());
}

#[test]
fn best_location_does_not_misread_a_coordinate_value_as_a_postcode() {
    use super::best_au_location_estimate;
    // A coordinate from a non-anchoring source (so NOT person-anchored) whose
    // longitude digits ("…151.2093") contain a postcode-shaped token ("2093").
    // It must yield no fix — coordinates are excluded from the postcode rung, so
    // the digits of a lat/lon are never misread as a residential postcode.
    let coord = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.8, "s");
    assert!(best_au_location_estimate(&[coord]).is_none());
}

#[test]
fn best_location_uses_a_landline_area_code_region_when_nothing_finer() {
    use super::best_au_location_estimate;
    // A subject known only by a Queensland geographic landline (`07…`) — no
    // coordinate, address or postcode. The coarsest rung resolves the area code to
    // its ACMA region centroid (Brisbane), a region-grain fix.
    let phone = Entity::new(EntityKind::Phone, "+61 7 3739 4511", 0.7, "s");
    let est = best_au_location_estimate(&[phone]).expect("a QLD landline yields a region fix");
    assert_eq!(est.basis, "landline area-code region");
    assert_eq!(est.state, "QLD");
    assert!(
        est.radius_km >= 600.0,
        "a region fix carries an honestly large radius, got {}",
        est.radius_km
    );
    assert!(
        est.confidence > 0.0 && est.confidence <= 0.35,
        "region grain is a weak, capped fix, got {}",
        est.confidence
    );
}

#[test]
fn best_location_ignores_a_mobile_number_with_no_region() {
    use super::best_au_location_estimate;
    // A mobile (`04…`) is fully portable and carries NO geographic area code, so it
    // must not yield a location fix — only geographic fixed lines do.
    let mobile = Entity::new(EntityKind::Phone, "+61 412 345 678", 0.8, "s");
    assert!(best_au_location_estimate(&[mobile]).is_none());
}

#[test]
fn best_location_prefers_any_finer_signal_over_a_landline_region() {
    use super::best_au_location_estimate;
    // A Brisbane coordinate AND a NSW (`02…`) landline: the coordinate (rung 2) must
    // win over the region rung, so a precise fix is never masked by a coarse one.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.7, "s");
    coord.add_evidence(Evidence::new("geocode", "Brisbane fix"));
    let phone = Entity::new(EntityKind::Phone, "+61 2 9876 5432", 0.9, "s");
    let est = best_au_location_estimate(&[coord, phone]).unwrap();
    assert_eq!(est.basis, "confirmed coordinate");
    assert_eq!(est.state, "QLD");
}

#[test]
fn best_location_excludes_a_platform_infra_tagged_landline() {
    use super::best_au_location_estimate;
    // A landline scraped from a third-party page (a business footer, say) is tagged
    // platform-infra — not subject-owned, so it must not anchor the subject.
    let mut phone = Entity::new(EntityKind::Phone, "+61 7 3739 4511", 0.7, "s");
    phone.tag("platform-infra");
    assert!(best_au_location_estimate(&[phone]).is_none());
}

#[test]
fn best_location_uses_a_breach_login_ip_city_when_nothing_finer() {
    use super::best_au_location_estimate;
    // A subject located only by their breach login IP (geolocation-lead → ip_geo
    // Brisbane) still gets a city-grain headline fix — the common breach-victim
    // case with no GPS, address or postcode.
    let mut ip = Entity::new(EntityKind::IpAddress, "1.132.97.84", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "1.132.97.84"));

    let est = best_au_location_estimate(&[ip, coord]).expect("a login-IP city fix");
    assert_eq!(est.basis, "breach login-IP city");
    assert_eq!(est.state, "QLD");
    assert!(est.confidence <= 0.50, "city/IP grain is capped low");
    assert!(est.radius_km <= 25.0 + 1e-9, "fixed-line city grain");
}

#[test]
fn best_location_prefers_a_postcode_over_a_breach_login_ip() {
    use super::best_au_location_estimate;
    // A name-matched postcode (suburb grain) outranks a coarser login-IP city.
    let mut addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    addr.tag("exact-name-match");
    let mut ip = Entity::new(EntityKind::IpAddress, "1.132.97.84", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "1.132.97.84"));

    let est = best_au_location_estimate(&[addr, ip, coord]).unwrap();
    assert_eq!(
        est.basis, "name-matched address (postcode grain)",
        "a postcode is finer than an IP city"
    );
}

#[test]
fn location_corroboration_counts_independent_classes() {
    use super::au_location_corroboration;
    // Two INDEPENDENT methods (electoral roll + unclaimed-money directory) place
    // the subject's circle at the same postcode — corroboration, not a lone guess.
    let mut a = Entity::new(EntityKind::Person, "A Person", 0.6, "s");
    a.add_evidence(Evidence::new("au_electoral", "roll").with_attr("postcode", "4000"));
    let mut b = Entity::new(EntityKind::Person, "B Person", 0.6, "s");
    b.add_evidence(Evidence::new("qld_unclaimed", "register").with_attr("postcode", "4000"));

    let c = au_location_corroboration(&[a, b]).expect("two AU postcode signals");
    assert_eq!(
        c.independent_classes, 2,
        "electoral + directory are independent"
    );
    assert_eq!(c.signal_count, 2);
    assert_eq!(c.state, "QLD");
    assert!(
        c.confidence > 0.65 && c.confidence < 0.75,
        "2 independent classes ≈ 0.70, got {}",
        c.confidence
    );
}

#[test]
fn location_corroboration_same_source_class_is_single_source() {
    use super::au_location_corroboration;
    // Two rows from the SAME breach source (one method) are NOT independent
    // corroboration, even at the same postcode — independence counts CLASSES.
    let mut a = Entity::new(EntityKind::Person, "A Person", 0.6, "s");
    a.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "4000"));
    let mut b = Entity::new(EntityKind::Person, "B Person", 0.6, "s");
    b.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("postcode", "4000"));

    let c = au_location_corroboration(&[a, b]).unwrap();
    assert_eq!(c.independent_classes, 1, "one breach source = one method");
    assert!(
        c.confidence < 0.5,
        "single-source stays low, got {}",
        c.confidence
    );
}

#[test]
fn location_corroboration_prefers_the_better_corroborated_locality() {
    use super::au_location_corroboration;
    // Two independent classes agree on Brisbane (4000); a lone Perth (6000) signal
    // ~3600 km away. The better-corroborated locality must win.
    let mut a = Entity::new(EntityKind::Person, "A Person", 0.6, "s");
    a.add_evidence(Evidence::new("au_electoral", "roll").with_attr("postcode", "4000"));
    let mut b = Entity::new(EntityKind::Person, "B Person", 0.6, "s");
    b.add_evidence(Evidence::new("qld_unclaimed", "register").with_attr("postcode", "4000"));
    let mut perth = Entity::new(EntityKind::Person, "C Person", 0.6, "s");
    perth.add_evidence(Evidence::new("au_people", "directory").with_attr("postcode", "6000"));

    let c = au_location_corroboration(&[a, b, perth]).unwrap();
    assert_eq!(
        c.state, "QLD",
        "the 2-class Brisbane cluster beats the lone Perth signal"
    );
    assert_eq!(c.independent_classes, 2);
}

#[test]
fn location_corroboration_none_without_any_au_signal() {
    use super::au_location_corroboration;
    let e = Entity::new(EntityKind::Email, "x@y.com", 0.8, "s");
    assert!(au_location_corroboration(&[e]).is_none());
}

#[test]
fn location_corroboration_admits_person_breach_login_ip() {
    use super::au_location_corroboration;
    // A breach login IP (tagged geolocation-lead) geolocated to Brisbane — the
    // person's own connection — is a coarse but real person-location signal.
    let mut ip = Entity::new(EntityKind::IpAddress, "1.132.97.84", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(
        Evidence::new("ip_geo", "IP geolocation for 1.132.97.84").with_attr("ip", "1.132.97.84"),
    );
    let c = au_location_corroboration(&[ip, coord]).expect("a person login-IP geo is a signal");
    assert_eq!(c.state, "QLD");
    assert!(c.class_names.contains(&"network-ip"));
}

#[test]
fn location_corroboration_breach_ip_corroborates_a_postcode() {
    use super::au_location_corroboration;
    // An electoral-roll postcode (Brisbane 4000) AND the person's breach login IP
    // (also Brisbane) are two INDEPENDENT methods converging on one locality.
    let mut person = Entity::new(EntityKind::Person, "A Person", 0.6, "s");
    person.add_evidence(Evidence::new("au_electoral", "roll").with_attr("postcode", "4000"));
    let mut ip = Entity::new(EntityKind::IpAddress, "1.132.97.84", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "1.132.97.84"));

    let c = au_location_corroboration(&[person, ip, coord]).unwrap();
    assert_eq!(c.independent_classes, 2, "electoral + network-ip");
    assert!(c.class_names.contains(&"electoral") && c.class_names.contains(&"network-ip"));
    assert!(c.confidence > 0.65);
}

#[test]
fn location_corroboration_rejects_a_datacenter_ip_geo() {
    use super::au_location_corroboration;
    // A hosting/datacenter IP geo is the server's location, never the person's —
    // it must not be admitted even when tagged a geolocation-lead.
    let mut ip = Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.6, "s");
    ip.tag("geolocation-lead");
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.tag("hosting");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "8.8.8.8"));
    assert!(
        au_location_corroboration(&[ip, coord]).is_none(),
        "a datacenter IP geo is not a person fix"
    );
}

#[test]
fn location_corroboration_ignores_ip_geo_without_a_login_lead() {
    use super::au_location_corroboration;
    // An ip_geo coordinate whose IP is NOT a person breach login lead (e.g. a
    // resolved infrastructure IP) is not a person-location signal.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4683,153.0322", 0.6, "s");
    coord.add_evidence(Evidence::new("ip_geo", "g").with_attr("ip", "203.0.113.7"));
    assert!(au_location_corroboration(&[coord]).is_none());
}

#[test]
fn au099_reverse_geocodes_coordinate_to_locality() {
    // A Brisbane fix → "Brisbane, QLD" with a small distance.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored, not infra
    let r = super::rules::rule_au_099_coordinate_reverse_geocode(&[coord], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-099");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("Brisbane"));
    assert!(r[0].description.contains("QLD"));
    assert!(r[0].description.contains("reverse geocode"));
}

#[test]
fn au099_ignores_foreign_and_weak_coordinates() {
    // A New York coordinate is not in Australia → no locality.
    let ny = Entity::new(EntityKind::Coordinates, "40.7128,-74.0060", 0.8, "s");
    // A weak (candidate) AU coordinate is below the 0.50 confidence gate.
    let weak = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.40, "s");
    assert!(super::rules::rule_au_099_coordinate_reverse_geocode(&[ny, weak], "s", 0).is_empty());
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
fn au045_046_reject_junk_and_role_handles_as_identity_anchors() {
    // Regression for a live person-scan: `from` (a bare function word) and `dns`
    // (a 3-char acronym) were mis-extracted as usernames and, "confirmed" across
    // two source families, fired AU-045 "confirmed identity". They are parser
    // artifacts, not aliases — the handle-quality gate must drop them.
    let junk = |val: &str| {
        let mut u = Entity::new(EntityKind::Username, val, 0.6, "scan");
        for s in ["github_user", "reddit_user"] {
            u.add_evidence(Evidence::new(s, "confirmed"));
        }
        u
    };
    // Covers both the length path (`dns`, `www` are < 4 chars) and the
    // non-identity-token path (`from`, `http` are 4 chars but never handles).
    for bad in ["from", "dns", "www", "http"] {
        assert!(
            super::rules::rule_au_045_multi_service_identity(&[junk(bad)], "scan", 0).is_empty(),
            "AU-045 must not promote junk handle '{bad}' to a confirmed identity"
        );
    }

    // A role mailbox confirmed across families is an org desk, not the subject.
    let mut role = Entity::new(EntityKind::Email, "abuse@acme.com", 0.7, "scan");
    for s in ["github_user", "hibp"] {
        role.add_evidence(Evidence::new(s, "found"));
    }
    assert!(
        super::rules::rule_au_045_multi_service_identity(&[role], "scan", 0).is_empty(),
        "AU-045 must not promote a role mailbox to a confirmed identity"
    );

    // Control: a distinctive handle across the SAME two families still fires —
    // the gate removes junk, not genuine cross-family confirmation.
    let mut good = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        good.add_evidence(Evidence::new(s, "confirmed"));
    }
    assert_eq!(
        super::rules::rule_au_045_multi_service_identity(&[good], "scan", 0).len(),
        1,
        "a distinctive handle across two families must still fire AU-045"
    );

    // AU-046: the same junk handle must not be selected as a resolvable alias.
    let mut email = Entity::new(EntityKind::Email, "k@example.com", 0.7, "scan");
    email.add_evidence(Evidence::new("github_user", "maintainer email"));
    let mut junk_alias = Entity::new(EntityKind::Username, "from", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        junk_alias.add_evidence(Evidence::new(s, "confirmed account"));
    }
    assert!(
        super::rules::rule_au_046_cross_platform_identity_resolution(
            &[junk_alias, email.clone()],
            "scan",
            0,
        )
        .is_empty(),
        "AU-046 must not resolve a junk handle to identifiers"
    );

    // Control: a distinctive alias across two platform families still resolves.
    let mut real_alias = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        real_alias.add_evidence(Evidence::new(s, "confirmed account"));
    }
    let hits = super::rules::rule_au_046_cross_platform_identity_resolution(
        &[real_alias, email],
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a distinctive alias must still resolve via AU-046"
    );
    assert_eq!(hits[0].rule_id, "AU-046");
}

#[test]
fn au046_resolves_only_the_alias_own_account_identifiers() {
    // AU-046 used to fuse EVERY platform-sourced Email/Person in the whole scan
    // into every alias, even a stranger from a different platform account or a
    // role mailbox. It must resolve only identifiers the alias's OWN account(s)
    // published — those sharing a concrete corroborating source with the alias.
    let mut alias = Entity::new(EntityKind::Username, "kylo4kylo", 0.6, "scan");
    for s in ["github_user", "reddit_user"] {
        alias.add_evidence(Evidence::new(s, "confirmed account"));
    }
    // The alias's OWN github account published this email → shares github_user.
    let mut own = Entity::new(EntityKind::Email, "kylo@real.example", 0.7, "scan");
    own.add_evidence(Evidence::new("github_user", "profile email"));
    // A co-author's email from a DIFFERENT platform account the alias does not
    // share (gitlab, code family) → must NOT be fused into the alias's identity.
    let mut stranger = Entity::new(EntityKind::Email, "coauthor@other.example", 0.7, "scan");
    stranger.add_evidence(Evidence::new("gitlab_user", "co-maintainer email"));
    // A role mailbox published even by the alias's own account is a support/registrar
    // desk, never the person's real-world identifier.
    let mut role = Entity::new(EntityKind::Email, "noreply@github.com", 0.7, "scan");
    role.add_evidence(Evidence::new("github_user", "profile email"));

    let hits = super::rules::rule_au_046_cross_platform_identity_resolution(
        &[alias.clone(), own.clone(), stranger.clone(), role.clone()],
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "the alias resolves via its own account");
    assert!(
        hits[0].entity_uids.contains(&own.uid),
        "the alias's own-account email must resolve"
    );
    assert!(
        !hits[0].entity_uids.contains(&stranger.uid),
        "a stranger from an unshared platform account must not be fused"
    );
    assert!(
        !hits[0].entity_uids.contains(&role.uid),
        "a role mailbox must not be treated as a real-world identifier"
    );
    assert!(
        hits[0].description.contains("1 real-world identifier"),
        "only the one own-account identifier is counted: {}",
        hits[0].description
    );
}

#[test]
fn au047_links_identities_by_a_reused_unique_secret_only() {
    // The account-linking rule, and its precision gate. A salted hash carried against
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
fn au047_discloses_when_the_identifier_list_is_truncated() {
    // The description enumerates at most 6 implicated identifiers, but a
    // secret genuinely reused across MANY accounts must say so — not silently
    // cut the list with no indication, the same "(+N more)" convention AU-048/
    // AU-076/AU-106 all share via join_capped.
    let emails: Vec<String> = (0..9).map(|i| format!("acct{i}@breach-corp.io")).collect();
    let email_refs: Vec<&str> = emails.iter().map(String::as_str).collect();
    let mut cred = Entity::new(
        EntityKind::Credential,
        "$2a$10$manyAccountsShareThisOneHashXYZ",
        0.6,
        "scan",
    );
    for em in &email_refs {
        cred.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("email", *em));
    }
    let hits = super::rules::rule_au_047_reused_secret_identity(&[cred], "scan", 0);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0]
            .description
            .contains("9 otherwise-separate accounts"),
        "the true total must still be stated: {}",
        hits[0].description
    );
    assert!(
        hits[0].description.contains("(+3 more)"),
        "the enumerated (top-6) identifier list must disclose the 3 it omitted: {}",
        hits[0].description
    );
}

#[test]
fn au047_links_on_reused_plaintext_password_and_session_token() {
    // Password reuse, session/cookie tokens and raw credentials are all valid
    // cross-correlation join-keys. AU-047 must link on a reused HIGH-ENTROPY
    // plaintext password (High — slight coincidence risk) and a reused
    // session/cookie token (Critical — random by construction), while still
    // refusing a common/weak password (no false identities).
    let cred = |value: &str, tags: &[&str], emails: &[&str]| {
        let mut c = Entity::new(EntityKind::Credential, value, 0.6, "scan");
        for t in tags {
            c.tag(*t);
        }
        for em in emails {
            c.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("email", *em));
        }
        c
    };
    let a = Entity::new(EntityKind::Email, "burner1@proton.me", 0.6, "scan");
    let b = Entity::new(EntityKind::Email, "real.name@gmail.com", 0.6, "scan");

    // Reused high-entropy plaintext password → High link.
    let pw = cred(
        "Tr0ub4dor&3xK9!q",
        &["plaintext-credential"],
        &[&a.value, &b.value],
    );
    let hits =
        super::rules::rule_au_047_reused_secret_identity(&[pw, a.clone(), b.clone()], "scan", 0);
    assert_eq!(hits.len(), 1, "reused strong password must link accounts");
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(hits[0].description.contains("password"));

    // Reused session/cookie token → Critical link.
    let tok = cred(
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        &["session-token"],
        &[&a.value, &b.value],
    );
    let hits =
        super::rules::rule_au_047_reused_secret_identity(&[tok, a.clone(), b.clone()], "scan", 0);
    assert_eq!(hits.len(), 1, "reused session token must link accounts");
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].description.contains("session/cookie token"));

    // PRECISION: a reused COMMON password must NOT link (millions share it).
    let weak = cred(
        "password123",
        &["plaintext-credential"],
        &[&a.value, &b.value],
    );
    assert!(
        super::rules::rule_au_047_reused_secret_identity(&[weak, a.clone(), b.clone()], "scan", 0)
            .is_empty(),
        "a common password must not manufacture an identity link"
    );

    // PRECISION: a bare hex digest WITHOUT session-token provenance stays
    // unlinkable (it may be an unsalted hash of a common password).
    let bare_hex = cred(
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        &[], // no session-token tag
        &[&a.value, &b.value],
    );
    assert!(
        super::rules::rule_au_047_reused_secret_identity(&[bare_hex, a, b], "scan", 0).is_empty(),
        "an untagged hex digest must not link (unsalted-hash collision risk)"
    );
}

#[test]
fn au047_links_on_password_entity_and_credits_unique_sources() {
    // The breach/stealer modules emit a leaked plaintext password as a
    // first-class `Password` entity (not the `username@host` `Credential`
    // string). AU-047 must link identities on a reused high-entropy `Password`
    // in its own right, and CREDIT cross-source spread: the same password seen
    // across ≥2 independent breach datasets is more individuating than one seen
    // inside a single dump, so it rises from High to Critical.
    let pw_entity = |sources: &[&str], emails: &[&str]| {
        let mut c = Entity::new(EntityKind::Password, "Tr0ub4dor&3xK9!q", 0.6, "scan");
        c.tag("credential");
        // One evidence record per (source, email): the importer stamps `source`
        // (See-Know) or `dbname` (OathNet) provenance onto each.
        for (i, em) in emails.iter().enumerate() {
            let src = sources.get(i).copied().unwrap_or("unknown");
            c.add_evidence(
                Evidence::new("see-know", "breach record")
                    .with_attr("email", *em)
                    .with_attr("source", src),
            );
        }
        c
    };
    let a = Entity::new(EntityKind::Email, "burner1@proton.me", 0.6, "scan");
    let b = Entity::new(EntityKind::Email, "real.name@gmail.com", 0.6, "scan");

    // Reused `Password` across 2 accounts but only ONE distinct source → High.
    let single_src = pw_entity(&["collection1", "collection1"], &[&a.value, &b.value]);
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &[single_src, a.clone(), b.clone()],
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1, "reused Password entity must link accounts");
    assert_eq!(
        hits[0].severity,
        super::Severity::High,
        "single-source reuse stays High"
    );

    // Same reused `Password` spread across TWO distinct sources → Critical, and
    // the description names the unique-source count.
    let cross_src = pw_entity(&["collection1", "antipublic"], &[&a.value, &b.value]);
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &[cross_src, a.clone(), b.clone()],
        "scan",
        0,
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].severity,
        super::Severity::Critical,
        "cross-source reuse (≥2 independent datasets) is a near-certain controller link"
    );
    assert!(
        hits[0].description.contains("2 sources"),
        "description must surface the unique-source count, got: {}",
        hits[0].description
    );

    // A reused `Password` whose value is a salted hash is labelled a hash and
    // stays Critical (construction-unique), never demoted to the plaintext tier.
    let mut hashed = Entity::new(
        EntityKind::Password,
        "$2b$12$abcdefghijklmnopqrstuv",
        0.6,
        "scan",
    );
    hashed.tag("password-hash");
    for em in [&a.value, &b.value] {
        hashed.add_evidence(Evidence::new("oathnet", "breach").with_attr("email", em));
    }
    let hits = super::rules::rule_au_047_reused_secret_identity(&[hashed, a, b], "scan", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].description.contains("password hash"));
}

#[test]
fn au047_links_username_keyed_accounts_and_resists_single_record_self_link() {
    // Potentiation: a breach footprint keyed by USERNAME (username + hash, no
    // email — a very common dump shape) must link its accounts on a shared unique
    // secret exactly as an email-keyed one does, so reverse-searching a handle is
    // not a dead end. Previously AU-047 counted only distinct EMAILS to fire, so a
    // unique hash shared across two usernames went unlinked despite the rule's own
    // documented intent to link on "email/username".
    let mut by_username = Entity::new(
        EntityKind::Password,
        "$2b$12$usernamekeyedreuse00",
        0.6,
        "scan",
    );
    by_username.tag("password-hash");
    // Two DISTINCT usernames (no email anywhere) carry the identical salted hash.
    for u in ["ghost_91", "nightcrawler"] {
        by_username.add_evidence(Evidence::new("oathnet", "breach").with_attr("username", u));
    }
    let u1 = Entity::new(EntityKind::Username, "ghost_91", 0.6, "scan");
    let u2 = Entity::new(EntityKind::Username, "nightcrawler", 0.6, "scan");
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &[by_username.clone(), u1.clone(), u2.clone()],
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a unique hash across 2 distinct usernames must link them (username-keyed reverse search)"
    );
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(
        hits[0].entity_uids.contains(&u1.uid) && hits[0].entity_uids.contains(&u2.uid),
        "both username identities must be linked into the controller cluster"
    );

    // SAME-RECORD SAFETY: one record carrying an email and its MATCHING username
    // is ONE account — the handles collapse to a single canonical handle, so no
    // phantom "2 accounts" link is manufactured from a single record.
    let mut one_account = Entity::new(
        EntityKind::Password,
        "$2b$12$oneaccounttwoids0000",
        0.6,
        "scan",
    );
    one_account.tag("password-hash");
    one_account.add_evidence(
        Evidence::new("oathnet", "breach")
            .with_attr("email", "alice@example.com")
            .with_attr("username", "alice"),
    );
    let em = Entity::new(EntityKind::Email, "alice@example.com", 0.6, "scan");
    let un = Entity::new(EntityKind::Username, "alice", 0.6, "scan");
    assert!(
        super::rules::rule_au_047_reused_secret_identity(&[one_account, em, un], "scan", 0)
            .is_empty(),
        "an email and its matching username from one record are one account, not a link"
    );

    // A unique hash shared across an email and a GENUINELY DIFFERENT username
    // (distinct handles) still links — the cross-representation reverse pivot.
    let mut cross = Entity::new(
        EntityKind::Password,
        "$2b$12$crossrepresentation0",
        0.6,
        "scan",
    );
    cross.tag("password-hash");
    cross.add_evidence(Evidence::new("oathnet", "breach").with_attr("email", "burner@proton.me"));
    cross.add_evidence(Evidence::new("oathnet", "breach").with_attr("username", "bob_work"));
    let e3 = Entity::new(EntityKind::Email, "burner@proton.me", 0.6, "scan");
    let u3 = Entity::new(EntityKind::Username, "bob_work", 0.6, "scan");
    let hits = super::rules::rule_au_047_reused_secret_identity(
        &[cross, e3.clone(), u3.clone()],
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a unique hash across an email and a different-handle username must link them"
    );
    assert!(hits[0].entity_uids.contains(&e3.uid) && hits[0].entity_uids.contains(&u3.uid));
}

#[test]
fn au018_includes_full_member_set_so_finalize_supersedes_live() {
    use super::rules::rule_au_018_email_address_colocation;
    // Regression: a live "Haigen Bamford" scan persisted AU-018 twice
    // ("co-located with 6" and "with 9"). The rule sampled take(5) of a growing
    // address set, so the live and finalize rows had DISJOINT 5-address samples
    // that storage's superset-supersede dedup couldn't fold. The member set must
    // be the FULL set, so the (monotonically growing) finalize set is a superset
    // of the live set and supersedes it.
    let mut email = Entity::new(EntityKind::Email, "haigen@visionhomesqld.com.au", 0.70, "s");
    email.add_evidence(Evidence::new("see_know", "x"));
    let mut ents = vec![email];
    for i in 0..7 {
        let mut a = Entity::new(EntityKind::Address, format!("Suburb {i}, QLD"), 0.60, "s");
        a.tag("geoint");
        ents.push(a);
    }
    let out = rule_au_018_email_address_colocation(&ents, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-018");
    // 1 email + all 7 addresses — not capped at take(5) — so a later superset
    // (more addresses) strictly contains this set and supersedes it in storage.
    assert_eq!(
        out[0].entity_uids.len(),
        8,
        "full member set, not a take(5) sample: {:?}",
        out[0].entity_uids
    );
}

#[test]
fn au018_excludes_role_mailboxes_from_the_identity_location_link() {
    use super::rules::rule_au_018_email_address_colocation;
    // A role/provider mailbox (a shared registrar/abuse desk) is not the
    // subject's identity, so co-locating it with the subject's address forges a
    // false identity↔location linkage — the same false positive AU-001 was
    // patched for (`abuse@godaddy.com`). AU-018 must exclude it, exactly as
    // AU-001/AU-045/AU-002 already do.
    let mut addr = Entity::new(EntityKind::Address, "Booroobin, QLD", 0.80, "s");
    addr.tag("geoint");

    // Role mailbox alone with the address must NOT fire — even at high confidence.
    let role = Entity::new(EntityKind::Email, "abuse@godaddy.com", 0.90, "s");
    let only_role = vec![role, addr.clone()];
    let out = rule_au_018_email_address_colocation(&only_role, "s", 0);
    assert!(
        out.is_empty(),
        "a role mailbox must not co-locate to a person's address: {out:?}"
    );

    // A genuine personal email in the same scene still fires (no false negative).
    let person = Entity::new(EntityKind::Email, "haigen.bamford@gmail.com", 0.90, "s");
    let with_person = vec![
        person,
        Entity::new(EntityKind::Email, "abuse@godaddy.com", 0.90, "s"),
        addr,
    ];
    let out = rule_au_018_email_address_colocation(&with_person, "s", 0);
    assert_eq!(out.len(), 1, "the personal email still links: {out:?}");
    assert_eq!(out[0].rule_id, "AU-018");
    // The role mailbox is excluded from the member set, so exactly 1 email + 1
    // address are linked, not 2 emails.
    assert_eq!(
        out[0].entity_uids.len(),
        2,
        "only the personal email + the address, role mailbox dropped: {:?}",
        out[0].entity_uids
    );
}

#[test]
fn au027_chains_only_the_dominant_coherent_location() {
    use super::rules::rule_au_027_address_coordinates_chain;
    // Regression from a deep "Haigen Bamford" scan: a Brisbane subject also
    // picked up a Cairns coordinate ~1700 km away, and AU-027 fused all of them
    // into one continent-spanning "validated chain". It must anchor on the
    // dominant coherent cluster (Brisbane) and exclude the far Cairns point.
    let coord = |v: &str| {
        let mut e = Entity::new(EntityKind::Coordinates, v, 0.75, "scan");
        e.tag("geocoded");
        e
    };
    let mut brisbane_addr = Entity::new(EntityKind::Address, "Brisbane, QLD", 0.80, "scan");
    brisbane_addr.tag("geoint");
    let cairns_uid = coord("-16.9186,145.7781").uid;
    let ents = vec![
        brisbane_addr,
        coord("-27.4698,153.0251"), // Brisbane CBD
        coord("-27.4690,153.0235"), // Brisbane CBD (~0.2 km away)
        coord("-16.9186,145.7781"), // Cairns, ~1700 km north
    ];
    let out = rule_au_027_address_coordinates_chain(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-027");
    // Dominant cluster = Brisbane's 2 coords, anchored near Brisbane; Cairns out.
    assert!(
        out[0].description.contains("2 coordinate set(s)"),
        "dominant cluster only: {}",
        out[0].description
    );
    assert!(
        out[0].description.contains("-27.4"),
        "anchored near Brisbane: {}",
        out[0].description
    );
    assert!(
        !out[0].entity_uids.contains(&cairns_uid),
        "the far Cairns coordinate must not be in the chain"
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

    // ONE account whose key evidence carries both its login and its email is
    // two identifier strings but a single controller — it must NOT fire a
    // Critical "controls 2 accounts". The canonical-handle fold collapses
    // "alice" and "alice@x.com" to one handle.
    let mut same_acct = Entity::new(EntityKind::Credential, "ssh:1acct2attrs", 0.85, "scan");
    same_acct.tag("ssh-key");
    same_acct.add_evidence(
        Evidence::new("github_user", "SSH key published by @alice")
            .with_attr("github_login", "alice")
            .with_attr("email", "alice@x.com"),
    );
    assert!(
        super::rules::rule_au_048_shared_public_key(&[same_acct], "scan", 0).is_empty(),
        "login + email of ONE account must not count as two accounts"
    );

    // A genuine cross-identifier link (a login and a DIFFERENT person-handle
    // email sharing one key) still fires.
    let mut cross = Entity::new(EntityKind::Credential, "ssh:2realaccts", 0.85, "scan");
    cross.tag("pgp-key");
    cross.add_evidence(
        Evidence::new("github_user", "key published by @alice").with_attr("github_login", "alice"),
    );
    cross.add_evidence(
        Evidence::new("pgp", "key bound to bob@x.com").with_attr("email", "bob@x.com"),
    );
    let hits = super::rules::rule_au_048_shared_public_key(&[cross], "scan", 0);
    assert_eq!(hits.len(), 1, "distinct handles sharing a key must link");
}

#[test]
fn au048_reports_distinct_controllers_not_identifier_spellings() {
    // A key whose evidence names alice under BOTH her login and her email, PLUS a
    // second owner bob = 3 identifier spellings but only 2 distinct account owners
    // (alice, bob). The finding must report "controls 2 accounts", not 3 — the
    // count is the distinct-controller measure the guard already uses (which treats
    // "alice" + "alice@x.com" as ONE account), so reporting the spelling count
    // over-states control by the rule's own definition.
    let mut key = Entity::new(EntityKind::Credential, "ssh:count-check", 0.9, "scan");
    key.tag("ssh-key");
    key.add_evidence(
        Evidence::new("github_user", "SSH key published by @alice")
            .with_attr("github_login", "alice")
            .with_attr("email", "alice@x.com"),
    );
    key.add_evidence(
        Evidence::new("github_user", "same key published by @bob").with_attr("github_login", "bob"),
    );
    let hits = super::rules::rule_au_048_shared_public_key(&[key], "scan", 0);
    assert_eq!(hits.len(), 1, "two distinct owners sharing a key must link");
    assert!(
        hits[0].description.contains("controls 2 accounts"),
        "must report 2 distinct account owners, not 3 identifier spellings: {}",
        hits[0].description
    );
}

#[test]
fn au048_discloses_when_the_account_list_is_truncated() {
    // The description enumerates at most 6 accounts, but a key genuinely
    // shared across MANY accounts (a stolen/reused keypair pushed to several
    // profiles) must say so — not silently cut the list with no indication,
    // the same "(+N more)" convention AU-076 already uses via join_capped.
    let mut key = Entity::new(EntityKind::Credential, "ssh:widelyshared", 0.85, "scan");
    key.tag("ssh-key");
    for i in 0..9 {
        key.add_evidence(
            Evidence::new("github_user", format!("SSH key published by @acct{i}"))
                .with_attr("github_login", format!("acct{i}")),
        );
    }
    let hits = super::rules::rule_au_048_shared_public_key(&[key], "scan", 0);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0].description.contains("9 accounts"),
        "the true total must still be stated: {}",
        hits[0].description
    );
    assert!(
        hits[0].description.contains("(+3 more)"),
        "the enumerated (top-6) list must disclose the 3 it omitted: {}",
        hits[0].description
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
fn au049_references_every_reachable_handle_not_a_capped_eight() {
    // Full-fidelity: a large household / share-house can have more than 8 associated
    // email/phone handles at one residence; the correlation's entity_uids (the actual
    // linkage it asserts) must reference EVERY reachable handle, not a silent
    // bounded-8 subset. Fail-before: capped at 8.
    let addr = "123 Main St, Springfield";
    let mut ents = vec![
        person_at("Jordan Meyers", addr),
        person_at("Dana Meyers", addr),
        Entity::new(EntityKind::Address, addr, 0.58, "s"),
    ];
    let mut handle_uids: Vec<String> = Vec::new();
    for i in 0..10 {
        let mut email = Entity::new(
            EntityKind::Email,
            format!("user{i:02}@example.com"),
            0.72,
            "s",
        );
        email.add_evidence(Evidence::new("import:dossier", "e").with_attr("address", addr));
        handle_uids.push(email.uid.clone());
        ents.push(email);
    }
    let hits = super::rules::rule_au_049_shared_address_association(&ents, "s", 0);
    assert_eq!(hits.len(), 1);
    let referenced = handle_uids
        .iter()
        .filter(|u| hits[0].entity_uids.contains(u))
        .count();
    assert_eq!(
        referenced, 10,
        "every reachable handle must be referenced, not capped at 8; got {referenced}"
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
fn au050_excludes_shared_business_and_service_lines() {
    // A shared AU business/service line — freephone (1800) or local-rate
    // (13/1300) — is an organisational desk many unrelated people legitimately
    // reach, not evidence they are associates. It must NOT fire AU-050.
    for service in ["1800 123 456", "1300 975 707"] {
        let ents = vec![
            person_with_phone("Jordan Meyers", service),
            person_with_phone("Casey Lin", service),
        ];
        let hits = super::rules::rule_au_050_shared_phone_association(&ents, "s", 0);
        assert!(
            hits.is_empty(),
            "shared business/service line {service} must not link unrelated people: {hits:?}"
        );
    }

    // A shared PERSONAL line (a mobile) still links the two people — no false
    // negative — even across formatting variants that collapse to one key.
    let mobile = vec![
        person_with_phone("Jordan Meyers", "0412 345 678"),
        person_with_phone("Casey Lin", "(0412) 345-678"),
    ];
    let hits = super::rules::rule_au_050_shared_phone_association(&mobile, "s", 0);
    assert_eq!(
        hits.len(),
        1,
        "a shared personal mobile still links: {hits:?}"
    );
    assert_eq!(hits[0].rule_id, "AU-050");
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

#[test]
fn au051_common_surname_is_a_high_lead_not_critical_kin() {
    // Two "Smith"s sharing one building address (unit numbers absent from the
    // data) must NOT be asserted as Critical "likely relatives" — a common surname
    // makes the shared-residence a coincidence risk (an apartment tower collapses
    // unrelated co-residents onto one key). It still fires, but as a High LEAD to
    // verify; a distinctive surname (Meyers, above) stays Critical.
    let ents = vec![
        person_at("Jordan Smith", "123 Main St, Springfield"),
        person_at("Dana Smith", "123 Main St, Springfield"),
    ];
    let hits = super::rules::rule_au_051_shared_surname_kin(&ents, "s", 0);
    assert_eq!(hits.len(), 1, "still fires — it is a lead, not silence");
    assert_eq!(hits[0].rule_id, "AU-051");
    assert_eq!(
        hits[0].severity,
        super::Severity::High,
        "a common surname is a High lead, not a Critical kin assertion"
    );
    assert!(hits[0].description.contains("common surname"));
}

// ─── Shared organisational email domain (AU-087) ─────────────────────────────

#[cfg(test)]
fn org_email_ent(addr: &str) -> Entity {
    Entity::new(EntityKind::Email, addr, 0.72, "s")
}

#[test]
fn au087_fires_on_two_addresses_at_one_org_domain() {
    // Two distinct addresses at a specific (non-freemail) organisational domain
    // form an employer / institution affiliation surface.
    let e1 = org_email_ent("john.smith@acme.com.au");
    let e2 = org_email_ent("jane.doe@acme.com.au");
    let (u1, u2) = (e1.uid.clone(), e2.uid.clone());
    let hits = super::rules::rule_au_087_shared_org_email_domain(&[e1, e2], "s", 0);
    assert_eq!(hits.len(), 1, "one org-domain affiliation cluster");
    let c = &hits[0];
    assert_eq!(c.rule_id, "AU-087");
    assert_eq!(c.severity, super::Severity::Medium);
    assert!(c.description.contains("acme.com.au"));
    assert!(c.entity_uids.contains(&u1) && c.entity_uids.contains(&u2));
}

#[test]
fn au087_excludes_freemail_and_isp_webmail() {
    // Freemail (gmail) and ISP webmail (bigpond) are millions-strong shared
    // services, not an organisation — two addresses on either never fire.
    let gmail = vec![
        org_email_ent("alice@gmail.com"),
        org_email_ent("bob@gmail.com"),
    ];
    assert!(super::rules::rule_au_087_shared_org_email_domain(&gmail, "s", 0).is_empty());
    let isp = vec![
        org_email_ent("a@bigpond.com"),
        org_email_ent("b@bigpond.com"),
    ];
    assert!(super::rules::rule_au_087_shared_org_email_domain(&isp, "s", 0).is_empty());
}

#[test]
fn au087_needs_two_distinct_addresses() {
    // A single address at an org domain is not a shared surface.
    let one = vec![org_email_ent("solo@acme.com.au")];
    assert!(super::rules::rule_au_087_shared_org_email_domain(&one, "s", 0).is_empty());
    // The same address in different case (recalled + re-discovered) is ONE
    // distinct address after normalisation, not a cluster of two.
    let dup = vec![
        org_email_ent("solo@acme.com.au"),
        org_email_ent("SOLO@acme.com.au"),
    ];
    assert!(super::rules::rule_au_087_shared_org_email_domain(&dup, "s", 0).is_empty());
}

#[test]
fn au087_rides_along_named_person_and_covers_edu_domains() {
    // A university (.edu.au) domain fires, and a Person whose name derives one of
    // the local-parts is linked — the affiliation names a real person.
    let e1 = org_email_ent("j.citizen@uq.edu.au");
    let e2 = org_email_ent("m.lee@uq.edu.au");
    let mut person = Entity::new(EntityKind::Person, "Jane Citizen", 0.62, "s");
    person.tag("au");
    let puid = person.uid.clone();
    let hits = super::rules::rule_au_087_shared_org_email_domain(&[e1, e2, person], "s", 0);
    assert_eq!(hits.len(), 1);
    assert!(hits[0].description.contains("uq.edu.au"));
    assert!(
        hits[0].entity_uids.contains(&puid),
        "the named affiliate rides along in the firing"
    );
}

// ─── Authoritative AU register confirmation (AU-088) ─────────────────────────

#[cfg(test)]
fn ent_from_source(kind: EntityKind, value: &str, source: &str) -> Entity {
    let mut e = Entity::new(kind, value, 0.70, "s");
    e.add_evidence(Evidence::new(source, "register record"));
    e
}

#[test]
fn au088_single_register_is_high_confirmation() {
    // One authoritative register returning subject data is a High confirmation.
    let p = ent_from_source(EntityKind::Person, "Jane Citizen", "ahpra");
    let hits = super::rules::rule_au_088_authoritative_register_confirmation(&[p], "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_id, "AU-088");
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(hits[0].description.contains("AHPRA"));
    assert!(hits[0].description.contains("1 authoritative"));
}

#[test]
fn au088_two_distinct_registers_is_critical() {
    // Two DIFFERENT authorities agreeing is the strongest identity signal → Critical.
    let p = ent_from_source(EntityKind::Person, "Jane Citizen", "ahpra");
    let o = ent_from_source(EntityKind::Person, "Jane Citizen", "au_electoral");
    let hits = super::rules::rule_au_088_authoritative_register_confirmation(&[p, o], "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, super::Severity::Critical);
    assert!(hits[0].description.contains("2 authoritative"));
    assert!(hits[0].description.contains("AHPRA") && hits[0].description.contains("electoral"));
}

#[test]
fn au088_asic_subfeeds_collapse_to_one_authority() {
    // Three ASIC feeds are ONE issuing authority — High, not Critical.
    let a = ent_from_source(EntityKind::Person, "Jo Director", "asic_persons");
    let b = ent_from_source(EntityKind::Organisation, "Acme Pty Ltd", "asic_director");
    let c = ent_from_source(EntityKind::Person, "Jo Director", "asic_banned_orgs");
    let hits = super::rules::rule_au_088_authoritative_register_confirmation(&[a, b, c], "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].severity,
        super::Severity::High,
        "3 ASIC feeds collapse to a single authority"
    );
    assert!(hits[0].description.contains("1 authoritative"));
}

#[test]
fn au088_non_register_sources_do_not_fire() {
    // Search-engine / name-derivation hits are not authoritative registers.
    let p = ent_from_source(EntityKind::Person, "Jane Citizen", "search_engines");
    let e = ent_from_source(EntityKind::Email, "jane@gmail.com", "name_intel");
    assert!(
        super::rules::rule_au_088_authoritative_register_confirmation(&[p, e], "s", 0).is_empty()
    );
}

// ─── Australian corporate network (AU-089) ───────────────────────────────────

#[test]
fn au089_two_distinct_companies_fire_medium() {
    // ACN 004085616 and the company ABN 53004085616 are the SAME company → must
    // collapse to one; add a second, distinct company (ACN 000000019) to fire.
    let a = Entity::new(EntityKind::AbnAcn, "53004085616", 0.80, "s"); // company ABN
    let b = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s"); // its ACN (same co.)
    let c = Entity::new(EntityKind::AbnAcn, "000000019", 0.80, "s"); // a 2nd company
    let hits = super::rules::rule_au_089_corporate_network(&[a, b, c], "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_id, "AU-089");
    assert_eq!(hits[0].severity, super::Severity::Medium);
    // Exactly two distinct companies, ABN+ACN of the first deduped to one.
    assert!(hits[0].description.contains("2 distinct"));
    assert!(hits[0].description.contains("004 085 616"));
    assert!(hits[0].description.contains("000 000 019"));
}

#[test]
fn au089_single_company_does_not_fire() {
    // A company seen as both its ABN and its derived ACN is still ONE company.
    let a = Entity::new(EntityKind::AbnAcn, "53004085616", 0.80, "s");
    let b = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s");
    assert!(super::rules::rule_au_089_corporate_network(&[a, b], "s", 0).is_empty());
}

#[test]
fn au089_three_companies_escalate_to_high() {
    let a = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s");
    let b = Entity::new(EntityKind::AbnAcn, "000000019", 0.80, "s");
    // A third distinct, checksum-valid ACN (prefix 01000000 → check digit 3).
    let c = Entity::new(EntityKind::AbnAcn, "010000003", 0.80, "s");
    let hits = super::rules::rule_au_089_corporate_network(&[a, b, c], "s", 0);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, super::Severity::High);
    assert!(hits[0].description.contains("3 distinct"));
}

#[test]
fn au089_non_company_abn_is_excluded() {
    // 51824753556 is a valid ABN but NOT a company (no embedded ACN), so it is
    // not a corporate vehicle — one real company alongside it must not fire.
    let sole = Entity::new(EntityKind::AbnAcn, "51824753556", 0.80, "s");
    let company = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s");
    assert!(super::rules::rule_au_089_corporate_network(&[sole, company], "s", 0).is_empty());
}

#[cfg(test)]
fn api_key_ent(value: &str, service: &str, criticality: &str, detection: &str) -> Entity {
    let mut e = Entity::new(EntityKind::ApiKey, value, 0.80, "s");
    e.tag("api-key");
    e.tag(format!("service:{service}"));
    e.tag(format!("key-criticality:{criticality}"));
    e.tag(format!("detection:{detection}"));
    if matches!(criticality, "critical" | "high") {
        e.tag("high-value");
    }
    e
}

#[test]
fn au095_ranks_portfolio_critical_first() {
    let aws = api_key_ent("AKIA_aws_secret", "aws", "critical", "proven");
    let analytics = api_key_ent("ph_low_token", "posthog", "low", "probable");
    let r = super::rules::rule_au_095_exposed_key_portfolio(&[analytics, aws], "s", 0);
    assert_eq!(r.len(), 1, "one portfolio summary");
    assert_eq!(r[0].rule_id, "AU-095");
    assert_eq!(r[0].severity, super::Severity::Critical); // a high-value key present
    assert!(r[0].description.contains("2 exposed API key"));
    assert!(r[0].description.contains("2 provider"));
    assert!(r[0].description.contains("1 high-criticality"));
    // The critical AWS key must lead the revoke-first list, before the low one.
    let aws_pos = r[0].description.find("aws").expect("aws listed");
    let ph_pos = r[0].description.find("posthog").expect("posthog listed");
    assert!(
        aws_pos < ph_pos,
        "critical key ranked before low-criticality key"
    );
    assert!(
        r[0].description.contains("not reused"),
        "states the no-reuse policy"
    );
}

#[test]
fn au095_flags_exploitable_and_handles_unrated() {
    let mut jwt = api_key_ent("eyJ.none.token", "jwt_token", "low", "potential");
    jwt.tag(crate::core::tags::VULNERABLE); // e.g. alg:none
    // A found_keys-path key with no criticality tag → counts, ranks unrated.
    let mut bare = Entity::new(EntityKind::ApiKey, "foreignkey123", 0.7, "s");
    bare.tag("api-key");
    bare.tag("foreign-key");
    let r = super::rules::rule_au_095_exposed_key_portfolio(&[jwt, bare], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::High); // no high-criticality key
    assert!(r[0].description.contains("outright exploitable"));
    assert!(
        r[0].description.contains("unrated"),
        "untagged key ranks unrated"
    );
}

#[test]
fn au095_discloses_when_the_priority_list_is_truncated() {
    // The revoke-first list is capped at 5, but the description must never
    // read as complete when it isn't — the same "(+N more)" disclosure
    // AU-047/AU-048/AU-106 already carry via join_capped.
    let keys: Vec<Entity> = (0..7)
        .map(|i| api_key_ent(&format!("key-{i}"), &format!("svc{i}"), "high", "proven"))
        .collect();
    let r = super::rules::rule_au_095_exposed_key_portfolio(&keys, "s", 0);
    assert_eq!(r.len(), 1);
    assert!(
        r[0].description.contains("7 exposed API key"),
        "the true total must still be stated: {}",
        r[0].description
    );
    assert!(
        r[0].description.contains("(+2 more)"),
        "the capped (top-5) priority list must disclose the 2 it omitted: {}",
        r[0].description
    );
}

#[test]
fn au095_no_keys_no_finding() {
    let p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    assert!(super::rules::rule_au_095_exposed_key_portfolio(&[p], "s", 0).is_empty());
}

#[cfg(test)]
fn osint_key_ent(value: &str, service: &str, category: &str) -> Entity {
    let mut e = Entity::new(EntityKind::ApiKey, value, 0.80, "s");
    e.tag("api-key");
    e.tag(format!("service:{service}"));
    e.tag("osint-practitioner");
    e.tag(format!("osint-category:{category}"));
    e
}

#[test]
fn au096_flags_osint_practitioner_with_tradecraft() {
    let shodan = osint_key_ent(
        "shodankey32xxxxxxxxxxxxxxxxxxxxxx",
        "shodan",
        "attack-surface",
    );
    let dehashed = osint_key_ent("dehashedkey", "dehashed", "breach-leak");
    let r = super::rules::rule_au_096_osint_practitioner(&[shodan, dehashed], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-096");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("2 OSINT/recon-provider API key"));
    assert!(r[0].description.contains("shodan") && r[0].description.contains("dehashed"));
    assert!(
        r[0].description.contains("attack-surface") && r[0].description.contains("breach-leak")
    );
}

#[test]
fn au097_consumer_isp_is_medium_residency_signal() {
    // An IP whose `isp` evidence names an Australian consumer ISP.
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "s");
    ip.add_evidence(
        Evidence::new("ip_geo", "geo")
            .with_attr("isp", "Telstra")
            .with_attr("as", "AS1221 Telstra"),
    );
    let r = super::rules::rule_au_097_au_isp_network(&[ip], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-097");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("Telstra"));
    assert!(r[0].description.contains("consumer ISP"));
}

#[test]
fn au097_aarnet_is_high_academic_affiliation() {
    // An ASN entity valued with AARNet → academic/research network.
    let asn = Entity::new(EntityKind::Asn, "AS7575 AARNet", 0.8, "s");
    let r = super::rules::rule_au_097_au_isp_network(&[asn], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("AARNet"));
    assert!(r[0].description.contains("academic"));
}

#[test]
fn au097_ignores_foreign_and_non_network_entities() {
    // A foreign ISP must not fire; a non-IP/ASN entity is ignored.
    let mut foreign = Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.8, "s");
    foreign.add_evidence(Evidence::new("ip_geo", "geo").with_attr("isp", "Google LLC"));
    let person = Entity::new(EntityKind::Person, "Telstra Smith", 0.8, "s"); // name, not a network
    assert!(super::rules::rule_au_097_au_isp_network(&[foreign, person], "s", 0).is_empty());
}

#[test]
fn au097_short_token_needs_word_boundary() {
    // "tpg" must not match inside a longer word (no false AU attribution).
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "s");
    ip.add_evidence(Evidence::new("ripestat", "asn").with_attr("descr", "ACMETPGENETICS LIMITED"));
    assert!(super::rules::rule_au_097_au_isp_network(&[ip], "s", 0).is_empty());
}

#[test]
fn au096_ignores_non_osint_keys() {
    // A plain infra key (no osint-practitioner tag) must not trigger AU-096.
    let mut aws = Entity::new(EntityKind::ApiKey, "AKIAxxxx", 0.8, "s");
    aws.tag("api-key");
    aws.tag("service:aws");
    assert!(super::rules::rule_au_096_osint_practitioner(&[aws], "s", 0).is_empty());
}

#[test]
fn au094_non_company_abn_is_a_sole_trader_signal() {
    // 51824753556 — valid ABN, no embedded ACN → a non-company (sole trader/trust).
    let sole = Entity::new(EntityKind::AbnAcn, "51 824 753 556", 0.80, "s");
    let r = super::rules::rule_au_094_sole_trader_abn(&[sole], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-094");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(
        r[0].description.contains("51 824 753 556"),
        "ABN shown grouped"
    );
    assert!(r[0].description.contains("sole-trader"));
}

#[test]
fn au094_excludes_companies_and_acns() {
    // A company ABN (53004085616) and a bare ACN are companies — AU-089's domain,
    // not AU-094's. Neither must fire the sole-trader rule.
    let company_abn = Entity::new(EntityKind::AbnAcn, "53004085616", 0.80, "s");
    let acn = Entity::new(EntityKind::AbnAcn, "004085616", 0.80, "s");
    assert!(super::rules::rule_au_094_sole_trader_abn(&[company_abn, acn], "s", 0).is_empty());
}

#[test]
fn au094_dedups_and_counts_distinct_non_company_abns() {
    // Same ABN in two formats collapses; a second distinct non-company ABN counts.
    let a1 = Entity::new(EntityKind::AbnAcn, "51824753556", 0.80, "s");
    let a1_spaced = Entity::new(EntityKind::AbnAcn, "51 824 753 556", 0.80, "s");
    // 18123456789 — a second valid ABN whose trailing nine (123456789) fail the
    // ACN check, so it is genuinely non-company.
    let a2 = Entity::new(EntityKind::AbnAcn, "18123456789", 0.80, "s");
    let r = super::rules::rule_au_094_sole_trader_abn(&[a1, a1_spaced, a2], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 non-company"));
}

#[test]
fn au100_work_email_surfaces_employer_affiliation() {
    // A .com.au work email → commercial employer; a .gov.au → government.
    let e1 = Entity::new(EntityKind::Email, "j.citizen@acme-widgets.com.au", 0.7, "s");
    let e2 = Entity::new(EntityKind::Email, "officer@health.nsw.gov.au", 0.7, "s");
    let r = super::rules::rule_au_100_au_employer_affiliation(&[e1, e2], "s", 0);
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|c| c.rule_id == "AU-100"));
    let commercial = r
        .iter()
        .find(|c| c.description.contains("acme-widgets.com.au"))
        .unwrap();
    assert!(commercial.description.contains("commercial"));
    assert!(commercial.description.contains("ABN/ACN"));
    let gov = r
        .iter()
        .find(|c| c.description.contains("health.nsw.gov.au"))
        .unwrap();
    assert!(gov.description.contains("government"));
}

#[test]
fn au100_excludes_freemail_personal_and_foreign() {
    // Freemail, a personal .id.au domain, and a foreign .com must NOT fire.
    let gmail = Entity::new(EntityKind::Email, "subject@gmail.com", 0.8, "s");
    let personal = Entity::new(EntityKind::Email, "me@haigen.id.au", 0.8, "s");
    let foreign = Entity::new(EntityKind::Email, "x@example.com", 0.8, "s");
    assert!(
        super::rules::rule_au_100_au_employer_affiliation(&[gmail, personal, foreign], "s", 0)
            .is_empty()
    );
}

#[test]
fn au100_dedups_multiple_emails_on_one_domain() {
    let e1 = Entity::new(EntityKind::Email, "a@acme.com.au", 0.7, "s");
    let e2 = Entity::new(EntityKind::Email, "b@acme.com.au", 0.7, "s");
    let r = super::rules::rule_au_100_au_employer_affiliation(&[e1, e2], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 email(s)"));
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

/// An Overpass map-POI coordinate: a camera / cell tower scraped near a
/// geolocated point, tagged `infra:*` and sourced only from `overpass`. Not a
/// sighting of the person.
#[cfg(test)]
fn overpass_poi(value: &str, infra_tag: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Coordinates, value, 0.55, "s");
    e.add_evidence(Evidence::new("overpass", "nearby map feature"));
    e.tag(infra_tag);
    e
}

#[test]
fn au052_excludes_overpass_poi_cluster_live_toronto_case() {
    // Regression from a real scan: ~20 Overpass POIs (surveillance cameras, cell
    // towers) cluster tightly around one IP-geolocated point. They are map
    // features, not sightings — an exclude-list missed `overpass` and would have
    // built a tight downtown footprint with a geometric median on a traffic
    // camera. The positive person-anchor allowlist drops them all.
    let mut ents: Vec<Entity> = (0..20)
        .map(|i| {
            let lat = 43.650 + (i as f64) * 0.0003;
            overpass_poi(&format!("{lat:.4},-79.3830"), "infra:surveillance")
        })
        .collect();
    // Plus the central IP-geo point (hosting) — also excluded.
    ents.push(hosting_coord("43.6532,-79.3832", "ip_geo"));
    assert!(
        super::rules::rule_au_052_geographic_area_of_operation(&ents, "s", 0).is_empty(),
        "Overpass POIs must not form a person's footprint"
    );
    assert!(
        super::rules::rule_au_053_out_of_area_location(&ents, "s", 0).is_empty(),
        "Overpass POIs must not establish an area for the anomaly rule either"
    );
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

#[test]
fn severity_as_canonical_matches_serde() {
    // CONVENTIONS.md §3 pin. as_canonical feeds the persisted
    // `correlations.severity` column AND the SQL `ORDER BY CASE` in
    // `correlations_for_scan` hard-codes these exact strings in this exact ORDER,
    // so a drift between as_canonical, the serde wire form, and the weight/Ord
    // ranking would silently desync the stored value from the query that ranks it
    // (and the in-memory `rank_and_sort` from the persisted order).
    //
    // `EVERY` is walked by an arm-less `match` (no `_`): adding a Severity variant
    // fails to compile until it is listed — the compile-forced guard a hardcoded
    // array lacks. (RelationKind::SharesSecretWith silently slipped exactly this
    // way, staying unpinned until the array-based test was made exhaustive.)
    const EVERY: &[Severity] = &[
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for &sev in EVERY {
        match sev {
            Severity::Low | Severity::Medium | Severity::High | Severity::Critical => {}
        }
        let json = serde_json::to_string(&sev).unwrap();
        assert_eq!(
            json.trim_matches('"'),
            sev.as_canonical(),
            "as_canonical vs serde: {sev:?}"
        );
        // Display is the deliberately UPPERCASE human form — never the wire form.
        assert_eq!(
            sev.to_string(),
            sev.as_canonical().to_uppercase(),
            "Display vs as_canonical: {sev:?}"
        );
        // The persisted string must deserialise back to the same variant.
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sev, "serde round-trip: {sev:?}");
    }

    // The three ranking representations must encode ONE order: declaration order
    // (EVERY) == weight() ascending == Ord ascending. `rank_and_sort` ranks by
    // `weight()` and tie-breaks by the derived `Ord`, and the SQL `ORDER BY CASE`
    // mirrors it — so a variant whose weight or Ord disagreed with its position
    // would make the persisted and in-memory rankings diverge. Pin strict
    // monotonic agreement across every consecutive pair.
    for pair in EVERY.windows(2) {
        assert!(
            pair[0].weight() < pair[1].weight(),
            "weight order must match declaration: {:?} !< {:?}",
            pair[0],
            pair[1]
        );
        assert!(
            pair[0] < pair[1],
            "Ord must match declaration: {:?} !< {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn au_056_corroborates_when_coord_and_address_agree_on_state() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // A Brisbane coordinate (tagged au-state:QLD by the geo builders) and a QLD
    // address independently name the same state → High corroboration.
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4766,153.0166",
            "geocode",
            &["geoint", "au-relevant", "au-state:QLD"],
        ),
        mk_tagged(
            EntityKind::Address,
            "12 Mary Street, Brisbane City QLD 4000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_056_jurisdiction_cross_check(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-056");
    assert_eq!(out[0].severity, super::Severity::High);
    assert!(out[0].description.contains("QLD"));
    assert!(out[0].description.contains("corroborated"));
    assert_eq!(out[0].entity_uids.len(), 2);
}

#[test]
fn au_056_derives_coord_state_from_latlong_without_a_tag() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // Regression from a live scan: a Brisbane coordinate person-anchored via a
    // search-engine snippet carries NO au-state tag, yet the rule must still
    // derive QLD from the lat/long and corroborate the QLD address. `search_engines`
    // is an anchoring geo source, so the coordinate is a real subject fix (not
    // infrastructure geo excluded by `coord_state`).
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4698,153.0251",
            "search_engines",
            &["geoint"], // deliberately no au-state: tag
        ),
        mk_tagged(EntityKind::Address, "Brisbane, QLD", "search_engines", &[]),
    ];
    let out = rule_au_056_jurisdiction_cross_check(&ents, "scan", 0);
    assert_eq!(out.len(), 1, "cross-check must fire on a tag-less AU coord");
    assert_eq!(out[0].rule_id, "AU-056");
    assert!(out[0].description.contains("QLD"));
    assert!(out[0].rule_name.contains("corroborated"));
}

#[test]
fn au_056_flags_conflict_when_states_disagree() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // Coordinate says QLD, the address says VIC → disjoint → Medium conflict.
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4766,153.0166",
            "geocode",
            &["geoint", "au-state:QLD"],
        ),
        mk_tagged(
            EntityKind::Address,
            "5 Collins Street, Melbourne VIC 3000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_056_jurisdiction_cross_check(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].rule_name.contains("conflict") || out[0].description.contains("travel"));
    assert!(out[0].description.contains("QLD") && out[0].description.contains("VIC"));
}

#[test]
fn au_056_agreement_stays_medium_and_lists_the_split_side() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // Two coordinate fixes — one QLD, one NSW — but the address is QLD only. The
    // classes AGREE on QLD (a shared state ⇒ corroboration), yet the coordinate
    // side is internally split, so severity drops from High to Medium and the
    // description enumerates each side. This exercises the split-agreement branch
    // (the only path that emits the "(coordinates: …; addresses: …)" enumeration).
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4766,153.0166",
            "geocode",
            &["geoint", "au-state:QLD"],
        ),
        mk_tagged(
            EntityKind::Coordinates,
            "-33.8688,151.2093",
            "geocode",
            &["geoint", "au-state:NSW"],
        ),
        mk_tagged(
            EntityKind::Address,
            "12 Mary Street, Brisbane City QLD 4000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_056_jurisdiction_cross_check(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].severity,
        super::Severity::Medium,
        "a split on one side downgrades corroboration to Medium"
    );
    assert!(out[0].rule_name.contains("corroborated"));
    // BTreeSet ordering makes the enumeration deterministic and slash-joined.
    assert!(
        out[0]
            .description
            .contains("(coordinates: NSW/QLD; addresses: QLD)"),
        "split side is enumerated: {}",
        out[0].description
    );
}

#[test]
fn au_056_silent_without_both_signal_classes() {
    use super::rules::rule_au_056_jurisdiction_cross_check;

    // Only a coordinate (no address) → nothing to cross-check.
    let coord_only = vec![mk_tagged(
        EntityKind::Coordinates,
        "-27.4766,153.0166",
        "geocode",
        &["au-state:QLD"],
    )];
    assert!(rule_au_056_jurisdiction_cross_check(&coord_only, "scan", 0).is_empty());

    // Only an address → likewise nothing.
    let addr_only = vec![mk_tagged(
        EntityKind::Address,
        "12 Mary Street, Brisbane City QLD 4000",
        "see_know",
        &[],
    )];
    assert!(rule_au_056_jurisdiction_cross_check(&addr_only, "scan", 0).is_empty());
}

// ─── AU-085 tests (phone-region jurisdiction cross-check) ─────────────────────

#[test]
fn au_085_corroborates_when_phone_region_matches_address_state() {
    use super::rules::rule_au_085_phone_region_jurisdiction;

    // A NSW landline (02 → Central East: NSW/ACT) and a NSW address agree.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "+61 2 9876 5432", "phone_au", &[]),
        mk_tagged(
            EntityKind::Address,
            "12 Smith Street, Sydney NSW 2000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_085_phone_region_jurisdiction(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-085");
    assert!(out[0].rule_name.contains("corroborates"));
    assert!(out[0].description.contains("NSW"));
    assert_eq!(out[0].entity_uids.len(), 2);
}

#[test]
fn au_056_infrastructure_address_does_not_vote_jurisdiction() {
    use super::rules::rule_au_056_jurisdiction_cross_check;
    // A hosting datacentre address is the HOST's location, not the subject's.
    // Paired with the subject's real QLD coordinate, the pre-fix rule read the
    // datacentre "Sydney NSW" as an address-state and fired a false NSW-vs-QLD
    // "jurisdiction conflict". The address side must exclude infrastructure geo
    // exactly as the coordinate side (`coord_state`) already does.
    let ents = vec![
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4766,153.0166",
            "geocode",
            &["geoint", "au-state:QLD"],
        ),
        mk_tagged(
            EntityKind::Address,
            "Sydney NSW, AU",
            "urlscan",
            &[crate::core::tags::HOSTING],
        ),
    ];
    assert!(
        rule_au_056_jurisdiction_cross_check(&ents, "scan", 0).is_empty(),
        "a hosting datacentre address must not vote the subject's jurisdiction"
    );
}

#[test]
fn au_085_infrastructure_address_does_not_corroborate_phone_region() {
    use super::rules::rule_au_085_phone_region_jurisdiction;
    // The AU-056 fix applies identically here: a WHOIS-registrant / hosting
    // datacentre address must not corroborate the subject's phone region. A NSW
    // landline + a registrant "Sydney NSW" address previously manufactured an NSW
    // agreement from pure infrastructure geo.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "+61 2 9876 5432", "phone_au", &[]),
        mk_tagged(
            EntityKind::Address,
            "Sydney NSW, AU",
            "whois",
            &[crate::core::tags::REGISTRANT],
        ),
    ];
    assert!(
        rule_au_085_phone_region_jurisdiction(&ents, "scan", 0).is_empty(),
        "a registrant datacentre address must not corroborate the phone region"
    );
}

#[test]
fn au_085_corroborates_against_a_tagless_coordinate_state() {
    use super::rules::rule_au_085_phone_region_jurisdiction;

    // A QLD landline (07) and a Brisbane coordinate with NO au-state tag — the
    // state is still derived from the lat/long, so the cross-check fires.
    // `search_engines` is an anchoring geo source, so the coordinate is a real
    // subject fix (not infrastructure geo excluded by `coord_state`).
    let ents = vec![
        mk_tagged(EntityKind::Phone, "(07) 3000 1234", "import", &[]),
        mk_tagged(
            EntityKind::Coordinates,
            "-27.4698,153.0251",
            "search_engines",
            &["geoint"],
        ),
    ];
    let out = rule_au_085_phone_region_jurisdiction(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-085");
    assert!(out[0].description.contains("QLD"));
}

#[test]
fn au_085_flags_conflict_when_region_disagrees_with_address() {
    use super::rules::rule_au_085_phone_region_jurisdiction;

    // A VIC/TAS landline (03 → South East) but the only known address is in WA
    // (Central & West) → disjoint → a conflict worth surfacing.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "+61 3 9876 5432", "phone_au", &[]),
        mk_tagged(
            EntityKind::Address,
            "5 Hay Street, Perth WA 6000",
            "see_know",
            &[],
        ),
    ];
    let out = rule_au_085_phone_region_jurisdiction(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-085");
    assert!(out[0].rule_name.contains("conflicts"));
    assert!(out[0].description.contains("WA"));
}

#[test]
fn au_085_silent_for_mobile_or_missing_class() {
    use super::rules::rule_au_085_phone_region_jurisdiction;

    // A mobile has no geographic region — even with an address, nothing fires.
    let mobile = vec![
        mk_tagged(EntityKind::Phone, "+61 412 345 678", "phone_au", &[]),
        mk_tagged(
            EntityKind::Address,
            "12 Smith Street, Sydney NSW 2000",
            "x",
            &[],
        ),
    ];
    assert!(rule_au_085_phone_region_jurisdiction(&mobile, "scan", 0).is_empty());

    // A geographic landline but no address/coordinate → nothing to cross-check.
    let phone_only = vec![mk_tagged(
        EntityKind::Phone,
        "+61 2 9876 5432",
        "phone_au",
        &[],
    )];
    assert!(rule_au_085_phone_region_jurisdiction(&phone_only, "scan", 0).is_empty());
}

// ─── AU-102 tests (phone line-type profile) ──────────────────────────────────

#[test]
fn au_102_profiles_premises_mobile_and_business_lines() {
    use super::rules::rule_au_102_phone_line_type_profile;

    // A QLD landline (premises), a personal mobile, and a 1300 business line.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "(07) 3000 1234", "phone_au", &[]),
        mk_tagged(EntityKind::Phone, "+61 412 345 678", "phone_au", &[]),
        mk_tagged(EntityKind::Phone, "1300 975 707", "import", &[]),
    ];
    let out = rule_au_102_phone_line_type_profile(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-102");
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].description.contains("geographic fixed line"));
    assert!(out[0].description.contains("North East")); // 07 → QLD region
    assert!(out[0].description.contains("personal mobile"));
    assert!(out[0].description.contains("business/service line"));
    assert_eq!(out[0].entity_uids.len(), 3);
}

#[test]
fn au_102_two_mobiles_only_is_low_and_fires() {
    use super::rules::rule_au_102_phone_line_type_profile;

    // Two distinct personal mobiles — no premises/business line → Low, but the
    // multiple-handset signal is worth surfacing.
    let ents = vec![
        mk_tagged(EntityKind::Phone, "+61 412 345 678", "phone_au", &[]),
        mk_tagged(EntityKind::Phone, "0413 222 333", "phone_au", &[]),
    ];
    let out = rule_au_102_phone_line_type_profile(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Low);
    assert!(out[0].description.contains("2 personal mobiles"));
    assert!(out[0].description.contains("multiple personal mobiles"));
}

#[test]
fn au_102_silent_for_a_single_lone_mobile() {
    use super::rules::rule_au_102_phone_line_type_profile;

    // One mobile alone is left to the bare Phone entity — no finding.
    let ents = vec![mk_tagged(
        EntityKind::Phone,
        "+61 412 345 678",
        "phone_au",
        &[],
    )];
    assert!(rule_au_102_phone_line_type_profile(&ents, "scan", 0).is_empty());
}

#[test]
fn au_102_dedups_the_same_number_across_formats() {
    use super::rules::rule_au_102_phone_line_type_profile;

    // The same QLD landline in two formats normalises to one E.164 value → it is
    // counted once, so the profile reads "1 geographic fixed line".
    let ents = vec![
        mk_tagged(EntityKind::Phone, "(07) 3000 1234", "phone_au", &[]),
        mk_tagged(EntityKind::Phone, "0730001234", "import", &[]),
    ];
    let out = rule_au_102_phone_line_type_profile(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert!(out[0].description.contains("1 geographic fixed line"));
    assert!(!out[0].description.contains("2 geographic"));
}

// ─── AU-103 tests (autonomous device self-location) ──────────────────────────

#[test]
fn au_103_gps_fix_with_corroboration_is_high_self_location() {
    use super::rules::rule_au_103_device_self_location;

    // A Brisbane GPS fix (device-sensor) + Wi-Fi APs + a serving AU cell.
    let mut fix = mk_tagged(
        EntityKind::Coordinates,
        "-27.4705,153.0260",
        "signal_radar",
        &["device-sensor", "provider:gps", "accuracy:8m", "geoint"],
    );
    fix.confidence = 0.90;
    let wifi1 = mk_tagged(
        EntityKind::MacAddress,
        "AA:BB:CC:DD:EE:01",
        "signal_radar",
        &[crate::core::tags::WIFI_AP],
    );
    let wifi2 = mk_tagged(
        EntityKind::MacAddress,
        "AA:BB:CC:DD:EE:02",
        "signal_radar",
        &[crate::core::tags::WIFI_AP],
    );
    let cell = mk_tagged(
        EntityKind::DeviceId,
        "505-1-100-200",
        "signal_radar",
        &[crate::core::tags::CELL_TOWER],
    );
    let out = rule_au_103_device_self_location(&[fix, wifi1, wifi2, cell], "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-103");
    assert_eq!(out[0].severity, super::Severity::High);
    assert!(out[0].description.contains("near Brisbane"));
    assert!(out[0].description.contains("GPS fix"));
    assert!(out[0].description.contains("±8 m"));
    assert!(out[0].description.contains("2 Wi-Fi APs"));
    assert!(out[0].description.contains("no seed input"));
    assert_eq!(out[0].entity_uids.len(), 4);
}

#[test]
fn au_103_network_fix_only_is_medium() {
    use super::rules::rule_au_103_device_self_location;

    // A network-grade fix (no provider:gps tag) → Medium.
    let mut fix = mk_tagged(
        EntityKind::Coordinates,
        "-31.9523,115.8613",
        "device_sensors",
        &["device-sensor", "provider:network", "accuracy:450m"],
    );
    fix.confidence = 0.60;
    let out = rule_au_103_device_self_location(&[fix], "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].description.contains("network fix"));
    assert!(out[0].description.contains("Perth"));
}

#[test]
fn au_103_presence_only_without_a_fix_is_low() {
    use super::rules::rule_au_103_device_self_location;

    // No coordinate fix, but Wi-Fi + cell + Bluetooth establish presence → Low.
    let wifi = mk_tagged(
        EntityKind::MacAddress,
        "AA:BB:CC:DD:EE:01",
        "signal_radar",
        &[crate::core::tags::WIFI_AP],
    );
    let cell = mk_tagged(
        EntityKind::DeviceId,
        "505-2-1-2",
        "signal_radar",
        &[crate::core::tags::CELL_TOWER],
    );
    let bt = mk_tagged(
        EntityKind::MacAddress,
        "11:22:33:44:55:66",
        "signal_radar",
        &["bluetooth"],
    );
    let out = rule_au_103_device_self_location(&[wifi, cell, bt], "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::Low);
    assert!(out[0].description.contains("no precise fix"));
    assert!(out[0].description.contains("1 Wi-Fi AP"));
    assert!(out[0].description.contains("1 Bluetooth device"));
}

#[test]
fn au_103_flags_foreign_cell_under_an_au_fix() {
    use super::rules::rule_au_103_device_self_location;

    // An AU GPS fix served by a non-AU cell (MCC 310, USA) → roaming/SIM note.
    let mut fix = mk_tagged(
        EntityKind::Coordinates,
        "-27.4705,153.0260",
        "signal_radar",
        &["device-sensor", "provider:gps", "accuracy:10m"],
    );
    fix.confidence = 0.90;
    let cell = mk_tagged(
        EntityKind::DeviceId,
        "310-260-1-2",
        "signal_radar",
        &[crate::core::tags::CELL_TOWER],
    );
    let out = rule_au_103_device_self_location(&[fix, cell], "scan", 0);
    assert_eq!(out.len(), 1);
    assert!(out[0].description.contains("MCC 310 is non-Australian"));
}

#[test]
fn au_103_silent_with_no_device_signals() {
    use super::rules::rule_au_103_device_self_location;

    // A remote subject's coordinate (NOT device-sensor tagged) must not fire — the
    // rule concerns only the operator's own device.
    let subject = mk_tagged(
        EntityKind::Coordinates,
        "-33.8688,151.2093",
        "see_know",
        &[],
    );
    assert!(rule_au_103_device_self_location(&[subject], "scan", 0).is_empty());
    assert!(rule_au_103_device_self_location(&[], "scan", 0).is_empty());
}

// ─── AU-057 tests ─────────────────────────────────────────────────────────────

#[test]
fn au_057_two_brisbane_coords_produce_synthesised_fix() {
    use super::rules::rule_au_057_synthesised_location_fix;

    // Two Brisbane coordinates both at confidence 0.70 → AU-057 fires with
    // a synthesised point between them; severity is Medium (2 inputs).
    let ents = vec![
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.70, "scan");
            e.add_evidence(Evidence::new("geocode", "Brisbane CBD fix".to_string()));
            e
        },
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4766,153.0166", 0.70, "scan");
            e.add_evidence(Evidence::new("wigle", "Brisbane suburb fix".to_string()));
            e
        },
    ];
    let out = rule_au_057_synthesised_location_fix(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-057");
    assert_eq!(out[0].severity, super::Severity::Medium);
    assert!(out[0].description.contains("2 confirmed"));
    assert!(out[0].entity_uids.len() == 2);
    // The synthesised median is named via the offline reverse geocoder.
    assert!(
        out[0]
            .description
            .contains("primary location near Brisbane, QLD"),
        "synthesised fix is reverse-geocoded: {}",
        out[0].description
    );
}

#[test]
fn au_057_single_coord_does_not_fire() {
    use super::rules::rule_au_057_synthesised_location_fix;

    let ents = vec![{
        let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.70, "scan");
        e.add_evidence(Evidence::new("geocode", "single fix".to_string()));
        e
    }];
    assert!(rule_au_057_synthesised_location_fix(&ents, "scan", 0).is_empty());
}

#[test]
fn au_057_low_confidence_coords_do_not_fire() {
    use super::rules::rule_au_057_synthesised_location_fix;

    // Both coords are below the 0.60 threshold → rule is silent.
    let ents = vec![
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.55, "scan");
            e.add_evidence(Evidence::new("geocode", "Brisbane CBD fix".to_string()));
            e
        },
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4766,153.0166", 0.55, "scan");
            e.add_evidence(Evidence::new("ip_geo", "Brisbane suburb fix".to_string()));
            e
        },
    ];
    assert!(rule_au_057_synthesised_location_fix(&ents, "scan", 0).is_empty());
}

#[test]
fn au_057_three_coords_produce_high_severity() {
    use super::rules::rule_au_057_synthesised_location_fix;

    let ents: Vec<Entity> = [
        ("-27.4698,153.0251", "geocode"),
        ("-27.4766,153.0166", "photon"),
        ("-27.4750,153.0200", "wigle"),
    ]
    .iter()
    .map(|(v, src)| {
        let mut e = Entity::new(EntityKind::Coordinates, *v, 0.70, "scan");
        e.add_evidence(Evidence::new(*src, "fix".to_string()));
        e
    })
    .collect();
    let out = rule_au_057_synthesised_location_fix(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, super::Severity::High);
}

#[test]
fn au_057_excludes_infrastructure_coordinates() {
    use super::rules::rule_au_057_synthesised_location_fix;
    // Two IP-geo / hosting coordinates must NOT synthesise a subject "location
    // fix" — they locate the datacentre. Parity with AU-030/AU-099/AU-017.
    let ents = vec![
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.70, "scan");
            e.add_evidence(Evidence::new("ip_geo", "host city".to_string()));
            e
        },
        {
            let mut e = Entity::new(EntityKind::Coordinates, "-27.4766,153.0166", 0.70, "scan");
            e.tag(crate::core::tags::HOSTING);
            e.add_evidence(Evidence::new("ip_registry", "host city".to_string()));
            e
        },
    ];
    assert!(
        rule_au_057_synthesised_location_fix(&ents, "scan", 0).is_empty(),
        "infrastructure coordinates must not synthesise a subject location fix"
    );
}

// ─── AU-058 tests ─────────────────────────────────────────────────────────────

#[test]
fn au_058_ratemyagent_url_extracts_suburb() {
    use super::rules::rule_au_058_professional_profile_geo;

    let ents = vec![{
        let mut e = Entity::new(
            EntityKind::Url,
            "https://www.ratemyagent.com.au/real-estate-agent/haigen-bamford-paddington-as105/",
            0.50,
            "scan",
        );
        e.add_evidence(Evidence::new("social_probe", "profile found".to_string()));
        e
    }];
    let out = rule_au_058_professional_profile_geo(&ents, "scan", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-058");
    assert!(out[0].description.contains("paddington"));
    assert!(out[0].description.contains("T1591.002"));
}

#[test]
fn au_058_non_real_estate_url_does_not_fire() {
    use super::rules::rule_au_058_professional_profile_geo;

    let ents = vec![{
        let mut e = Entity::new(
            EntityKind::Url,
            "https://www.linkedin.com/in/haigen-bamford",
            0.50,
            "scan",
        );
        e.add_evidence(Evidence::new("social_probe", "profile".to_string()));
        e
    }];
    // linkedin is not in PROF_HOSTS for AU-058 (ratemyagent/homely/soho only)
    assert!(rule_au_058_professional_profile_geo(&ents, "scan", 0).is_empty());
}

#[test]
fn au_058_below_confidence_threshold_does_not_fire() {
    use super::rules::rule_au_058_professional_profile_geo;

    let ents = vec![{
        let mut e = Entity::new(
            EntityKind::Url,
            "https://www.ratemyagent.com.au/real-estate-agent/haigen-bamford-paddington-as105/",
            0.40,
            "scan",
        );
        e.add_evidence(Evidence::new("social_probe", "low-conf".to_string()));
        e
    }];
    assert!(rule_au_058_professional_profile_geo(&ents, "scan", 0).is_empty());
}

// ─── Recursive-scan simulation: cross-seed geo synergy for a subject ─────────
//
// An offline, deterministic stand-in for a live recursive scan. Real modules
// hit the network; here we construct the `Coordinates` entities those modules
// *would* emit for a subject (one per orthogonal source class) and drive the
// real correlation pipeline (`correlate_entities`) over them. This proves the
// end-to-end geo-synergy behaviour — AU-059 convergence, AU restriction, and
// orthogonal-class scoring — from many *random combinations of starting seeds*,
// without a live PII collection. Pure fixtures + the production rule set.
mod geo_synergy_sim {
    use super::super::rules::location::geo_source_class;
    use super::super::{Correlation, Severity, correlate_entities};
    use crate::core::entity::{Entity, EntityKind, Evidence};

    /// One simulated person-anchored geo sighting: the `Coordinates` an emitting
    /// module would produce. `source` selects the orthogonal class; the AU-state
    /// tag mirrors what collection-time tagging attaches.
    fn sighting(source: &str, lat: f64, lon: f64, conf: f64, state: &str) -> Entity {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.4},{lon:.4}"),
            conf,
            "scan",
        );
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
        e.add_evidence(Evidence::new(
            source,
            "person-anchored geo sighting".to_string(),
        ));
        e
    }

    /// Did AU-059 fire, and on which state/severity? Returns the matching
    /// correlation if present.
    fn au059(corrs: &[Correlation]) -> Option<&Correlation> {
        corrs.iter().find(|c| c.rule_id == "AU-059")
    }

    /// The canonical Sydney/NSW fixture coordinates, one per orthogonal class.
    /// Tight cluster (~Paddington/CBD) so the centroid is unambiguous.
    fn nsw_sources() -> Vec<(&'static str, f64, f64, f64)> {
        vec![
            ("abn_lookup", -33.8841, 151.2310, 0.82), // registry  (ABN registered office)
            ("exif_geo", -33.8850, 151.2300, 0.74),   // photo-gps (geotagged image)
            ("wigle", -33.8835, 151.2325, 0.66),      // wifi      (observed AP)
            ("au_people", -33.8860, 151.2290, 0.55),  // directory (White Pages AU)
            ("social_location", -33.8848, 151.2312, 0.60), // social (profile bio)
            ("phone_area_geo", -33.8700, 151.2090, 0.52), // phone (02 area code → Sydney)
        ]
    }

    #[test]
    fn single_class_never_converges() {
        // Two sightings, but BOTH registry → one orthogonal class → no synergy.
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("acnc_charities", -33.8850, 151.2300, 0.70, "NSW"),
        ];
        let corrs = correlate_entities(&ents, "scan");
        assert!(
            au059(&corrs).is_none(),
            "a single orthogonal class must not assert a synergy fix"
        );
    }

    #[test]
    fn two_orthogonal_classes_converge_in_nsw() {
        // A name→registry hit plus a photo GPS: the minimum useful seed combo.
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("exif_geo", -33.8850, 151.2300, 0.74, "NSW"),
        ];
        let corrs = correlate_entities(&ents, "scan");
        let c = au059(&corrs).expect("two orthogonal AU classes must fire AU-059");
        assert_eq!(c.severity, Severity::Medium, "exactly 2 classes ⇒ Medium");
        assert!(c.description.contains("state=NSW"));
    }

    #[test]
    fn three_plus_classes_are_high_severity() {
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("exif_geo", -33.8850, 151.2300, 0.74, "NSW"),
            sighting("wigle", -33.8835, 151.2325, 0.66, "NSW"),
        ];
        let corrs = correlate_entities(&ents, "scan");
        let c = au059(&corrs).expect("three orthogonal classes must fire AU-059");
        assert_eq!(c.severity, Severity::High, "≥3 classes ⇒ High");
    }

    /// The core requirement: geolocation must be achievable from *as many random
    /// combinations of starting seeds as possible*. Enumerate every 2-and-3
    /// subset of the orthogonal NSW source set; each subset whose sources span
    /// ≥2 distinct classes MUST converge on NSW. This is the combinatorial proof
    /// that the fix doesn't depend on any one privileged seed.
    #[test]
    fn every_multi_class_seed_combination_converges() {
        let all = nsw_sources();
        let n = all.len();
        let mut tested_combos = 0usize;

        // All 2- and 3-element subsets (bitmask enumeration; n is small).
        for mask in 1u32..(1 << n) {
            let chosen: Vec<_> = (0..n)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| all[i])
                .collect();
            if !(2..=3).contains(&chosen.len()) {
                continue;
            }
            // Distinct orthogonal classes in this subset.
            let classes: std::collections::HashSet<_> = chosen
                .iter()
                .map(|(src, ..)| geo_source_class(src))
                .collect();

            let ents: Vec<Entity> = chosen
                .iter()
                .map(|(src, lat, lon, conf)| sighting(src, *lat, *lon, *conf, "NSW"))
                .collect();
            let corrs = correlate_entities(&ents, "scan");
            let fired = au059(&corrs);

            if classes.len() >= 2 {
                let c = fired.unwrap_or_else(|| {
                    panic!(
                        "multi-class seed combo {:?} ({} classes) must converge",
                        chosen.iter().map(|(s, ..)| *s).collect::<Vec<_>>(),
                        classes.len()
                    )
                });
                assert!(
                    c.description.contains("state=NSW"),
                    "combo {:?} must localise to NSW",
                    chosen.iter().map(|(s, ..)| *s).collect::<Vec<_>>()
                );
                tested_combos += 1;
            } else {
                assert!(
                    fired.is_none(),
                    "single-class combo {:?} must NOT converge",
                    chosen.iter().map(|(s, ..)| *s).collect::<Vec<_>>()
                );
            }
        }
        // Sanity: we actually exercised a meaningful number of combinations.
        assert!(
            tested_combos >= 15,
            "expected many converging combos, exercised {tested_combos}"
        );
    }

    /// AU restriction: a non-Australian sighting must never contribute a class,
    /// even if it would otherwise complete a 2-class quorum. Here the only AU
    /// point is a registry hit; the photo GPS is in London → no synergy.
    #[test]
    fn foreign_sighting_cannot_complete_quorum() {
        let mut london = Entity::new(EntityKind::Coordinates, "51.5074,-0.1278", 0.80, "scan");
        london.add_evidence(Evidence::new("exif_geo", "overseas trip photo".to_string()));
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            london,
        ];
        let corrs = correlate_entities(&ents, "scan");
        assert!(
            au059(&corrs).is_none(),
            "a foreign coordinate must not complete the AU synergy quorum"
        );
    }

    /// The dominant-state report follows the majority of contributing sightings:
    /// 3 NSW + 1 VIC ⇒ NSW. (Mixed-state input still converges; the centroid and
    /// reported state reflect the weight of evidence.)
    #[test]
    fn majority_state_wins_the_report() {
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("exif_geo", -33.8850, 151.2300, 0.74, "NSW"),
            sighting("au_people", -33.8860, 151.2290, 0.55, "NSW"),
            sighting("wigle", -37.8136, 144.9631, 0.66, "VIC"),
        ];
        let corrs = correlate_entities(&ents, "scan");
        let c = au059(&corrs).expect("multi-class input must converge");
        assert!(
            c.description.contains("state=NSW"),
            "majority NSW evidence must report NSW: {}",
            c.description
        );
    }

    /// Infrastructure geo (a CDN edge, an Overpass POI) must never enter the fix
    /// — the person-anchor gate is shared with AU-052/053. Here two genuine
    /// person sources converge while a `hosting`-tagged point is ignored.
    #[test]
    fn infrastructure_points_are_excluded() {
        let mut cdn = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.90, "scan");
        cdn.tag("au-state:NSW");
        cdn.tag(crate::core::tags::HOSTING);
        cdn.add_evidence(Evidence::new("ip_geo", "CDN edge".to_string()));
        let ents = vec![
            sighting("abn_lookup", -33.8841, 151.2310, 0.82, "NSW"),
            sighting("exif_geo", -33.8850, 151.2300, 0.74, "NSW"),
            cdn,
        ];
        let corrs = correlate_entities(&ents, "scan");
        let c = au059(&corrs).expect("two person sources still converge");
        // The hosting point's uid (uid is derived from kind+value) must not
        // appear among AU-059's children.
        let cdn_uid = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.0, "scan").uid;
        assert!(
            !c.entity_uids.contains(&cdn_uid),
            "a hosting-tagged CDN point must not enter the synergy fix"
        );
    }
}

// ── All-eleven-class integration proof ───────────────────────────────────
//
// Drives all 11 orthogonal AU geo source classes (PhotoGps, WifiSensor,
// Geocode, Registry, Directory, Social, Phone, Enrichment, Search,
// Electoral, Property) through the real `correlate_entities` pipeline in
// one pass, then asserts:
//   1. AU-059 fires for every possible 2-class and 3-class subset.
//   2. The best-location extractor recovers every structured field.
//   3. Severity escalates correctly (Medium→High) as class count grows.
//   4. No infrastructure or foreign point enters any fix.
//
// This is the offline authoritative proof that geolocation converges from
// every seed-combination relevant to an AU subject, without live PII.
mod all_eleven_classes {
    use super::super::rules::location::geo_source_class;
    use super::super::{Correlation, Severity, correlate_entities};
    use crate::api::scan_export::extract_au_location_fix;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    /// One AU Coordinates entity per source class, all near Sydney NSW.
    /// Each source is the canonical representative of its orthogonal class.
    fn all_class_fixtures() -> Vec<(&'static str, f64, f64, f64)> {
        vec![
            // (source, lat, lon, confidence)
            ("exif_geo", -33.8688, 151.2093, 0.85), // PhotoGps
            ("wigle", -33.8700, 151.2100, 0.78),    // WifiSensor
            ("geocode", -33.8695, 151.2080, 0.82),  // Geocode
            ("abn_lookup", -33.8710, 151.2110, 0.80), // Registry
            ("au_people", -33.8680, 151.2070, 0.72), // Directory
            ("github_user", -33.8720, 151.2120, 0.68), // Social
            ("phone_area_geo", -33.8660, 151.2060, 0.65), // Phone
            ("epieos", -33.8730, 151.2130, 0.75),   // Enrichment
            ("search_engines", -33.8650, 151.2050, 0.62), // Search
            ("au_electoral", -33.8740, 151.2140, 0.74), // Electoral
            ("au_property", -33.8670, 151.2090, 0.74), // Property
        ]
    }

    fn au_coord(source: &str, lat: f64, lon: f64, conf: f64) -> Entity {
        let value = format!("{lat:.4},{lon:.4}");
        let mut e = Entity::new(EntityKind::Coordinates, &value, conf, "s");
        e.tag("au-state:NSW");
        e.tag("country:AU");
        e.add_evidence(Evidence::new(source, "fixture"));
        e
    }

    fn au059(corrs: &[Correlation]) -> Option<&Correlation> {
        corrs
            .iter()
            .filter(|c| c.rule_id == "AU-059")
            .max_by(|a, b| {
                a.rank
                    .partial_cmp(&b.rank)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    #[test]
    fn all_eleven_classes_present_and_distinct() {
        use std::collections::HashSet;
        let fixtures = all_class_fixtures();
        let classes: HashSet<_> = fixtures
            .iter()
            .map(|(src, _, _, _)| geo_source_class(src))
            .collect();
        assert_eq!(
            classes.len(),
            11,
            "fixture must cover exactly 11 distinct geo source classes; got {}: {:?}",
            classes.len(),
            classes
        );
    }

    #[test]
    fn all_eleven_fires_au059_at_critical_severity() {
        let ents: Vec<Entity> = all_class_fixtures()
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();
        let corrs = correlate_entities(&ents, "s");
        let c = au059(&corrs).expect("11 classes must fire AU-059");
        assert!(
            c.description.contains("state=NSW"),
            "all-class fix must report NSW: {}",
            c.description
        );
        assert_eq!(
            c.severity,
            Severity::High,
            "≥3 orthogonal classes must produce High (or better) severity"
        );
    }

    #[test]
    fn all_eleven_best_location_field_is_fully_structured() {
        let ents: Vec<Entity> = all_class_fixtures()
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();
        let corrs = correlate_entities(&ents, "s");
        let fix = extract_au_location_fix(&corrs, &ents);

        assert!(fix.is_object(), "best_location must be a JSON object");
        assert_eq!(fix["state"], "NSW", "state must be NSW");
        assert_eq!(fix["rule_id"], "AU-059");

        let lat = fix["lat"].as_f64().expect("lat must be f64");
        let lon = fix["lon"].as_f64().expect("lon must be f64");
        assert!(
            (-34.5..-33.0).contains(&lat),
            "centroid lat must be near Sydney: {lat}"
        );
        assert!(
            (150.5..152.0).contains(&lon),
            "centroid lon must be near Sydney: {lon}"
        );

        let gh = fix["geohash"].as_str().expect("geohash must be a string");
        assert!(!gh.is_empty(), "geohash must be non-empty");
        assert_eq!(gh.len(), 6, "geohash must be 6 chars (precision 6)");

        let sc = fix["synergy_confidence"]
            .as_f64()
            .expect("synergy_confidence must be f64");
        assert!(
            (0.0..=0.97).contains(&sc) && sc > 0.5,
            "synergy_confidence must be > 0.5 for 11 classes: {sc}"
        );

        let class_count = fix["class_count"]
            .as_u64()
            .expect("class_count must be u64");
        assert!(
            class_count >= 3,
            "class_count must be ≥ 3 for 11 sources: {class_count}"
        );

        let source_count = fix["source_count"]
            .as_u64()
            .expect("source_count must be u64");
        assert!(
            source_count >= 11,
            "source_count must be ≥ 11: {source_count}"
        );
    }

    /// Every 2-element subset of the 11 classes must independently fire AU-059.
    /// Uses bitmask enumeration: 2^11 = 2048 masks, C(11,2) = 55 two-class pairs.
    #[test]
    fn every_two_class_pair_fires_au059() {
        let fixtures = all_class_fixtures();
        let n = fixtures.len();
        let mut checked = 0u32;
        let mut failures: Vec<String> = Vec::new();

        for mask in 0u32..(1 << n) {
            if mask.count_ones() != 2 {
                continue;
            }
            let ents: Vec<Entity> = fixtures
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, (src, lat, lon, conf))| au_coord(src, *lat, *lon, *conf))
                .collect();

            let corrs = correlate_entities(&ents, "s");
            let selected: Vec<String> = fixtures
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, (src, _, _, _))| src.to_string())
                .collect();

            if au059(&corrs).is_none() {
                failures.push(format!("{selected:?}"));
            }
            checked += 1;
        }

        assert_eq!(checked, 55, "must check exactly C(11,2)=55 pairs");
        assert!(
            failures.is_empty(),
            "{} two-class pair(s) failed to fire AU-059: {}",
            failures.len(),
            failures.join("; ")
        );
    }

    /// Three-class subsets must produce High severity; two-class Medium.
    #[test]
    fn severity_escalates_with_class_count() {
        let fixtures = all_class_fixtures();

        // Two-class: first two fixtures (PhotoGps + WifiSensor).
        let two_ents: Vec<Entity> = fixtures[..2]
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();
        let two_corrs = correlate_entities(&two_ents, "s");
        let two_fix = au059(&two_corrs).expect("2 classes must fire");
        assert_eq!(
            two_fix.severity,
            Severity::Medium,
            "2 orthogonal classes must be Medium severity"
        );

        // Three-class: first three fixtures (PhotoGps + WifiSensor + Geocode).
        let three_ents: Vec<Entity> = fixtures[..3]
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();
        let three_corrs = correlate_entities(&three_ents, "s");
        let three_fix = au059(&three_corrs).expect("3 classes must fire");
        assert_eq!(
            three_fix.severity,
            Severity::High,
            "3 orthogonal classes must be High severity"
        );
    }

    /// Adding a foreign (non-AU) point to a 2-class AU set must not displace
    /// the AU fix — the foreign point is excluded by the AU bounding-box gate.
    #[test]
    fn foreign_sighting_does_not_contaminate_au_fix() {
        let fixtures = all_class_fixtures();
        let mut ents: Vec<Entity> = fixtures[..2]
            .iter()
            .map(|(src, lat, lon, conf)| au_coord(src, *lat, *lon, *conf))
            .collect();

        // A US coordinate tagged with a non-AU source.
        let mut us = Entity::new(EntityKind::Coordinates, "40.7128,-74.0060", 0.90, "s");
        us.add_evidence(Evidence::new("geocode", "New York fixture"));
        // No country:AU tag — bounding-box check will exclude it.
        ents.push(us);

        let corrs = correlate_entities(&ents, "s");
        let fix = extract_au_location_fix(&corrs, &ents);
        assert_eq!(
            fix["state"], "NSW",
            "AU fix must survive a foreign sighting: {fix}"
        );
    }
}

/// AU-059's fix must be OUTLIER-ROBUST — that's the entire point of using the
/// confidence-weighted geometric median (Weiszfeld) instead of a plain
/// weighted centroid (PROBLEM_TREE C5). Two orthogonal classes agree near
/// Sydney (combined weight 64% of the total); a third, *higher-confidence*
/// class disagrees from Perth, ~3,300 km away (weight 36%). Because the
/// majority holds more than the median's 50% breakdown point, the fix must
/// stay anchored near Sydney — a plain weighted centroid, which has no notion
/// of "majority" and is dragged proportionally to weight share regardless of
/// spatial agreement, would not.
#[test]
fn au059_synergy_fix_resists_a_single_high_confidence_outlier() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let sighting = |lat: f64, lon: f64, conf: f64, source: &str, state: &str| {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.4},{lon:.4}"),
            conf,
            "s",
        );
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
        e.add_evidence(Evidence::new(source, "fixture"));
        e
    };

    let entities = vec![
        sighting(-33.8688, 151.2093, 0.85, "exif_geo", "NSW"), // PhotoGps
        sighting(-33.8700, 151.2100, 0.78, "wigle", "NSW"),    // WifiSensor
        sighting(-31.9505, 115.8605, 0.90, "geocode", "WA"),   // Geocode — the outlier
    ];

    let fix = au059_synergy_fix(&entities).expect("3 orthogonal AU classes must converge");

    // The plain weighted centroid the pre-fix code used, computed directly for
    // comparison. It has no notion of "majority", so Perth's 36% weight share
    // still drags the average roughly a third of the way there — the sanity
    // check below proves this fixture is actually discriminating.
    let weighted: Vec<((f64, f64), f64)> = entities
        .iter()
        .map(|e| {
            let ll = crate::util::geohash::parse_coords(&e.value).unwrap();
            (ll, e.confidence)
        })
        .collect();
    let centroid = crate::util::geometry::weighted_centroid(&weighted).unwrap();
    assert!(
        centroid.1 < 145.0,
        "sanity: the plain centroid must itself be pulled toward Perth for this \
         fixture to be a meaningful test of outlier-robustness, got lon={:.2}",
        centroid.1
    );

    assert!(
        fix.lon > 145.0,
        "the geometric-median fix must stay anchored near the Sydney majority \
         (lon > 145) despite the higher-confidence Perth outlier, not drift \
         toward it the way the plain weighted centroid (lon={:.2}) does: \
         fix.lon={:.2}",
        centroid.1,
        fix.lon
    );
}

#[test]
fn au059_class_diversity_bonus_is_per_point_not_a_global_no_op() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // A coordinate corroborated across MORE orthogonal source classes is
    // stronger location evidence and must pull the synthesised fix
    // proportionally more. The class-diversity bonus used to be derived from the
    // scan-wide class count and applied to every point identically — a global
    // rescaling the weighted geometric median is invariant to, so it moved the
    // fix not at all. It is now per-point.
    //
    // This test isolates that: two scans differ ONLY in the class SPAN of the
    // eastern (Sydney) coordinate `A`, holding its source COUNT (2) — and hence
    // its `c_effective` — and every other point fixed. Under the old global
    // scalar the two fixes are byte-identical (the bonus can't move a weighted
    // median and A's weight is unchanged); under the per-point bonus the
    // multi-class scan must pull the fix east toward A.
    let mk = |lat: f64, lon: f64, sources: &[&str], state: &str| {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.4},{lon:.4}"),
            0.80,
            "s",
        );
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
        for s in sources {
            e.add_evidence(Evidence::new(*s, "fixture"));
        }
        e
    };

    // B (Darwin) and C (Perth) are fixed single-class points. With A (Sydney)
    // they form a genuine triangle (all interior angles < 120°), so the
    // geometric median is an interior Fermat point that responds continuously to
    // each vertex's weight — not a near-collinear set that pins the median to the
    // middle vertex regardless of weight.
    let b = mk(-12.4634, 130.8456, &["geocode"], "NT"); // Darwin — Geocode
    let c = mk(-31.9505, 115.8605, &["mylnikov"], "WA"); // Perth — WifiSensor

    // Three-class A: Registry + WifiSensor + PhotoGps → per-point count 3 → 1.20×.
    let a_multi = mk(
        -33.8688,
        151.2093,
        &["abn_lookup", "wigle", "exif_geo"],
        "NSW",
    );
    // One-class A: abn_lookup + opencorporates + acnc_charities → all Registry →
    // per-point count 1 → 1.00×. Same source COUNT (3) ⇒ identical c_effective.
    let a_mono = mk(
        -33.8688,
        151.2093,
        &["abn_lookup", "opencorporates", "acnc_charities"],
        "NSW",
    );

    let multi = au059_synergy_fix(&[a_multi, b.clone(), c.clone()])
        .expect("4 orthogonal AU classes converge");
    let mono = au059_synergy_fix(&[a_mono, b, c]).expect("3 orthogonal AU classes converge");

    assert!(
        multi.lon > mono.lon + 1e-4,
        "the per-point class-diversity bonus must pull the fix east toward the \
         multi-class Sydney coordinate: multi-class lon={:.5} must exceed \
         single-class lon={:.5} (they would be equal under the old global scalar)",
        multi.lon,
        mono.lon
    );
}

// ── T1.3: firing assertions for the 12 previously-unasserted rules ────────────
// (PROBLEM_TREE §3.1 T1.3 — these rules were dispatched but no test proved they
// actually produce a correlation; a silently-dead rule would pass CI.)

#[test]
fn au019_fires_for_three_breach_dates_within_30_days() {
    let mk = |v: &str, d: &str| {
        let mut e = Entity::new(EntityKind::Email, v, 0.8, "s");
        e.tag("breach");
        e.add_evidence(Evidence::new("hibp", "b").with_attr("breach_date", d));
        e
    };
    let ents = vec![
        mk("a@x.com", "2024-01-01"),
        mk("b@x.com", "2024-01-10"),
        mk("c@x.com", "2024-01-20"),
    ];
    let r = rule_au_019_temporal_breach_cluster(&ents, "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-019");
    assert_eq!(r[0].severity, Severity::High);
    assert_eq!(r[0].entity_uids.len(), 3);
}

#[test]
fn au020_fires_for_two_person_entities() {
    let ents = vec![
        Entity::new(EntityKind::Person, "Jane Doe", 0.6, "s"),
        Entity::new(EntityKind::Person, "John Roe", 0.6, "s"),
    ];
    let r = rule_au_020_person_entity_cluster(&ents, "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-020");
    assert_eq!(r[0].severity, Severity::Medium);
}

#[test]
fn au022_fires_for_org_co_located_with_breach() {
    let org = Entity::new(EntityKind::Organisation, "Acme Pty Ltd", 0.7, "s");
    let mut breached = Entity::new(EntityKind::Email, "x@acme.com", 0.6, "s");
    breached.tag("breach");
    let r = rule_au_022_organisation_with_breach(&[org, breached], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-022");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au023_fires_for_person_from_two_identity_sources() {
    let mut p = Entity::new(EntityKind::Person, "Jane Doe", 0.7, "s");
    p.add_evidence(Evidence::new("keybase", "x"));
    p.add_evidence(Evidence::new("github_user", "x"));
    let r = rule_au_023_cross_platform_identity(&[p], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-023");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au024_fires_for_email_with_two_risk_signals() {
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.6, "s");
    e.tag("breach");
    e.tag("disposable");
    let r = rule_au_024_email_fraud_signal(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-024");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au025_fires_for_opencorporates_org_with_person() {
    let mut org = Entity::new(EntityKind::Organisation, "Acme Pty Ltd", 0.7, "s");
    org.tag("opencorporates");
    let person = Entity::new(EntityKind::Person, "Jane Doe", 0.7, "s");
    let r = rule_au_025_corporate_identity_link(&[org, person], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-025");
    assert_eq!(r[0].severity, Severity::Medium);
}

#[test]
fn au026_fires_for_address_from_two_geo_sources() {
    let mut a = Entity::new(EntityKind::Address, "1 Main St, Sydney NSW 2000", 0.6, "s");
    a.add_evidence(Evidence::new("geocode", "x"));
    a.add_evidence(Evidence::new("photon", "x"));
    let r = rule_au_026_validated_address(&[a], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-026");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au028_fires_for_subdomain_takeover_tag() {
    let mut d = Entity::new(EntityKind::Domain, "ghost.example.com", 0.6, "s");
    d.tag("subdomain-takeover");
    let r = rule_au_028_subdomain_takeover_risk(&[d], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-028");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au029_fires_for_cloud_storage_vulnerable_tags() {
    let mut e = Entity::new(EntityKind::Url, "https://bucket.s3.amazonaws.com", 0.6, "s");
    e.tag("cloud-storage");
    e.tag(crate::core::tags::VULNERABLE);
    let r = rule_au_029_cloud_storage_exposure(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-029");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au040_fires_for_breach_exposed_wallet() {
    let mut w = Entity::new(EntityKind::CryptoAddress, "0xdeadbeef", 0.6, "s");
    w.add_evidence(Evidence::new("oathnet_pro", "leak"));
    let r = rule_au_040_wallet_breach_exposure(&[w], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-040");
    assert_eq!(r[0].severity, Severity::High);
}

#[test]
fn au041_fires_for_ens_tagged_username() {
    let mut u = Entity::new(EntityKind::Username, "vitalik.eth", 0.6, "s");
    u.tag("ens");
    let r = rule_au_041_ens_identity(&[u], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-041");
    assert_eq!(r[0].severity, Severity::Medium);
}

#[test]
fn au042_does_not_fire_for_a_single_pgp_linked_email() {
    // A lone pgp-linked email is not multi-email same-owner evidence — a "links 1
    // email to one owner" assertion is degenerate and must not fire (the rule's
    // contract is "two or more addresses bound to the same key").
    let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.6, "s");
    e.tag("pgp-linked");
    e.add_evidence(Evidence::new("pgp", "uid").with_attr("key_fingerprint", "DEADBEEF00000000"));
    assert!(
        rule_au_042_pgp_email_identity(&[e], "s", 0).is_empty(),
        "one email bound to a key is not a multi-email identity link"
    );
}

#[test]
fn au021_fires_for_api_key_entity() {
    let e = Entity::new(EntityKind::ApiKey, "AKIAIOSFODNN7EXAMPLE", 0.9, "s");
    let r = rule_au_021_api_key_exposure(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-021");
    assert_eq!(r[0].severity, Severity::Critical);
}

#[test]
fn au030_fires_for_three_source_geo_cluster() {
    // Genuine person-anchoring geo sources converging — AU-030 fires.
    let mut c1 = Entity::new(EntityKind::Coordinates, "51.5,0.1", 0.7, "s");
    c1.add_evidence(Evidence::new("geocode", "x"));
    c1.add_evidence(Evidence::new("wigle", "x"));
    let mut c2 = Entity::new(EntityKind::Coordinates, "51.6,0.2", 0.7, "s");
    c2.add_evidence(Evidence::new("exif_geo", "x"));
    let r = rule_au_030_geo_convergence_score(&[c1, c2], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-030");
    assert_eq!(r[0].severity, Severity::Medium);

    // H5: the same shape built from IP-geo lookups (the host's location, not the
    // subject's) is infrastructure geo and must NOT manufacture convergence.
    let mut ip1 = Entity::new(EntityKind::Coordinates, "51.5,0.1", 0.7, "s");
    ip1.add_evidence(Evidence::new("ip_geo", "x"));
    ip1.add_evidence(Evidence::new("ipinfo", "x"));
    let mut ip2 = Entity::new(EntityKind::Coordinates, "51.6,0.2", 0.7, "s");
    ip2.add_evidence(Evidence::new("maxmind", "x"));
    assert!(
        rule_au_030_geo_convergence_score(&[ip1, ip2], "s", 0).is_empty(),
        "IP-geo coordinates are the host's location, not subject geo convergence"
    );
}

#[test]
fn au062_multipath_corroboration_fires_on_orthogonal_routes() {
    use crate::core::relation::{Relation, RelationKind};
    let mk_rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };
    // a↔b joined by two edge-disjoint routes through different source families:
    // a—domain(infra)—b and a—org(identity_registry)—b.
    let a = ent(EntityKind::Email, "a@x.com", 0.8, "s", false);
    let b = ent(EntityKind::Username, "bob", 0.8, "s", false);
    let d = ent(EntityKind::Domain, "x.com", 0.8, "dns_intel", false);
    let o = ent(
        EntityKind::Organisation,
        "Acme Pty",
        0.8,
        "opencorporates",
        false,
    );
    let rels = [
        mk_rel(&a, &d, RelationKind::BelongsToDomain),
        mk_rel(&d, &b, RelationKind::DerivedFrom),
        mk_rel(&a, &o, RelationKind::RegisteredBy),
        mk_rel(&o, &b, RelationKind::DerivedFrom),
    ];
    let out = rule_au_062_multipath_corroboration(&[a, b, d, o], &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-062");
}

#[test]
fn au063_corroboration_gap_flags_a_lone_transitive_link() {
    use crate::core::relation::{Relation, RelationKind};
    let mk_rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };
    // a—domain(infra)—b: a single transitive route, no orthogonal corroboration.
    let a = ent(EntityKind::Email, "a@x.com", 0.8, "s", false);
    let b = ent(EntityKind::Username, "bob", 0.8, "s", false);
    let d = ent(EntityKind::Domain, "x.com", 0.8, "dns_intel", false);
    let rels = [
        mk_rel(&a, &d, RelationKind::BelongsToDomain),
        mk_rel(&d, &b, RelationKind::DerivedFrom),
    ];
    let out = rule_au_063_corroboration_gap(&[a, b, d], &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-063");
}

#[test]
fn au064_generalized_template_fires_on_a_repeated_route() {
    use crate::core::relation::{Relation, RelationKind};
    let mk_rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };
    let mk = |kind: EntityKind, v: &str| Entity::new(kind, v, 0.8, "s");
    // Two pairs share the route Email→belongs_to_domain→Domain→registered_by→Person.
    let e1 = mk(EntityKind::Email, "a@x.com");
    let d1 = mk(EntityKind::Domain, "x.com");
    let p1 = mk(EntityKind::Person, "Alice");
    let e2 = mk(EntityKind::Email, "b@y.com");
    let d2 = mk(EntityKind::Domain, "y.com");
    let p2 = mk(EntityKind::Person, "Bob");
    let rels = [
        mk_rel(&e1, &d1, RelationKind::BelongsToDomain),
        mk_rel(&d1, &p1, RelationKind::RegisteredBy),
        mk_rel(&e2, &d2, RelationKind::BelongsToDomain),
        mk_rel(&d2, &p2, RelationKind::RegisteredBy),
    ];
    let out = rule_au_064_generalized_pathway_template(&[e1, d1, p1, e2, d2, p2], &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-064");
}

#[test]
fn au067_resolved_identity_cluster_fires_on_three_linked_identities() {
    use crate::core::relation::{Relation, RelationKind};
    let mk_rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };
    let mk = |kind: EntityKind, v: &str| Entity::new(kind, v, 0.8, "s");
    // Email, person and username all hang off one domain hub → a single
    // transitive equivalence class of three identities (a resolved identity).
    let email = mk(EntityKind::Email, "a@x.com");
    let domain = mk(EntityKind::Domain, "x.com");
    let person = mk(EntityKind::Person, "Alice");
    let uname = mk(EntityKind::Username, "alice");
    let rels = [
        mk_rel(&email, &domain, RelationKind::BelongsToDomain),
        mk_rel(&domain, &person, RelationKind::RegisteredBy),
        mk_rel(&domain, &uname, RelationKind::DerivedFrom),
    ];
    let out = rule_au_067_resolved_identity_cluster(&[email, domain, person, uname], &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-067");
}

#[test]
fn au068_anonymous_sim_fires_on_a_voip_tagged_phone() {
    // hlr_cnam tags a VoIP/virtual-carrier phone `sim-voip`; AU-068 surfaces it.
    let mut phone = Entity::new(EntityKind::Phone, "+61400000000", 0.85, "s");
    phone.tag("sim-voip");
    let out = rule_au_068_anonymous_sim(&[phone], "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-068");
}

#[test]
fn au069_high_integrity_connection_fires_on_an_end_to_end_strong_route() {
    use crate::core::relation::{Relation, RelationKind};
    let edge = |from: &Entity, to: &Entity, c: f64| {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            c,
            "s",
        )
    };
    let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
    // email —0.9— person —0.9— username: every link on the route is strong.
    let a = mk(EntityKind::Email, "a@x.com");
    let mid = mk(EntityKind::Person, "Alice");
    let b = mk(EntityKind::Username, "alice");
    let rels = [edge(&a, &mid, 0.9), edge(&mid, &b, 0.9)];
    let out = rule_au_069_high_integrity_connection(&[a, mid, b], &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-069");
}

#[test]
fn au070_connection_broker_fires_on_a_hub_holding_three_identities() {
    use crate::core::relation::{Relation, RelationKind};
    let edge = |from: &Entity, to: &Entity| {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        )
    };
    let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
    // A domain hub is the sole link between three identities — its removal would
    // fragment all three, so it is a connection broker.
    let hub = mk(EntityKind::Domain, "x.com");
    let email = mk(EntityKind::Email, "a@x.com");
    let uname = mk(EntityKind::Username, "alice");
    let person = mk(EntityKind::Person, "Bob");
    let rels = [edge(&email, &hub), edge(&uname, &hub), edge(&person, &hub)];
    let out = rule_au_070_connection_broker(&[hub, email, uname, person], &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-070");
}

#[test]
fn au071_robust_identity_cluster_fires_on_a_redundantly_bound_cluster() {
    use crate::core::relation::{Relation, RelationKind};
    let edge = |from: &Entity, to: &Entity| {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        )
    };
    let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
    // Three identities each bound to TWO shared anchors — removing either leaves
    // them connected via the other, so the cluster has no single point of failure.
    let email = mk(EntityKind::Email, "a@x.com");
    let uname = mk(EntityKind::Username, "alice");
    let person = mk(EntityKind::Person, "Alice");
    let d1 = mk(EntityKind::Domain, "x.com");
    let d2 = mk(EntityKind::Domain, "y.com");
    let rels = [
        edge(&email, &d1),
        edge(&uname, &d1),
        edge(&person, &d1),
        edge(&email, &d2),
        edge(&uname, &d2),
        edge(&person, &d2),
    ];
    let out = rule_au_071_robust_identity_cluster(&[email, uname, person, d1, d2], &rels, "s", 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "AU-071");
}

// ── AU-109 — shared-registrant domain co-ownership (relation rule) ──────────

#[test]
fn au109_fires_on_shared_registrant_org() {
    use crate::core::relation::{Relation, RelationKind};
    // Two distinct domains both RegisteredBy the same genuine Organisation →
    // one High co-ownership finding naming both domains and the registrant.
    let d1 = Entity::new(EntityKind::Domain, "alpha-co.example", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "beta-co.example", 0.8, "s");
    let org = Entity::new(EntityKind::Organisation, "Acme Holdings Pty Ltd", 0.8, "s");
    let rels = vec![
        Relation::new(
            d1.uid.clone(),
            org.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
        Relation::new(
            d2.uid.clone(),
            org.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
    ];
    let r = rule_au_109_shared_registrant(&[d1.clone(), d2.clone(), org.clone()], &rels, "s", 0);
    assert_eq!(r.len(), 1, "shared registrant must fire one correlation");
    assert_eq!(r[0].rule_id, "AU-109");
    assert_eq!(r[0].severity, Severity::High);
    assert!(r[0].entity_uids.contains(&org.uid));
    assert!(r[0].entity_uids.contains(&d1.uid));
    assert!(r[0].entity_uids.contains(&d2.uid));
    assert!(r[0].description.contains("alpha-co.example"));
    assert!(r[0].description.contains("beta-co.example"));
    assert!(r[0].description.contains("Acme Holdings Pty Ltd"));
}

#[test]
fn au109_fires_on_shared_registrant_email() {
    use crate::core::relation::{Relation, RelationKind};
    // A personal (freemail) registrant email shared across two domains is a
    // genuine co-ownership signal — only infra/proxy mailboxes are excluded.
    let d1 = Entity::new(EntityKind::Domain, "one.example", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "two.example", 0.8, "s");
    let email = Entity::new(EntityKind::Email, "owner.person@protonmail.com", 0.8, "s");
    let rels = vec![
        Relation::new(
            d1.uid.clone(),
            email.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
        Relation::new(
            d2.uid.clone(),
            email.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
    ];
    let r = rule_au_109_shared_registrant(&[d1, d2, email.clone()], &rels, "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-109");
    assert!(r[0].description.contains("registrant email"));
    assert!(r[0].entity_uids.contains(&email.uid));
}

#[test]
fn au109_no_fire_on_privacy_proxy_registrant() {
    use crate::core::relation::{Relation, RelationKind};
    // The critical false-positive guard: domains sharing a WHOIS privacy proxy
    // (Domains By Proxy / WhoisGuard / an `abuse@` registrar role) must NOT be
    // linked — millions of unrelated domains share these.
    let d1 = Entity::new(EntityKind::Domain, "p1.example", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "p2.example", 0.8, "s");
    let proxy_org = Entity::new(EntityKind::Organisation, "Domains By Proxy, LLC", 0.8, "s");
    let proxy_email = Entity::new(EntityKind::Email, "abuse@whoisguard.com", 0.8, "s");
    for who in [&proxy_org, &proxy_email] {
        let rels = vec![
            Relation::new(
                d1.uid.clone(),
                who.uid.clone(),
                RelationKind::RegisteredBy,
                0.8,
                "s",
            ),
            Relation::new(
                d2.uid.clone(),
                who.uid.clone(),
                RelationKind::RegisteredBy,
                0.8,
                "s",
            ),
        ];
        let r =
            rule_au_109_shared_registrant(&[d1.clone(), d2.clone(), who.clone()], &rels, "s", 0);
        assert!(
            r.is_empty(),
            "privacy-proxy registrant '{}' must not link domains, got {r:?}",
            who.value
        );
    }
}

#[test]
fn au109_no_fire_on_single_domain_or_redacted() {
    use crate::core::relation::{Relation, RelationKind};
    let d1 = Entity::new(EntityKind::Domain, "solo.example", 0.8, "s");
    let org = Entity::new(EntityKind::Organisation, "Solo Trader", 0.8, "s");
    // One domain → no co-ownership.
    let rels = vec![Relation::new(
        d1.uid.clone(),
        org.uid.clone(),
        RelationKind::RegisteredBy,
        0.8,
        "s",
    )];
    assert!(rule_au_109_shared_registrant(&[d1.clone(), org], &rels, "s", 0).is_empty());
    // A "REDACTED FOR PRIVACY" placeholder registrant is excluded even with two
    // domains (substring marker `redacted`/`privacy`).
    let d2 = Entity::new(EntityKind::Domain, "solo2.example", 0.8, "s");
    let redacted = Entity::new(EntityKind::Organisation, "REDACTED FOR PRIVACY", 0.8, "s");
    let rels2 = vec![
        Relation::new(
            d1.uid.clone(),
            redacted.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
        Relation::new(
            d2.uid.clone(),
            redacted.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        ),
    ];
    assert!(rule_au_109_shared_registrant(&[d1, d2, redacted], &rels2, "s", 0).is_empty());
}

#[test]
fn au109_deterministic_across_edge_order() {
    use crate::core::relation::{Relation, RelationKind};
    let d1 = Entity::new(EntityKind::Domain, "x.example", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "y.example", 0.8, "s");
    let org = Entity::new(EntityKind::Organisation, "Shared Owner Inc", 0.8, "s");
    let mk = |a: &Entity, b: &Entity| {
        Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::RegisteredBy,
            0.8,
            "s",
        )
    };
    let ents = [d1.clone(), d2.clone(), org.clone()];
    let r1 = rule_au_109_shared_registrant(&ents, &[mk(&d1, &org), mk(&d2, &org)], "s", 0);
    let r2 = rule_au_109_shared_registrant(&ents, &[mk(&d2, &org), mk(&d1, &org)], "s", 0);
    assert_eq!(r1.len(), 1);
    assert_eq!(
        r1[0].description, r2[0].description,
        "member-domain ordering must be edge-order-independent"
    );
    assert_eq!(r1[0].entity_uids, r2[0].entity_uids);
}

// ── AU-110 — shared dedicated-IP co-hosting (relation rule) ─────────────────

/// Build a Domain→IpAddress `ResolvesTo` edge for the AU-110 fixtures.
fn resolves(d: &Entity, ip: &Entity) -> crate::core::relation::Relation {
    use crate::core::relation::{Relation, RelationKind};
    Relation::new(
        d.uid.clone(),
        ip.uid.clone(),
        RelationKind::ResolvesTo,
        0.8,
        "s",
    )
}

#[test]
fn au110_fires_on_two_distinct_sites_one_dedicated_ip() {
    // Two DIFFERENT sites on one non-CDN, routable IP → Medium co-hosting lead.
    let d1 = Entity::new(EntityKind::Domain, "alpha-site.com", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "beta-site.org", 0.8, "s");
    let ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let rels = vec![resolves(&d1, &ip), resolves(&d2, &ip)];
    let r = rule_au_110_shared_hosting_ip(&[d1.clone(), d2.clone(), ip.clone()], &rels, "s", 0);
    assert_eq!(
        r.len(),
        1,
        "two distinct sites on one dedicated IP must fire"
    );
    assert_eq!(r[0].rule_id, "AU-110");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].entity_uids.contains(&ip.uid));
    assert!(r[0].entity_uids.contains(&d1.uid));
    assert!(r[0].entity_uids.contains(&d2.uid));
    assert!(r[0].description.contains("45.33.32.156"));
    assert!(r[0].description.contains("alpha-site.com"));
    assert!(r[0].description.contains("beta-site.org"));
}

#[test]
fn au110_no_fire_on_subdomains_of_one_site() {
    // Co-RESIDENCE, not co-ownership: www/api/blog of ONE site share its origin
    // IP. All reduce to one registrable domain → must NOT fire.
    let d1 = Entity::new(EntityKind::Domain, "www.example.com", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "api.example.com", 0.8, "s");
    let d3 = Entity::new(EntityKind::Domain, "blog.example.com", 0.8, "s");
    let ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let rels = vec![resolves(&d1, &ip), resolves(&d2, &ip), resolves(&d3, &ip)];
    let r = rule_au_110_shared_hosting_ip(&[d1, d2, d3, ip], &rels, "s", 0);
    assert!(
        r.is_empty(),
        "one site's own subdomains are co-residence, not co-ownership: {r:?}"
    );
}

#[test]
fn au110_no_fire_on_cdn_or_nonroutable_ip() {
    // Guard 1: a Cloudflare edge (104.16/13) and non-routable IPs each front
    // unrelated sites — co-tenancy, never co-ownership.
    let d1 = Entity::new(EntityKind::Domain, "alpha-site.com", 0.8, "s");
    let d2 = Entity::new(EntityKind::Domain, "beta-site.org", 0.8, "s");
    for ip_val in ["104.16.5.5", "192.168.1.10", "203.0.113.7"] {
        let ip = Entity::new(EntityKind::IpAddress, ip_val, 0.8, "s");
        let rels = vec![resolves(&d1, &ip), resolves(&d2, &ip)];
        let r = rule_au_110_shared_hosting_ip(&[d1.clone(), d2.clone(), ip.clone()], &rels, "s", 0);
        assert!(
            r.is_empty(),
            "{ip_val}: CDN/non-routable IP must not link, got {r:?}"
        );
    }
}

#[test]
fn au110_no_fire_on_shared_hosting_fanout() {
    // Guard 3: many distinct sites on one IP → shared hosting, skipped.
    let ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let mut ents = vec![ip.clone()];
    let mut rels = Vec::new();
    for i in 0..8 {
        let d = Entity::new(
            EntityKind::Domain,
            format!("site{i}-distinct.com"),
            0.8,
            "s",
        );
        rels.push(resolves(&d, &ip));
        ents.push(d);
    }
    let r = rule_au_110_shared_hosting_ip(&ents, &rels, "s", 0);
    assert!(
        r.is_empty(),
        "8 distinct sites on one IP is shared hosting, not co-ownership: {r:?}"
    );
}

// ── AU-113 — direct-connect origin-candidate unmasking (relation rule) ─────

#[test]
fn au113_fires_when_cdn_apex_has_a_direct_connect_sibling() {
    // apex.com resolves ONLY to a Cloudflare edge; mail.apex.com (an MX
    // sibling) resolves directly to a real, routable IP — a genuine
    // origin-candidate lead.
    let apex = Entity::new(EntityKind::Domain, "apex.com", 0.8, "s");
    let cdn_ip = Entity::new(EntityKind::IpAddress, "104.16.5.5", 0.8, "s");
    let mut mx = Entity::new(EntityKind::Domain, "mail.apex.com", 0.8, "s");
    mx.tag("mx");
    let origin_ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");

    let ents = vec![apex.clone(), cdn_ip.clone(), mx.clone(), origin_ip.clone()];
    let rels = vec![resolves(&apex, &cdn_ip), resolves(&mx, &origin_ip)];

    let r = rule_au_113_direct_connect_origin_candidate(&ents, &rels, "s", 0);
    assert_eq!(
        r.len(),
        1,
        "a CDN apex with a direct-connect sibling must fire: {r:?}"
    );
    assert_eq!(r[0].rule_id, "AU-113");
    assert_eq!(r[0].severity, Severity::Medium);
    assert!(r[0].entity_uids.contains(&apex.uid));
    assert!(r[0].entity_uids.contains(&mx.uid));
    assert!(r[0].entity_uids.contains(&origin_ip.uid));
    assert!(r[0].description.contains("apex.com"));
    assert!(r[0].description.contains("mail.apex.com"));
    assert!(r[0].description.contains("45.33.32.156"));
}

#[test]
fn au113_fires_for_a_direct_connect_subdomain_brute_hit() {
    // cpanel.apex.org (subdomain + dns-brute, a direct-connect label) is the
    // sibling here, instead of an MX record.
    let apex = Entity::new(EntityKind::Domain, "apex.org", 0.8, "s");
    let cdn_ip = Entity::new(EntityKind::IpAddress, "172.64.1.1", 0.8, "s");
    let mut cpanel = Entity::new(EntityKind::Domain, "cpanel.apex.org", 0.8, "s");
    cpanel.tag("subdomain");
    cpanel.tag("dns-brute");
    let origin_ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");

    let ents = vec![
        apex.clone(),
        cdn_ip.clone(),
        cpanel.clone(),
        origin_ip.clone(),
    ];
    let rels = vec![resolves(&apex, &cdn_ip), resolves(&cpanel, &origin_ip)];

    let r = rule_au_113_direct_connect_origin_candidate(&ents, &rels, "s", 0);
    assert_eq!(
        r.len(),
        1,
        "a direct-connect dns-brute sibling must fire: {r:?}"
    );
    assert!(r[0].description.contains("cpanel.apex.org"));
}

#[test]
fn au113_no_fire_when_apex_is_not_cdn_fronted() {
    // apex.com resolves to an ordinary, non-CDN IP — nothing to unmask.
    let apex = Entity::new(EntityKind::Domain, "apex.com", 0.8, "s");
    let apex_ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let mut mx = Entity::new(EntityKind::Domain, "mail.apex.com", 0.8, "s");
    mx.tag("mx");
    let mx_ip = Entity::new(EntityKind::IpAddress, "45.33.32.200", 0.8, "s");

    let ents = vec![apex.clone(), apex_ip.clone(), mx.clone(), mx_ip.clone()];
    let rels = vec![resolves(&apex, &apex_ip), resolves(&mx, &mx_ip)];

    let r = rule_au_113_direct_connect_origin_candidate(&ents, &rels, "s", 0);
    assert!(r.is_empty(), "a non-CDN apex has nothing to unmask: {r:?}");
}

#[test]
fn au113_no_fire_when_sibling_also_resolves_to_a_cdn_edge() {
    // Both apex and its MX sibling sit behind the CDN — no leak.
    let apex = Entity::new(EntityKind::Domain, "apex.com", 0.8, "s");
    let cdn_ip = Entity::new(EntityKind::IpAddress, "104.16.5.5", 0.8, "s");
    let mut mx = Entity::new(EntityKind::Domain, "mail.apex.com", 0.8, "s");
    mx.tag("mx");
    let mx_cdn_ip = Entity::new(EntityKind::IpAddress, "104.16.9.9", 0.8, "s");

    let ents = vec![apex.clone(), cdn_ip.clone(), mx.clone(), mx_cdn_ip.clone()];
    let rels = vec![resolves(&apex, &cdn_ip), resolves(&mx, &mx_cdn_ip)];

    let r = rule_au_113_direct_connect_origin_candidate(&ents, &rels, "s", 0);
    assert!(
        r.is_empty(),
        "an equally CDN-fronted sibling leaks nothing: {r:?}"
    );
}

// ─── AU-111 tests (CDN origin candidate) ──────────────────────────────────────

fn cdn_fronted_domain(value: &str, provider: &str) -> Entity {
    let mut d = Entity::new(EntityKind::Domain, value, 0.9, "s");
    d.tag("waf-detected");
    d.tag(format!("waf:{provider}"));
    d.add_evidence(Evidence::new(
        "waf_detect",
        format!("WAF/CDN detected: {provider}"),
    ));
    d
}

fn spf_ip(value: &str, for_domain: &str) -> Entity {
    let mut ip = Entity::new(EntityKind::IpAddress, value, 0.75, "s");
    ip.tag("dns");
    ip.tag("spf");
    ip.add_evidence(
        Evidence::new(
            "dns_intel",
            format!("SPF authorised sender for {for_domain}"),
        )
        .with_attr("domain", for_domain),
    );
    ip
}

#[test]
fn au111_fires_on_cloudflare_fronted_domain_with_spf_ip() {
    let dom = cdn_fronted_domain("example.com", "Cloudflare");
    let ip = spf_ip("203.0.113.9", "example.com");
    let r = rule_au_111_cdn_origin_candidate(&[dom.clone(), ip.clone()], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-111");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("example.com"));
    assert!(r[0].description.contains("203.0.113.9"));
    assert!(r[0].description.contains("Cloudflare"));
    assert_eq!(
        r[0].entity_uids,
        vec![dom.uid.clone(), ip.uid.clone()],
        "the fronted domain and the origin-candidate IP are both cited"
    );
}

#[test]
fn au111_does_not_fire_without_cdn_fingerprint() {
    // A domain with no `waf-detected` tag at all — no CDN evidence, no fire
    // even though an SPF IP exists for it.
    let mut dom = Entity::new(EntityKind::Domain, "plain.com", 0.9, "s");
    dom.tag("mx"); // some other, unrelated dns_intel tag
    let ip = spf_ip("203.0.113.9", "plain.com");
    assert!(rule_au_111_cdn_origin_candidate(&[dom, ip], "s", 0).is_empty());
}

#[test]
fn au111_does_not_fire_for_onprem_waf_appliances() {
    // F5 BIG-IP is fingerprinted by the same module but is NOT a global
    // anycast CDN — treating it as "the DNS record isn't the origin" would be
    // an unsupported generalisation, so it must not fire.
    let dom = cdn_fronted_domain("example.com", "F5 BIG-IP");
    let ip = spf_ip("203.0.113.9", "example.com");
    assert!(
        rule_au_111_cdn_origin_candidate(&[dom, ip], "s", 0).is_empty(),
        "an on-premise WAF appliance must not be treated as a DNS-fronting CDN"
    );
}

#[test]
fn au113_no_fire_for_a_generic_subdomain_or_unrelated_domain() {
    // A generic subdomain (no mx tag, no direct-connect label) resolving
    // off-CDN is not evidence of anything — deliberately narrow scope. A
    // domain under a DIFFERENT registrable domain must not cross-match either.
    let apex = Entity::new(EntityKind::Domain, "apex.com", 0.8, "s");
    let cdn_ip = Entity::new(EntityKind::IpAddress, "104.16.5.5", 0.8, "s");
    let mut generic = Entity::new(EntityKind::Domain, "assets.apex.com", 0.8, "s");
    generic.tag("subdomain");
    generic.tag("dns-brute");
    let generic_ip = Entity::new(EntityKind::IpAddress, "45.33.32.156", 0.8, "s");
    let other = Entity::new(EntityKind::Domain, "unrelated.net", 0.8, "s");
    let other_ip = Entity::new(EntityKind::IpAddress, "45.33.32.200", 0.8, "s");

    let ents = vec![
        apex.clone(),
        cdn_ip.clone(),
        generic.clone(),
        generic_ip.clone(),
        other.clone(),
        other_ip.clone(),
    ];
    let rels = vec![
        resolves(&apex, &cdn_ip),
        resolves(&generic, &generic_ip),
        resolves(&other, &other_ip),
    ];

    let r = rule_au_113_direct_connect_origin_candidate(&ents, &rels, "s", 0);
    assert!(
        r.is_empty(),
        "a generic subdomain label / unrelated domain must not fire: {r:?}"
    );
}

#[test]
fn au111_does_not_fire_for_an_unrelated_domains_spf_ip() {
    // The SPF IP is authorised for a DIFFERENT domain than the CDN-fronted
    // one — must not cross-attribute.
    let dom = cdn_fronted_domain("example.com", "Cloudflare");
    let ip = spf_ip("203.0.113.9", "other-site.com");
    assert!(rule_au_111_cdn_origin_candidate(&[dom, ip], "s", 0).is_empty());
}

#[test]
fn au111_ignores_a_non_spf_ip_address() {
    // An IpAddress entity with no `spf` tag (e.g. a plain A record) must not
    // be treated as an origin candidate.
    let dom = cdn_fronted_domain("example.com", "Cloudflare");
    let mut ip = Entity::new(EntityKind::IpAddress, "203.0.113.9", 0.9, "s");
    ip.tag("ipv4");
    ip.add_evidence(
        Evidence::new("dns_intel", "A record for example.com").with_attr("domain", "example.com"),
    );
    assert!(rule_au_111_cdn_origin_candidate(&[dom, ip], "s", 0).is_empty());
}

// ─── AU-112 tests (shared CIDR infrastructure) ────────────────────────────────

fn cidr_block(value: &str) -> Entity {
    Entity::new(EntityKind::Cidr, value, 0.75, "s")
}

fn plain_ip(value: &str) -> Entity {
    let mut ip = Entity::new(EntityKind::IpAddress, value, 0.7, "s");
    ip.tag("banner-grab");
    ip.add_evidence(Evidence::new(
        "banner_grab",
        format!("Open port on {value}"),
    ));
    ip
}

#[test]
fn au112_fires_when_an_independently_discovered_ip_falls_in_a_narrow_block() {
    let block = cidr_block("203.0.113.0/24");
    let ip = plain_ip("203.0.113.42");
    let r = rule_au_112_shared_cidr_infrastructure(&[block.clone(), ip.clone()], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-112");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("203.0.113.42"));
    assert!(r[0].description.contains("203.0.113.0/24"));
    assert_eq!(r[0].entity_uids, vec![block.uid.clone(), ip.uid.clone()]);
}

#[test]
fn au112_does_not_fire_for_an_ip_outside_the_block() {
    let block = cidr_block("203.0.113.0/24");
    let ip = plain_ip("198.51.100.7");
    assert!(rule_au_112_shared_cidr_infrastructure(&[block, ip], "s", 0).is_empty());
}

#[test]
fn au112_does_not_fire_for_a_broad_isp_scale_block() {
    // /16 is well above the MIN_IPV4_CIDR_PREFIX floor — an ISP/cloud
    // allocation spanning thousands of unrelated customers must not fire.
    let block = cidr_block("203.0.0.0/16");
    let ip = plain_ip("203.0.113.42");
    assert!(
        rule_au_112_shared_cidr_infrastructure(&[block, ip], "s", 0).is_empty(),
        "a broad /16 block must not be treated as a shared-infrastructure signal"
    );
}

#[test]
fn au112_does_not_fire_when_already_explicitly_linked() {
    // The `netblock` module already tags a host it expanded from this exact
    // block with a `cidr` evidence attribute — re-deriving that as a fresh
    // AU-112 inference would just restate an already-explicit relationship.
    let block = cidr_block("203.0.113.0/24");
    let mut ip = Entity::new(EntityKind::IpAddress, "203.0.113.42", 0.7, "s");
    ip.tag("netblock-member");
    ip.add_evidence(
        Evidence::new(
            "netblock",
            "Host 203.0.113.42 in network block 203.0.113.0/24",
        )
        .with_attr("cidr", "203.0.113.0/24"),
    );
    assert!(rule_au_112_shared_cidr_infrastructure(&[block, ip], "s", 0).is_empty());
}

#[test]
fn au112_fires_for_a_narrow_ipv6_block() {
    let block = cidr_block("2001:db8:1::/64");
    let ip = plain_ip("2001:db8:1::42");
    let r = rule_au_112_shared_cidr_infrastructure(&[block.clone(), ip.clone()], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].entity_uids, vec![block.uid.clone(), ip.uid.clone()]);
}

#[test]
fn au112_does_not_fire_for_a_broad_ipv6_allocation() {
    // /32 is a typical ISP-scale IPv6 allocation, well above the /48 floor.
    let block = cidr_block("2001:db8::/32");
    let ip = plain_ip("2001:db8:1::42");
    assert!(rule_au_112_shared_cidr_infrastructure(&[block, ip], "s", 0).is_empty());
}

// ─── AU-114 tests (sanctions / debarment / PEP exposure) ──────────────────────

fn flagged_person(name: &str, conf: f64, tag: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Person, name, conf, "s");
    e.tag("opensanctions");
    e.tag(tag);
    e
}

#[test]
fn au114_sanctioned_person_fires_critical() {
    // A definitive opensanctions match carries tags::SANCTIONED at MATCH_CONF
    // (0.60). The highest-consequence OSINT signal must surface as a Critical
    // finding rather than sitting un-named in the graph.
    let e = flagged_person(
        "Designated Test Subject",
        0.60,
        crate::core::tags::SANCTIONED,
    );
    let r = rule_au_114_sanctions_exposure(std::slice::from_ref(&e), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-114");
    assert_eq!(r[0].severity, super::Severity::Critical);
    assert!(r[0].description.contains("sanctions designation"));
    assert!(r[0].description.contains("Designated Test Subject"));
    assert_eq!(r[0].entity_uids, vec![e.uid]);
}

#[test]
fn au114_debarred_only_fires_high() {
    let e = flagged_person("Barred Vendor Pty", 0.60, crate::core::tags::DEBARRED);
    let r = rule_au_114_sanctions_exposure(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("debarred"));
}

#[test]
fn au114_pep_only_fires_medium_and_frames_as_a_lead() {
    // Wikidata's PEP signal (tags::PEP == "pep") is a due-diligence lead, not a
    // determination — it must fire only Medium and never assert guilt.
    let e = flagged_person("Public Office Holder", 0.72, crate::core::tags::PEP);
    let r = rule_au_114_sanctions_exposure(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("politically-exposed"));
    assert!(
        r[0].description.contains("not a legal determination"),
        "a PEP finding must be framed as a signal, not a determination"
    );
}

#[test]
fn au114_takes_the_strongest_flag_when_several_are_present() {
    // A subject both sanctioned AND debarred is graded by the strongest flag
    // (Critical), with every flag enumerated in the description.
    let mut e = flagged_person("Dual Flagged Entity", 0.60, crate::core::tags::SANCTIONED);
    e.tag(crate::core::tags::DEBARRED);
    let r = rule_au_114_sanctions_exposure(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Critical);
    assert!(r[0].description.contains("sanctioned"));
    assert!(r[0].description.contains("debarred"));
}

#[test]
fn au114_surfaces_the_sanctions_programme_from_evidence() {
    let mut e = flagged_person("Programme Listed", 0.60, crate::core::tags::SANCTIONED);
    e.add_evidence(
        Evidence::new("opensanctions", "OpenSanctions match").with_attr("program_id", "US-RUSHAR"),
    );
    let r = rule_au_114_sanctions_exposure(&[e], "s", 0);
    assert_eq!(r.len(), 1);
    assert!(
        r[0].description.contains("US-RUSHAR"),
        "the sanctions programme must be surfaced from evidence, got {:?}",
        r[0].description
    );
}

#[test]
fn au114_does_not_fire_for_an_unflagged_or_low_confidence_entity() {
    // No risk tag → no finding.
    let plain = Entity::new(EntityKind::Person, "Ordinary Person", 0.80, "s");
    assert!(rule_au_114_sanctions_exposure(&[plain], "s", 0).is_empty());
    // Flagged but below the 0.55 definitive-match floor → no finding (a weak,
    // speculative person must never be asserted as sanctioned).
    let weak = flagged_person("Weak Match", 0.40, crate::core::tags::SANCTIONED);
    assert!(
        rule_au_114_sanctions_exposure(&[weak], "s", 0).is_empty(),
        "a sub-floor confidence entity must not fire a sanctions finding"
    );
}

// ─── AU-084 tests (cell tower dual-source) ────────────────────────────────────

fn cell_tower(tower_id: &str, sources: &[&str]) -> Entity {
    let mut e = Entity::new(EntityKind::DeviceId, tower_id, 0.78, "s");
    e.tag(crate::core::tags::CELL_TOWER);
    for src in sources {
        e.add_evidence(Evidence::new(*src, format!("tower {tower_id}")));
    }
    e
}

#[test]
fn au084_fires_when_both_sources_present() {
    use super::rules::rule_au_084_cell_tower_dual_source;
    let ents = vec![cell_tower(
        "505-1-1234-56789",
        &["cell_intel", "opencellid"],
    )];
    let r = rule_au_084_cell_tower_dual_source(&ents, "s", 0);
    assert_eq!(r.len(), 1, "dual-source cell tower must fire AU-084");
    assert_eq!(r[0].rule_id, "AU-084");
}

#[test]
fn au084_does_not_fire_on_single_source() {
    use super::rules::rule_au_084_cell_tower_dual_source;
    let ents = vec![cell_tower("505-1-1234-56789", &["cell_intel"])];
    let r = rule_au_084_cell_tower_dual_source(&ents, "s", 0);
    assert!(r.is_empty(), "single-source tower must not fire AU-084");
}

#[test]
fn au084_medium_severity_for_three_or_more_towers() {
    use super::rules::rule_au_084_cell_tower_dual_source;
    let ents = vec![
        cell_tower("505-1-1234-11111", &["cell_intel", "opencellid"]),
        cell_tower("505-1-1234-22222", &["cell_intel", "opencellid"]),
        cell_tower("505-1-1234-33333", &["cell_intel", "opencellid"]),
    ];
    let r = rule_au_084_cell_tower_dual_source(&ents, "s", 0);
    assert_eq!(r.len(), 1, "three dual-source towers must fire one AU-084");
    assert_eq!(r[0].severity, Severity::Medium);
}

#[test]
fn au084_ignores_non_cell_tower_device_ids() {
    use super::rules::rule_au_084_cell_tower_dual_source;
    let mut e = Entity::new(EntityKind::DeviceId, "aa:bb:cc:dd:ee:ff", 0.8, "s");
    e.add_evidence(Evidence::new("cell_intel", "mac addr"));
    e.add_evidence(Evidence::new("opencellid", "mac addr"));
    // No cell-tower tag → must not fire.
    let r = rule_au_084_cell_tower_dual_source(&[e], "s", 0);
    assert!(r.is_empty(), "non-cell-tower DeviceId must not fire AU-084");
}

#[test]
fn au076_email_username_localpart_bridge_fires_on_canonical_match() {
    use super::rules::rule_au_076_email_username_localpart_bridge;
    // Local part "haigen_bamford" strips separators → "haigenbamford".
    // Username "haigen.bamford" also strips → "haigenbamford". They match.
    let mut email = Entity::new(EntityKind::Email, "haigen_bamford@acme.com", 0.9, "s");
    email.add_evidence(Evidence::new("breach", "x".to_string()));
    let mut uname = Entity::new(EntityKind::Username, "haigen.bamford", 0.8, "s");
    uname.add_evidence(Evidence::new("github_user", "x".to_string()));
    let r = rule_au_076_email_username_localpart_bridge(&[email, uname], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-076 must fire when local-part canonicalises to a username"
    );
    assert_eq!(r[0].rule_id, "AU-076");
    assert_eq!(r[0].severity, super::Severity::High);
}

#[test]
fn au076_consolidates_permutation_flood_into_one_per_canonical_handle() {
    use super::rules::rule_au_076_email_username_localpart_bridge;
    // A name seed's flood: many email forms + many username forms that all
    // canonicalise to the SAME handle "matthewdiegmann". A naive per-pair emission
    // would fire len(emails)×len(usernames) High findings; consolidation must emit
    // exactly ONE, listing every form, with no value lost.
    let mut ents = Vec::new();
    for host in ["yahoo.com", "msn.com", "gmail.com", "outlook.com"] {
        ents.push(Entity::new(
            EntityKind::Email,
            format!("matthew.diegmann@{host}"),
            0.3,
            "s",
        ));
    }
    for u in ["matthew.diegmann", "matthewdiegmann", "matthew_diegmann"] {
        ents.push(Entity::new(EntityKind::Username, u, 0.3, "s"));
    }
    let r = rule_au_076_email_username_localpart_bridge(&ents, "s", 0);
    assert_eq!(
        r.len(),
        1,
        "the 4×3 permutation flood must consolidate to ONE finding, got {}",
        r.len()
    );
    assert_eq!(r[0].rule_id, "AU-076");
    assert_eq!(r[0].severity, super::Severity::High);
    // No value is lost: the consolidated finding names every form and links them.
    assert!(r[0].description.contains("matthewdiegmann"));
    assert!(r[0].description.contains("4 email form"));
    assert!(r[0].description.contains("3 username form"));
    // All 7 contributing entities are referenced for pivoting.
    assert_eq!(r[0].entity_uids.len(), 7);
}

#[test]
fn au077_name_derived_username_confirmed_fires_on_predict_plus_confirm() {
    use super::rules::rule_au_077_name_derived_username_confirmed;
    // Username that was BOTH predicted by name_intel and confirmed by github_user.
    let mut u = Entity::new(EntityKind::Username, "hbamford", 0.8, "s");
    u.add_evidence(Evidence::new(
        "name_intel",
        "Derived from Haigen Bamford".to_string(),
    ));
    u.add_evidence(Evidence::new(
        "github_user",
        "Found profile github.com/hbamford".to_string(),
    ));
    let r = rule_au_077_name_derived_username_confirmed(&[u], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-077 must fire when derivation + live confirmation coexist"
    );
    assert_eq!(r[0].rule_id, "AU-077");
    assert_eq!(r[0].severity, super::Severity::High);
    // A username with only derivation (no discovery) must NOT fire.
    let mut derived_only = Entity::new(EntityKind::Username, "hbamford2", 0.8, "s");
    derived_only.add_evidence(Evidence::new("name_intel", "Derived handle".to_string()));
    let r2 = rule_au_077_name_derived_username_confirmed(&[derived_only], "s", 0);
    assert!(r2.is_empty(), "derivation alone must not fire AU-077");
}

#[test]
fn au086_name_derived_email_confirmed_fires_on_predict_plus_confirm() {
    use super::rules::rule_au_086_name_derived_email_confirmed;
    // An email name_intel permuted from the subject AND confirmed by a breach
    // corpus (HIBP) — the "guessed address verified real" signal.
    let mut e = Entity::new(EntityKind::Email, "moale.mcknight@gmail.com", 0.30, "s");
    e.tag("name-derived");
    e.add_evidence(Evidence::new(
        "name_intel",
        "Speculative email permuted from name",
    ));
    e.add_evidence(Evidence::new("hibp", "found in 2 breaches"));
    let r = rule_au_086_name_derived_email_confirmed(&[e], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-086 must fire on derivation + breach confirmation"
    );
    assert_eq!(r[0].rule_id, "AU-086");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("hibp"));

    // Derivation alone (an unconfirmed permutation) must NOT fire.
    let mut guess = Entity::new(EntityKind::Email, "mmcknight@gmail.com", 0.30, "s");
    guess.tag("name-derived");
    guess.add_evidence(Evidence::new("name_intel", "permuted"));
    assert!(
        rule_au_086_name_derived_email_confirmed(&[guess], "s", 0).is_empty(),
        "an unconfirmed permutation must not fire AU-086"
    );

    // A real (non-derived) breach email must not fire either — the rule is about
    // confirming a PREDICTION, not flagging every breached address.
    let mut found = Entity::new(EntityKind::Email, "someone@corp.com", 0.72, "s");
    found.add_evidence(Evidence::new("hibp", "breached"));
    assert!(
        rule_au_086_name_derived_email_confirmed(&[found], "s", 0).is_empty(),
        "a non-derived breach email must not fire AU-086"
    );
}

#[test]
fn au078_hub_entity_fires_for_hub_tagged_entity() {
    use super::rules::rule_au_078_hub_entity;
    let mut e = Entity::new(EntityKind::Email, "repeat@example.com", 0.9, "s");
    e.add_evidence(Evidence::new("history", "x".to_string()));
    e.tag("hub-entity");
    let r = rule_au_078_hub_entity(&[e], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-078 must fire for hub-entity tagged entities"
    );
    assert_eq!(r[0].rule_id, "AU-078");
    assert_eq!(r[0].severity, super::Severity::Medium);
    // Untagged entity must NOT fire.
    let plain = Entity::new(EntityKind::Email, "other@example.com", 0.9, "s");
    let r2 = rule_au_078_hub_entity(&[plain], "s", 0);
    assert!(r2.is_empty(), "untagged entity must not fire AU-078");
}

#[test]
fn au079_bio_cross_mention_fires_on_structured_twitter_attr() {
    use super::rules::rule_au_079_bio_cross_mention;
    // GitHub entity carries a `twitter` attribute pointing to another username.
    let mut gh = Entity::new(EntityKind::Username, "hbamford_github", 0.85, "s");
    let ev = Evidence::new("github_user", "GitHub profile".to_string())
        .with_attr("twitter", "hbamford_tw");
    gh.add_evidence(ev);
    // The referenced Twitter handle is also in the scan as a Username entity.
    let mut tw = Entity::new(EntityKind::Username, "hbamford_tw", 0.80, "s");
    tw.add_evidence(Evidence::new("social_probe", "Twitter profile".to_string()));
    let r = rule_au_079_bio_cross_mention(&[gh, tw], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-079 must fire when twitter attr names a known username"
    );
    assert_eq!(r[0].rule_id, "AU-079");
    assert_eq!(r[0].severity, super::Severity::High);
}

#[test]
fn au079_bio_cross_mention_fires_on_at_mention_in_bio() {
    use super::rules::rule_au_079_bio_cross_mention;
    let mut gh = Entity::new(EntityKind::Username, "hbamford", 0.85, "s");
    let ev = Evidence::new("github_user", "GitHub profile".to_string())
        .with_attr("bio", "Find me on Reddit: @hbamford_reddit");
    gh.add_evidence(ev);
    let mut reddit = Entity::new(EntityKind::Username, "hbamford_reddit", 0.80, "s");
    reddit.add_evidence(Evidence::new("reddit_user", "Reddit profile".to_string()));
    let r = rule_au_079_bio_cross_mention(&[gh, reddit], "s", 0);
    assert!(!r.is_empty(), "AU-079 must fire on @-mention in bio");
    assert_eq!(r[0].rule_id, "AU-079");
    // Must NOT fire linking entity to itself (no self-loop)
    let no_self: Vec<_> = r
        .iter()
        .filter(|c| c.entity_uids[0] == c.entity_uids[1])
        .collect();
    assert!(
        no_self.is_empty(),
        "AU-079 must never produce a self-loop correlation"
    );
}

#[test]
fn au080_recurring_cooccurrence_link_fires_on_tagged_pair() {
    use super::rules::rule_au_080_recurring_cooccurrence_link;
    let mut a = Entity::new(EntityKind::Email, "alice@example.com", 0.9, "s");
    // The co-occurrence summary format exactly matches COOCCURRENCE_MARKER prefix.
    a.add_evidence(Evidence::new(
        "cross_scan_history",
        "Co-occurred with `bob@example.com` across 2 earlier scan(s) in the local \
         intelligence database — a recurring association that bridges investigations"
            .to_string(),
    ));
    a.tag("cross-scan-cooccurrence");
    let mut b = Entity::new(EntityKind::Email, "bob@example.com", 0.9, "s");
    b.add_evidence(Evidence::new("breach", "Breach record".to_string()));
    let r = rule_au_080_recurring_cooccurrence_link(&[a, b], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-080 must fire when a co-occurrence partner is present"
    );
    assert_eq!(r[0].rule_id, "AU-080");
    assert_eq!(r[0].severity, super::Severity::Medium);
    // Hub-level (≥3 scans) escalates to High
    let mut a2 = Entity::new(EntityKind::Email, "alice2@example.com", 0.9, "s");
    a2.add_evidence(Evidence::new(
        "cross_scan_history",
        "Co-occurred with `bob2@example.com` across 3 earlier scan(s) in the local \
         intelligence database — a recurring association that bridges investigations"
            .to_string(),
    ));
    a2.tag("cross-scan-cooccurrence");
    a2.tag("hub-cooccurrence");
    let b2 = Entity::new(EntityKind::Email, "bob2@example.com", 0.9, "s");
    let r2 = rule_au_080_recurring_cooccurrence_link(&[a2, b2], "s", 0);
    assert!(
        !r2.is_empty(),
        "AU-080 must fire for hub-level co-occurrence"
    );
    assert_eq!(
        r2[0].severity,
        super::Severity::High,
        "hub-level must be High severity"
    );
}

#[test]
fn au081_canonical_person_name_match_fires_on_cross_source_same_name() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Two Person entities: one from a breach (family "breach"), one from a social
    // profile (family "social"). Same canonical name, different source families.
    let mut breach_p = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    breach_p.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social_p = Entity::new(EntityKind::Person, "HAIGEN BAMFORD", 0.75, "s");
    social_p.add_evidence(Evidence::new("social_probe", "Social profile".to_string()));
    let r = rule_au_081_canonical_person_name_match(&[breach_p, social_p], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-081 must fire for same-name persons from different source families"
    );
    assert_eq!(r[0].rule_id, "AU-081");
    assert_eq!(r[0].severity, super::Severity::High);
    // "Last, First" vs "First Last" must also match
    let mut breach2 = Entity::new(EntityKind::Person, "Bamford, Haigen", 0.8, "s");
    breach2.add_evidence(Evidence::new("dehashed", "Breach record".to_string()));
    let mut social2 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.75, "s");
    social2.add_evidence(Evidence::new("github_user", "GitHub profile".to_string()));
    let r2 = rule_au_081_canonical_person_name_match(&[breach2, social2], "s", 0);
    assert!(
        !r2.is_empty(),
        "AU-081 must match 'Last, First' vs 'First Last' format"
    );
    // Same source must NOT fire
    let mut dup1 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    dup1.add_evidence(Evidence::new("name_intel", "Derived".to_string()));
    let mut dup2 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    dup2.add_evidence(Evidence::new("name_intel", "Derived".to_string()));
    let r3 = rule_au_081_canonical_person_name_match(&[dup1, dup2], "s", 0);
    assert!(
        r3.is_empty(),
        "AU-081 must not fire for identical source sets"
    );
}

#[test]
fn au081_same_family_different_databases_is_not_independent() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Two Person records with the SAME canonical name, from two DIFFERENT breach
    // databases (`dehashed` and `leakcheck`). Their source strings differ, but
    // `source_family` maps both to "breach" — so they are co-derived, not
    // independent, and the family gate must suppress the match. (Guards the
    // independence contract: distinct database names alone are not independence.)
    let mut dehashed_p = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    dehashed_p.add_evidence(Evidence::new("dehashed", "Breach record".to_string()));
    let mut leakcheck_p = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    leakcheck_p.add_evidence(Evidence::new("leakcheck", "Breach record".to_string()));
    let r = rule_au_081_canonical_person_name_match(&[dehashed_p, leakcheck_p], "s", 0);
    assert!(
        r.is_empty(),
        "two databases of the same source family are not independent — must not fire"
    );
}

#[test]
fn au081_common_name_is_a_medium_lead_not_a_high_assert() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Two independently-sourced "John Smith" records — a breach dump and a
    // proxycurl profile. The rule cannot tell whether these are one person or
    // two unrelated strangers who happen to share the single most common
    // full-name shape in the anglophone world. Asserting High "same
    // individual" there is a confident false merge; it must be a Medium lead
    // to VERIFY instead. ("smith" is in COMMON_SURNAMES.)
    let mut breach_p = Entity::new(EntityKind::Person, "John Smith", 0.8, "s");
    breach_p.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social_p = Entity::new(EntityKind::Person, "Smith John", 0.75, "s");
    social_p.add_evidence(Evidence::new("proxycurl", "LinkedIn profile".to_string()));
    let r = rule_au_081_canonical_person_name_match(&[breach_p, social_p], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-081 must still fire on a shared canonical name — the discount \
         changes severity, not whether the lead surfaces"
    );
    assert_eq!(
        r[0].severity,
        super::Severity::Medium,
        "a common full name is a high-volume coincidence — must be a Medium \
         lead, not a High identity assertion"
    );
    assert!(
        r[0].description.contains("VERIFY"),
        "a common-name match must be phrased as a lead to verify, not a merge: {}",
        r[0].description
    );

    // Control: a DISTINCTIVE full name (no common token) stays a High
    // identity bridge — the discount must not blunt genuine matches.
    let mut breach_d = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    breach_d.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let mut social_d = Entity::new(EntityKind::Person, "Bamford Haigen", 0.75, "s");
    social_d.add_evidence(Evidence::new("proxycurl", "LinkedIn profile".to_string()));
    let rd = rule_au_081_canonical_person_name_match(&[breach_d, social_d], "s", 0);
    assert!(!rd.is_empty(), "AU-081 must fire on the distinctive name");
    assert_eq!(
        rd[0].severity,
        super::Severity::High,
        "a distinctive full name must remain a High identity bridge"
    );
    assert!(
        rd[0].description.contains("same individual"),
        "a distinctive-name match keeps the confident 'same individual' wording: {}",
        rd[0].description
    );
}

#[test]
fn au081_tool_derived_name_is_not_independent_corroboration() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // The manufactured-corroboration hole: one Person is a REAL record from a
    // code-hosting profile (`github_user` → family "code"); the other carries the
    // SAME canonical name but its ONLY evidence is `name_intel` — the tool's own
    // firstname/lastname permutation of the seed (a non-corroborating enrichment
    // pass that maps to the real "identity_registry" family). Their source
    // strings differ AND their families differ, so the old raw-`evidence` gates
    // both passed and AU-081 fired a High "independently-sourced records for the
    // same individual". But `name_intel` did not independently OBSERVE anyone — it
    // derived the name from the seed — so this is the tool corroborating itself.
    // The finding must NOT fire.
    let mut real = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    real.add_evidence(Evidence::new("github_user", "GitHub profile".to_string()));
    let mut derived = Entity::new(EntityKind::Person, "Bamford, Haigen", 0.7, "s");
    derived.add_evidence(Evidence::new("name_intel", "Derived from name".to_string()));
    let r = rule_au_081_canonical_person_name_match(&[real, derived], "s", 0);
    assert!(
        r.is_empty(),
        "a name known only from the tool's own derivation (name_intel) is not an \
         independent record — AU-081 must not manufacture corroboration from it"
    );
}

#[test]
fn au081_still_fires_when_a_genuine_second_source_is_also_name_enriched() {
    use super::rules::rule_au_081_canonical_person_name_match;
    // Control for the fix: a legitimate cross-source match must survive even when
    // `name_intel` ALSO enriched one side. `e1` carries a REAL code-hosting source
    // (`github_user` → "code") PLUS the tool's `name_intel` derivation; `e2` is a
    // REAL breach record (`oathnet_pro` → "breach"). After filtering the
    // non-corroborating `name_intel`, both sides still hold a genuine, distinct
    // source family (code vs breach), so the match is real and must fire — the fix
    // refuses `name_intel` as the SOLE independence, it does not blunt a real one.
    let mut e1 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.8, "s");
    e1.add_evidence(Evidence::new("github_user", "GitHub profile".to_string()));
    e1.add_evidence(Evidence::new("name_intel", "Derived from name".to_string()));
    let mut e2 = Entity::new(EntityKind::Person, "Bamford Haigen", 0.75, "s");
    e2.add_evidence(Evidence::new("oathnet_pro", "Breach record".to_string()));
    let r = rule_au_081_canonical_person_name_match(&[e1, e2], "s", 0);
    assert!(
        !r.is_empty(),
        "a genuine code+breach cross-source match must still fire even when \
         name_intel also enriched one side"
    );
    assert_eq!(r[0].severity, super::Severity::High);
    // The human-readable label must name the genuine source, never `name_intel`.
    assert!(
        r[0].description.contains("github_user") && !r[0].description.contains("name_intel"),
        "the match must be labelled by its genuine source, not the enrichment pass: {}",
        r[0].description
    );
}

#[test]
fn au082_api_key_dual_pathway_fires_on_code_plus_breach() {
    use super::rules::rule_au_082_api_key_dual_pathway;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    // Same API key found in a code repo (github_code_search → code family)
    // and in a breach pool (oathnet_pro → breach family).
    let mut e = Entity::new(EntityKind::ApiKey, "sk-realkey-abc123xyz", 0.85, "s");
    e.add_evidence(Evidence::new(
        "github_code_search",
        "Found in public repository".to_string(),
    ));
    e.add_evidence(Evidence::new(
        "oathnet_pro",
        "Found in stealer log".to_string(),
    ));
    let r = rule_au_082_api_key_dual_pathway(&[e], "s", 0);
    assert!(
        !r.is_empty(),
        "AU-082 must fire when same API key appears in code+breach families"
    );
    assert_eq!(r[0].rule_id, "AU-082");
    assert_eq!(r[0].severity, super::Severity::Critical);
    // Single-family key must NOT fire AU-082 (AU-021 handles that).
    let mut single = Entity::new(EntityKind::ApiKey, "sk-only-breach", 0.85, "s");
    single.add_evidence(Evidence::new("oathnet_pro", "Stealer".to_string()));
    let r2 = rule_au_082_api_key_dual_pathway(&[single], "s", 0);
    assert!(
        r2.is_empty(),
        "AU-082 must not fire for a single-family API key"
    );
}

#[test]
fn au082_does_not_fire_on_a_recall_replay_of_the_same_sighting() {
    // Regression: a single genuine sighting (github_code_search → "code") plus
    // the SAME observation re-attached by the `recall` replay pass (a prior
    // scan's evidence re-injected, not a new independent sighting) must NOT
    // read as a second "source family". Before the fix, `recall` fell through
    // to the unclassified "other" bucket, so `{code, other}.len() >= 2`
    // trivially fired a false Critical "dual-pathway... key was already
    // circulating outside the original leak" alert from one real sighting.
    use super::rules::rule_au_082_api_key_dual_pathway;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut e = Entity::new(EntityKind::ApiKey, "sk-realkey-abc123xyz", 0.85, "s");
    e.add_evidence(Evidence::new(
        "github_code_search",
        "Found in public repository".to_string(),
    ));
    e.add_evidence(Evidence::new(
        crate::core::entity::RECALL_SOURCE,
        "Recalled from a prior scan".to_string(),
    ));
    let r = rule_au_082_api_key_dual_pathway(&[e], "s", 0);
    assert!(
        r.is_empty(),
        "a recall replay of the same sighting must not manufacture a second \
         source family: {r:?}"
    );

    // A deterministic enrichment pass riding along (geo_normalize/name_intel/
    // payid) must be excluded too — it's a derivation of the input, not an
    // independent observation.
    let mut e2 = Entity::new(EntityKind::ApiKey, "sk-anotherkey-def456", 0.85, "s");
    e2.add_evidence(Evidence::new(
        "github_code_search",
        "Found in public repository".to_string(),
    ));
    e2.add_evidence(Evidence::new("payid", "Derived enrichment".to_string()));
    let r2 = rule_au_082_api_key_dual_pathway(&[e2], "s", 0);
    assert!(
        r2.is_empty(),
        "an enrichment-pass evidence entry must not manufacture a second \
         source family: {r2:?}"
    );
}

#[test]
fn correlator_budget_stops_starting_new_rules_past_the_deadline() {
    use super::{evaluate_relation_rules_on, evaluate_rules_on};
    // A confirmed entity that WOULD produce correlations under several rules.
    let mut e = Entity::new(EntityKind::Email, "moale.mcknight@gmail.com", 0.72, "s");
    e.tag("name-derived");
    e.add_evidence(Evidence::new("name_intel", "permuted"));
    e.add_evidence(Evidence::new("hibp", "breached"));
    let ents = vec![e];

    // No deadline → rules run normally (AU-086 fires for this predict+confirm email).
    let full = evaluate_rules_on(&ents, "s", 0, None);
    assert!(
        full.iter().any(|c| c.rule_id == "AU-086"),
        "without a budget the confirmed name-derived email must fire AU-086"
    );

    // A deadline already in the past → no rule is started, empty result, no hang.
    let past = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
    assert!(
        evaluate_rules_on(&ents, "s", 0, past).is_empty(),
        "an elapsed budget must stop the entity-rule pass immediately"
    );
    assert!(
        evaluate_relation_rules_on(&ents, &[], "s", 0, past).is_empty(),
        "an elapsed budget must stop the relation-rule pass immediately"
    );
}

#[test]
fn readme_correlator_rule_count_matches_the_registry() {
    // The README's headline "N correlator rules" is hand-maintained and had
    // drifted badly (it read 74 / "AU-001 through AU-086" against a real total of
    // 110 / AU-112). Pin it to the live dispatch tables — `RULES` (entity rules)
    // plus `RELATION_RULES` (graph-aware rules) — so adding a rule without
    // updating the README fails CI, the same guard the module count already has.
    // Lives here (a `core::correlator` unit test) because both tables are private
    // to this module; the integration `tests/architecture.rs` can't see them.
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("README.md must exist at the crate root");
    let n = RULES.len() + RELATION_RULES.len();
    let idx = readme
        .find("correlator rules")
        .expect("README must state the correlator rule count as 'N correlator rules'");
    // The integer immediately preceding "correlator rules" (commas stripped).
    let stated: usize = readme[..idx]
        .trim_end()
        .rsplit(|c: char| !c.is_ascii_digit() && c != ',')
        .next()
        .unwrap_or_default()
        .replace(',', "")
        .parse()
        .expect("a numeric rule count must immediately precede 'correlator rules' in README");
    assert_eq!(
        stated,
        n,
        "README says {stated} correlator rules but the registry dispatches {n} \
         (RULES {} + RELATION_RULES {}); update the count in README.md",
        RULES.len(),
        RELATION_RULES.len()
    );
}

// ─── Bench-only entry points (F.3 / SOL-F3) ────────────────────────────────
//
// `bench_synthetic_entities`/`bench_correlate_entities` are wholly new `pub`
// surface added solely so `benches/correlation_pass.rs` (a separate
// compilation unit that only sees this crate's public API) can reach the
// `pub(crate)` correlation pass. Git-stash-provable: the pre-fix tree has
// neither function, so these tests fail to compile against it — the
// strongest possible regression signal for wholly new code, the same
// precedent the 2026-07-14 cargo-fuzz cycle established for
// `fuzz_entry_parse_der`.

/// Canonical JSON encoding of an entity set for equality comparison, with
/// every live-clock field zeroed first: each `Entity::observed_at` and every
/// `Evidence::recorded_at` in its evidence chain.
///
/// Both are stamped from the real wall clock (`unix_now()`, inside
/// `Entity::new`/`Evidence::new`) — `bench_synthetic_entities` calls both for
/// every entity it builds, so despite its own doc comment's "pure and
/// deterministic (no RNG)" claim, two calls a moment apart legitimately
/// produce different `observed_at`/`recorded_at` whenever they straddle a
/// real second boundary. This is the identical bug class
/// [`ts_blind_json`] fixes for `Correlation` just below (see its doc
/// comment for the live-reproduced CI failure this whole family of fixes
/// responds to) — found by checking this file's OTHER full-JSON-equality
/// determinism test for the same latent flakiness rather than assuming it
/// was fine, and confirmed real the same way: forcing a real 1.1s sleep
/// between two calls reliably fails the raw (pre-fix) comparison here too.
fn ts_blind_entities_json(ents: &[Entity]) -> String {
    let blinded: Vec<Entity> = ents
        .iter()
        .cloned()
        .map(|mut e| {
            e.observed_at = 0;
            for ev in &mut e.evidence {
                ev.recorded_at = 0;
            }
            e
        })
        .collect();
    serde_json::to_string(&blinded).unwrap()
}

#[test]
fn bench_synthetic_entities_yields_exactly_n_deterministic_entities() {
    for &n in &[0usize, 1, 4, 37, 200] {
        let a = bench_synthetic_entities(n);
        let b = bench_synthetic_entities(n);
        assert_eq!(
            a.len(),
            n,
            "bench_synthetic_entities({n}) must yield exactly n entities"
        );
        // Neither `Entity` nor `Correlation` derive `PartialEq` (large,
        // evolving structs — see e.g. line ~366's precedent), so compare via
        // their canonical JSON encoding, same as this file already does
        // elsewhere for structural equality — `ts`-blind, see
        // `ts_blind_entities_json`'s own doc comment for why.
        assert_eq!(
            ts_blind_entities_json(&a),
            ts_blind_entities_json(&b),
            "bench_synthetic_entities is documented pure/deterministic (no RNG) — \
             two calls at the same n must produce identical entities (bar the real \
             wall-clock observed_at/recorded_at stamps), or bench-to-bench \
             comparisons and the perf-guard ratio assertion it also feeds \
             (core::correlator::perf) would be meaningless"
        );
    }
}

#[test]
fn bench_synthetic_entities_is_ts_blind_deterministic_across_a_real_second_boundary() {
    // Same forced-race technique as `bench_correlate_entities_is_ts_blind_
    // deterministic_across_a_real_second_boundary` just below — see its doc
    // comment for why a real sleep past a real clock boundary, not a
    // mocked/injected clock.
    let a = bench_synthetic_entities(200);
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let b = bench_synthetic_entities(200);

    assert_ne!(
        a.first().map(|e| e.observed_at),
        b.first().map(|e| e.observed_at),
        "this test's whole point is to force a real second-boundary crossing \
         between the two calls — if observed_at didn't move, the sleep isn't \
         doing its job and this test isn't actually proving anything"
    );
    assert_eq!(
        ts_blind_entities_json(&a),
        ts_blind_entities_json(&b),
        "entity content must stay identical even when the two calls land in \
         different wall-clock seconds"
    );
}

/// Canonical JSON encoding of a correlation set for equality comparison,
/// with every `ts` zeroed first.
///
/// `ts` is stamped from the real wall clock (`unix_now()`, called fresh
/// inside `evaluate_rules` on every invocation) — it legitimately differs
/// between two calls made a moment apart, whenever they happen to straddle
/// a real second boundary. That's correct behaviour for a field that
/// records *when* a correlation fired, not a determinism defect in the
/// rules themselves. Live-reproduced on 2026-07-15: a real GitHub Actions
/// run failed `bench_correlate_entities_matches_the_internal_pass_and_is_
/// deterministic` with `left`/`right` differing in exactly one respect —
/// every one of 106 findings carried `ts=1784092984` on one side and
/// `ts=1784092985` on the other (rule firings, descriptions, entity_uids,
/// ranks, and ordering were all byte-identical) — because the runner was
/// briefly slow enough for two back-to-back calls to cross a real second.
/// The property this file actually needs to guarantee — that the RULES'
/// decisions (which fire, on which entities, in which order, ranked how)
/// are a pure function of the input — holds regardless; comparing through
/// this `ts`-blind view is what actually tests that, without also
/// asserting something about the OS clock that was never the point.
/// Neither `Correlation` nor `Entity` derive `PartialEq` (see this file's
/// header comment), so equality is still via canonical JSON, same
/// precedent as every other struct-equality check here — just of a
/// `ts`-blind clone rather than the raw value.
fn ts_blind_json(corrs: &[Correlation]) -> String {
    let blinded: Vec<Correlation> = corrs
        .iter()
        .cloned()
        .map(|mut c| {
            c.ts = 0;
            c
        })
        .collect();
    serde_json::to_string(&blinded).unwrap()
}

#[test]
fn bench_correlate_entities_matches_the_internal_pass_and_is_deterministic() {
    let ents = bench_synthetic_entities(200);
    // Delegates straight to `correlate_entities` — must produce byte-identical
    // output (bar the real wall-clock `ts`, see `ts_blind_json`) to calling
    // the internal pass directly, not a divergent copy.
    let via_bench = bench_correlate_entities(&ents, "scan");
    let via_internal = correlate_entities(&ents, "scan");
    assert_eq!(
        ts_blind_json(&via_bench),
        ts_blind_json(&via_internal),
        "bench_correlate_entities must be a pure delegation to correlate_entities, \
         not an independently-drifting copy"
    );
    // Determinism-by-construction (docs/CONVENTIONS.md §5): running the pass
    // twice over the same input must yield identical rule decisions — the
    // property the criterion bench and the perf module's
    // `pass_is_subquadratic` guard both implicitly rely on when comparing
    // timings/ratios across runs.
    let again = bench_correlate_entities(&ents, "scan");
    assert_eq!(
        ts_blind_json(&via_bench),
        ts_blind_json(&again),
        "the correlation pass must be deterministic across repeated calls on \
         identical input"
    );
    assert!(
        !bench_correlate_entities(&ents, "scan").is_empty(),
        "the representative synthetic set (shared handles, breach/stealer tags) \
         must exercise at least one firing rule, or the bench would be timing an \
         early-exit no-op rather than real correlation work"
    );
}

#[test]
fn bench_correlate_entities_is_ts_blind_deterministic_across_a_real_second_boundary() {
    // Directly, reliably reproduces the 2026-07-15 live CI failure above
    // instead of relying on the two calls happening to straddle a wall-clock
    // second by luck: sleeps a real 1.1s (guaranteeing `unix_now()`, which
    // truncates to whole seconds, advances by at least one full second
    // between the calls) and confirms `ts` DOES genuinely differ — proving
    // this test is actually exercising the race, not accidentally passing —
    // while the `ts`-blind view stays equal. A real sleep past a real clock
    // boundary, not a mocked/injected clock: the same "exercise real
    // behaviour, don't fake it" discipline this file uses for its other
    // timing-sensitive coverage.
    let ents = bench_synthetic_entities(200);
    let first = correlate_entities(&ents, "scan");
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let second = correlate_entities(&ents, "scan");

    assert_ne!(
        first.first().map(|c| c.ts),
        second.first().map(|c| c.ts),
        "this test's whole point is to force a real second-boundary crossing \
         between the two calls — if ts didn't move, the sleep isn't doing its \
         job and this test isn't actually proving anything"
    );
    assert_eq!(
        ts_blind_json(&first),
        ts_blind_json(&second),
        "rule firings/attribution/ranking must stay identical even when the \
         two calls land in different wall-clock seconds"
    );
}
