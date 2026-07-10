//! Unit tests for the scan engine.
//!
//! Split out of the module file (mechanical, behaviour-preserving) so the
//! source reads as implementation; tests reach private items via `use super::*`.

use super::*;

#[test]
fn consolidate_address_localities_folds_postcode_variants_codebase_wide() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // Two granularities of ONE suburb, from DIFFERENT modules (as if one came
    // from search_engines and the postcode form from a geocode API in a later
    // expansion round) — plus a genuinely different locality that must survive.
    let mut bare = Entity::new(EntityKind::Address, "Murrumbateman, NSW", 0.45, "s");
    bare.add_evidence(Evidence::new("search_engines", "near truelocal"));
    let mut withpc = Entity::new(EntityKind::Address, "Murrumbateman, NSW 2582", 0.50, "s");
    withpc.add_evidence(Evidence::new("geocode", "geocoded"));
    let other = Entity::new(EntityKind::Address, "Brisbane, QLD 4000", 0.45, "s");
    let unrelated = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");

    let mut entities = vec![bare, withpc, other, unrelated];
    consolidate_address_localities(&mut entities);

    let addrs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    // The two Murrumbateman variants collapse to ONE; Brisbane survives → 2.
    assert_eq!(addrs.len(), 2, "postcode variants must fold: {addrs:?}");
    let murrum = addrs
        .iter()
        .find(|e| e.value.contains("Murrumbateman"))
        .expect("murrumbateman survives");
    // The most-specific (postcode-bearing) spelling is kept...
    assert_eq!(murrum.value, "Murrumbateman, NSW 2582");
    // ...and BOTH sources' evidence folded in (confidence took the max).
    let srcs: std::collections::BTreeSet<&str> =
        murrum.evidence.iter().map(|e| e.source.as_str()).collect();
    assert!(srcs.contains("search_engines") && srcs.contains("geocode"));
    assert!((murrum.confidence - 0.50).abs() < 1e-9);
    // The unrelated email is untouched.
    assert!(entities.iter().any(|e| e.kind == EntityKind::Email));
}

/// Free, offline cross-angle confirmation: a lone single-source family-candidate
/// near the subject's confirmed location is promoted (tagged + corroborated) into
/// a reliable relative, while a far namesake is left alone — and the pass is
/// idempotent across re-runs.
#[test]
fn promote_geo_corroborated_family_lifts_only_in_area_relatives() {
    use crate::core::entity::{Classification, Entity, EntityKind, Evidence};

    // Subject's confirmed GPS near Woodford, QLD.
    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
    // A single-source (QLD register) family-candidate near the subject.
    let mut erik = Entity::new(EntityKind::Person, "Erik Moreau", 0.32, "s");
    erik.tag("family-candidate");
    erik.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "4518"));
    assert_eq!(
        erik.classify(),
        Classification::Candidate,
        "starts as a lone candidate"
    );
    // A far relative (Cairns) — same surname, but not the subject's area.
    let mut far = Entity::new(EntityKind::Address, "QLD 4870, Australia", 0.32, "s");
    far.tag("family-candidate");
    far.add_evidence(Evidence::new("qld_unclaimed", "owner"));

    let mut ents = vec![gps, erik, far];
    assert_eq!(
        promote_geo_corroborated_family(&mut ents),
        1,
        "only the in-area relative is promoted"
    );

    let erik = ents.iter().find(|e| e.value == "Erik Moreau").unwrap();
    assert!(erik.has_tag("geo-corroborated"));
    assert!(
        erik.evidence
            .iter()
            .any(|ev| ev.source == "geo_corroboration")
    );
    assert_eq!(
        erik.source_count(),
        2,
        "qld register + geo confirmation = two independent signals"
    );
    assert!(
        erik.c_effective() > 0.50,
        "lifted above candidate → reliable"
    );
    assert_eq!(erik.classify(), Classification::Probable);

    let far = ents.iter().find(|e| e.value.contains("4870")).unwrap();
    assert!(
        !far.has_tag("geo-corroborated"),
        "a far namesake stays a candidate"
    );

    // Idempotent: a second pass (or a recall on a re-scan) promotes nothing new.
    assert_eq!(promote_geo_corroborated_family(&mut ents), 0);

    // No confirmed subject fix → nothing is promoted.
    let mut lone = vec![{
        let mut e = Entity::new(EntityKind::Address, "QLD 4518, Australia", 0.32, "s");
        e.tag("family-candidate");
        e
    }];
    assert_eq!(promote_geo_corroborated_family(&mut lone), 0);
}

/// People-centric "return to old data": a breach candidate whose locality
/// resolves to the subject's confirmed metro AND whose own row name shares the
/// subject's surname is re-promoted out of namesake quarantine. A same-surname
/// record in a different state stays quarantined (geo gate); a SAME-metro record
/// with a DIFFERENT surname also stays quarantined (name gate — the stranger the
/// old geo-only pass wrongly fused onto the subject). The pass is non-circular
/// (no confirmed fix → no promotion) and idempotent.
#[test]
fn promote_breach_candidate_geo_corroborated_requires_same_place_and_same_surname() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // Named subject "Matt Avery" + a confirmed GPS fix in Brisbane. The Person
    // gives the surname the promotion gates on; the GPS gives the location anchor.
    let mut subject = Entity::new(EntityKind::Person, "Matt Avery", 0.9, "s");
    subject.tag("subject");
    let mut gps = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    gps.tag("geoint");

    let breach_candidate = |email: &str, postcode: &str, row_name: &str| {
        let mut e = Entity::new(EntityKind::Email, email, 0.25, "s");
        e.tag(crate::core::tags::CANDIDATE);
        e.tag("breach");
        e.add_evidence(
            Evidence::new("oathnet_pro", "breach row")
                .with_attr("postcode", postcode)
                .with_attr("breach_row_name", row_name),
        );
        e
    };

    // Same metro (South Brisbane 4101, ~2 km) AND same surname → promoted.
    let near = breach_candidate("matt@example.com", "4101", "Matt Avery");
    // Same surname but interstate (Perth 6000) → stays (geo gate).
    let far = breach_candidate("matt2@example.com", "6000", "Matthew Avery");
    // Same metro but a DIFFERENT surname → stays (name gate: a same-city stranger
    // the old geo-only pass would have fused onto the subject).
    let stranger = breach_candidate("parker@example.com", "4101", "Matt Parker");
    // Same metro but NO row name → cannot confirm identity → stays quarantined.
    let mut nameless = Entity::new(EntityKind::Email, "anon@example.com", 0.25, "s");
    nameless.tag(crate::core::tags::CANDIDATE);
    nameless.tag("breach");
    nameless.add_evidence(Evidence::new("oathnet_pro", "row").with_attr("postcode", "4101"));

    let mut ents = vec![subject, gps, near, far, stranger, nameless];
    assert_eq!(
        promote_breach_candidate_geo_corroborated(&mut ents),
        1,
        "only the same-metro, same-surname record is re-promoted"
    );

    let get = |v: &str| ents.iter().find(|e| e.value == v).unwrap().clone();
    let near = get("matt@example.com");
    assert!(
        !near.has_tag(crate::core::tags::CANDIDATE),
        "un-quarantined"
    );
    assert!(near.has_tag("breach-corroborated"));
    assert!(near.confidence >= 0.50, "lifted to Probable");
    assert!(
        near.evidence
            .iter()
            .any(|ev| ev.source == "geo_corroboration")
    );

    assert!(
        get("matt2@example.com").has_tag(crate::core::tags::CANDIDATE),
        "an interstate same-surname namesake stays quarantined (geo gate)"
    );
    assert!(
        get("parker@example.com").has_tag(crate::core::tags::CANDIDATE),
        "a same-metro DIFFERENT-surname stranger stays quarantined (name gate)"
    );
    assert!(
        get("anon@example.com").has_tag(crate::core::tags::CANDIDATE),
        "a same-metro record with no row name cannot be confirmed → stays quarantined"
    );

    // Idempotent: a second pass promotes nothing new.
    assert_eq!(promote_breach_candidate_geo_corroborated(&mut ents), 0);

    // Non-circular: with NO confirmed subject location, nothing is promoted even
    // with a resolvable postcode and a matching name.
    let mut lone = vec![
        {
            let mut p = Entity::new(EntityKind::Person, "Matt Avery", 0.9, "s");
            p.tag("subject");
            p
        },
        breach_candidate("x@y.com", "4101", "Matt Avery"),
    ];
    assert_eq!(promote_breach_candidate_geo_corroborated(&mut lone), 0);
}

/// Free, offline: an identity pair joined by two orthogonal pathways has BOTH
/// its endpoints promoted (tagged + corroborated) so the confirmed connection
/// strengthens the scan output — while the conduit intermediates are left alone
/// and the pass is idempotent across re-runs. Shares the AU-062 detector, so
/// this is the boost side of the same finding the correlator reports.
#[test]
fn promote_multipath_corroborated_lifts_only_orthogonally_linked_endpoints() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::relation::{Relation, RelationKind};

    let sourced = |kind: EntityKind, value: &str, source: &str| {
        let mut e = Entity::new(kind, value, 0.8, "s");
        e.add_evidence(Evidence::new(source, "ev"));
        e
    };
    let rel = |from: &Entity, to: &Entity, kind: RelationKind| {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    };

    // Two identity endpoints linked by two edge-disjoint routes through
    // NON-identity intermediates of DIFFERENT source families (infra + registry)
    // — the AU-062 criterion. The only identity pair is (email, username).
    let email = Entity::new(EntityKind::Email, "a@x.com", 0.8, "s");
    let user = Entity::new(EntityKind::Username, "bob", 0.8, "s");
    let dom = sourced(EntityKind::Domain, "x.com", "dns_intel"); // infra
    let org = sourced(EntityKind::Organisation, "Acme Pty", "opencorporates"); // registry
    let rels = [
        rel(&email, &dom, RelationKind::BelongsToDomain),
        rel(&dom, &user, RelationKind::DerivedFrom),
        rel(&email, &org, RelationKind::RegisteredBy),
        rel(&org, &user, RelationKind::DerivedFrom),
    ];
    let mut ents = vec![email.clone(), user.clone(), dom.clone(), org.clone()];

    assert_eq!(
        promote_multipath_corroborated(&mut ents, &rels),
        2,
        "both identity endpoints are promoted"
    );
    for v in ["a@x.com", "bob"] {
        let e = ents.iter().find(|e| e.value == v).unwrap();
        assert!(e.has_tag("multipath-corroborated"), "{v} must be tagged");
        assert!(
            e.evidence
                .iter()
                .any(|ev| ev.source == "multipath_corroboration"),
            "{v} must carry corroboration evidence"
        );
    }
    // The conduit intermediates are NOT themselves corroborated.
    for v in ["x.com", "Acme Pty"] {
        let e = ents.iter().find(|e| e.value == v).unwrap();
        assert!(
            !e.has_tag("multipath-corroborated"),
            "{v} is a conduit, not a corroborated endpoint"
        );
    }

    // Idempotent: a second pass (or a recall on a re-scan) promotes nothing new.
    assert_eq!(promote_multipath_corroborated(&mut ents, &rels), 0);

    // A single route is not multi-pathway corroboration → nothing promoted.
    let e2 = Entity::new(EntityKind::Email, "c@z.com", 0.8, "s");
    let u2 = Entity::new(EntityKind::Username, "carol", 0.8, "s");
    let d2 = sourced(EntityKind::Domain, "z.com", "dns_intel");
    let single = [
        rel(&e2, &d2, RelationKind::BelongsToDomain),
        rel(&d2, &u2, RelationKind::DerivedFrom),
    ];
    let mut one_route = vec![e2, u2, d2];
    assert_eq!(
        promote_multipath_corroborated(&mut one_route, &single),
        0,
        "a single pathway is not corroboration"
    );
}

/// Free, offline: the cross-scan gap boost lifts exactly the endpoints the engine
/// queued (a fragile link whose route shape is proven in prior scans) — the
/// accumulated-knowledge counterpart to the multipath boost — and is idempotent.
#[test]
fn promote_cross_scan_corroborated_lifts_queued_endpoints_idempotently() {
    use crate::core::entity::{Entity, EntityKind};
    use std::collections::HashMap;

    let a = Entity::new(EntityKind::Email, "a@x.com", 0.4, "s");
    let b = Entity::new(EntityKind::Username, "bob", 0.4, "s");
    let other = Entity::new(EntityKind::Domain, "x.com", 0.4, "s");
    let (ua, ub) = (a.uid.clone(), b.uid.clone());
    let mut ents = vec![a, b, other];

    let reason = "route shape proven in 2 prior scans".to_string();
    let mut boost: HashMap<String, String> = HashMap::new();
    boost.insert(ua.clone(), reason.clone());
    boost.insert(ub.clone(), reason);

    assert_eq!(
        promote_cross_scan_corroborated(&mut ents, &boost),
        2,
        "both queued endpoints are promoted"
    );
    for uid in [&ua, &ub] {
        let e = ents.iter().find(|e| &e.uid == uid).unwrap();
        assert!(
            e.has_tag("cross-scan-corroborated"),
            "endpoint must be tagged"
        );
        assert!(
            e.evidence
                .iter()
                .any(|ev| ev.source == "cross_scan_corroboration"),
            "endpoint must carry cross-scan evidence"
        );
    }
    // An entity not in the boost set is untouched.
    let other = ents.iter().find(|e| e.value == "x.com").unwrap();
    assert!(!other.has_tag("cross-scan-corroborated"));

    // Idempotent, and an empty boost set is a no-op.
    assert_eq!(promote_cross_scan_corroborated(&mut ents, &boost), 0);
    assert_eq!(
        promote_cross_scan_corroborated(&mut ents, &HashMap::new()),
        0
    );
}

/// The precision complement, surname-aware: a far same-surname candidate is tagged
/// `geo-discordant` (a likely namesake) ONLY when the shared surname is common — a
/// distinctive surname carries kinship across any distance, so a rare-surname
/// subject's interstate kin are left alone. Tag-only (no confidence change), an
/// in-area relative is untouched, and the flag is idempotent.
#[test]
fn flag_geo_discordant_namesakes_is_surname_aware_and_tag_only() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // Subject's confirmed GPS near Woodford, QLD (Brisbane catchment).
    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
    // Far (Perth, ~3600 km) COMMON-surname candidate → a likely namesake.
    let mut common = Entity::new(EntityKind::Person, "Curt Smith", 0.32, "s");
    common.tag("family-candidate");
    common.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "6000"));
    let conf_before = common.c_effective();
    let sources_before = common.source_count();
    // Far DISTINCTIVE-surname candidate (same distance) → distant kin, NOT a namesake.
    let mut rare = Entity::new(EntityKind::Person, "Curt Moreau", 0.32, "s");
    rare.tag("family-candidate");
    rare.add_evidence(Evidence::new("qld_unclaimed", "owner").with_attr("postcode", "6000"));
    // In-area relative (Beerwah) — the positive pass's job, not this one.
    let mut near = Entity::new(EntityKind::Address, "QLD 4519, Australia", 0.32, "s");
    near.tag("family-candidate");

    let mut ents = vec![gps, common, rare, near];
    assert_eq!(
        flag_geo_discordant_namesakes(&mut ents),
        1,
        "only the far COMMON-surname namesake is flagged"
    );

    let common = ents.iter().find(|e| e.value == "Curt Smith").unwrap();
    assert!(common.has_tag("geo-discordant"));
    // Tag-only: confidence and the corroboration count are untouched, so a
    // negative signal can never PROMOTE the namesake it means to demote.
    assert!((common.c_effective() - conf_before).abs() < 1e-9);
    assert_eq!(common.source_count(), sources_before);
    assert!(
        !common.evidence.iter().any(|ev| ev.source == "geo_discord"),
        "discord adds no evidence record"
    );

    // A far DISTINCTIVE surname is distant kin, not a namesake.
    let rare = ents.iter().find(|e| e.value == "Curt Moreau").unwrap();
    assert!(
        !rare.has_tag("geo-discordant"),
        "a far distinctive surname is kin, never a namesake"
    );
    let near = ents.iter().find(|e| e.value.contains("4519")).unwrap();
    assert!(
        !near.has_tag("geo-discordant"),
        "an in-area relative is never a namesake"
    );

    // Idempotent, and nothing to judge without a confirmed subject fix.
    assert_eq!(flag_geo_discordant_namesakes(&mut ents), 0);
    let mut lone = vec![{
        let mut e = Entity::new(EntityKind::Person, "Curt Smith", 0.32, "s");
        e.tag("family-candidate");
        e
    }];
    assert_eq!(
        flag_geo_discordant_namesakes(&mut lone),
        0,
        "no subject fix → nothing flagged"
    );
}

/// The subject's surname gates the whole pass: with a named subject present, a
/// candidate is judged by the SUBJECT's surname — which every family-candidate
/// shares — not its own. So a rare-surname subject's kin are protected even when
/// the candidate is a bare Address that carries no name of its own to fall back on.
#[test]
fn namesake_flagging_uses_the_subject_surname() {
    use crate::core::entity::{Entity, EntityKind};

    let mut gps = Entity::new(EntityKind::Coordinates, "-26.815,152.814", 0.9, "s");
    gps.tag("geoint");
    // A far family-candidate Address (no name of its own) in Perth, WA.
    let mut far = Entity::new(EntityKind::Address, "WA 6000, Australia", 0.32, "s");
    far.tag("family-candidate");

    // A rare-surname subject protects the far candidate.
    let mut rare_subject = Entity::new(EntityKind::Person, "Pat Moreau", 0.9, "s");
    rare_subject.tag("subject");
    let mut ents = vec![gps.clone(), rare_subject, far.clone()];
    assert_eq!(
        flag_geo_discordant_namesakes(&mut ents),
        0,
        "a distinctive subject surname leaves even a far address-only candidate alone"
    );

    // A common-surname subject makes the same far candidate a namesake.
    let mut common_subject = Entity::new(EntityKind::Person, "Pat Smith", 0.9, "s");
    common_subject.tag("subject");
    let mut ents = vec![gps, common_subject, far];
    assert_eq!(flag_geo_discordant_namesakes(&mut ents), 1);
    assert!(
        ents.iter()
            .any(|e| e.value.contains("6000") && e.has_tag("geo-discordant"))
    );
}

/// FTA invariant (cuts MCS-A): the local/environmental sensor modules read
/// the OPERATOR's own device/network, so they must never engage on a
/// remote-subject seed — otherwise the operator's GPS/Wi-Fi/cell/LAN data is
/// attributed to the subject (e.g. a device GPS fix surfacing as the
/// subject's Verified location on a `name` scan). They run only on a
/// deliberately-local seed (coordinates / MAC). Pinning the whole gate set
/// here stops a future sensor module silently reopening the cut.
#[test]
fn local_passive_sensor_modules_reject_remote_subject_seeds() {
    use crate::core::scan::{Target, TargetKind};
    let reg = crate::modules::registry();
    for name in LOCAL_PASSIVE_MODULES {
        let m = reg
            .iter()
            .find(|m| m.name() == *name)
            .unwrap_or_else(|| panic!("{name} not in registry"));
        for k in [
            TargetKind::FullName,
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::Domain,
            TargetKind::IpAddress,
            TargetKind::Url,
            TargetKind::Organisation,
        ] {
            assert!(
                !m.accepts(&Target::new(k, "x")),
                "{name} must reject remote-subject seed {k:?} (fault-tree MCS-A)"
            );
        }
        assert!(
            m.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")),
            "{name} must still engage on a deliberately-local coordinates seed"
        );
    }
}

#[tokio::test]
async fn module_panic_is_contained_as_error_not_process_abort() {
    // Error-tree ECS-1: a panicking module (bad/hostile upstream tripping an
    // unwrap/slice) must be caught at the dispatch boundary and reported as a
    // normal, counted module error — never unwind into the loop / JoinSet or
    // abort the process. Requires panic = "unwind" (set for every profile).
    let out = run_module_guarded(5_000, "boom", async { panic!("kaboom on bad upstream") }).await;
    match out {
        Ok(Err(Error::Module { module, message })) => {
            assert_eq!(module, "boom");
            assert!(message.contains("panicked"), "msg: {message}");
            assert!(message.contains("kaboom on bad upstream"), "msg: {message}");
        }
        other => panic!("expected a contained module error, got {other:?}"),
    }
}

#[test]
fn finalise_correlation_pass_survives_a_panicking_rule() {
    use crate::core::correlator::Correlation;

    // Error-tree ECS-2: the finalise-time correlation pass must not be able to
    // abort `finalise_scan`. A rule panicking on adversarial persisted data (a
    // slice-index bug over a crafted entity) previously unwound the whole finalise
    // block — losing the terminal `ScanComplete` event and the API-key pool the
    // scan harvested. The guard degrades a caught panic to `None` (no finalise
    // correlations), exactly as the live incremental pass does, so the scan still
    // finalises.
    let panicked = guarded_finalise_correlation("s", || panic!("kaboom in a correlation rule"));
    assert!(
        panicked.is_none(),
        "a panicking finalise pass must be caught and degrade to no firings, not unwind"
    );

    // A returned error is likewise swallowed to `None` (unchanged behaviour).
    let errored = guarded_finalise_correlation("s", || Err(Error::module("correlator", "boom")));
    assert!(errored.is_none(), "a returned error yields no firings");

    // The happy path passes the firings straight through for emission.
    let ok = guarded_finalise_correlation("s", || {
        Ok(vec![Correlation::new(
            "AU-000",
            "test correlation",
            crate::core::correlator::Severity::Low,
            "synthetic".to_string(),
            vec!["uid-a".into(), "uid-b".into()],
            "s",
            0,
        )])
    })
    .expect("a successful pass returns Some(firings)");
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].rule_id, "AU-000");
}

#[tokio::test]
async fn run_module_guarded_passes_success_and_error_through() {
    use crate::core::module::ModuleResult;
    // Success and a returned error flow through unchanged (the guard only
    // intercepts panics, matching a returned error's shape exactly).
    let ok = run_module_guarded(5_000, "ok", async { Ok(ModuleResult::new()) }).await;
    assert!(matches!(ok, Ok(Ok(_))));
    let err = run_module_guarded(5_000, "e", async {
        Err(Error::module("e", "regular failure"))
    })
    .await;
    assert!(matches!(err, Ok(Err(Error::Module { .. }))));
}

#[test]
fn visit_key_normalises_email() {
    let t = Target::new(TargetKind::Email, "ALICE@Example.COM");
    let (kind, val) = visit_key(&t);
    assert_eq!(kind, TargetKind::Email);
    assert_eq!(val, "alice@example.com");
}

#[test]
fn cmp_expansion_candidates_is_a_consistent_total_order() {
    // CORRECTNESS: `cmp_expansion_candidates` is handed to `sort_by`, which
    // requires a *total order* — an inconsistent comparator can panic
    // ("comparator violates total order") or silently mis-sort. The tricky
    // part is f64 weights including NaN. Prove the contract generatively over
    // a deterministic pseudo-random corpus (deterministic so the test itself
    // is reproducible): the relation must be a total order, and sorting must
    // be idempotent and self-consistent.
    use std::cmp::Ordering;

    // splitmix64 — a tiny deterministic PRNG (no dev-dependency, reproducible).
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    // Small value/kind domains so ties (and the tie-breaks) actually occur.
    let kinds = [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Domain,
        TargetKind::IpAddress,
    ];
    let weights = [f64::NAN, 0.0, 0.5, 0.5, 0.9, -1.0, f64::INFINITY];
    let values = ["a", "b", "c", "a"];
    let mk = |r: &mut dyn FnMut() -> u64| {
        let k = kinds[(r() % kinds.len() as u64) as usize];
        let w = weights[(r() % weights.len() as u64) as usize];
        let v = values[(r() % values.len() as u64) as usize];
        (Target::new(k, v), w, "p".to_string())
    };

    // 1. The relation is a TOTAL ORDER over a random sample: antisymmetric,
    //    transitive, and total (every pair is comparable, which Ordering is).
    let sample: Vec<_> = (0..40).map(|_| mk(&mut next)).collect();
    for a in &sample {
        assert_eq!(
            cmp_expansion_candidates(a, a),
            Ordering::Equal,
            "reflexivity"
        );
        for b in &sample {
            let ab = cmp_expansion_candidates(a, b);
            let ba = cmp_expansion_candidates(b, a);
            assert_eq!(ab, ba.reverse(), "antisymmetry");
            for c in &sample {
                let bc = cmp_expansion_candidates(b, c);
                // Transitivity: a<=b and b<=c ⇒ a<=c.
                if ab != Ordering::Greater && bc != Ordering::Greater {
                    assert_ne!(
                        cmp_expansion_candidates(a, c),
                        Ordering::Greater,
                        "transitivity"
                    );
                }
            }
        }
    }

    // 2. Sorting many random vectors never panics, is idempotent, and the
    //    output is non-decreasing under the comparator.
    for _ in 0..200 {
        let n = (next() % 30) as usize;
        let mut v: Vec<_> = (0..n).map(|_| mk(&mut next)).collect();
        v.sort_by(cmp_expansion_candidates);
        for w in v.windows(2) {
            assert_ne!(
                cmp_expansion_candidates(&w[0], &w[1]),
                Ordering::Greater,
                "sorted output must be non-decreasing"
            );
        }
        let once: Vec<_> = v.iter().map(|c| (c.0.value.clone(), c.1)).collect();
        v.sort_by(cmp_expansion_candidates); // idempotent
        let twice: Vec<_> = v.iter().map(|c| (c.0.value.clone(), c.1)).collect();
        // NaN != NaN, so compare structurally with NaN normalised.
        let norm = |xs: &[(String, f64)]| {
            xs.iter()
                .map(|(s, w)| {
                    (
                        s.clone(),
                        if w.is_nan() {
                            "nan".into()
                        } else {
                            w.to_string()
                        },
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(norm(&once), norm(&twice), "sort must be idempotent");
    }
}

#[test]
fn allowlist_applies_on_expansion_rounds_not_just_the_seed() {
    // Regression: the allowlist ("only these modules run", docs/USAGE.md) was
    // gated by `!is_expansion`, so non-allowlisted modules ran on discovered
    // entities during expansion — a real defect (focused/offline scans fanned
    // out to every network module the moment they expanded).
    use crate::core::scan::{ScanOptions, Target, TargetKind};
    let reg = crate::modules::registry();
    let hibp = reg
        .iter()
        .find(|m| m.name() == "hibp")
        .expect("hibp registered");
    let target = Target::new(TargetKind::Email, "a@b.com");

    // Not in the allowlist → skipped on the seed round AND every expansion round.
    let only_name_intel = ScanOptions {
        modules: Some(vec!["name_intel".into()]),
        ..Default::default()
    };
    for is_expansion in [false, true] {
        assert_eq!(
            module_skip_reason(hibp.as_ref(), &target, &only_name_intel, is_expansion, 0),
            Some("not in allowlist"),
            "a non-allowlisted module must be skipped (is_expansion={is_expansion})"
        );
    }

    // In the allowlist → the allowlist gate must pass on expansion too (other
    // gates are independent, so assert only that this reason is not returned).
    let only_hibp = ScanOptions {
        modules: Some(vec!["hibp".into()]),
        ..Default::default()
    };
    assert_ne!(
        module_skip_reason(hibp.as_ref(), &target, &only_hibp, true, 9),
        Some("not in allowlist"),
        "an allowlisted module must not be skipped for the allowlist reason"
    );
}

#[test]
fn module_dispatch_is_logged_keyed_by_module_name() {
    // OBSERVABILITY: every module's *start* must appear in the raw debug log,
    // keyed by `module=<name>` so a single file's whole lifecycle is greppable.
    // `log_module_dispatch` is synchronous, so a scoped capturing subscriber
    // proves the line is emitted without touching the global subscriber.
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct VecWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for VecWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl tracing_subscriber::fmt::MakeWriter<'_> for VecWriter {
        type Writer = VecWriter;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(VecWriter(Arc::clone(&buf)))
        .with_max_level(tracing::Level::DEBUG)
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        log_module_dispatch("hibp", &Target::new(TargetKind::Email, "a@b.com"));
    });
    let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(
        out.contains("dispatch"),
        "dispatch event missing; got: {out:?}"
    );
    assert!(
        out.contains("module") && out.contains("hibp"),
        "dispatch line must be keyed by module name; got: {out:?}"
    );
}

#[test]
fn expansion_candidate_order_is_deterministic_under_input_permutation() {
    // DETERMINISM REQUIREMENT (evidence): the candidate ranking must not
    // depend on the HashMap-iteration order it is built from. Three candidates
    // share the SAME weight; whatever order they arrive in, the comparator
    // must produce one fixed order (by kind, then value), so a budget
    // `truncate` keeps the same set every run.
    let mk = |k: TargetKind, v: &str, w: f64| (Target::new(k, v), w, "p".to_string());
    let canonical = {
        let mut v = [
            mk(TargetKind::Email, "a@x.com", 0.5),
            mk(TargetKind::Email, "b@x.com", 0.5),
            mk(TargetKind::Username, "a@x.com", 0.5),
        ];
        v.sort_by(cmp_expansion_candidates);
        v.iter().map(|c| c.0.value.clone()).collect::<Vec<_>>()
    };
    // Every permutation of the same tied candidates yields the same order.
    for perm in [[2, 0, 1], [1, 2, 0], [0, 2, 1], [2, 1, 0]] {
        let src = [
            mk(TargetKind::Email, "a@x.com", 0.5),
            mk(TargetKind::Email, "b@x.com", 0.5),
            mk(TargetKind::Username, "a@x.com", 0.5),
        ];
        let mut v: Vec<_> = perm.iter().map(|&i| src[i].clone()).collect();
        v.sort_by(cmp_expansion_candidates);
        let got: Vec<_> = v.iter().map(|c| c.0.value.clone()).collect();
        assert_eq!(got, canonical, "ranking depended on input order");
    }
    // Higher weight always wins regardless of tie-break, and NaN sorts last.
    let mut wv = [
        mk(TargetKind::Email, "z@x.com", 0.9),
        mk(TargetKind::Email, "a@x.com", f64::NAN),
        mk(TargetKind::Email, "m@x.com", 0.5),
    ];
    wv.sort_by(cmp_expansion_candidates);
    assert_eq!(wv[0].0.value, "z@x.com"); // 0.9 first
    assert_eq!(wv[2].0.value, "a@x.com"); // NaN last
}

#[test]
fn visit_key_normalises_domain_trailing_dot() {
    let t = Target::new(TargetKind::Domain, "example.com.");
    let (_, val) = visit_key(&t);
    assert_eq!(val, "example.com");
}

#[test]
fn budget_check_none_when_no_limits() {
    let opts = ScanOptions::default();
    let started = Instant::now();
    assert!(budget_check(&opts, started, 1000).is_none());
}

#[test]
fn budget_check_max_entities_triggers() {
    let opts = ScanOptions {
        max_entities: Some(5),
        ..Default::default()
    };
    let started = Instant::now();
    assert!(budget_check(&opts, started, 4).is_none());
    assert!(budget_check(&opts, started, 5).is_some());
}

#[test]
fn budget_check_wall_time_triggers() {
    let opts = ScanOptions {
        max_wall_time_secs: Some(0),
        ..Default::default()
    };
    let started = Instant::now() - Duration::from_secs(1);
    assert!(budget_check(&opts, started, 0).is_some());
}

#[test]
fn stop_reason_labels_are_descriptive() {
    assert!(StopReason::NoMoreCandidates.label().contains("candidate"));
    assert!(StopReason::DepthExhausted.label().contains("depth"));
    assert!(StopReason::MaxEntities(10).label().contains("10"));
    assert!(StopReason::MaxWallTime(60).label().contains("60"));
    assert!(StopReason::Cancelled.label().contains("cancel"));
}

// -- dispatch tests (from former dispatch.rs) --

struct StubModule {
    name: &'static str,
    cost: ModuleCost,
    passive: bool,
}

#[async_trait::async_trait]
impl Module for StubModule {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, _: &Target) -> bool {
        true
    }
    fn cost(&self) -> ModuleCost {
        self.cost
    }
    fn is_passive(&self) -> bool {
        self.passive
    }
    async fn process(
        &self,
        _: &Target,
        _: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        Ok(crate::core::module::ModuleResult::new())
    }
}

/// Neutral public IP target used by skip-reason tests so the
/// universal preflight gate doesn't fire on the test fixture.
fn pub_target() -> Target {
    Target::new(TargetKind::IpAddress, "1.1.1.1")
}

#[test]
fn circuit_breaker_trip_skips_the_module_at_the_dispatch_gate() {
    // Wiring proof for the circuit breaker: once a module trips (a rate-limit /
    // quota wall, as the debug log showed hackertarget/urlscan hitting every
    // round), `module_skip_reason` must skip it so the rest of the scan stops
    // re-dispatching a dead provider and hands that budget to working sources.
    // A unique module name keeps this independent of the process-global breaker
    // state the circuit unit tests touch.
    let m = StubModule {
        name: "test_circuit_gate",
        cost: ModuleCost::Free,
        passive: false,
    };
    let opts = ScanOptions::default();

    // Healthy → not skipped for circuit reasons.
    assert!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none(),
        "a healthy module must not be gated"
    );

    // Trip it as a 429/quota response would, then the gate skips it.
    super::circuit::record_rate_limit(m.name());
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("circuit-open — rate-limited/quota/repeated failure (cooling down)"),
        "a tripped module must be skipped at the dispatch gate"
    );

    // A success clears the trip — the gate trusts a recovered provider again.
    super::circuit::record_success(m.name());
    assert!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none(),
        "a recovered module must dispatch again"
    );
}

#[tokio::test]
async fn cache_replay_does_not_feed_the_circuit_breaker_success_path() {
    use crate::core::module::ModuleResult;
    use crate::core::test_support::InMemoryStore;

    // A cache REPLAY makes no provider call, so it must be invisible to the
    // breaker: recording a success on it would clear a failure streak the live
    // calls legitimately earned this scan, masking a degrading provider. Drive
    // the real `finalise_module_result` with from_cache=true and prove the streak
    // survives; contrast with a real dispatch (from_cache=false) that clears it.
    // Unique module names keep this independent of the process-global breaker
    // state the other tests touch.
    let store: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::new(vec![], store, bus);

    let target = Target::new(TargetKind::Email, "seed@gmail.com");
    let opts = ScanOptions::default();
    let cx = DispatchCx {
        scan_id: "replay-scan",
        target: &target,
        opts: &opts,
        is_expansion: false,
        seed_kind: TargetKind::Email,
    };
    let mut entity_map: HashMap<String, Entity> = HashMap::new();
    let mut stats = ModuleStats::default();
    let mut dispatched: DispatchLog = DispatchLog::new();
    let mut state = DispatchState {
        entity_map: &mut entity_map,
        stats: &mut stats,
        dispatched: &mut dispatched,
    };

    // ── Replay path: the streak MUST survive ────────────────────────────────
    let replayed = "test_replay_breaker_cached";
    super::circuit::record_soft_failure(replayed);
    super::circuit::record_soft_failure(replayed); // streak = 2 (threshold 3)
    assert!(
        !super::circuit::is_open(replayed),
        "a streak of 2 must not have tripped yet"
    );
    engine.finalise_module_result(
        &cx,
        replayed,
        Ok(Ok(ModuleResult::new())),
        &mut state,
        &[],
        true, // from_cache
    );
    super::circuit::record_soft_failure(replayed); // streak → 3 iff the replay left it
    assert!(
        super::circuit::is_open(replayed),
        "a cache replay must NOT reset the streak — the 3rd real failure must trip the breaker"
    );

    // ── Real-dispatch path: the streak IS cleared (regression contrast) ──────
    let dispatched_name = "test_replay_breaker_real";
    super::circuit::record_soft_failure(dispatched_name);
    super::circuit::record_soft_failure(dispatched_name); // streak = 2
    engine.finalise_module_result(
        &cx,
        dispatched_name,
        Ok(Ok(ModuleResult::new())),
        &mut state,
        &[],
        false, // real dispatch → record_success clears the streak
    );
    super::circuit::record_soft_failure(dispatched_name); // streak → 1 after a clear
    assert!(
        !super::circuit::is_open(dispatched_name),
        "a real dispatch clears the streak, so a single later failure must not trip it"
    );
}

fn free_active() -> StubModule {
    StubModule {
        name: "test_free",
        cost: ModuleCost::Free,
        passive: false,
    }
}

fn keygated() -> StubModule {
    StubModule {
        name: "test_keygated",
        cost: ModuleCost::KeyGated,
        passive: false,
    }
}

fn paid_passive() -> StubModule {
    StubModule {
        name: "test_paid",
        cost: ModuleCost::Paid,
        passive: true,
    }
}

#[test]
fn skip_reason_none_for_default_opts() {
    let m = free_active();
    let opts = ScanOptions::default();
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

#[test]
fn skip_reason_not_in_allowlist() {
    let m = free_active();
    let opts = ScanOptions {
        modules: Some(vec!["other_module".into()]),
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("not in allowlist")
    );
}

#[test]
fn skip_reason_in_allowlist_passes() {
    let m = free_active();
    let opts = ScanOptions {
        modules: Some(vec!["test_free".into()]),
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

#[test]
fn skip_reason_gates_live_sensors_to_radar_only() {
    // A live device-sensor module (name in LOCAL_PASSIVE_MODULES) reads the
    // OPERATOR's own environment, so it must NEVER run on a manual scan — only
    // under `hse radar`'s `allow_live_sensors` activation.
    let sensor = StubModule {
        name: "signal_radar",
        cost: ModuleCost::Free,
        passive: true,
    };
    // Default manual scan → skipped.
    assert_eq!(
        module_skip_reason(&sensor, &pub_target(), &ScanOptions::default(), false, 0),
        Some("live sensor — radar-only activation"),
    );
    // Even an explicit `hse scan --modules signal_radar` keeps it off: the
    // activation is `hse radar`, not an allowlist on an ordinary scan.
    let allowlisted = ScanOptions {
        modules: Some(vec!["signal_radar".into()]),
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&sensor, &pub_target(), &allowlisted, false, 0),
        Some("live sensor — radar-only activation"),
    );
    // Radar activation → the sensor passes the gate.
    let radar = ScanOptions {
        modules: Some(vec!["signal_radar".into()]),
        allow_live_sensors: true,
        ..Default::default()
    };
    assert!(module_skip_reason(&sensor, &pub_target(), &radar, false, 0).is_none());
    // A non-sensor module is unaffected by the gate.
    assert!(
        module_skip_reason(
            &free_active(),
            &pub_target(),
            &ScanOptions::default(),
            false,
            0
        )
        .is_none()
    );
}

#[test]
fn skip_reason_excluded() {
    let m = free_active();
    let opts = ScanOptions {
        exclude_modules: vec!["test_free".into()],
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("excluded")
    );
}

#[test]
fn skip_reason_outside_category_focus() {
    // A non-empty category focus that omits the module's category skips it on
    // every round. `free_active` is a StubModule, whose `category()` defaults to
    // `Other`; a focus of People/Phone/Geo therefore excludes it.
    use crate::core::module::ModuleCategory;
    let m = free_active();
    let opts = ScanOptions {
        category_focus: vec![
            ModuleCategory::People,
            ModuleCategory::Phone,
            ModuleCategory::Geo,
        ],
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("outside category focus")
    );
}

#[test]
fn skip_reason_inside_category_focus_passes() {
    // The same module passes when its category IS in the focus, and an empty
    // focus (the default) never restricts.
    use crate::core::module::ModuleCategory;
    let m = free_active(); // category() defaults to Other
    let focused = ScanOptions {
        category_focus: vec![ModuleCategory::Other],
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &focused, false, 0).is_none());
    let unfocused = ScanOptions {
        category_focus: Vec::new(),
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &unfocused, false, 0).is_none());
}

#[test]
fn skip_reason_free_only_skips_keygated() {
    let m = keygated();
    let opts = ScanOptions {
        free_only: true,
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("requires key/payment")
    );
}

#[test]
fn skip_reason_free_only_passes_free() {
    let m = free_active();
    let opts = ScanOptions {
        free_only: true,
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

#[test]
fn skip_reason_passive_only_skips_active() {
    let m = free_active();
    let opts = ScanOptions {
        passive_only: true,
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("not passive")
    );
}

#[test]
fn skip_reason_passive_only_passes_passive() {
    let m = paid_passive();
    let opts = ScanOptions {
        passive_only: true,
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

// ── high-value-API cross-correlation gate (oathnet_pro) ────────────────

/// Stub standing in for the high-value paid module by name.
fn high_value() -> StubModule {
    StubModule {
        name: "oathnet_pro",
        cost: ModuleCost::Paid,
        passive: false,
    }
}

#[test]
fn high_value_module_runs_on_seed_regardless_of_sources() {
    // Seed round (is_expansion=false): always allowed, even with 0 sources
    // (the seed target isn't an entity yet).
    let m = high_value();
    let opts = ScanOptions::default();
    assert!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none(),
        "high-value module must run on the initial seed query"
    );
}

#[test]
fn high_value_module_skipped_on_expansion_below_cross_correlation() {
    // Expansion, target corroborated by only 1 distinct source → skip.
    let m = high_value();
    let opts = ScanOptions::default();
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, true, 1),
        Some("high-value API — awaiting cross-correlation (>=2 sources)"),
        "single-source discovered entity must NOT trigger the high-value API"
    );
    // 0 sources (not yet in map) on expansion is likewise gated.
    assert!(module_skip_reason(&m, &pub_target(), &opts, true, 0).is_some());
}

#[test]
fn high_value_module_runs_on_expansion_when_cross_correlated() {
    // Expansion, target corroborated by >=2 distinct sources → allowed.
    let m = high_value();
    let opts = ScanOptions::default();
    assert!(
        module_skip_reason(&m, &pub_target(), &opts, true, 2).is_none(),
        "cross-correlated (>=2 sources) entity must reach the high-value API on expansion"
    );
    assert!(module_skip_reason(&m, &pub_target(), &opts, true, 5).is_none());
}

#[test]
fn non_high_value_module_unaffected_by_source_gate() {
    // A normal module is never subject to the high-value cross-correlation
    // gate, even at 0 sources on expansion.
    let m = free_active();
    let opts = ScanOptions::default();
    assert!(module_skip_reason(&m, &pub_target(), &opts, true, 0).is_none());
}

fn wigle() -> StubModule {
    StubModule {
        name: "wigle",
        cost: ModuleCost::KeyGated,
        passive: false,
    }
}

fn coords_target() -> Target {
    Target::new(TargetKind::Coordinates, "-27.47,153.02")
}

#[test]
fn wigle_finaliser_gated_on_uncorroborated_coordinate() {
    // The GEOINT-finaliser rule: on EXPANSION, WiGLE must not spend a query on
    // a Coordinates target the free geo layer hasn't corroborated (>=2 distinct
    // sources). 0 or 1 source → skip; >=2 (recursion agreed, high confidence)
    // → allowed.
    let m = wigle();
    let opts = ScanOptions::default();
    assert_eq!(
        module_skip_reason(&m, &coords_target(), &opts, true, 1),
        Some("WiGLE finaliser — awaiting GEOINT corroboration (>=2 geo sources)"),
        "single-source coordinate must not reach the paid WiGLE finaliser"
    );
    assert!(module_skip_reason(&m, &coords_target(), &opts, true, 0).is_some());
    assert!(
        module_skip_reason(&m, &coords_target(), &opts, true, 2).is_none(),
        "a coordinate >=2 geo sources agree on (high confidence) reaches WiGLE"
    );
}

#[test]
fn target_distinct_sources_excludes_geo_normalize_enrichment() {
    // The WiGLE finaliser gate keys on this count. A Coordinates entity always
    // receives a `geo_normalize` evidence row from the enrichment pass, but that
    // is deterministic self-enrichment, NOT an independent geo source — so a
    // coordinate produced by ONE real module must count as 1, not 2. Counting
    // raw evidence_sources would credit it as 2 and fire WiGLE on an
    // uncorroborated coordinate, defeating the gate.
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use std::collections::HashMap;

    let mut coord = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.8, "s");
    coord.add_evidence(Evidence::new("ip_geo", "Geolocation for 1.2.3.4"));
    coord.add_evidence(Evidence::new("geo_normalize", "Geospatial enrichment"));
    let mut map: HashMap<String, Entity> = HashMap::new();
    map.insert(coord.uid.clone(), coord.clone());

    let target = Target::new(TargetKind::Coordinates, "-27.470000,153.020000");
    assert_eq!(
        target_distinct_sources(&map, &target),
        1,
        "one real geo source + geo_normalize must count as 1, not 2"
    );

    // A genuine second geo source lifts it to 2 → WiGLE may fire.
    let e = map.get_mut(&coord.uid).unwrap();
    e.add_evidence(Evidence::new("geocode", "reverse geocode"));
    assert_eq!(target_distinct_sources(&map, &target), 2);

    // An absent target is 0.
    let absent = Target::new(TargetKind::Coordinates, "10.0,20.0");
    assert_eq!(target_distinct_sources(&map, &absent), 0);
}

#[test]
fn wigle_runs_on_seed_coordinate_and_on_any_bssid() {
    let m = wigle();
    let opts = ScanOptions::default();
    // Seed round: a Coordinates seed is the operator's explicit target.
    assert!(
        module_skip_reason(&m, &coords_target(), &opts, false, 0).is_none(),
        "WiGLE runs on a coordinate SEED regardless of corroboration"
    );
    // A MacAddress/BSSID is WiGLE's PRIMARY pivot — exempt from the
    // geo-corroboration precondition even on expansion at 0 sources (its own
    // BSSID budget bounds it). The universal-preflight gate doesn't touch MACs.
    let mac = Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff");
    assert!(
        module_skip_reason(&m, &mac, &opts, true, 0).is_none(),
        "a discovered BSSID must reach WiGLE — it is the primary resolver"
    );
}

#[test]
fn skip_reason_allowlist_takes_priority_over_exclude() {
    let m = free_active();
    let opts = ScanOptions {
        modules: Some(vec!["test_free".into()]),
        exclude_modules: vec!["test_free".into()],
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("excluded")
    );
}

// -- universal preflight gate (private IP / local domain) --

#[test]
fn skip_reason_rejects_private_ip_for_external_module() {
    let m = free_active();
    let private = Target::new(TargetKind::IpAddress, "192.168.1.1");
    let opts = ScanOptions::default();
    assert_eq!(
        module_skip_reason(&m, &private, &opts, false, 0),
        Some("private/reserved IP — external API would reject")
    );
}

#[test]
fn skip_reason_rejects_local_domain_for_external_module() {
    let m = free_active();
    let local = Target::new(TargetKind::Domain, "router.local");
    let opts = ScanOptions::default();
    assert_eq!(
        module_skip_reason(&m, &local, &opts, false, 0),
        Some("local/reserved domain — external API would reject")
    );
}

#[test]
fn skip_reason_lets_local_passive_module_see_private_ip() {
    // local_net, device_sensors, wifi_intel, cell_intel are
    // listed in LOCAL_PASSIVE_MODULES and bypass the preflight.
    let m = StubModule {
        name: "local_net",
        cost: ModuleCost::Free,
        passive: true,
    };
    let private = Target::new(TargetKind::IpAddress, "192.168.1.1");
    // The private-IP preflight bypass only matters when the sensor is actually
    // active (`hse radar`); on a manual scan the radar-only gate skips it first.
    let opts = ScanOptions {
        allow_live_sensors: true,
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &private, &opts, false, 0).is_none());
}

#[test]
fn skip_reason_passes_public_ip_through() {
    let m = free_active();
    let opts = ScanOptions::default();
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

#[test]
fn skip_reason_passes_public_ipv6_through() {
    // Regression: the universal preflight previously rejected
    // every `:`-containing string via should_skip_external_ipv4,
    // silently breaking IPv6 lookups for v6-capable modules
    // (shodan, censys, abuseipdb, RDAP, etc.). The v6-tolerant
    // gate must let public IPv6 pass through to module dispatch.
    let m = free_active();
    let opts = ScanOptions::default();
    for v6 in [
        "2606:4700:4700::1111", // Cloudflare
        "2001:4860:4860::8888", // Google
        "2620:fe::fe",          // Quad9
    ] {
        let t = Target::new(TargetKind::IpAddress, v6);
        assert!(
            module_skip_reason(&m, &t, &opts, false, 0).is_none(),
            "public IPv6 {v6} should NOT be rejected by the universal gate",
        );
    }
}

#[test]
fn skip_reason_rejects_url_with_private_host_ssrf_gate() {
    // SSRF gate: a Url target whose host parses as a private IP
    // or a local domain must not reach external-API modules.
    // Without this, autonomous expansion that yields
    // `http://192.168.1.1/admin` would coerce HSE into hitting
    // the operator's internal LAN.
    let m = free_active();
    let opts = ScanOptions::default();
    for hostile in [
        "http://192.168.1.1/admin",
        "http://10.0.0.1:8080/",
        "http://127.0.0.1/health",
        "http://[::1]/",
        // IPv4-mapped IPv6 literal: the OS connects this to the underlying
        // IPv4 metadata host, so the bracket-stripped host must canonicalise
        // to v4 and be refused (regression guard for the to_canonical fix).
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://router.local/",
        "https://intra.internal/api",
    ] {
        let t = Target::new(TargetKind::Url, hostile);
        let reason = module_skip_reason(&m, &t, &opts, false, 0);
        assert!(
            reason.is_some_and(|r| r.contains("SSRF") || r.contains("private")),
            "Url {hostile} should be SSRF-rejected, got {reason:?}",
        );
    }
}

#[test]
fn skip_reason_lets_public_url_through() {
    let m = free_active();
    let opts = ScanOptions::default();
    for benign in [
        "https://example.com/",
        "https://api.github.com/users/octocat",
        "http://[2606:4700:4700::1111]/",
    ] {
        let t = Target::new(TargetKind::Url, benign);
        assert!(
            module_skip_reason(&m, &t, &opts, false, 0).is_none(),
            "Url {benign} should pass through",
        );
    }
}

#[test]
fn skip_reason_still_rejects_private_ipv6() {
    // Loopback / unique-local / link-local IPv6 are private and
    // should still be skipped by the universal gate.
    let m = free_active();
    let opts = ScanOptions::default();
    for private_v6 in ["::1", "fc00::1", "fe80::1"] {
        let t = Target::new(TargetKind::IpAddress, private_v6);
        assert!(
            module_skip_reason(&m, &t, &opts, false, 0).is_some(),
            "private IPv6 {private_v6} should be rejected",
        );
    }
}

// -- dispatch dedup tests --

#[test]
fn dispatch_key_normalises_consistently() {
    let t1 = Target::new(TargetKind::Email, "ALICE@Example.COM");
    let t2 = Target::new(TargetKind::Email, "alice@example.com");
    assert_eq!(dispatch_key("hibp", &t1), dispatch_key("hibp", &t2));
}

#[test]
fn dispatch_key_differs_across_modules() {
    let t = Target::new(TargetKind::Email, "alice@example.com");
    assert_ne!(dispatch_key("hibp", &t), dispatch_key("shodan", &t));
}

#[test]
fn dispatch_key_differs_across_target_kinds() {
    let email = Target::new(TargetKind::Email, "alice@example.com");
    let domain = Target::new(TargetKind::Domain, "alice@example.com");
    assert_ne!(dispatch_key("hibp", &email), dispatch_key("hibp", &domain));
}

#[test]
fn dispatch_log_prevents_duplicate_keyed_module() {
    let mut log: DispatchLog = DispatchLog::new();
    let t = Target::new(TargetKind::Email, "alice@example.com");
    let key = dispatch_key("hibp", &t);
    assert!(log.insert(key.clone()), "first insert should succeed");
    assert!(!log.insert(key), "second insert should be rejected");
}

#[test]
fn dispatch_log_allows_same_module_on_different_targets() {
    let mut log: DispatchLog = DispatchLog::new();
    let t1 = Target::new(TargetKind::Email, "alice@example.com");
    let t2 = Target::new(TargetKind::Domain, "example.com");
    assert!(log.insert(dispatch_key("hibp", &t1)));
    assert!(log.insert(dispatch_key("hibp", &t2)));
}

#[test]
fn dispatch_log_allows_different_modules_on_same_target() {
    let mut log: DispatchLog = DispatchLog::new();
    let t = Target::new(TargetKind::IpAddress, "1.2.3.4");
    assert!(log.insert(dispatch_key("shodan", &t)));
    assert!(log.insert(dispatch_key("greynoise", &t)));
}

// ── End-to-end engine throughput benchmark (ignored; opt-in) ──────────────
//
// Drives a full multi-round expansion scan over the in-memory store with a
// deterministic fan-out module (no network, no SQLite), so the measured time
// is pure engine orchestration: per-round dispatch, entity merge, incremental
// correlation, ranking, and checkpointing. Run on demand:
//   cargo test -p huntsman-search-engine --lib core::engine::tests::bench_ -- \
//     --ignored --nocapture
//
// Finding (debug build, ~10x slower than release): orchestration scales
// ~O(n^1.4) in the entity count — superlinear (the incremental correlation
// and checkpoint each re-touch the whole working set per round) but firmly
// sub-quadratic. In release that is ~tens of ms for a few thousand entities,
// which is negligible against a real scan's network time (every module awaits
// HTTP for 100s of ms–seconds; HSE is IO-bound by design). So this is a
// baseline/diagnostic, NOT an assertive guard: end-to-end timing carries too
// much tokio-scheduling variance for a stable threshold, and the dominant
// pure-CPU cost (the correlation pass) is already guarded by
// `correlator::perf::pass_is_subquadratic`. Re-run this if the orchestration
// is ever reworked, to confirm it stays sub-quadratic.
use crate::core::entity::EntityKind;
use std::sync::atomic::{AtomicU64, Ordering};

/// Emits `WIDTH` fresh Username entities per dispatch (unique values via a
/// global counter), at a confidence above the expansion threshold — so the
/// scan fans out every round until it hits the `max_entities` budget. That
/// budget is the knob the benchmark sweeps to expose end-to-end scaling.
struct FanoutModule {
    width: u64,
}

static FANOUT_SEQ: AtomicU64 = AtomicU64::new(0);

#[async_trait::async_trait]
impl Module for FanoutModule {
    fn name(&self) -> &'static str {
        "bench_fanout"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, _: &Target) -> bool {
        true
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[EntityKind::Username];
        K
    }
    async fn process(
        &self,
        _: &Target,
        ctx: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        let mut r = crate::core::module::ModuleResult::new();
        for _ in 0..self.width {
            let n = FANOUT_SEQ.fetch_add(1, Ordering::Relaxed);
            let mut e = Entity::new(EntityKind::Username, format!("user{n}"), 0.9, &ctx.scan_id);
            e.tag("bench");
            e.add_evidence(crate::core::entity::Evidence::new(
                "bench_fanout",
                "synthetic",
            ));
            r.push(e);
        }
        Ok(r)
    }
}

async fn run_bench_scan(max_entities: usize) -> (usize, std::time::Duration) {
    use crate::core::test_support::InMemoryStore;
    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, _rx) = tokio::sync::broadcast::channel(4096);
    let engine = ScanEngine::new(
        vec![Arc::new(FanoutModule { width: 8 })],
        store_port,
        bus.clone(),
    );
    let opts = ScanOptions {
        depth: 12,
        max_entities: Some(max_entities),
        max_concurrent: 4,
        ..Default::default()
    };
    let target = Target::new(TargetKind::Username, "seed");
    let scan = Scan::new(
        crate::core::entity::scan_id("username", "seed"),
        target.clone(),
    )
    .with_options(opts);
    let ctx = ModuleContext {
        scan_id: scan.id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    };
    let start = std::time::Instant::now();
    let _ = engine.run(scan, target, ctx).await;
    let elapsed = start.elapsed();
    (store.entity_count(), elapsed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "engine throughput baseline; run with --ignored --nocapture"]
async fn bench_end_to_end_scan_scaling() {
    // Warm up allocator / code paths so the first sample isn't penalised.
    FANOUT_SEQ.store(0, Ordering::Relaxed);
    let _ = run_bench_scan(1000).await;

    eprintln!("end-to-end scan — min-of-3 total time by entity budget (debug build):");
    for &cap in &[1000usize, 2000, 4000] {
        let mut best = std::time::Duration::MAX;
        let mut n = 0;
        for _ in 0..3 {
            FANOUT_SEQ.store(0, Ordering::Relaxed);
            let (c, dt) = run_bench_scan(cap).await;
            best = best.min(dt);
            n = c;
        }
        eprintln!(
            "  max_entities={cap:5}  entities={n:5}  {:8.1} ms",
            best.as_secs_f64() * 1e3
        );
    }
}

/// ROI truncation must RELEASE the visited keys of the candidates it cuts.
/// A cut candidate was queued but never dispatched, so leaving its key in
/// `visited` excluded the same lead as `already_dispatched_this_scan` in
/// every later round — a lead whose weight rises with corroboration was
/// silently lost for the rest of the scan. The kept (still-queued) heads
/// stay visited.
#[test]
fn roi_cutoff_releases_visited_keys_of_truncated_candidates() {
    let mk = |v: &str| Target::new(TargetKind::Domain, v.to_string());
    let mut next: Vec<(Target, f64, String)> = vec![
        (mk("leader.com"), 50.0, "p".to_string()),
        (mk("kept.com"), 40.0, "p".to_string()),
        (mk("tail-a.com"), 0.5, "p".to_string()),
        (mk("tail-b.com"), 0.2, "p".to_string()),
    ];
    let mut visited: HashSet<(TargetKind, String)> =
        next.iter().map(|(t, _, _)| visit_key(t)).collect();

    apply_roi_cutoff(&mut next, &mut visited, 0);

    // Knee at 5% of the leader (2.5): the two tail candidates are cut even
    // though top-K (10 at max_concurrent=0) would have kept them.
    assert_eq!(next.len(), 2, "knee should cut the sub-2.5-weight tail");
    assert!(visited.contains(&visit_key(&mk("leader.com"))));
    assert!(visited.contains(&visit_key(&mk("kept.com"))));
    assert!(
        !visited.contains(&visit_key(&mk("tail-a.com"))),
        "cut candidate must be released to compete in a later round"
    );
    assert!(!visited.contains(&visit_key(&mk("tail-b.com"))));
}

/// The persistent store is a SOURCE, not just a sink: prior-scan findings for a
/// target are pulled back at scan start, stamped as observed this scan, and
/// tagged `recalled` (provenance) while keeping their original tags/evidence.
/// Exercises `recall_prior_entities` directly (no full `run`, so the global
/// search-regional toggle the engine sets is left untouched).
#[tokio::test]
async fn recall_prior_entities_pulls_and_tags_prior_scan_findings() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();

    // A prior scan ("prior-scan") of this Username: the seed anchor plus a
    // discovered email that NO live module will re-emit.
    let mut seed = Entity::new(EntityKind::Username, "recallsubject", 0.9, "prior-scan");
    seed.add_evidence(Evidence::new("anchor", "seed"));
    let mut email = Entity::new(
        EntityKind::Email,
        "plantedlead@gmail.com",
        0.8,
        "prior-scan",
    );
    email.tag("planted");
    email.add_evidence(Evidence::new("plant", "found in an earlier scan"));
    store.upsert_entity(&seed).unwrap();
    store.upsert_entity(&email).unwrap();

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(vec![], store_port, bus);
    let target = Target::new(TargetKind::Username, "recallsubject");

    // Recall for a NEW scan id surfaces the prior email, re-stamped + tagged.
    let recalled = engine.recall_prior_entities(&target, "current-scan", true);
    let got = recalled
        .iter()
        .find(|e| e.value == "plantedlead@gmail.com")
        .expect("recall surfaces the prior scan's email from the database");
    assert!(
        got.has_tag("recalled"),
        "recalled node carries the provenance tag"
    );
    assert!(got.has_tag("planted"), "original tags survive recall");
    assert_eq!(
        got.scan_id, "current-scan",
        "recalled node is stamped as observed in the current scan"
    );
    assert_eq!(
        got.corroboration, 0,
        "recalled nodes contribute zero corroboration so re-persisting is \
         idempotent — the DB already holds the true count; re-scans must not \
         compound it"
    );

    // A scan never recalls its own rows: asking as "prior-scan" (the only scan
    // that observed the seed) excludes itself ⇒ nothing to recall.
    assert!(
        engine
            .recall_prior_entities(&target, "prior-scan", true)
            .is_empty(),
        "the sole prior scan is the requesting scan ⇒ empty recall"
    );
}

/// Recall's confidence-DESC sort must carry a total, deterministic tie-break so
/// equal-confidence nodes come back in a fixed order — otherwise WHICH of them
/// survive the internal `truncate(MAX_ENTITIES)` boundary cut is decided by
/// `HashMap` iteration order (`merged.into_values()`), leaking non-determinism
/// into the persisted working set. The tie-break is `uid` ascending, so a run of
/// same-confidence recalled entities must emerge uid-sorted, identically on every
/// call even though each call rebuilds the `merged` map (fresh random seed).
#[tokio::test]
async fn recall_prior_entities_tie_breaks_equal_confidence_by_uid() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();

    // A prior scan whose seed Username anchors the recall, plus 24 discovered
    // emails ALL at the same confidence. Their uids (hex(SHA-256("email:...")))
    // scatter relative to insertion order, so only an explicit uid tie-break can
    // make the recalled run monotonic — a stable sort alone preserves the
    // randomised HashMap order.
    let seed = Entity::new(EntityKind::Username, "tiebreaksubject", 0.95, "prior-scan");
    store.upsert_entity(&seed).unwrap();
    for i in 0..24u32 {
        let mut email = Entity::new(
            EntityKind::Email,
            format!("tiebreak{i:02}@example.com"),
            0.8,
            "prior-scan",
        );
        email.add_evidence(Evidence::new("plant", "found in an earlier scan"));
        store.upsert_entity(&email).unwrap();
    }

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(vec![], store_port, bus);
    let target = Target::new(TargetKind::Username, "tiebreaksubject");

    // The uid sequence of the equal-confidence emails, in recalled order.
    let email_uids = |recalled: &[Entity]| -> Vec<String> {
        recalled
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.uid.clone())
            .collect::<Vec<_>>()
    };

    let first = engine.recall_prior_entities(&target, "current-scan", true);
    let first_uids = email_uids(&first);
    assert_eq!(
        first_uids.len(),
        24,
        "every planted email is recalled — no cap loses any at this size"
    );
    let mut sorted = first_uids.clone();
    sorted.sort();
    assert_eq!(
        first_uids, sorted,
        "equal-confidence recalled entities emerge uid-ascending, not in HashMap order"
    );

    // Rebuild-independence: a second recall constructs a fresh `merged` HashMap
    // (new random seed) yet must yield the identical order.
    let second = email_uids(&engine.recall_prior_entities(&target, "current-scan", true));
    assert_eq!(
        first_uids, second,
        "recall order is deterministic across calls despite the internal HashMap"
    );
}

/// A FullName seed must recall prior intel even though the stored Person anchor
/// is reformatted by name parsing: the `seed_uid` derives from the raw,
/// un-title-cased input and misses, so the value-match fallback's token-set key
/// has to rescue case, comma order, and a trailing year. Run against a REAL
/// SQLite store because the fallback depends on FTS token matching, which the
/// in-memory test double's substring search can't model.
#[tokio::test]
async fn recall_resolves_a_fullname_seed_despite_reformatting() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::storage::Store;

    let path = format!(
        "{}/.hse-recall-name-{}.db",
        std::env::temp_dir().to_string_lossy(),
        std::process::id()
    );
    let cleanup = |p: &str| {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(format!("{p}-wal"));
        let _ = std::fs::remove_file(format!("{p}-shm"));
    };
    cleanup(&path);
    let store: Arc<dyn StoragePort> = Arc::new(Store::open(&path).unwrap());

    // A prior scan stored the Person anchor TITLE-CASED (as name parsing does)
    // plus a discovered email no live module will re-emit.
    store
        .upsert_scan(&Scan::new(
            "prior",
            Target::new(TargetKind::FullName, "Jordan Meyers"),
        ))
        .unwrap();
    let mut person = Entity::new(EntityKind::Person, "Jordan Meyers", 0.9, "prior");
    person.add_evidence(Evidence::new("name_intel", "seed"));
    let mut email = Entity::new(EntityKind::Email, "jordanlead@gmail.com", 0.8, "prior");
    email.add_evidence(Evidence::new("hibp", "breach"));
    store.upsert_entity(&person).unwrap();
    store.upsert_entity(&email).unwrap();

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(vec![], store, bus);

    // Each input mismatches the stored title-case `seed_uid`, so recall depends
    // on the token-set fallback: lower-case, "Last, First" order, trailing year.
    for input in ["jordan meyers", "Meyers, Jordan", "Jordan Meyers 1987"] {
        let target = Target::new(TargetKind::FullName, input);
        let recalled = engine.recall_prior_entities(&target, "current", true);
        assert!(
            recalled
                .iter()
                .any(|e| e.value == "jordanlead@gmail.com" && e.has_tag("recalled")),
            "recall must resolve FullName '{input}' to the prior scan's email via the token-set fallback"
        );
    }

    cleanup(&path);
}

/// The seed-aware incidental-infrastructure admission gate
/// ([`dispatch::is_incidental_infra_entity`]): on an identity-seeded scan, shared
/// provider/CDN/registrar/DNS estate and role mailboxes are dropped as noise,
/// while the subject's own findings (freemail address, own domain, residential
/// IP) survive — and an infrastructure-seeded scan keeps everything, because
/// there the infrastructure IS the subject.
#[test]
fn incidental_infra_is_dropped_only_on_identity_seeds() {
    use crate::core::entity::{Entity, EntityKind};
    use dispatch::is_incidental_infra_entity;

    let ip_cdn = Entity::new(EntityKind::IpAddress, "104.20.37.187", 0.6, "dns"); // Cloudflare edge
    let ip_home = Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.6, "dns"); // routable, not edge
    let dom_infra = Entity::new(EntityKind::Domain, "ns1.jomax.net", 0.6, "dns");
    let dom_mega = Entity::new(EntityKind::Domain, "facebook.com", 0.6, "se");
    let dom_subject = Entity::new(EntityKind::Domain, "goatlegal.com.au", 0.6, "whois");
    let mail_role = Entity::new(EntityKind::Email, "abuse@cloudflare.com", 0.6, "whois");
    let mail_infra = Entity::new(EntityKind::Email, "bounce@jomax.net", 0.6, "soa");
    let mail_subject = Entity::new(EntityKind::Email, "haigen@gmail.com", 0.6, "hibp");

    // ── Identity seed (Username): provider estate + role mailboxes are noise. ──
    let seed = TargetKind::Username;
    for noise in [&ip_cdn, &dom_infra, &dom_mega, &mail_role, &mail_infra] {
        assert!(
            is_incidental_infra_entity(seed, noise),
            "{} should be dropped as incidental infra on an identity seed",
            noise.value
        );
    }
    // The subject's own findings must SURVIVE — they are the point of the scan.
    for keep in [&ip_home, &dom_subject, &mail_subject] {
        assert!(
            !is_incidental_infra_entity(seed, keep),
            "{} is a subject finding and must NOT be dropped",
            keep.value
        );
    }
    // Freemail vs role-mailbox asymmetry holds for other identity seeds too.
    assert!(!is_incidental_infra_entity(
        TargetKind::Email,
        &mail_subject
    ));
    assert!(is_incidental_infra_entity(TargetKind::Phone, &mail_role));

    // ── Infrastructure seed: the estate IS the subject ⇒ nothing is incidental. ─
    for seed in [
        TargetKind::Domain,
        TargetKind::IpAddress,
        TargetKind::Cidr,
        TargetKind::Asn,
        TargetKind::Url,
    ] {
        for e in [&ip_cdn, &dom_infra, &dom_mega, &mail_role, &mail_infra] {
            assert!(
                !is_incidental_infra_entity(seed, e),
                "{} must be kept on an infrastructure ({seed:?}) seed",
                e.value
            );
        }
    }
}

/// A module that emits one subject finding and declares a known, distinctive
/// ATT&CK Reconnaissance technique. Used to prove the engine stamps that
/// technique onto the admitted entity — overriding `attack_techniques()`
/// directly (the `ModuleCategory::Other` default maps to an empty set) so the
/// expected tag is deterministic and independent of the live registry.
struct AttackStampModule;

#[async_trait::async_trait]
impl Module for AttackStampModule {
    fn name(&self) -> &'static str {
        "attack_stamp_probe"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::Email
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        // "Email Addresses" — a real catalogued Reconnaissance sub-technique.
        &["T1589.002"]
    }
    async fn process(
        &self,
        _: &Target,
        ctx: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        // A subject freemail address: survives every admission filter (not a
        // placeholder, not infra, freemail is exempt from the incidental-infra
        // gate) so the only thing that can be asserted is the ATT&CK stamping.
        let mut e = Entity::new(
            EntityKind::Email,
            "foundsubject@gmail.com",
            0.9,
            &ctx.scan_id,
        );
        e.add_evidence(Evidence::new("attack_stamp_probe", "synthetic finding"));
        let mut r = crate::core::module::ModuleResult::new();
        r.push(e);
        Ok(r)
    }
}

/// Universal MITRE ATT&CK provenance: EVERY admitted entity must carry an
/// `attack:<ID>` tag for each Reconnaissance technique its producing module
/// declares, so the technique that collected a datum travels with the scan data
/// (the entity's `tags`, hence JSON output, the dossier, and the DB). Drives the
/// real admission path (`dispatch_target` → `finalise_module_result`) on BOTH the
/// sequential (`max_concurrent == 0`) and concurrent (`max_concurrent > 0`, which
/// carries the techniques through `DispatchOutcome` to the join site) codepaths,
/// then inspects the merged working set. Exercises `dispatch_target` directly
/// rather than the full `run` so the process-global search-regional toggle the
/// engine sets is left untouched (it would race the `search_engines` query tests).
#[tokio::test]
async fn admitted_entities_are_stamped_with_their_modules_attack_techniques() {
    use crate::core::test_support::InMemoryStore;

    for max_concurrent in [0usize, 4] {
        let store: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
        let (bus, _rx) = tokio::sync::broadcast::channel(64);
        let engine = ScanEngine::new(vec![Arc::new(AttackStampModule)], store, bus.clone());

        let target = Target::new(TargetKind::Email, "seed@gmail.com");
        let opts = ScanOptions {
            max_concurrent,
            ..Default::default()
        };
        let mut ctx = ModuleContext {
            scan_id: "stamp-scan".to_string(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        };

        let cx = DispatchCx {
            scan_id: "stamp-scan",
            target: &target,
            opts: &opts,
            is_expansion: false,
            seed_kind: TargetKind::Email,
        };
        let mut entity_map: HashMap<String, Entity> = HashMap::new();
        let mut stats = ModuleStats::default();
        let mut dispatched: DispatchLog = DispatchLog::new();
        let mut state = DispatchState {
            entity_map: &mut entity_map,
            stats: &mut stats,
            dispatched: &mut dispatched,
        };

        engine
            .dispatch_target(&cx, &mut ctx, &mut state)
            .await
            .expect("dispatch runs");

        let found = entity_map
            .values()
            .find(|e| e.value == "foundsubject@gmail.com")
            .unwrap_or_else(|| {
                panic!("the probe's finding must be admitted (max_concurrent={max_concurrent})")
            });
        assert!(
            found.has_tag("attack:T1589.002"),
            "the admitted entity must carry its module's ATT&CK technique as an \
             inline tag (max_concurrent={max_concurrent}); tags were {:?}",
            found.tags
        );
        // Exactly the producing module's technique(s) — none invented, none dropped.
        let attack_tags: Vec<&str> = found
            .tags
            .iter()
            .filter(|t| t.starts_with("attack:"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            attack_tags,
            vec!["attack:T1589.002"],
            "exactly the producing module's technique(s) are stamped \
             (max_concurrent={max_concurrent})"
        );
    }
}

/// Emits exactly one unique entity per instance and does no internal
/// `.await`, so a task runs to completion the instant the executor polls it
/// — the property `concurrent_dispatch_stops_near_max_entities_not_after_the
/// _full_module_set` relies on to force a deterministic interleave.
struct SingleFindingModule {
    name: &'static str,
    value: &'static str,
}

#[async_trait::async_trait]
impl Module for SingleFindingModule {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, _: &Target) -> bool {
        true
    }
    async fn process(
        &self,
        _: &Target,
        ctx: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let mut e = Entity::new(EntityKind::Username, self.value, 0.9, &ctx.scan_id);
        e.add_evidence(Evidence::new(self.name, "synthetic"));
        let mut r = crate::core::module::ModuleResult::new();
        r.push(e);
        Ok(r)
    }
}

/// Regression for `PROBLEM_TREE` T2.11 LOW: the concurrent dispatcher's
/// `max_entities` gate must see completed sibling results as they land, not
/// only the snapshot from before this target's spawn loop started —
/// otherwise a target with many accepting modules dispatches its FULL
/// module set even after the cap is already reached, instead of stopping
/// close to it. `max_concurrent: 1` forces the spawn loop to await a permit
/// before every module past the first, which — because each
/// [`SingleFindingModule`] task completes with no internal `.await` — gives
/// the previous module's result a chance to be drained by the interleaved
/// `try_join_next` (added in [`dispatch_target_concurrent`]) before the next
/// `max_entities` check. With `max_entities: Some(1)` against ten accepting
/// modules, at most two should ever be spawned; before that interleave was
/// added, this test failed with `entity_map.len() == 10` (every module ran).
#[tokio::test]
async fn concurrent_dispatch_stops_near_max_entities_not_after_the_full_module_set() {
    use crate::core::test_support::InMemoryStore;

    const NAMES: [&str; 10] = [
        "overdispatch_probe_0",
        "overdispatch_probe_1",
        "overdispatch_probe_2",
        "overdispatch_probe_3",
        "overdispatch_probe_4",
        "overdispatch_probe_5",
        "overdispatch_probe_6",
        "overdispatch_probe_7",
        "overdispatch_probe_8",
        "overdispatch_probe_9",
    ];
    let modules: Vec<Arc<dyn Module>> = NAMES
        .iter()
        .map(|&name| Arc::new(SingleFindingModule { name, value: name }) as Arc<dyn Module>)
        .collect();

    let store: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::new(modules, store, bus.clone());

    let target = Target::new(TargetKind::Username, "overdispatch-seed");
    let opts = ScanOptions {
        max_concurrent: 1,
        max_entities: Some(1),
        ..Default::default()
    };
    let mut ctx = ModuleContext {
        scan_id: "overdispatch-scan".to_string(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    };
    let cx = DispatchCx {
        scan_id: "overdispatch-scan",
        target: &target,
        opts: &opts,
        is_expansion: false,
        seed_kind: TargetKind::Username,
    };
    let mut entity_map: HashMap<String, Entity> = HashMap::new();
    let mut stats = ModuleStats::default();
    let mut dispatched: DispatchLog = DispatchLog::new();
    let mut state = DispatchState {
        entity_map: &mut entity_map,
        stats: &mut stats,
        dispatched: &mut dispatched,
    };

    engine
        .dispatch_target(&cx, &mut ctx, &mut state)
        .await
        .expect("dispatch runs");

    assert!(
        entity_map.len() < NAMES.len(),
        "max_entities=1 must cut concurrent dispatch short of the full \
         {}-module set; got {} entities — the concurrent path is \
         over-dispatching by the whole module set again",
        NAMES.len(),
        entity_map.len()
    );
}

#[test]
fn rank_enrichment_leverage_orders_join_keys_by_cross_scan_degree() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::test_support::InMemoryStore;

    let store = InMemoryStore::new();
    let up = |k, v, s| store.upsert_entity(&Entity::new(k, v, 0.7, s)).unwrap();

    // An email observed across THREE investigations — in the in-memory store the
    // accumulated corroboration is the observation_count, i.e. cross-scan degree 3.
    for s in ["scan-a", "scan-b", "scan-c"] {
        up(EntityKind::Email, "jane@example.com", s);
    }
    // A phone seen in ONE scan → degree 1.
    up(EntityKind::Phone, "+61400111222", "scan-a");
    // A mega/infra domain seen across FIVE scans — high degree, but NOT a join key,
    // so it must never rank (the gate, not the degree, decides inclusion).
    for s in ["s1", "s2", "s3", "s4", "s5"] {
        up(EntityKind::Domain, "google.com", s);
    }

    let candidates = vec![
        Entity::new(EntityKind::Email, "jane@example.com", 0.7, "now"),
        Entity::new(EntityKind::Phone, "+61400111222", 0.7, "now"),
        Entity::new(EntityKind::Domain, "google.com", 0.9, "now"),
    ];

    let ranked = rank_enrichment_leverage(&store, &candidates, 10);
    assert_eq!(ranked.len(), 2, "the non-join-key domain is excluded");
    assert_eq!(ranked[0].value, "jane@example.com");
    assert_eq!(
        ranked[0].cross_scan_degree, 3,
        "email bridges 3 investigations"
    );
    assert_eq!(ranked[1].value, "+61400111222");
    assert_eq!(ranked[1].cross_scan_degree, 1);
    assert!(
        ranked.iter().all(|r| r.kind != EntityKind::Domain),
        "infrastructure is never an enrichment join key, whatever its degree"
    );

    // `limit` caps the result to the strongest-leverage identifiers.
    let top1 = rank_enrichment_leverage(&store, &candidates, 1);
    assert_eq!(top1.len(), 1);
    assert_eq!(top1[0].value, "jane@example.com");
}

#[test]
fn enrich_offline_geo_parses_addresses_and_derives_city_coordinates() {
    use crate::core::engine::enrich_offline_geo;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // A sourced AU address whose city resolves in the offline table, plus an
    // imported bare coordinate carrying no geohash yet.
    let mut addr = Entity::new(
        EntityKind::Address,
        "12 Smith Street, Sydney NSW 2000",
        0.60,
        "s",
    );
    addr.add_evidence(Evidence::new("import:dossier", "breach record"));
    let coord = Entity::new(EntityKind::Coordinates, "-37.8136,144.9631", 0.70, "s");

    let mut ents = vec![addr, coord];
    enrich_offline_geo(&mut ents, "s");

    // The address gained a deterministic geo_normalize parse.
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Address
            && e.evidence.iter().any(|ev| ev.source == "geo_normalize")),
        "the address must be parsed/normalised"
    );
    // A Sydney coordinate was derived from the address (offline city lookup).
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Coordinates
            && e.has_tag("addr-derived")
            && e.value.starts_with("-33.8688")),
        "a Coordinates fix must be derived from the Sydney address"
    );
    // Every coordinate (imported + derived) now carries a geohash tag, so the
    // geo-proximity correlation can match them.
    assert!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .all(|e| e.tags.iter().any(|t| t.starts_with("geohash:"))),
        "all coordinates must be geohash-enriched"
    );
}

#[test]
fn enrich_offline_geo_is_a_noop_without_geocodable_addresses() {
    use crate::core::engine::enrich_offline_geo;
    use crate::core::entity::{Entity, EntityKind};

    // No Address/Coordinates → nothing to enrich, no new entities.
    let mut ents = vec![
        Entity::new(EntityKind::Email, "a@b.com", 0.8, "s"),
        Entity::new(EntityKind::Username, "bob", 0.6, "s"),
    ];
    let before = ents.len();
    enrich_offline_geo(&mut ents, "s");
    assert_eq!(
        ents.len(),
        before,
        "non-geo entities must not spawn coordinates"
    );
}

/// The composite autonomous priority must reward all three axes: stronger pivot
/// kind, more cross-investigation leverage, and higher confidence — and none of
/// them alone can top a target that is weak on the others.
#[test]
fn autonomous_target_score_multiplies_pivot_leverage_and_confidence() {
    use super::autonomous_target_score;
    use crate::core::entity::EntityKind;

    // Same leverage + confidence: a stronger pivot kind scores higher.
    let email = autonomous_target_score(&EntityKind::Email, 2, 0.8);
    let coord = autonomous_target_score(&EntityKind::Coordinates, 2, 0.8);
    assert!(
        email > coord,
        "email out-pivots a coordinate: {email} > {coord}"
    );

    // Same kind + confidence: more cross-scan degree lifts the score, but a log
    // curve keeps it sub-linear (10× the degree is far less than 10× the score).
    let d0 = autonomous_target_score(&EntityKind::Email, 0, 0.9);
    let d1 = autonomous_target_score(&EntityKind::Email, 1, 0.9);
    let d10 = autonomous_target_score(&EntityKind::Email, 10, 0.9);
    assert!(d1 > d0, "any corroboration beats none");
    assert!(d10 > d1, "more corroboration ranks higher");
    assert!(
        d10 < d1 * 10.0,
        "leverage is logarithmic, not linear: count can't dominate"
    );

    // degree 0 is the neutral leverage 1.0 — score collapses to pivot × confidence.
    let expected = super::kind_pivot_value(&EntityKind::Email) * 0.9;
    assert!((d0 - expected).abs() < 1e-9, "degree 0 ⇒ neutral leverage");

    // Confidence scales linearly and is clamped to 0..=1.
    let lo = autonomous_target_score(&EntityKind::Person, 3, 0.2);
    let hi = autonomous_target_score(&EntityKind::Person, 3, 0.95);
    assert!(hi > lo, "a corroborated fact out-ranks a speculative one");
    let clamped = autonomous_target_score(&EntityKind::Person, 3, 5.0);
    let unit = autonomous_target_score(&EntityKind::Person, 3, 1.0);
    assert!((clamped - unit).abs() < 1e-9, "confidence clamps at 1.0");
}

/// The sweep planner classifies and orders the whole working set, honours the
/// `exclude` set a continuous loop maintains, drops non-pivotable kinds, and
/// truncates to `limit` — deterministically. At `diversity = 0` it is a pure
/// composite-score ranking.
#[test]
fn plan_autonomous_sweep_orders_excludes_and_truncates() {
    use super::plan_autonomous_sweep;
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::TargetKind;
    use std::collections::HashSet;

    let entities = vec![
        Entity::new(EntityKind::Email, "a@b.com", 0.9, "s"),
        Entity::new(EntityKind::Phone, "+61400111222", 0.9, "s"),
        Entity::new(EntityKind::Credential, "secret", 0.9, "s"), // not a cross-scan candidate
        Entity::new(EntityKind::Coordinates, "-33.8,151.2", 0.9, "s"), // coarse geo — gated out
        Entity::new(EntityKind::Username, "alice", 0.6, "s"),
    ];
    // Uniform degree so the ordering is decided by pivot × confidence alone.
    let degree_of = |_uid: &str| 2usize;
    let exclude = HashSet::new();

    // diversity = 0 ⇒ pure composite-score order.
    let ranked = plan_autonomous_sweep(&entities, degree_of, &exclude, 10, 0.0).queue;
    assert_eq!(
        ranked.len(),
        3,
        "only the cross-scan-candidate pivots (email/phone/username) survive the gate"
    );
    assert_eq!(ranked[0].kind, TargetKind::Email, "email pivots strongest");
    assert_eq!(ranked[1].kind, TargetKind::Phone, "phone next");
    assert!(
        ranked.iter().all(|t| t.value != "secret"),
        "no non-pivotable target survives"
    );
    assert!(
        ranked[0].score >= ranked[1].score && ranked[1].score >= ranked[2].score,
        "strongest-first ordering"
    );

    // Excluding the top UID removes it; the next-strongest becomes the head.
    let mut ex = HashSet::new();
    ex.insert(ranked[0].uid.clone());
    let after = plan_autonomous_sweep(&entities, degree_of, &ex, 10, 0.0).queue;
    assert_eq!(after.len(), 2, "the excluded target is gone");
    assert!(
        after.iter().all(|t| t.uid != ranked[0].uid),
        "a loop never re-seeds an excluded target"
    );

    // `limit` caps the queue to the strongest candidates.
    let top1 = plan_autonomous_sweep(&entities, degree_of, &exclude, 1, 0.0).queue;
    assert_eq!(top1.len(), 1);
    assert_eq!(top1[0].kind, TargetKind::Email);
}

/// With `diversity = 0` the sweep planner reproduces the pure score ranking; with
/// positive diversity it interleaves kinds so the loop doesn't tunnel a whole
/// budget on the single most-represented kind.
#[test]
fn plan_autonomous_sweep_interleaves_kinds_under_diversity() {
    use super::{DEFAULT_SWEEP_DIVERSITY, plan_autonomous_sweep};
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::TargetKind;
    use std::collections::HashSet;

    // Three emails (strongest pivot) and one phone. Pure score order would place
    // the phone last (behind all three emails); diversity should pull it forward.
    let entities = vec![
        Entity::new(EntityKind::Email, "a@x.com", 0.9, "s"),
        Entity::new(EntityKind::Email, "b@x.com", 0.85, "s"),
        Entity::new(EntityKind::Email, "c@x.com", 0.8, "s"),
        Entity::new(EntityKind::Phone, "+61400111222", 0.9, "s"),
    ];
    let degree_of = |_uid: &str| 1usize;
    let exclude = HashSet::new();

    // diversity = 0 ⇒ pure composite-score order. With email pivot 1.0 and phone
    // 0.95 at uniform degree, the scores are 0.9 / 0.855 / 0.85 / 0.8, so the phone
    // (0.855) sits ahead of the two weaker emails: [Email, Phone, Email, Email].
    let flat = plan_autonomous_sweep(&entities, degree_of, &exclude, 10, 0.0);
    assert_eq!(flat.considered, 4);
    assert_eq!(flat.kinds_covered, 2, "email + phone represented");
    assert_eq!(
        flat.queue.iter().map(|t| t.kind).collect::<Vec<_>>(),
        vec![
            TargetKind::Email,
            TargetKind::Phone,
            TargetKind::Email,
            TargetKind::Email
        ],
        "zero diversity must match pure score order"
    );

    // Positive diversity ⇒ the phone is promoted ahead of the weaker emails.
    let spread = plan_autonomous_sweep(&entities, degree_of, &exclude, 10, DEFAULT_SWEEP_DIVERSITY);
    assert_eq!(
        spread.queue[0].kind,
        TargetKind::Email,
        "strongest still first"
    );
    let phone_pos = spread
        .queue
        .iter()
        .position(|t| t.kind == TargetKind::Phone)
        .expect("phone is in the queue");
    assert!(
        phone_pos < 3,
        "diversity pulls the lone phone ahead of the third email (pos {phone_pos})"
    );
    // Every candidate is still present — diversity reorders, never drops.
    assert_eq!(spread.queue.len(), 4);
}

/// The sweep planner honours `exclude` (loop convergence) and the `limit` cap, and
/// reports coverage honestly.
#[test]
fn plan_autonomous_sweep_respects_exclude_and_limit() {
    use super::plan_autonomous_sweep;
    use crate::core::entity::{Entity, EntityKind};
    use std::collections::HashSet;

    let entities = vec![
        Entity::new(EntityKind::Email, "a@x.com", 0.9, "s"),
        Entity::new(EntityKind::Phone, "+61400111222", 0.9, "s"),
        Entity::new(EntityKind::Username, "alice", 0.7, "s"),
    ];
    let degree_of = |_uid: &str| 1usize;

    // Exclude the top email: it must not reappear, and coverage drops accordingly.
    let top = plan_autonomous_sweep(&entities, degree_of, &HashSet::new(), 10, 0.5);
    let mut ex = HashSet::new();
    ex.insert(top.queue[0].uid.clone());
    let after = plan_autonomous_sweep(&entities, degree_of, &ex, 10, 0.5);
    assert_eq!(
        after.considered, 2,
        "the excluded target is not even considered"
    );
    assert!(
        after.queue.iter().all(|t| t.uid != top.queue[0].uid),
        "a loop never re-seeds an excluded target"
    );

    // `limit` caps the queue; kinds_covered reflects only what was queued.
    let capped = plan_autonomous_sweep(&entities, degree_of, &HashSet::new(), 2, 0.5);
    assert_eq!(capped.queue.len(), 2);
    assert_eq!(
        capped.considered, 3,
        "all three were considered, two were queued"
    );
    assert!(capped.kinds_covered <= 2);
}

/// Identity-aware ranking collapses a co-referent cluster (email + username of
/// one person, joined by an AliasOf edge) to a SINGLE target, and scores it with
/// the identity's aggregated leverage + breadth bonus — so it outranks an equally-
/// confident lone selector of the same kind.
#[test]
fn identity_aware_ranking_collapses_clusters_and_aggregates_leverage() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::relation::{Relation, RelationKind};
    use std::collections::HashSet;

    // One person's two selectors, joined as aliases → one identity cluster.
    let email = Entity::new(EntityKind::Email, "jsmith@gmail.com", 0.8, "s");
    let user = Entity::new(EntityKind::Username, "jsmith", 0.8, "s");
    // An unrelated lone email of the same kind/confidence, in no cluster.
    let lone = Entity::new(EntityKind::Email, "solo@example.com", 0.8, "s");
    let ents = vec![email.clone(), user.clone(), lone.clone()];
    let (lo, hi) = if email.uid <= user.uid {
        (&email, &user)
    } else {
        (&user, &email)
    };
    let rels = vec![Relation::new(
        lo.uid.clone(),
        hi.uid.clone(),
        RelationKind::AliasOf,
        0.8,
        "s",
    )];

    // Each selector observed in 2 scans → degree 2.
    let degree_of = |_uid: &str| 2usize;
    let exclude = HashSet::new();
    let ranked = rank_identity_aware_targets(&ents, &rels, degree_of, &exclude, 10);

    // Two identities: the {email,username} cluster and the lone email.
    assert_eq!(
        ranked.len(),
        2,
        "the cluster is one target, plus the singleton"
    );
    let cluster = ranked
        .iter()
        .find(|t| t.cluster_size == 2)
        .expect("the co-referent pair collapses to one target");
    assert_eq!(cluster.distinct_kinds, 2, "email + username");
    assert_eq!(
        cluster.member_uids.len(),
        2,
        "both selectors are reported as members"
    );
    assert_eq!(
        cluster.representative.cross_scan_degree, 4,
        "leverage is aggregated across the identity (2 + 2)"
    );
    // The resolved identity outranks the equally-confident lone selector.
    assert_eq!(
        ranked[0].cluster_size, 2,
        "the richer identity is investigated first"
    );
    let solo = ranked.iter().find(|t| t.cluster_size == 1).unwrap();
    assert!(cluster.representative.score > solo.representative.score);
}

/// A singleton identity scores EXACTLY as the pure per-selector sweep ranking
/// (`plan_autonomous_sweep` at `diversity = 0`) would — the identity-aware ranker
/// is a strict additive generalisation.
#[test]
fn identity_aware_ranking_matches_flat_ranking_for_singletons() {
    use super::plan_autonomous_sweep;
    use crate::core::entity::{Entity, EntityKind};
    use std::collections::HashSet;

    let ents = vec![
        Entity::new(EntityKind::Email, "a@b.com", 0.9, "s"),
        Entity::new(EntityKind::Username, "alice", 0.6, "s"),
    ];
    let degree_of = |_uid: &str| 3usize;
    let exclude = HashSet::new();

    // No relations → no clusters → every entity is its own singleton identity.
    let aware = rank_identity_aware_targets(&ents, &[], degree_of, &exclude, 10);
    let flat = plan_autonomous_sweep(&ents, degree_of, &exclude, 10, 0.0).queue;
    assert_eq!(aware.len(), flat.len());
    for (a, f) in aware.iter().zip(flat.iter()) {
        assert_eq!(a.representative.uid, f.uid, "same order");
        assert_eq!(a.cluster_size, 1, "no cluster ⇒ singleton");
        assert!(
            (a.representative.score - f.score).abs() < 1e-9,
            "singleton score is identical to the flat ranker"
        );
    }
}

/// `exclude` is honoured per member: excluding the representative falls to the
/// next-best member; excluding ALL of a cluster's members drops it (convergence).
#[test]
fn identity_aware_ranking_honours_exclude_per_member() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::relation::{Relation, RelationKind};
    use std::collections::HashSet;

    let email = Entity::new(EntityKind::Email, "jsmith@gmail.com", 0.9, "s");
    let user = Entity::new(EntityKind::Username, "jsmith", 0.6, "s");
    let ents = vec![email.clone(), user.clone()];
    let (lo, hi) = if email.uid <= user.uid {
        (&email, &user)
    } else {
        (&user, &email)
    };
    let rels = vec![Relation::new(
        lo.uid.clone(),
        hi.uid.clone(),
        RelationKind::AliasOf,
        0.8,
        "s",
    )];
    let degree_of = |_uid: &str| 1usize;

    // Exclude the email (the stronger pivot): the cluster survives via the username.
    let mut ex = HashSet::new();
    ex.insert(email.uid.clone());
    let one = rank_identity_aware_targets(&ents, &rels, degree_of, &ex, 10);
    assert_eq!(
        one.len(),
        1,
        "the cluster still yields its non-excluded member"
    );
    assert_eq!(one[0].representative.uid, user.uid);

    // Exclude both members → the identity drops out entirely.
    ex.insert(user.uid.clone());
    assert!(
        rank_identity_aware_targets(&ents, &rels, degree_of, &ex, 10).is_empty(),
        "an all-excluded identity is gone, so the loop converges"
    );
}

/// Direct coverage of the entity-admission drop-filter policy, extracted from
/// `finalise_module_result` into the pure `admission_rejection` so it is testable
/// in isolation (previously every filter was exercised only end-to-end). One case
/// per filter proves the reason string, plus the load-bearing ordering.
#[test]
fn admission_rejection_covers_every_drop_filter_and_order() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::TargetKind;

    let ent = |k: EntityKind, v: &str, c: f64| Entity::new(k, v, c, "adm-test");
    // Identity seed so the incidental-infra gate is active (infrastructure-seeded
    // scans are exempt from it — there the infra IS the subject).
    let seed = TargetKind::FullName;

    // A clean, confident identity finding is admitted (no gate trips).
    assert_eq!(
        admission_rejection(seed, Some(0.3), &ent(EntityKind::Person, "Jane Smith", 0.9)),
        None,
        "a clean identity finding must be admitted",
    );

    // One representative per drop-filter, each yielding its reason string.
    assert_eq!(
        admission_rejection(seed, Some(0.5), &ent(EntityKind::Email, "jane@ok.com", 0.1)),
        Some("below_min_confidence"),
    );
    assert_eq!(
        admission_rejection(seed, None, &ent(EntityKind::IpAddress, "198.18.0.1", 0.9)),
        Some("bogus_ip"),
    );
    assert_eq!(
        admission_rejection(seed, None, &ent(EntityKind::Domain, "example.com", 0.9)),
        Some("placeholder_artifact"),
    );
    assert_eq!(
        admission_rejection(seed, None, &ent(EntityKind::Email, "@gmail", 0.9)),
        Some("fragment_value"),
    );
    assert_eq!(
        admission_rejection(seed, None, &ent(EntityKind::Phone, "+1240893", 0.9)),
        Some("implausible_phone"),
    );
    assert_eq!(
        admission_rejection(
            seed,
            None,
            &ent(EntityKind::Email, "admin@bendigobank.com.au", 0.9)
        ),
        Some("incidental_infra"),
        "a role mailbox on an identity scan is incidental infrastructure",
    );
    assert_eq!(
        admission_rejection(
            seed,
            None,
            &ent(EntityKind::Organisation, "p\u{0430}ypal.com", 0.9)
        ),
        Some("confusable_homoglyph"),
        "a Cyrillic-spoofed value is a homoglyph",
    );
    assert_eq!(
        admission_rejection(seed, None, &ent(EntityKind::Person, "ZonJZRJHHWD", 0.9)),
        Some("gibberish_value"),
    );

    // ORDER is load-bearing: an entity that trips MULTIPLE gates reports the
    // FIRST (cheapest / most-decisive) — a below-confidence bogus IP is rejected
    // as below_min_confidence, not bogus_ip.
    assert_eq!(
        admission_rejection(
            seed,
            Some(0.5),
            &ent(EntityKind::IpAddress, "198.18.0.1", 0.1)
        ),
        Some("below_min_confidence"),
        "the earliest gate in the chain wins",
    );
}

/// Paid stub that sleeps `sleep_ms` then emits one entity named after itself, so
/// a test can prove both that it ran (its entity is present) and how long the
/// PHASE took (concurrent ⇒ ~max sleep, serial ⇒ ~sum of sleeps).
struct SleepyPaidModule {
    name: &'static str,
    sleep_ms: u64,
}

#[async_trait::async_trait]
impl Module for SleepyPaidModule {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, _: &Target) -> bool {
        true
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[EntityKind::Username];
        K
    }
    async fn process(
        &self,
        _: &Target,
        ctx: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        tokio::time::sleep(std::time::Duration::from_millis(self.sleep_ms)).await;
        let mut r = crate::core::module::ModuleResult::new();
        let mut e = Entity::new(EntityKind::Username, self.name, 0.9, &ctx.scan_id);
        e.add_evidence(crate::core::entity::Evidence::new(self.name, "synthetic"));
        r.push(e);
        Ok(r)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paid_phase_runs_modules_concurrently() {
    // Regression guard for the paid-phase parallelization: three Paid modules
    // that each sleep 200ms must run CONCURRENTLY (~200ms wall), not serially
    // (~600ms). Before the fix, run_paid_phase was a serial loop that awaited each
    // paid module to completion — so see_know's 55–80s answer blocked every other
    // module and the seed round never finished on a default scan.
    use crate::core::test_support::InMemoryStore;
    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, _rx) = tokio::sync::broadcast::channel(4096);
    let modules: Vec<Arc<dyn Module>> = vec![
        Arc::new(SleepyPaidModule {
            name: "paid_a",
            sleep_ms: 200,
        }),
        Arc::new(SleepyPaidModule {
            name: "paid_b",
            sleep_ms: 200,
        }),
        Arc::new(SleepyPaidModule {
            name: "paid_c",
            sleep_ms: 200,
        }),
    ];
    let engine = ScanEngine::new(modules, store_port, bus.clone());
    let opts = ScanOptions {
        depth: 0,
        max_concurrent: 4,
        // Leave the process-global REGIONAL_SEARCH toggle at its default (false):
        // the engine calls `set_regional(opts.regional_search)` at scan start, and
        // a concurrently-running `search_engines::build_queries` test asserts the
        // default geolocation-neutral query set. This test needs no regional
        // augmentation, so keep it from polluting that shared global.
        regional_search: false,
        ..Default::default()
    };
    let target = Target::new(TargetKind::Username, "seed");
    let scan = Scan::new(
        crate::core::entity::scan_id("username", "seed"),
        target.clone(),
    )
    .with_options(opts);
    let ctx = ModuleContext {
        scan_id: scan.id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    };
    let start = std::time::Instant::now();
    let _ = engine.run(scan, target, ctx).await;
    let elapsed = start.elapsed();

    // All three paid modules ran (their entities are present).
    for n in ["paid_a", "paid_b", "paid_c"] {
        assert!(
            store.entity_values().iter().any(|v| v == n),
            "paid module {n} must have run and emitted its entity"
        );
    }
    // Concurrent, not serial: 3×200ms serial ≈ 600ms; concurrent ≈ 200ms. A 500ms
    // ceiling is a wide margin that still fails the old serial behaviour.
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "paid phase must run concurrently (took {elapsed:?}, serial would be ~600ms)"
    );
}
