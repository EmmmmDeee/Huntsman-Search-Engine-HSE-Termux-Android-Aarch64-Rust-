//! Unit tests for the scan engine.
//!
//! Split out of the module file (mechanical, behaviour-preserving) so the
//! source reads as implementation; tests reach private items via `use super::*`.

use super::*;

#[tokio::test]
async fn injected_module_runtime_is_used_by_the_engine() {
    use crate::core::test_support::InMemoryStore;

    struct RecordingRuntime(Arc<std::sync::atomic::AtomicU64>);

    impl ModuleRuntime for RecordingRuntime {
        fn reset_per_scan(&self, _scan_id: &str) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    let resets = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let runtime: Arc<dyn ModuleRuntime> = Arc::new(RecordingRuntime(Arc::clone(&resets)));
    let store: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
    let (bus, _rx) = tokio::sync::broadcast::channel(16);
    let engine = ScanEngine::with_module_runtime(vec![], store, bus.clone(), runtime);
    let target = Target::new(TargetKind::Username, "subject");
    let scan = Scan::new(
        crate::core::entity::scan_id("username", "subject"),
        target.clone(),
    );
    let ctx = ModuleContext {
        scan_id: scan.id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: Default::default(),
        cancel: Default::default(),
    };

    engine.run(scan, target, ctx).await.expect("should succeed");

    assert_eq!(resets.load(std::sync::atomic::Ordering::Relaxed), 1);
}

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
    gps.add_evidence(crate::core::entity::Evidence::new("signal_radar", "gps")); // anchoring source
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

    let erik = ents
        .iter()
        .find(|e| e.value == "Erik Moreau")
        .expect("should succeed");
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

    let far = ents
        .iter()
        .find(|e| e.value.contains("4870"))
        .expect("should succeed");
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

/// People-centric "return to old data": a same-name breach candidate whose
/// locality resolves to the subject's confirmed metro is re-promoted out of
/// namesake quarantine, while a same-name record in a different state stays a
/// candidate — and the pass is non-circular (no confirmed fix → no promotion)
/// and idempotent.
#[test]
fn promote_breach_candidate_geo_corroborated_lifts_same_place_same_name_records() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // Subject's confirmed GPS in Brisbane.
    let mut gps = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    gps.tag("geoint");
    gps.add_evidence(crate::core::entity::Evidence::new("signal_radar", "gps")); // anchoring source

    // A same-name breach candidate in the same metro (South Brisbane 4101, ~2 km).
    let mut near = Entity::new(EntityKind::Email, "matt@example.com", 0.25, "s");
    near.tag(crate::core::tags::CANDIDATE);
    near.tag("breach");
    near.add_evidence(Evidence::new("oathnet_pro", "breach row").with_attr("postcode", "4101"));

    // A same-name breach candidate in another state (Perth 6000) — a namesake.
    let mut far = Entity::new(EntityKind::Email, "matt2@example.com", 0.25, "s");
    far.tag(crate::core::tags::CANDIDATE);
    far.tag("breach");
    far.add_evidence(Evidence::new("oathnet_pro", "breach row").with_attr("postcode", "6000"));

    let mut ents = vec![gps, near, far];
    assert_eq!(
        promote_breach_candidate_geo_corroborated(&mut ents),
        1,
        "only the same-metro breach record is re-promoted"
    );

    let near = ents
        .iter()
        .find(|e| e.value == "matt@example.com")
        .expect("should succeed");
    assert!(
        !near.has_tag(crate::core::tags::CANDIDATE),
        "un-quarantined out of candidate"
    );
    assert!(near.has_tag("breach-corroborated"));
    assert!(near.confidence >= 0.50, "lifted to Probable");
    assert!(
        near.evidence
            .iter()
            .any(|ev| ev.source == "geo_corroboration")
    );

    let far = ents
        .iter()
        .find(|e| e.value == "matt2@example.com")
        .expect("should succeed");
    assert!(
        far.has_tag(crate::core::tags::CANDIDATE),
        "an interstate same-name namesake stays quarantined"
    );

    // Idempotent: a second pass promotes nothing new.
    assert_eq!(promote_breach_candidate_geo_corroborated(&mut ents), 0);

    // Non-circular: with NO confirmed subject location, nothing is promoted even
    // though the breach candidate carries a resolvable postcode.
    let mut lone = vec![{
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.25, "s");
        e.tag(crate::core::tags::CANDIDATE);
        e.tag("breach");
        e.add_evidence(Evidence::new("oathnet_pro", "row").with_attr("postcode", "4101"));
        e
    }];
    assert_eq!(promote_breach_candidate_geo_corroborated(&mut lone), 0);
}

/// Reconsideration must keep running on a LARGE working set — the case where
/// coming back to a set-aside lead matters most. Before this was split from the
/// live-correlation bound, a working set over 400 entities skipped the whole
/// free/offline re-promotion pass, so a breach candidate that a later round had
/// geo-corroborated was never lifted above the expansion floor and so never
/// expanded (finalise re-promotes it, but finalise is after the last expansion
/// round). This builds a set well past the old bound and asserts the promotion
/// still happens AND is written back dirty-tracked so it is checkpointed.
#[test]
fn reconsider_working_set_still_promotes_above_the_live_correlation_bound() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let mut map = TrackedEntityMap::new();

    // Subject's confirmed GPS in Brisbane, and a same-metro same-name breach
    // candidate (South Brisbane 4101, ~2 km) that reconsideration should lift.
    let mut gps = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.9, "s");
    gps.tag("geoint");
    gps.add_evidence(crate::core::entity::Evidence::new("signal_radar", "gps")); // anchoring source
    map.insert(gps.uid.clone(), gps);
    let mut cand = Entity::new(EntityKind::Email, "matt@example.com", 0.25, "s");
    cand.tag(crate::core::tags::CANDIDATE);
    cand.tag("breach");
    cand.add_evidence(Evidence::new("oathnet_pro", "breach row").with_attr("postcode", "4101"));
    let cand_uid = cand.uid.clone();
    map.insert(cand_uid.clone(), cand);

    // Pad with inert entities until the set is comfortably past the OLD bound
    // (the live-correlation threshold), so the only thing that lets the
    // promotion run is reconsideration's own, higher bound.
    let pad_target = ScanEngine::INCREMENTAL_CORRELATE_MAX_ENTITIES + 100;
    for i in 0..pad_target {
        let e = Entity::new(EntityKind::Username, format!("filler{i}"), 0.8, "s");
        map.insert(e.uid.clone(), e);
    }
    assert!(
        map.len() > ScanEngine::INCREMENTAL_CORRELATE_MAX_ENTITIES,
        "set must exceed the old gate for this test to be meaningful"
    );
    assert!(map.len() <= RECONSIDER_MAX_ENTITIES);

    // Clear the dirty set the setup inserts left behind, so the next
    // `take_dirty()` reflects ONLY what reconsideration itself changed.
    let _ = map.take_dirty();

    let promoted = reconsider_working_set(&mut map, &[]);
    assert_eq!(
        promoted, 1,
        "the geo-corroborated breach candidate is promoted"
    );

    // The re-promotion is visible in the map (written back)...
    let lifted = map.get(&cand_uid).expect("candidate still present");
    assert!(
        !lifted.has_tag(crate::core::tags::CANDIDATE),
        "un-quarantined"
    );
    assert!(lifted.has_tag("breach-corroborated"));
    assert!(lifted.confidence >= 0.50, "lifted to Probable");
    // ...and ONLY it is dirty-tracked. Writing the whole snapshot back would
    // dirty every entity in the working set on this single promotion and force
    // the round's checkpoint to persist all ~500 — the dirty set must contain
    // exactly the one entity that actually changed.
    let dirty = map.take_dirty();
    assert_eq!(
        dirty.len(),
        1,
        "exactly one entity changed, so exactly one must be dirty (got {})",
        dirty.len()
    );
    assert_eq!(dirty[0].uid, cand_uid);

    // A pathologically huge set is bounded out (the per-round clone guard), and
    // returns 0 rather than stalling.
    let mut huge = TrackedEntityMap::new();
    for i in 0..(RECONSIDER_MAX_ENTITIES + 1) {
        let e = Entity::new(EntityKind::Username, format!("u{i}"), 0.5, "s");
        huge.insert(e.uid.clone(), e);
    }
    assert_eq!(
        reconsider_working_set(&mut huge, &[]),
        0,
        "over-bound is skipped"
    );
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
        let e = ents.iter().find(|e| e.value == v).expect("should succeed");
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
        let e = ents.iter().find(|e| e.value == v).expect("should succeed");
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
        let e = ents.iter().find(|e| &e.uid == uid).expect("should succeed");
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
    let other = ents
        .iter()
        .find(|e| e.value == "x.com")
        .expect("should succeed");
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
    gps.add_evidence(crate::core::entity::Evidence::new("signal_radar", "gps")); // anchoring source
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

    let common = ents
        .iter()
        .find(|e| e.value == "Curt Smith")
        .expect("should succeed");
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
    let rare = ents
        .iter()
        .find(|e| e.value == "Curt Moreau")
        .expect("should succeed");
    assert!(
        !rare.has_tag("geo-discordant"),
        "a far distinctive surname is kin, never a namesake"
    );
    let near = ents
        .iter()
        .find(|e| e.value.contains("4519"))
        .expect("should succeed");
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
    gps.add_evidence(crate::core::entity::Evidence::new("signal_radar", "gps")); // anchoring source
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
    let panicked = guarded_correlation_pass("s", || panic!("kaboom in a correlation rule"));
    assert!(
        panicked.is_none(),
        "a panicking finalise pass must be caught and degrade to no firings, not unwind"
    );

    // A returned error is likewise swallowed to `None` (unchanged behaviour).
    let errored = guarded_correlation_pass("s", || Err(Error::module("correlator", "boom")));
    assert!(errored.is_none(), "a returned error yields no firings");

    // The happy path passes the firings straight through for emission.
    let ok = guarded_correlation_pass("s", || {
        Ok(crate::core::correlator::CorrelationRun {
            firings: vec![Correlation::new(
                "AU-000",
                "test correlation",
                crate::core::correlator::Severity::Low,
                "synthetic".to_string(),
                vec!["uid-a".into(), "uid-b".into()],
                "s",
                0,
            )],
            rules_run: 7,
            rules_total: 7,
        })
    })
    .expect("a successful pass returns Some(firings)");
    assert_eq!(ok.firings.len(), 1);
    assert_eq!(ok.firings[0].rule_id, "AU-000");
    assert!(
        ok.is_complete(),
        "the guard must pass completeness through untouched, not flatten it away"
    );
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
    // Regression: the allowlist ("only these modules run", `hse --help`) was
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
            self.0
                .lock()
                .expect("should succeed")
                .extend_from_slice(buf);
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
    let out =
        String::from_utf8(buf.lock().expect("should succeed").clone()).expect("should succeed");
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

/// A shared empty capability-quarantine set for `DispatchCx` test literals —
/// these tests exercise dispatch paths where capability-aware dispatch is off
/// (nothing quarantined), so they borrow one process-static empty set.
fn no_quarantine() -> &'static std::collections::HashSet<String> {
    static EMPTY: std::sync::OnceLock<std::collections::HashSet<String>> =
        std::sync::OnceLock::new();
    EMPTY.get_or_init(std::collections::HashSet::new)
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
        quarantined: no_quarantine(),
    };
    let mut entity_map: TrackedEntityMap = TrackedEntityMap::new();
    let mut stats = ModuleStats::default();
    let mut dispatched: DispatchLog = DispatchLog::new();
    let mut newly_inserted: Vec<String> = Vec::new();
    let mut state = DispatchState {
        entity_map: &mut entity_map,
        stats: &mut stats,
        dispatched: &mut dispatched,
        newly_inserted: &mut newly_inserted,
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
    let e = map.get_mut(&coord.uid).expect("should succeed");
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
    store.upsert_entity(&seed).expect("should succeed");
    store.upsert_entity(&email).expect("should succeed");

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

/// Recalled prior-scan knowledge is injected before the seed round, so it is
/// generation-0 background context for THIS scan — its stored generation
/// (relative to a different scan's seed) is meaningless here and must be reset.
#[tokio::test]
async fn recall_resets_generation_to_zero() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();

    let mut seed = Entity::new(EntityKind::Username, "recallgen", 0.9, "prior-scan");
    seed.add_evidence(Evidence::new("anchor", "seed"));
    let mut deep = Entity::new(EntityKind::Email, "deeplead@gmail.com", 0.8, "prior-scan");
    deep.generation = 5; // was a deep pivot in the PRIOR scan
    deep.add_evidence(Evidence::new("plant", "found deep in an earlier scan"));
    store.upsert_entity(&seed).expect("should succeed");
    store.upsert_entity(&deep).expect("should succeed");

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(vec![], store_port, bus);
    let target = Target::new(TargetKind::Username, "recallgen");

    let recalled = engine.recall_prior_entities(&target, "current-scan", true);
    let got = recalled
        .iter()
        .find(|e| e.value == "deeplead@gmail.com")
        .expect("recall surfaces the prior deep lead");
    assert_eq!(
        got.generation, 0,
        "a recalled node re-enters at generation 0, not its prior-scan generation"
    );
}

/// A role/provider mailbox (`dns@cloudflare.com`) admitted into the store by
/// an older or now-gated code path must never be resurrected by recall — the
/// live admission gate already refuses to mint one as a first-class Email
/// entity (dns_intel's SOA-admin path, whois, ripestat, search_engines all
/// agree), so recall replaying it forever regardless of that gate is the bug:
/// a live `see-know.xyz` scan recalled `dns@cloudflare.com` at
/// corroboration=396, glued together from 90+ unrelated domains' "Zone admin
/// for X" evidence purely because the value is shared Cloudflare-wide. A
/// genuine personal email must still recall normally.
#[tokio::test]
async fn recall_never_resurrects_a_role_mailbox_email() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();

    let mut seed = Entity::new(EntityKind::Domain, "see-know.xyz", 0.9, "prior-scan");
    seed.add_evidence(Evidence::new("anchor", "seed"));
    let mut role = Entity::new(EntityKind::Email, "dns@cloudflare.com", 0.65, "prior-scan");
    role.tag("dns-admin");
    role.add_evidence(Evidence::new(
        "dns_intel",
        "Zone admin for unrelated-domain.com",
    ));
    let mut personal = Entity::new(EntityKind::Email, "owner@see-know.xyz", 0.8, "prior-scan");
    personal.add_evidence(Evidence::new("whois", "Registrant contact"));
    store.upsert_entity(&seed).expect("should succeed");
    store.upsert_entity(&role).expect("should succeed");
    store.upsert_entity(&personal).expect("should succeed");

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(vec![], store_port, bus);
    let target = Target::new(TargetKind::Domain, "see-know.xyz");

    let recalled = engine.recall_prior_entities(&target, "current-scan", true);
    assert!(
        !recalled.iter().any(|e| e.value == "dns@cloudflare.com"),
        "a role mailbox must never be recalled, no matter how it got into the store"
    );
    assert!(
        recalled.iter().any(|e| e.value == "owner@see-know.xyz"),
        "a genuine personal/registrant email must still recall normally"
    );
}

/// Expansion stamps every entity's `generation` with the round it was first
/// discovered — its distance in pivots from the seed. A deterministic chain
/// module emits exactly one successor per target, so the seed round yields a
/// generation-0 child, round 1 a generation-1 child, round 2 a generation-2
/// child. Merges preserve the earliest generation, so a later round re-emitting
/// an earlier entity never resets it.
struct ChainModule;

#[async_trait::async_trait]
impl Module for ChainModule {
    fn name(&self) -> &'static str {
        "chain"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[EntityKind::Username];
        K
    }
    async fn process(
        &self,
        target: &Target,
        ctx: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        let mut r = crate::core::module::ModuleResult::new();
        let next = match target.value.as_str() {
            "seed" => Some("g0child"),
            "g0child" => Some("g1child"),
            "g1child" => Some("g2child"),
            _ => None,
        };
        if let Some(n) = next {
            let mut e = Entity::new(EntityKind::Username, n, 0.9, &ctx.scan_id);
            e.tag("chain");
            e.add_evidence(crate::core::entity::Evidence::new("chain", "synthetic"));
            r.push(e);
        }
        Ok(r)
    }
}

#[tokio::test]
async fn expansion_stamps_entity_generation_per_round() {
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let engine = ScanEngine::new(vec![Arc::new(ChainModule)], store_port, bus.clone());

    // depth 2 → rounds 1 and 2 run. Gates bypassed so the synthetic chain isn't
    // pruned as a wrong-identity / low-confidence pivot, and ROI off so the
    // adaptive-depth cutoff can't stop the chain early.
    let opts = ScanOptions {
        depth: 2,
        expand_all_identities: true,
        max_roi: false,
        min_expand_confidence: 0.0,
        ..Default::default()
    };
    let target = Target::new(TargetKind::Username, "seed");
    let scan = Scan::new(
        crate::core::entity::scan_id("username", "seed"),
        target.clone(),
    )
    .with_options(opts);
    let scan_id = scan.id.clone();
    let ctx = ModuleContext {
        scan_id: scan.id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    engine.run(scan, target, ctx).await.expect("should succeed");

    let ents = store.entities_for_scan(&scan_id).expect("should succeed");
    let gen_of = |v: &str| ents.iter().find(|e| e.value == v).map(|e| e.generation);
    // The seed's own anchor and its direct module output are generation 0 (zero pivots).
    assert_eq!(gen_of("seed"), Some(0), "seed anchor is generation 0");
    assert_eq!(
        gen_of("g0child"),
        Some(0),
        "seed-round child is generation 0"
    );
    // Each expansion round is one pivot further out along the derivation trail.
    assert_eq!(
        gen_of("g1child"),
        Some(1),
        "first expansion child is generation 1"
    );
    assert_eq!(
        gen_of("g2child"),
        Some(2),
        "second expansion child is generation 2"
    );
}

/// CONVENTIONS.md §5 determinism: `recall_prior_entities`'s cap (`MAX_ENTITIES`
/// = 300, matched here) sorts by confidence and truncates — the WHICH-SURVIVES
/// question, not just display order. Modules routinely stamp flat literal
/// confidences, so exact ties at the cutoff are realistic, and the entities'
/// starting order (a `HashMap`'s randomised-per-process iteration order in the
/// real caller) must not change which 300 survive. More than 300 identically-
/// confident entities, fed in forward vs. reversed order, must truncate to the
/// IDENTICAL surviving set.
#[test]
fn rank_recalled_and_cap_truncation_is_order_independent_on_ties() {
    use crate::core::entity::{Entity, EntityKind};

    let forward: Vec<Entity> = (0..305)
        .map(|i| {
            Entity::new(
                EntityKind::Email,
                format!("user{i}@example-real.com"),
                0.7,
                "s",
            )
        })
        .collect();
    let mut reversed = forward.clone();
    reversed.reverse();

    let a = rank_recalled_and_cap(forward, 300);
    let b = rank_recalled_and_cap(reversed, 300);

    assert_eq!(a.len(), 300);
    assert_eq!(b.len(), 300);
    let a_uids: Vec<&str> = a.iter().map(|e| e.uid.as_str()).collect();
    let b_uids: Vec<&str> = b.iter().map(|e| e.uid.as_str()).collect();
    assert_eq!(
        a_uids, b_uids,
        "the surviving 300 entities must be identical regardless of incoming order"
    );
}

/// Recall's confidence-DESC sort must carry a total, deterministic tie-break so
/// equal-confidence nodes come back in a fixed order — otherwise WHICH of them
/// survive the internal `truncate(MAX_ENTITIES)` boundary cut is decided by
/// `HashMap` iteration order (`merged.into_values()`), leaking non-determinism
/// into the persisted working set. The tie-break is `uid` ascending, so a run of
/// same-confidence recalled entities must emerge uid-sorted, identically on every
/// call even though each call rebuilds the `merged` map (fresh random seed).
/// Complements [`rank_recalled_and_cap_truncation_is_order_independent_on_ties`]
/// above (pure-function unit test) with the same property proven end-to-end
/// through the real `ScanEngine`/store recall path.
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
    store.upsert_entity(&seed).expect("should succeed");
    for i in 0..24u32 {
        let mut email = Entity::new(
            EntityKind::Email,
            format!("tiebreak{i:02}@example.com"),
            0.8,
            "prior-scan",
        );
        email.add_evidence(Evidence::new("plant", "found in an earlier scan"));
        store.upsert_entity(&email).expect("should succeed");
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
    let store: Arc<dyn StoragePort> = Arc::new(Store::open(&path).expect("should succeed"));

    // A prior scan stored the Person anchor TITLE-CASED (as name parsing does)
    // plus a discovered email no live module will re-emit.
    store
        .upsert_scan(&Scan::new(
            "prior",
            Target::new(TargetKind::FullName, "Jordan Meyers"),
        ))
        .expect("should succeed");
    let mut person = Entity::new(EntityKind::Person, "Jordan Meyers", 0.9, "prior");
    person.add_evidence(Evidence::new("name_intel", "seed"));
    let mut email = Entity::new(EntityKind::Email, "jordanlead@gmail.com", 0.8, "prior");
    email.add_evidence(Evidence::new("hibp", "breach"));
    store.upsert_entity(&person).expect("should succeed");
    store.upsert_entity(&email).expect("should succeed");

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

/// Real-behaviour regression (execution-validated): recall re-injects STORED
/// entities the database already counts, so re-persisting them across repeated
/// warm re-scans must be IDEMPOTENT in corroboration — the corroboration-0 reset
/// in [`ScanEngine::recall_prior_entities`] keeps the GREATEST-merge from
/// compounding the DB's count every scan. A live `see-know.xyz` run once
/// ballooned a recalled node to corroboration 396 this way, and a synthetic
/// name_intel re-scan loop reproduced 2 → 8 → 42 → 296 before the reset landed.
///
/// This pins the END-TO-END property the single-call `recall_resets_generation_
/// to_zero` test structurally cannot reach: the blow-up only emerges across
/// multiple persist→recall→persist cycles through the real merge. Drive eight
/// real recall/re-persist cycles against the SQLite store and assert the count
/// stays bounded — deleting the `corroboration = 0` line turns this into a
/// ≥ 2ⁿ explosion the bound catches immediately.
#[tokio::test]
async fn recall_re_persist_does_not_inflate_corroboration_across_rescans() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::storage::Store;

    let path = format!(
        "{}/.hse-recall-inflation-{}.db",
        std::env::temp_dir().to_string_lossy(),
        std::process::id()
    );
    let cleanup = |p: &str| {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(format!("{p}-wal"));
        let _ = std::fs::remove_file(format!("{p}-shm"));
    };
    cleanup(&path);
    let store: Arc<dyn StoragePort> = Arc::new(Store::open(&path).expect("should succeed"));

    // Scan 1 persists the seed + one discovered lead (each at the default
    // corroboration 1) — the state a warm-database re-scan starts from.
    store
        .upsert_scan(&Scan::new(
            "scan-1",
            Target::new(TargetKind::Username, "invtarget"),
        ))
        .expect("should succeed");
    let mut seed = Entity::new(EntityKind::Username, "invtarget", 0.9, "scan-1");
    seed.add_evidence(Evidence::new("anchor", "seed"));
    let mut lead = Entity::new(EntityKind::Email, "invlead@gmail.com", 0.8, "scan-1");
    lead.add_evidence(Evidence::new("hibp", "breach"));
    let lead_uid = lead.uid.clone();
    store.upsert_entity(&seed).expect("should succeed");
    store.upsert_entity(&lead).expect("should succeed");

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(vec![], store.clone(), bus);
    let target = Target::new(TargetKind::Username, "invtarget");

    // Eight warm re-scans: each recalls the prior entities (as the engine's seed
    // round does) and re-persists them (as checkpoint/finalise does).
    let mut corrs = Vec::new();
    for i in 2..=9 {
        let scan = format!("scan-{i}");
        let recalled = engine.recall_prior_entities(&target, &scan, true);
        assert!(
            recalled.iter().any(|e| e.uid == lead_uid),
            "recall must surface the prior lead on re-scan {i}"
        );
        store
            .upsert_entities_batch(&recalled)
            .expect("should succeed");
        let held = store
            .get_entity(&lead_uid)
            .expect("should succeed")
            .expect("lead persists across re-scans");
        corrs.push(held.corroboration);
    }

    // Idempotent: re-persisting recalled (count-0) data never compounds the
    // store's true count, so it stays flat. Without the reset this is the
    // 2 → 8 → 42 → 296 blow-up (≥ 2ⁿ), which this bound catches at cycle 3.
    assert!(
        corrs.iter().all(|&c| c <= 2),
        "recall re-persist inflated corroboration across re-scans (must stay bounded): {corrs:?}"
    );

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
        };

        let cx = DispatchCx {
            scan_id: "stamp-scan",
            target: &target,
            opts: &opts,
            is_expansion: false,
            seed_kind: TargetKind::Email,
            quarantined: no_quarantine(),
        };
        let mut entity_map: TrackedEntityMap = TrackedEntityMap::new();
        let mut stats = ModuleStats::default();
        let mut dispatched: DispatchLog = DispatchLog::new();
        let mut newly_inserted: Vec<String> = Vec::new();
        let mut state = DispatchState {
            entity_map: &mut entity_map,
            stats: &mut stats,
            dispatched: &mut dispatched,
            newly_inserted: &mut newly_inserted,
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
    };
    let cx = DispatchCx {
        scan_id: "overdispatch-scan",
        target: &target,
        opts: &opts,
        is_expansion: false,
        seed_kind: TargetKind::Username,
        quarantined: no_quarantine(),
    };
    let mut entity_map: TrackedEntityMap = TrackedEntityMap::new();
    let mut stats = ModuleStats::default();
    let mut dispatched: DispatchLog = DispatchLog::new();
    let mut newly_inserted: Vec<String> = Vec::new();
    let mut state = DispatchState {
        entity_map: &mut entity_map,
        stats: &mut stats,
        dispatched: &mut dispatched,
        newly_inserted: &mut newly_inserted,
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

/// A probe whose static metadata (priority / cost / category / declared outputs)
/// is fully configurable, and whose `process()` emits ONE entity tagged with a
/// distinctive value — so a truncated dispatch reveals WHICH module ran first.
struct ConvexProbe {
    name: &'static str,
    value: &'static str,
    priority: u8,
    cost: ModuleCost,
    category: crate::core::module::ModuleCategory,
    produces: &'static [crate::core::entity::EntityKind],
}

#[async_trait::async_trait]
impl Module for ConvexProbe {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> u8 {
        self.priority
    }
    fn accepts(&self, _: &Target) -> bool {
        true
    }
    fn cost(&self) -> ModuleCost {
        self.cost
    }
    fn category(&self) -> crate::core::module::ModuleCategory {
        self.category
    }
    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        self.produces
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

/// End-to-end proof that the convex query-value order is the one the engine
/// actually dispatches in under `convex_budget`. Two modules accept the seed: a
/// HIGH-priority, paid, terminal one (low query value) and a LOW-priority,
/// keyless, identity-producing one (high query value). Dispatched sequentially
/// with `max_entities: 1`, exactly ONE module runs — so the single surviving
/// entity names the module the engine chose to spend the budget on FIRST.
///
///   * `convex_budget: false` → plain priority order → the priority-90 paid
///     terminal module runs → the survivor is `terminal_hit`.
///   * `convex_budget: true`  → convex query-value order INVERTS it → the cheap,
///     keyless, identity-unlocking module runs despite its priority of 10 → the
///     survivor is `cascade_hit`.
///
/// This is the value-per-query guarantee: when the phone's budget truncates the
/// dispatch sequence, the convex order has already spent it on the highest-return
/// query. It also pins the safety property — the flag OFF is byte-identical to
/// the established priority behaviour.
#[tokio::test]
async fn convex_budget_dispatches_the_highest_query_value_module_first() {
    use crate::core::entity::EntityKind;
    use crate::core::module::ModuleCategory;
    use crate::core::test_support::InMemoryStore;

    const TERMINAL_OUT: &[EntityKind] = &[EntityKind::Coordinates];
    const CASCADE_OUT: &[EntityKind] = &[EntityKind::Email];

    // Run one sequential, max_entities=1 dispatch and return the single surviving
    // entity value — i.e. which module the engine fired first.
    async fn survivor(convex_budget: bool) -> String {
        let modules: Vec<Arc<dyn Module>> = vec![
            Arc::new(ConvexProbe {
                name: "hi_prio_paid_terminal",
                value: "terminal_hit",
                priority: 90,
                cost: ModuleCost::Paid,
                category: ModuleCategory::Threat,
                produces: TERMINAL_OUT,
            }),
            Arc::new(ConvexProbe {
                name: "lo_prio_free_cascade",
                value: "cascade_hit",
                priority: 10,
                cost: ModuleCost::Free,
                category: ModuleCategory::Breach,
                produces: CASCADE_OUT,
            }),
        ];
        let store: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
        let (bus, _rx) = tokio::sync::broadcast::channel(64);
        let engine = ScanEngine::new(modules, store, bus.clone());

        let target = Target::new(TargetKind::Username, "convex-order-seed");
        let opts = ScanOptions {
            // Sequential path: dispatches strictly in order, stops at the cap.
            max_concurrent: 0,
            max_entities: Some(1),
            convex_budget,
            ..Default::default()
        };
        let mut ctx = ModuleContext {
            scan_id: "convex-order-scan".to_string(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        };
        let cx = DispatchCx {
            scan_id: "convex-order-scan",
            target: &target,
            opts: &opts,
            is_expansion: false,
            seed_kind: TargetKind::Username,
            quarantined: no_quarantine(),
        };
        let mut entity_map: TrackedEntityMap = TrackedEntityMap::new();
        let mut stats = ModuleStats::default();
        let mut dispatched: DispatchLog = DispatchLog::new();
        let mut newly_inserted: Vec<String> = Vec::new();
        let mut state = DispatchState {
            entity_map: &mut entity_map,
            stats: &mut stats,
            dispatched: &mut dispatched,
            newly_inserted: &mut newly_inserted,
        };
        engine
            .dispatch_target(&cx, &mut ctx, &mut state)
            .await
            .expect("dispatch runs");
        assert_eq!(entity_map.len(), 1, "max_entities=1 must admit exactly one");
        entity_map
            .into_inner()
            .into_values()
            .next()
            .expect("should succeed")
            .value
    }

    // Flag OFF: established priority order — the priority-90 module wins.
    assert_eq!(
        survivor(false).await,
        "terminal_hit",
        "with convex_budget off the highest-PRIORITY module must dispatch first"
    );
    // Flag ON: convex order — the cheap, high-optionality query wins despite its
    // far lower priority.
    assert_eq!(
        survivor(true).await,
        "cascade_hit",
        "with convex_budget on the highest-QUERY-VALUE module must dispatch first"
    );
}

#[test]
fn rank_enrichment_leverage_orders_join_keys_by_cross_scan_degree() {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::test_support::InMemoryStore;

    let store = InMemoryStore::new();
    let up = |k, v, s| {
        store
            .upsert_entity(&Entity::new(k, v, 0.7, s))
            .expect("should succeed");
    };

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

/// C7 (forensic determinism): `checkpoint_entities` is the mid-scan durability
/// path — hit at every productive round boundary, far more often than the
/// bare-events-log recovery path a prior fix in this same session already
/// canonicalised. Without canonicalising here too, a scan interrupted after
/// reaching even one checkpoint (routine on Termux/Android) would read back
/// through `entities_for_scan`'s ordinary table path — which never
/// canonicalises — so concurrent dispatch's completion-order merging could
/// leak into the checkpointed/exported result.
///
/// The two evidence sources are already merged into ONE in-memory entity
/// before `checkpoint_entities` is ever called (mirroring
/// `entity_map.values().cloned().collect()`'s real shape) — that in-memory
/// merge order is exactly what varies run-to-run under concurrent dispatch,
/// so the fixture carries the two sources in opposite orders and proves the
/// checkpointed, stored order is canonical either way.
#[tokio::test]
async fn checkpoint_entities_canonicalizes_evidence_order_regardless_of_arrival_order() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::test_support::InMemoryStore;

    let mut zzz_then_aaa = Entity::new(EntityKind::Email, "shared@example.com", 0.5, "scan-a");
    zzz_then_aaa.add_evidence(Evidence::new("zzz_module", "seen"));
    zzz_then_aaa.add_evidence(Evidence::new("aaa_module", "seen"));
    let mut aaa_then_zzz = Entity::new(EntityKind::Email, "shared@example.com", 0.5, "scan-a");
    aaa_then_zzz.add_evidence(Evidence::new("aaa_module", "seen"));
    aaa_then_zzz.add_evidence(Evidence::new("zzz_module", "seen"));

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let store_a: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
    let engine_a = ScanEngine::new(vec![], store_a.clone(), bus.clone());
    engine_a.checkpoint_entities("scan-a", &mut [zzz_then_aaa]);

    let store_b: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
    let engine_b = ScanEngine::new(vec![], store_b.clone(), bus);
    engine_b.checkpoint_entities("scan-a", &mut [aaa_then_zzz]);

    let recovered_a = store_a.entities_for_scan("scan-a").expect("should succeed");
    let recovered_b = store_b.entities_for_scan("scan-a").expect("should succeed");
    assert_eq!(recovered_a.len(), 1);
    assert_eq!(recovered_b.len(), 1);
    let sources_a: Vec<&str> = recovered_a[0]
        .evidence
        .iter()
        .map(|ev| ev.source.as_str())
        .collect();
    let sources_b: Vec<&str> = recovered_b[0]
        .evidence
        .iter()
        .map(|ev| ev.source.as_str())
        .collect();
    assert_eq!(
        sources_a, sources_b,
        "checkpointed evidence order must be canonicalised, not leak arrival order: \
         {sources_a:?} vs {sources_b:?}"
    );
    assert_eq!(
        sources_a,
        ["aaa_module", "zzz_module"],
        "canonical order is lexicographic by source, per Entity::canonicalize_order"
    );
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

/// `rank_autonomous_targets` classifies and orders the whole working set, honours
/// the `exclude` set a continuous loop maintains, drops non-pivotable kinds, and
/// truncates to `limit` — deterministically.
#[test]
fn rank_autonomous_targets_orders_excludes_and_truncates() {
    use super::rank_autonomous_targets;
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::TargetKind;
    use std::collections::HashSet;

    // The fixture's coordinate is tagged COARSE so it is excluded for the reason
    // this test's comment always claimed — its GRAIN. It previously carried no
    // tag and was excluded merely because the gate refused every Coordinates by
    // kind, so it passed for the wrong reason; a precise fix is now seedable and
    // only a coarse centroid is not.
    let mut coarse_fix = Entity::new(EntityKind::Coordinates, "-33.8,151.2", 0.9, "s");
    coarse_fix.tag(crate::core::tags::COARSE);
    let entities = vec![
        Entity::new(EntityKind::Email, "a@b.com", 0.9, "s"),
        Entity::new(EntityKind::Phone, "+61400111222", 0.9, "s"),
        Entity::new(EntityKind::Credential, "secret", 0.9, "s"), // not a cross-scan candidate
        coarse_fix,                                              // coarse geo — gated out by grain
        Entity::new(EntityKind::Username, "alice", 0.6, "s"),
    ];
    // Uniform degree so the ordering is decided by pivot × confidence alone.
    let degree_of = |_uid: &str| 2usize;
    let exclude = HashSet::new();

    let ranked = rank_autonomous_targets(&entities, degree_of, &exclude, 10);
    assert_eq!(
        ranked.len(),
        3,
        "the seedable pivots survive; a Credential is non-pivotable and a COARSE \
         centroid is too imprecise to seed"
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
    let after = rank_autonomous_targets(&entities, degree_of, &ex, 10);
    assert_eq!(after.len(), 2, "the excluded target is gone");
    assert!(
        after.iter().all(|t| t.uid != ranked[0].uid),
        "a loop never re-seeds an excluded target"
    );

    // `limit` caps the queue to the strongest candidates.
    let top1 = rank_autonomous_targets(&entities, degree_of, &exclude, 1);
    assert_eq!(top1.len(), 1);
    assert_eq!(top1[0].kind, TargetKind::Email);
}

/// With `diversity = 0` the sweep planner reproduces the pure score ranking; with
/// positive diversity it interleaves kinds so the loop doesn't tunnel a whole
/// budget on the single most-represented kind.
#[test]
fn plan_autonomous_sweep_interleaves_kinds_under_diversity() {
    use super::{DEFAULT_SWEEP_DIVERSITY, plan_autonomous_sweep, rank_autonomous_targets};
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

    // diversity = 0 ⇒ identical order to the pure ranker.
    let flat = plan_autonomous_sweep(&entities, degree_of, &exclude, 10, 0.0);
    let ranked = rank_autonomous_targets(&entities, degree_of, &exclude, 10);
    assert_eq!(flat.considered, 4);
    assert_eq!(flat.kinds_covered, 2, "email + phone represented");
    assert_eq!(
        flat.queue.iter().map(|t| t.kind).collect::<Vec<_>>(),
        ranked.iter().map(|t| t.kind).collect::<Vec<_>>(),
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
    let solo = ranked
        .iter()
        .find(|t| t.cluster_size == 1)
        .expect("should succeed");
    assert!(cluster.representative.score > solo.representative.score);
}

/// A singleton identity scores EXACTLY as `rank_autonomous_targets` would — the
/// identity-aware ranker is a strict additive generalisation.
#[test]
fn identity_aware_ranking_matches_flat_ranking_for_singletons() {
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
    let flat = rank_autonomous_targets(&ents, degree_of, &exclude, 10);
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

/// A completed scan with a `webhook_url` configured must POST the `scan_complete`
/// payload to it. This is the wiring `finalise_scan` was missing: the CLI/live
/// paths thread `HUNTSMAN_WEBHOOK_URL` into `ScanOptions.webhook_url`, but the
/// engine never fired the POST, so a configured webhook silently never arrived.
/// Git-stash-proven: against the unfixed engine no connection is made and the
/// `recv_timeout` below elapses, failing the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_completion_fires_the_configured_webhook() {
    use crate::core::test_support::InMemoryStore;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    // One-shot local HTTP sink on an ephemeral port: accept a single connection,
    // read the request, reply 200, and hand the raw request back over a channel.
    // Blocking IO on a std thread, off the async runtime.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("should succeed");
    let port = listener.local_addr().expect("should succeed").port();
    let (tx, rx) = mpsc::channel::<String>();
    let sink = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            sock.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok();
            let mut acc = Vec::new();
            let mut buf = [0u8; 2048];
            // reqwest may flush headers and body separately — accumulate until the
            // JSON body is present (or the peer stops / times out).
            for _ in 0..10 {
                match sock.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        acc.extend_from_slice(&buf[..n]);
                        if String::from_utf8_lossy(&acc).contains("scan_complete") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            let _ = tx.send(String::from_utf8_lossy(&acc).to_string());
        }
    });

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::new(vec![], store_port, bus.clone());
    let opts = ScanOptions {
        webhook_url: Some(format!("http://127.0.0.1:{port}/hook/secret")),
        // Pin regional OFF so this test doesn't flip the process-global regional
        // search flag (`set_regional`, driven from `regional_search`) that the
        // `search_engines::build_queries` unit tests read — otherwise running a
        // real scan here races those tests in the concurrent runner.
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
    };
    let _ = engine.run(scan, target, ctx).await;

    let req = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("a scan_complete webhook POST must arrive after the scan finalises");
    sink.join().ok();
    assert!(
        req.starts_with("POST "),
        "expected an HTTP POST, got:\n{req}"
    );
    assert!(
        req.contains("\"event\":\"scan_complete\""),
        "webhook body must be the scan_complete event:\n{req}"
    );
    assert!(
        req.contains("\"target_value\":\"seed\""),
        "webhook body must carry the seed target:\n{req}"
    );
}

/// A module whose `accepts()` panics on a real dispatch target — the exact
/// bug class this test guards: only `Module::process()` is wrapped by
/// `run_module_guarded`'s `catch_unwind`, so a panic in a per-target GATING
/// call (`accepts()`, `cost()`, `cache_ttl_secs()`, ...), which every
/// dispatch loop calls directly on the dispatching task, sits entirely
/// outside that boundary. Must NOT panic for
/// `crate::core::dependency::PROBE_VALUE` — `ScanEngine::new()` eagerly
/// probes every module's `accepts()` against a synthetic value for every
/// `TargetKind` at module-graph construction time (see
/// `core::dependency::mod::build`), so an unconditional panic here would
/// crash at graph-build, before this test ever reaches `run_panic_safe` —
/// a real, distinct danger zone, but not the one under test.
struct PanicsInAcceptsModule;

#[async_trait::async_trait]
impl Module for PanicsInAcceptsModule {
    fn name(&self) -> &'static str {
        "panics_in_accepts"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        // Only gate on `Username` — graph-build probes every OTHER
        // `TargetKind` too, each with its own kind-specific normalisation
        // of `PROBE_VALUE` (e.g. `Phone`'s digit-only strip), so comparing
        // the probed value directly against the raw `PROBE_VALUE` constant
        // would spuriously panic during construction for those kinds.
        if t.kind != TargetKind::Username {
            return false;
        }
        if t.value == crate::core::dependency::PROBE_VALUE {
            return true;
        }
        panic!("kaboom in accepts() on a real dispatch target")
    }
    fn description(&self) -> &'static str {
        "test-only: panics in accepts() to prove run_panic_safe's boundary"
    }
    async fn process(
        &self,
        _target: &Target,
        _ctx: &ModuleContext,
    ) -> Result<crate::core::module::ModuleResult> {
        Ok(crate::core::module::ModuleResult::new())
    }
}

#[tokio::test]
async fn run_panic_safe_force_fails_a_scan_that_panics_outside_process() {
    use crate::core::test_support::InMemoryStore;
    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::new(
        vec![Arc::new(PanicsInAcceptsModule)],
        store_port,
        bus.clone(),
    );
    let target = Target::new(TargetKind::Username, "seed");
    let scan = Scan::new(
        crate::core::entity::scan_id("username", "seed"),
        target.clone(),
    );
    let scan_id = scan.id.clone();
    let ctx = ModuleContext {
        scan_id: scan_id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let result = engine.run_panic_safe(scan, target, ctx).await;
    assert!(
        result.is_err(),
        "a scan whose dispatch panics must surface as an Err, not silently vanish"
    );

    let persisted = store
        .get_scan(&scan_id)
        .expect("should succeed")
        .expect("the scan row must still exist");
    assert_eq!(
        persisted.status,
        ScanStatus::Failed,
        "a panicked scan must be force-marked Failed, never left stuck Running"
    );
    assert!(
        persisted
            .error
            .as_deref()
            .is_some_and(|e| e.contains("kaboom in accepts()")),
        "the persisted error should carry the panic message: {:?}",
        persisted.error
    );
    assert!(
        persisted.finished_at.is_some(),
        "a force-failed scan must have finished_at set"
    );
}

// ── TrackedEntityMap: dirty-tracking contract ───────────────────────────
//
// The round loop's checkpoint used to re-clone and re-persist the WHOLE
// accumulated entity_map every round with dispatch activity — round 50
// re-persisted round 1's untouched entities all over again. TrackedEntityMap
// narrows the checkpoint to only what changed since the last checkpoint,
// while leaving read access (and thus live correlation, which genuinely
// needs the full working set every round) completely unaffected. These
// tests pin the wrapper's contract directly, independent of a full scan.

fn tracked_test_entity(uid: &str) -> Entity {
    Entity::new(EntityKind::Email, uid, 0.5, "test-scan")
}

#[test]
fn tracked_entity_map_insert_marks_dirty() {
    let mut map = TrackedEntityMap::new();
    let e = tracked_test_entity("a@example.com");
    map.insert(e.uid.clone(), e.clone());
    let dirty = map.take_dirty();
    assert_eq!(dirty.len(), 1);
    assert_eq!(dirty[0].uid, e.uid);
}

#[test]
fn tracked_entity_map_get_mut_on_existing_key_marks_dirty() {
    let mut map = TrackedEntityMap::new();
    let e = tracked_test_entity("a@example.com");
    map.insert(e.uid.clone(), e.clone());
    let _ = map.take_dirty(); // clear the insert's own dirty mark

    map.get_mut(&e.uid).expect("entity present").confidence = 0.9;
    let dirty = map.take_dirty();
    assert_eq!(
        dirty.len(),
        1,
        "a get_mut on an existing key must mark it dirty"
    );
    assert_eq!(
        dirty[0].confidence, 0.9,
        "take_dirty must reflect the mutation"
    );
}

#[test]
fn tracked_entity_map_get_mut_on_missing_key_does_not_mark_dirty() {
    let mut map = TrackedEntityMap::new();
    assert!(map.get_mut("does-not-exist").is_none());
    assert!(
        map.take_dirty().is_empty(),
        "a get_mut miss must never fabricate a dirty entry"
    );
}

#[test]
fn tracked_entity_map_take_dirty_clears_the_set() {
    let mut map = TrackedEntityMap::new();
    let e = tracked_test_entity("a@example.com");
    map.insert(e.uid.clone(), e);
    assert_eq!(
        map.take_dirty().len(),
        1,
        "first drain returns the inserted entity"
    );
    assert!(
        map.take_dirty().is_empty(),
        "a second drain with no intervening mutation must be empty — this is exactly what \
         lets a round with no dispatch activity skip a checkpoint entirely"
    );
}

#[test]
fn tracked_entity_map_only_reports_entities_touched_since_the_last_drain() {
    // Models exactly the round-loop pattern this wrapper exists for: round 1
    // inserts two entities and checkpoints (draining both); round 2 mutates
    // only ONE of them. The second checkpoint must see only that one --- not
    // the untouched entity from round 1 re-persisted all over again.
    let mut map = TrackedEntityMap::new();
    let a = tracked_test_entity("a@example.com");
    let b = tracked_test_entity("b@example.com");
    map.insert(a.uid.clone(), a.clone());
    map.insert(b.uid.clone(), b.clone());
    let round1 = map.take_dirty();
    assert_eq!(
        round1.len(),
        2,
        "round 1's checkpoint sees everything inserted so far"
    );

    map.get_mut(&a.uid).expect("should succeed").confidence = 0.99;
    let round2 = map.take_dirty();
    assert_eq!(
        round2.len(),
        1,
        "round 2's checkpoint must see ONLY the mutated entity, not b re-persisted unchanged"
    );
    assert_eq!(round2[0].uid, a.uid);
}

#[test]
fn tracked_entity_map_deref_gives_full_read_access_regardless_of_dirty_state() {
    // Live correlation reads the FULL working set every round via Deref, not
    // just the dirty subset -- a correlation rule can legitimately relate an
    // entity from an early round to one just discovered. Prove read access
    // is never narrowed by dirty-tracking, including right after a drain.
    let mut map = TrackedEntityMap::new();
    let a = tracked_test_entity("a@example.com");
    let b = tracked_test_entity("b@example.com");
    let (a_uid, b_uid) = (a.uid.clone(), b.uid.clone());
    map.insert(a.uid.clone(), a);
    map.insert(b.uid.clone(), b);
    let _ = map.take_dirty(); // fully drained -- dirty-tracking is now empty

    assert_eq!(
        map.len(),
        2,
        "Deref read access must be unaffected by drained dirty state"
    );
    assert!(map.contains_key(&a_uid));
    assert!(map.contains_key(&b_uid));
    assert_eq!(map.values().count(), 2);
}

#[test]
fn tracked_entity_map_into_inner_yields_every_entity_regardless_of_dirty_state() {
    // finalise_scan's one-time full flush must see everything, dirty or not
    // -- it has no use for dirty-tracking, unlike the per-round checkpoint.
    let mut map = TrackedEntityMap::new();
    let a = tracked_test_entity("a@example.com");
    let b = tracked_test_entity("b@example.com");
    let (a_uid, b_uid) = (a.uid.clone(), b.uid.clone());
    map.insert(a.uid.clone(), a);
    map.insert(b.uid.clone(), b);
    let _ = map.take_dirty();

    let inner = map.into_inner();
    assert_eq!(inner.len(), 2);
    assert!(inner.contains_key(&a_uid));
    assert!(inner.contains_key(&b_uid));
}

// ── Final breach sweep + autonomous audit ───────────────────────────────────

/// A stand-in breach corpus. Its NAME is what matters: `source_family` classes
/// anything containing "breach" into the breach family, so
/// `is_breach_source` recognises it, the engine admits it to the sweep's
/// allow-list, and the consensus pass counts it as an attesting corpus — the
/// same three decisions a real corpus module goes through.
///
/// It answers every identity target with one Email entity derived from the
/// target's value, so a dispatched sweep probe is observable in the store. The
/// synthetic domain is deliberately NOT `example.*` — the engine's placeholder
/// filter rejects those, which would make the fixture silently produce nothing.
struct StubBreachCorpus {
    name: &'static str,
}

#[async_trait::async_trait]
impl Module for StubBreachCorpus {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> u8 {
        50
    }
    fn category(&self) -> crate::core::module::ModuleCategory {
        crate::core::module::ModuleCategory::Breach
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email | TargetKind::Username | TargetKind::FullName | TargetKind::Phone
        )
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[EntityKind::Email];
        K
    }
    async fn process(
        &self,
        target: &Target,
        ctx: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        let local: String = target
            .value
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        let mut e = Entity::new(
            EntityKind::Email,
            format!("{local}@leakset.net"),
            0.9,
            &ctx.scan_id,
        );
        e.add_evidence(crate::core::entity::Evidence::new(self.name, "synthetic"));
        let mut r = crate::core::module::ModuleResult::new();
        r.push(e);
        Ok(r)
    }
}

/// Collect every event the engine published, so a test can assert on the
/// pipeline's own record of what it did rather than on side effects.
fn drain_events(rx: &mut tokio::sync::broadcast::Receiver<crate::core::Event>) -> Vec<EventKind> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev.kind);
    }
    out
}

/// End-to-end: the final bulk breach query is compiled and dispatched by the
/// scan pipeline itself — not merely available to a CLI caller — and the
/// autonomous audit runs after it.
#[tokio::test]
async fn a_scan_runs_the_final_breach_sweep_and_then_audits_it() {
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, mut rx) = tokio::sync::broadcast::channel(4096);
    let engine = ScanEngine::new(
        vec![Arc::new(StubBreachCorpus {
            name: "stub_breach_corpus",
        })],
        store_port,
        bus.clone(),
    );

    let opts = ScanOptions {
        depth: 1,
        expand_all_identities: true,
        max_roi: false,
        ..Default::default()
    };
    let target = Target::new(TargetKind::Email, "subject@example.com");
    let scan = Scan::new(
        crate::core::entity::scan_id("email", "subject@example.com"),
        target.clone(),
    )
    .with_options(opts);
    let scan_id = scan.id.clone();
    let ctx = ModuleContext {
        scan_id: scan.id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    engine.run(scan, target, ctx).await.expect("should succeed");

    let events = drain_events(&mut rx);
    let sweep = events
        .iter()
        .find_map(|k| match k {
            EventKind::BreachSweep {
                anchors,
                probes,
                dropped,
            } => Some((*anchors, *probes, *dropped)),
            _ => None,
        })
        .expect("the scan pipeline must run the final breach sweep, not just offer it to the CLI");
    let (anchors, probes, _dropped) = sweep;
    assert!(
        probes > 0 && anchors > 0,
        "a confident Email seed must yield at least one anchor and probe; got \
         {anchors} anchors / {probes} probes"
    );

    let audit = events
        .iter()
        .find_map(|k| match k {
            EventKind::ConsensusAudit {
                verdict, examined, ..
            } => Some((verdict.clone(), *examined)),
            _ => None,
        })
        .expect("the sweep must be audited autonomously once it has been used");
    let (verdict, examined) = audit;
    assert!(
        examined > 0,
        "the corpus module attested entities, so the audit had a population to grade"
    );
    assert_ne!(
        verdict, "PENDING_REVIEW",
        "an un-run audit must never be reported as the scan's verdict"
    );

    // The sweep's dispatches actually reached the store, tagged and attributed.
    let ents = store.entities_for_scan(&scan_id).expect("should succeed");
    let swept: Vec<&Entity> = ents
        .iter()
        .filter(|e| e.has_tag(crate::core::breach_consensus::SWEEP_TAG))
        .collect();
    assert!(
        !swept.is_empty(),
        "sweep-discovered entities must be tagged `{}` so a reader can tell what the \
         final bulk query contributed; entities present: {:?}",
        crate::core::breach_consensus::SWEEP_TAG,
        ents.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
    // Sweep finds sit one generation beyond gap-fill's `depth + 1`.
    for e in &swept {
        assert_eq!(
            e.generation, 3,
            "a depth-1 scan's sweep finds belong at generation 3 (depth + 2): {}",
            e.value
        );
    }
}

/// The audit is grading, not collection: it costs no network I/O and answers a
/// question a shallow scan needs answered too. A depth-0 scan that touched a
/// corpus must still get a verdict — but must NOT run the sweep, which is
/// expansion and which the operator switched off by asking for depth 0.
#[tokio::test]
async fn the_audit_runs_on_a_depth_zero_scan_but_the_sweep_does_not() {
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, mut rx) = tokio::sync::broadcast::channel(4096);
    let engine = ScanEngine::new(
        vec![Arc::new(StubBreachCorpus {
            name: "stub_breach_corpus",
        })],
        store_port,
        bus.clone(),
    );

    let opts = ScanOptions {
        depth: 0,
        ..Default::default()
    };
    let target = Target::new(TargetKind::Email, "shallow@example.com");
    let scan = Scan::new(
        crate::core::entity::scan_id("email", "shallow@example.com"),
        target.clone(),
    )
    .with_options(opts);
    let ctx = ModuleContext {
        scan_id: scan.id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    engine.run(scan, target, ctx).await.expect("should succeed");

    let events = drain_events(&mut rx);
    assert!(
        !events
            .iter()
            .any(|k| matches!(k, EventKind::BreachSweep { .. })),
        "depth 0 means no pivoting at all — the sweep dispatches new targets and \
         must stay off"
    );
    assert!(
        events
            .iter()
            .any(|k| matches!(k, EventKind::ConsensusAudit { .. })),
        "the audit reads evidence already collected, so a depth-0 scan that hit a \
         corpus must still be graded"
    );
}

/// The sweep must never manufacture the corroboration the consensus reports.
/// Its grading pass records what the corpora said; it may not itself count as a
/// corpus, or the weakest findings would be the ones it flattered most.
#[tokio::test]
async fn the_audit_does_not_inflate_the_confidence_it_grades() {
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, _rx) = tokio::sync::broadcast::channel(4096);
    let engine = ScanEngine::new(
        vec![Arc::new(StubBreachCorpus {
            name: "stub_breach_corpus",
        })],
        store_port,
        bus.clone(),
    );

    let opts = ScanOptions {
        depth: 0,
        ..Default::default()
    };
    let target = Target::new(TargetKind::Email, "solo@example.com");
    let scan = Scan::new(
        crate::core::entity::scan_id("email", "solo@example.com"),
        target.clone(),
    )
    .with_options(opts);
    let scan_id = scan.id.clone();
    let ctx = ModuleContext {
        scan_id: scan.id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    engine.run(scan, target, ctx).await.expect("should succeed");

    let ents = store.entities_for_scan(&scan_id).expect("should succeed");
    let graded: Vec<&Entity> = ents
        .iter()
        .filter(|e| {
            e.evidence
                .iter()
                .any(|ev| ev.source == crate::core::entity::CONSENSUS_SOURCE)
        })
        .collect();
    assert!(
        !graded.is_empty(),
        "the fixture must actually be graded, or this test proves nothing"
    );
    for e in &graded {
        // Exactly one real corpus attested each of these; the consensus summary
        // must not have become a second "source" that lifts them.
        let corroborating = e.corroborating_sources();
        assert!(
            !corroborating.contains(&crate::core::entity::CONSENSUS_SOURCE),
            "the consensus summary counted itself as corroboration for {}",
            e.value
        );
    }
}

/// The autonomous sweep must be able to seed the GEOLOCATION pivots — a hardware
/// BSSID, a person-named SSID, a precise fix — while still refusing the ones that
/// geolocate nobody.
///
/// Both halves matter. Before `is_autonomous_seed_candidate` existed, the sweep
/// gated on `history::is_cross_scan_candidate`, whose `_ => false` arm rejected
/// all three kinds outright: the engine rated MacAddress/Ssid at `geo_npv` 14.0
/// with a 2.0x geo-proximity boost on the in-scan path, then refused to point a
/// scan at them on the autonomous path. And a gate that admitted them
/// indiscriminately would be just as wrong — it would flood the queue with
/// randomised privacy MACs and carrier-default network names that no observation
/// corpus can resolve to a place.
///
/// Also pins the two invariants the change must not break: the history gate's own
/// semantics are untouched, and `kind_pivot_value` ranks the geo kinds explicitly
/// instead of dumping them on the `_ => 0.12` catch-all floor.
#[test]
fn autonomous_sweep_seeds_specific_geo_pivots_and_refuses_generic_ones() {
    use super::{is_autonomous_seed_candidate, kind_pivot_value, rank_autonomous_targets};
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::scan::TargetKind;
    use std::collections::HashSet;

    // ── Admitted: each resolves to ONE place ────────────────────────────────
    let email = Entity::new(EntityKind::Email, "a@b.com", 0.90, "s");
    // 0x3c: U/L bit clear (a real IEEE-assigned OUI), I/G bit clear (unicast).
    let bssid = Entity::new(EntityKind::MacAddress, "3C:5A:B4:11:22:33", 0.60, "s");
    // A person-chosen name — the exact false-positive class the whole-token
    // matcher in `util::wifi` exists to protect.
    let ssid = Entity::new(EntityKind::Ssid, "Freeman-Family", 0.55, "s");
    // A genuine person-anchored fix carries an anchoring geo source (here an
    // EXIF GPS tag); without one `is_infrastructure_geo` treats a bare lat/lon as
    // an IP/WHOIS-derived infrastructure location, correctly NOT seedable.
    let mut fix = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.90, "s");
    fix.add_evidence(Evidence::new("exif_geo", "photo GPS"));

    // ── Refused: each geolocates nobody ─────────────────────────────────────
    // 0xaa: U/L bit set — a randomised privacy address that rotates ~15 min.
    let random_mac = Entity::new(EntityKind::MacAddress, "AA:BB:CC:DD:EE:FF", 0.90, "s");
    // All-zero placeholder: not a device.
    let zero_mac = Entity::new(EntityKind::MacAddress, "00:00:00:00:00:00", 0.90, "s");
    // Vendor default — thousands of unrelated routers share it.
    let generic_ssid = Entity::new(EntityKind::Ssid, "NETGEAR-7788", 0.90, "s");
    // Below the 4-character floor.
    let tiny_ssid = Entity::new(EntityKind::Ssid, "hub", 0.90, "s");
    // A region centroid a module explicitly flagged as non-specific.
    let mut coarse_fix = Entity::new(EntityKind::Coordinates, "-25.2744,133.7751", 0.90, "s");
    coarse_fix.tag(crate::core::tags::COARSE);
    // A datacentre fix — locates a server, never a person.
    let mut hosting_fix = Entity::new(EntityKind::Coordinates, "37.7749,-122.4194", 0.90, "s");
    hosting_fix.tag(crate::core::tags::HOSTING);
    // A real BSSID heard only faintly: ambient, below the confidence floor.
    let faint_bssid = Entity::new(EntityKind::MacAddress, "3C:5A:B4:99:88:77", 0.45, "s");
    // Group addresses. All are UNIVERSALLY administered — the U/L bit is clear —
    // so the U/L test alone lets them through; only the I/G bit rejects them.
    // Each names a protocol group, never one device at one premises.
    let ipv4_multicast = Entity::new(EntityKind::MacAddress, "01:00:5E:00:00:FB", 0.90, "s");
    let ipv6_multicast = Entity::new(EntityKind::MacAddress, "33:33:00:00:00:01", 0.90, "s");
    let broadcast = Entity::new(EntityKind::MacAddress, "FF:FF:FF:FF:FF:FF", 0.90, "s");
    // The radar sweep's `0,0` sentinel: minted seed/subject each sweep, but it
    // locates nobody — `is_infrastructure_geo`'s sentinel check rejects it, so it
    // can never seed an autonomous scan on null island.
    let mut sentinel_fix = Entity::new(EntityKind::Coordinates, "0.000000,0.000000", 0.90, "s");
    sentinel_fix.tag("seed");
    sentinel_fix.tag("subject");
    // An `infra:` map feature — a CCTV camera / cell tower scraped near a fix.
    let mut infra_poi = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.55, "s");
    infra_poi.tag("infra:surveillance");
    // A WHOIS registrant / privacy-service address: the domain owner's filing
    // location, not the subject's — the AU-092 class, now also excluded here.
    let mut registrant_addr = Entity::new(EntityKind::Address, "VIC, Australia", 0.50, "s");
    registrant_addr.tag(crate::core::tags::REGISTRANT);

    let admitted = [&email, &bssid, &ssid, &fix];
    let refused = [
        &random_mac,
        &zero_mac,
        &generic_ssid,
        &tiny_ssid,
        &coarse_fix,
        &hosting_fix,
        &faint_bssid,
        &ipv4_multicast,
        &ipv6_multicast,
        &broadcast,
        &sentinel_fix,
        &infra_poi,
        &registrant_addr,
    ];

    // 1) The predicate itself, named per entity so a regression is diagnosable.
    for e in admitted {
        assert!(
            is_autonomous_seed_candidate(e),
            "{:?} {} must be seedable — it resolves to one place",
            e.kind,
            e.value
        );
    }
    for e in refused {
        assert!(
            !is_autonomous_seed_candidate(e),
            "{:?} {} must NOT seed a scan — it geolocates nobody",
            e.kind,
            e.value
        );
    }

    // 2) The HISTORY gate is unchanged: none of the geo kinds became a
    //    cross-investigation join key. This is the constraint the separate
    //    predicate exists to honour — widening the shared gate instead would
    //    pass (1) and fail here.
    for e in [&bssid, &ssid, &fix] {
        assert!(
            !super::history::is_cross_scan_candidate(e),
            "{:?} is a SEED, never a cross-scan join key — history semantics must not move",
            e.kind
        );
    }

    // 3) End to end through the ranker.
    let mut entities: Vec<Entity> = Vec::new();
    entities.extend(admitted.iter().map(|e| (*e).clone()));
    entities.extend(refused.iter().map(|e| (*e).clone()));
    let degree_of = |_uid: &str| 2usize;
    let exclude = HashSet::new();

    let ranked = rank_autonomous_targets(&entities, degree_of, &exclude, 50);
    let kinds: HashSet<TargetKind> = ranked.iter().map(|t| t.kind).collect();
    for k in [
        TargetKind::Email,
        TargetKind::MacAddress,
        TargetKind::Ssid,
        TargetKind::Coordinates,
    ] {
        assert!(kinds.contains(&k), "{k:?} must be seedable by the sweep");
    }
    assert_eq!(ranked.len(), 4, "exactly the four admitted entities");
    for e in refused {
        assert!(
            ranked.iter().all(|t| t.uid != e.uid),
            "{} leaked into the autonomous queue",
            e.value
        );
    }

    // 4) The geo kinds are ranked on their merits, not on the catch-all floor.
    let mac = kind_pivot_value(&EntityKind::MacAddress);
    let net = kind_pivot_value(&EntityKind::Ssid);
    let coord = kind_pivot_value(&EntityKind::Coordinates);
    assert!(
        mac > net && net > coord,
        "BSSID (unique hardware) > SSID (a colliding name) > coordinate (terminal): \
         {mac} / {net} / {coord}"
    );
    assert!(
        coord > kind_pivot_value(&EntityKind::Domain),
        "a precise fix out-pivots shared infrastructure"
    );
    assert!(
        net > kind_pivot_value(&EntityKind::Credential),
        "the geo kinds must not sit on the `_ => 0.12` catch-all floor"
    );
}

/// The working-set snapshot every correlation pass reads must be deterministic.
///
/// `TrackedEntityMap` wraps a `HashMap`, so the old
/// `entity_map.values().cloned().collect()` handed the correlator whatever
/// order the hasher produced. That order is not cosmetic:
/// `correlator::confirmed_only` returns `Cow::Borrowed` in the common case, so
/// caller order reaches the rules verbatim, and rules that build `entity_uids`
/// in slice order bake it into a PERSISTED correlation row. `rank_and_sort`'s
/// tie-break even documents the assumption that "the per-group entity_uids are
/// already individually sorted" — false on the live path. The finalise pass
/// could not repair it, because `Store::upsert_correlation` short-circuits when
/// the new uid set is a subset of the old, so the live row survives.
///
/// Net effect: two runs over identical inputs could persist different
/// `entity_uids` orderings for the same finding. This pins the fix at the one
/// accessor all six snapshot sites now share.
#[test]
fn the_working_set_snapshot_is_deterministically_ordered() {
    use crate::core::entity::{Entity, EntityKind};

    // Insert in two different orders — what different hash seeds / different
    // module completion orders produce across runs.
    let values = [
        ("a@example.com", EntityKind::Email),
        ("b@example.com", EntityKind::Email),
        ("+61400111222", EntityKind::Phone),
        ("alice", EntityKind::Username),
        ("example.com", EntityKind::Domain),
    ];

    let mut forward = super::TrackedEntityMap::new();
    for (v, k) in &values {
        let e = Entity::new(k.clone(), *v, 0.8, "s");
        forward.insert(e.uid.clone(), e);
    }

    let mut backward = super::TrackedEntityMap::new();
    for (v, k) in values.iter().rev() {
        let e = Entity::new(k.clone(), *v, 0.8, "s");
        backward.insert(e.uid.clone(), e);
    }

    let a: Vec<String> = forward.snapshot().into_iter().map(|e| e.uid).collect();
    let b: Vec<String> = backward.snapshot().into_iter().map(|e| e.uid).collect();

    assert_eq!(
        a, b,
        "two insertion orders of the same entities must snapshot identically — \
         the correlator persists this order into entity_uids"
    );
    assert_eq!(a.len(), values.len(), "no entity lost by the snapshot");

    // And the order is the documented one: sorted by uid, a total order since
    // uid is a SHA-256 unique per entity.
    let mut expected = a.clone();
    expected.sort();
    assert_eq!(a, expected, "snapshot must be sorted by uid");
}

/// A watchdog task must be reaped when its owner unwinds, not detached.
///
/// The wall-time watchdog was held in a bare `tokio::JoinHandle`, aborted only
/// on the straight-line path at the end of the scan body. Dropping a
/// `JoinHandle` DETACHES the task — it does not abort it — and `Cargo.toml`
/// sets `panic = "unwind"`, so any panic between the spawn and that abort
/// unwound straight past it. The watchdog then slept out its full deadline and
/// fired `cancel()` on the caller's context long after the scan was gone,
/// poisoning a shared token under a long-lived `serve`/`radar` so an unrelated
/// later scan was cancelled with no operator-visible reason.
///
/// Drives the real hazard: a panic while the guard is live.
#[tokio::test]
async fn a_watchdog_guard_aborts_its_task_when_its_owner_unwinds() {
    use crate::core::cancel::CancelHandle;

    let cancel = CancelHandle::new();
    let cancel_task = cancel.clone();

    // Spawn under the guard, then panic while it is still in scope — exactly
    // what a panicking module below the watchdog spawn does to the scan body.
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = super::AbortOnDrop(tokio::spawn(async move {
            // Far shorter than a real deadline so the test is fast; the point
            // is that it must never get to run this at all.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            cancel_task.cancel();
        }));
        panic!("a module panicked below the watchdog spawn");
    }));
    assert!(panicked.is_err(), "the test must actually unwind");

    // Well past the task's own deadline. If the guard had merely detached it,
    // the task would have woken and cancelled the caller's token by now.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    assert!(
        !cancel.is_cancelled(),
        "an unwound scan must not leave a watchdog alive to cancel a token it \
         no longer owns — a later, unrelated scan would die for no visible reason"
    );
}
