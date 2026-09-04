use super::*;
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};
use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};

#[test]
fn report_consolidates_metrics_timing_and_pivots() {
    // subject — addr — relative: a 2-hop chain whose shared address is the pivot.
    let mut subject = Entity::new(EntityKind::Person, "Subject Person", 0.85, "s1");
    subject.tag("subject");
    let addr = Entity::new(EntityKind::Address, "1 Main St, Town", 0.6, "s1");
    let relative = Entity::new(EntityKind::Person, "Relative Person", 0.5, "s1");
    let relations = vec![
        Relation::new(
            subject.uid.as_str(),
            addr.uid.as_str(),
            RelationKind::LocatedAt,
            0.6,
            "s1",
        ),
        Relation::new(
            relative.uid.as_str(),
            addr.uid.as_str(),
            RelationKind::LocatedAt,
            0.6,
            "s1",
        ),
    ];
    let entities = vec![subject, addr.clone(), relative];

    let mut scan = Scan::new("s1", Target::new(TargetKind::FullName, "Subject Person"));
    scan.status = ScanStatus::Complete;
    scan.started_at = 1000;
    scan.finished_at = Some(1010); // 10 seconds
    scan.modules_run = 8;
    scan.modules_errored = 1;
    scan.modules_timed_out = 0;

    let r = report(&scan, &entities, &relations, &[]);

    assert_eq!(r.scan_id, "s1");
    assert_eq!(r.seed_kind, "full_name");
    assert_eq!(r.status, "complete");
    // Performance: 3 entities over 10 s = 0.3 entities/s.
    assert_eq!(r.duration_secs, Some(10));
    assert!((r.entities_per_sec - 0.3).abs() < 1e-9, "{}", r.entities_per_sec);
    assert_eq!(r.modules_run, 8);
    assert_eq!(r.modules_errored, 1);

    // Scorecard reflects the graph.
    assert_eq!(r.scorecard.total_entities, 3);
    assert_eq!(r.scorecard.total_relations, 2);
    assert_eq!(r.scorecard.multi_hop_depth, 2, "subject → addr → relative");
    assert!(
        (r.scorecard.graph_coverage - 1.0).abs() < 1e-9,
        "all entities reachable from the subject"
    );
    // Structural fragility: the shared address is the lone cut vertex, and both
    // person→address links are bridges (removing either isolates a person).
    assert_eq!(r.scorecard.cut_vertex_count, 1, "only the shared address fragments the graph");
    assert_eq!(r.scorecard.bridge_count, 2, "each person's link to the address is a bridge");
    // Structural cohesion (the complement): the chain is a tree, so degeneracy is 1 and
    // its three connected nodes form the 1-core — no redundantly-corroborated heart.
    assert_eq!(r.scorecard.degeneracy, 1, "a 2-hop chain has no 2-core");
    assert_eq!(r.scorecard.main_core_size, 3);
    assert_eq!(r.metrics.graph_degeneracy, 1, "the embedded metrics carry the same cohesion read");

    // The shared address is the top pivot.
    assert!(r.pivot_count >= 1);
    assert_eq!(
        r.top_pivot_uid.as_deref(),
        Some(addr.uid.as_str()),
        "the shared address bridges the two people"
    );

    // The full metrics are embedded for traceability.
    assert_eq!(r.metrics.total_entities, 3);
}

#[test]
fn scorecard_cut_vertex_count_is_the_full_articulation_total_past_the_pivot_cap() {
    // A 30-node path has 28 internal (articulation-point) nodes — more than the
    // pivot::detect PIVOT_CAP of 25. The scorecard must report the FULL 28; it used
    // to count cut vertices off the truncated top-25 pivot list, capping at 25.
    let nodes: Vec<Entity> = (0..30)
        .map(|i| Entity::new(EntityKind::Username, format!("n{i:02}"), 0.6, "s1"))
        .collect();
    let relations: Vec<Relation> = nodes
        .windows(2)
        .map(|w| {
            Relation::new(
                w[0].uid.as_str(),
                w[1].uid.as_str(),
                RelationKind::AssociatedWith,
                0.6,
                "s1",
            )
        })
        .collect();
    let mut scan = Scan::new("s1", Target::new(TargetKind::Username, "n00"));
    scan.status = ScanStatus::Complete;
    let r = report(&scan, &nodes, &relations, &[]);
    assert_eq!(
        r.scorecard.cut_vertex_count, 28,
        "all 28 internal path nodes are articulation points, not a cap of 25"
    );
}

#[test]
fn report_handles_an_unfinished_empty_scan_without_panicking() {
    let scan = Scan::new("s2", Target::new(TargetKind::Domain, "example.com"));
    let r = report(&scan, &[], &[], &[]);
    assert_eq!(r.duration_secs, None, "an unfinished scan has no duration");
    assert_eq!(r.entities_per_sec, 0.0);
    assert_eq!(r.scorecard.total_entities, 0);
    assert_eq!(r.scorecard.multi_hop_depth, 0);
    assert_eq!(r.scorecard.cut_vertex_count, 0);
    assert_eq!(r.scorecard.bridge_count, 0);
    assert_eq!(r.scorecard.degeneracy, 0, "an empty graph has degeneracy 0");
    assert_eq!(r.scorecard.main_core_size, 0);
    assert_eq!(r.pivot_count, 0);
    assert!(r.top_pivot_uid.is_none());
}

/// A dispatch event for the coverage-derivation tests below.
fn module_event(kind: crate::core::event::EventKind) -> crate::core::event::Event {
    crate::core::event::Event {
        scan_id: "s1".to_string(),
        ts: 0,
        kind,
    }
}

#[test]
fn a_scorecard_from_a_degraded_run_says_it_is_not_comparable() {
    use crate::core::event::{EventKind, SkipClass};
    // The scorecard exists to be set against another run's, field by field.
    // That reading is only sound if both runs asked the same questions: a run
    // whose providers had no credential yields fewer entities for a reason that
    // has nothing to do with the configuration under test, and attributing the
    // difference to the configuration is exactly the false conclusion a
    // benchmark is supposed to prevent.
    let scan = Scan::new("s1", Target::new(TargetKind::FullName, "Subject Person"));
    let entities = vec![Entity::new(EntityKind::Person, "Subject Person", 0.85, "s1")];

    // Unknown coverage is its own caveat — never silently a complete sweep.
    let blind = report(&scan, &entities, &[], &[]);
    assert!(blind.coverage.is_none());
    let caveat = blind
        .comparability_caveat
        .as_deref()
        .expect("unknown coverage is not comparable");
    assert!(caveat.contains("unknown"), "{caveat}");
    assert_eq!(blind.comparability_caveat(), blind.comparability_caveat.clone());

    // A provider that could not be used: the caveat names how many.
    let degraded = report(
        &scan,
        &entities,
        &[],
        &[
            module_event(EventKind::ModuleDone {
                module: "answered".to_string(),
                found: 1,
            }),
            module_event(EventKind::ModuleSkipped {
                module: "unkeyed".to_string(),
                reason: "needs API key".to_string(),
                class: Some(SkipClass::Unavailable),
            }),
        ],
    );
    let coverage = degraded.coverage.expect("coverage was derived");
    assert_eq!(coverage.unavailable_count, 1);
    assert_eq!(coverage.provider_count, 2);
    let caveat = degraded
        .comparability_caveat
        .as_deref()
        .expect("a degraded run is not comparable");
    assert!(caveat.contains("could not be used"), "{caveat}");

    // A run that asked everything carries no caveat at all — the absence of one
    // is the claim that the comparison is sound.
    let clean = report(
        &scan,
        &entities,
        &[],
        &[module_event(EventKind::ModuleDone {
            module: "answered".to_string(),
            found: 1,
        })],
    );
    assert!(
        clean.coverage.expect("coverage was derived").is_exhaustive(),
        "one provider, and it answered"
    );
    assert_eq!(clean.comparability_caveat, None);

    // Two scorecards with identical yield are NOT interchangeable when one of
    // the runs was degraded — which is the whole point of carrying the field.
    assert_eq!(clean.scorecard, degraded.scorecard);
    assert_ne!(clean.comparability_caveat, degraded.comparability_caveat);
}
