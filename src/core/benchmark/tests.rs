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

    let r = report(&scan, &entities, &relations);

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
fn report_handles_an_unfinished_empty_scan_without_panicking() {
    let scan = Scan::new("s2", Target::new(TargetKind::Domain, "example.com"));
    let r = report(&scan, &[], &[]);
    assert_eq!(r.duration_secs, None, "an unfinished scan has no duration");
    assert_eq!(r.entities_per_sec, 0.0);
    assert_eq!(r.scorecard.total_entities, 0);
    assert_eq!(r.scorecard.multi_hop_depth, 0);
    assert_eq!(r.pivot_count, 0);
    assert!(r.top_pivot_uid.is_none());
}
