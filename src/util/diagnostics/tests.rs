use super::cluster;
#[allow(clippy::wildcard_imports)]
use super::*;
use crate::core::entity::{Entity, EntityKind, Evidence};

fn ent(kind: EntityKind, val: &str, conf: f64, source: &str) -> Entity {
    let mut e = Entity::new(kind, val, conf, "test-scan-id");
    e.add_evidence(Evidence::new(source, format!("test ev from {source}")));
    e
}

#[test]
fn analyse_empty_scan() {
    let d = analyse("sid", "email", "x@y.com", 100, &[], &[]);
    assert_eq!(d.modules_by_yield.len(), 0);
    assert_eq!(d.geo_precision.coordinates_count, 0);
    assert!(!d.optimization_hints.is_empty());
}

#[test]
fn analyse_ranks_modules_by_yield() {
    let entities = vec![
        ent(EntityKind::Email, "a@b.com", 0.8, "modA"),
        ent(EntityKind::Email, "c@d.com", 0.8, "modA"),
        ent(EntityKind::Email, "e@f.com", 0.8, "modA"),
        ent(EntityKind::Username, "alice", 0.7, "modB"),
    ];
    let d = analyse("sid", "email", "x@y.com", 100, &entities, &[]);
    assert_eq!(d.modules_by_yield[0].name, "modA");
    assert_eq!(d.modules_by_yield[0].entities_emitted, 3);
    assert_eq!(d.modules_by_yield[1].name, "modB");
}

#[test]
fn entities_emitted_counts_entities_not_evidence_records() {
    // Regression: entities_emitted was incremented once per EVIDENCE record, so it
    // tracked evidence_count and over-counted any entity carrying multiple
    // same-source evidence records. One entity with two evidence records from the
    // same source is ONE entity from that source, but TWO evidence records — and
    // the inflated count fed the persisted total_entities / --adaptive routing.
    let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.8, "test-scan-id");
    e.add_evidence(Evidence::new("modX", "first observation"));
    e.add_evidence(Evidence::new("modX", "second observation"));
    let d = analyse("sid", "email", "x@y.com", 100, &[e], &[]);
    let m = d
        .modules_by_yield
        .iter()
        .find(|m| m.name == "modX")
        .expect("modX module present");
    assert_eq!(m.entities_emitted, 1, "one entity, not one-per-evidence");
    assert_eq!(m.evidence_count, 2, "two distinct evidence records");
}

#[test]
fn analyse_output_is_byte_reproducible() {
    // Charter (reproducibility): the analysis of a fixed entity set must be
    // byte-identical across runs. Sources of HashMap-iteration randomness —
    // the per-source/per-kind maps (now BTreeMaps) and every Vec sorted by a
    // non-unique key (modules_by_yield, cross_source_overlap, …) with a
    // stable name tiebreak — must produce a stable serialisation.
    //
    // `adaptive_routing` is EXCLUDED: it is intentionally history-dependent
    // (it reads + updates the persisted module-stats ledger), so it legitimately
    // changes between calls. Its own ranking order is made deterministic
    // separately (stable tiebreak), but it isn't a pure function of `entities`.
    let entities = vec![
        ent(EntityKind::Email, "a@b.com", 0.8, "modA"),
        ent(EntityKind::Domain, "b.com", 0.6, "modB"),
        ent(EntityKind::Username, "alice", 0.7, "modC"),
        ent(EntityKind::Email, "c@d.com", 0.9, "modA"),
        ent(EntityKind::Phone, "+61412345678", 0.5, "modD"),
    ];
    let pure = |d: ScanDiagnostics| {
        let mut v = serde_json::to_value(d).expect("should succeed");
        v.as_object_mut()
            .expect("should succeed")
            .remove("adaptive_routing");
        v
    };
    let a = pure(analyse("sid", "email", "seed", 100, &entities, &[]));
    let b = pure(analyse("sid", "email", "seed", 100, &entities, &[]));
    if a != b {
        for (k, av) in a.as_object().expect("should succeed") {
            assert!(
                av == &b[k],
                "non-deterministic diagnostics field `{k}`:\n  A={}\n  B={}",
                serde_json::to_string(av).expect("should succeed"),
                serde_json::to_string(&b[k]).expect("should succeed")
            );
        }
    }
    assert_eq!(a, b, "pure diagnostics must be byte-identical");
    // Guard the test's validity: the maps must carry several keys so order
    // actually matters.
    let d = analyse("sid", "email", "seed", 100, &entities, &[]);
    assert!(
        d.source_confidence.len() >= 3 && d.entity_kind_counts.len() >= 3,
        "expected multi-key maps for a meaningful reproducibility check"
    );
}

#[test]
fn analyse_computes_confidence_stats() {
    let entities = vec![
        ent(EntityKind::Email, "a", 0.5, "src"),
        ent(EntityKind::Email, "b", 0.7, "src"),
        ent(EntityKind::Email, "c", 0.9, "src"),
    ];
    let d = analyse("sid", "email", "x@y.com", 50, &entities, &[]);
    let s = &d.source_confidence["src"];
    assert_eq!(s.n, 3);
    assert!((s.mean - 0.7).abs() < 0.01);
    assert_eq!(s.min, 0.5);
    assert_eq!(s.max, 0.9);
}

#[test]
fn analyse_geo_precision_counts() {
    let mut c = Entity::new(EntityKind::Coordinates, "-33.86,151.21", 0.8, "sid");
    c.add_evidence(
        Evidence::new("ip_geo", "coord ev")
            .with_attr("geohash", "r3gx2f7")
            .with_attr("timezone", "Australia/Sydney"),
    );
    let mut a = Entity::new(EntityKind::Address, "Sydney, NSW, AU", 0.7, "sid");
    a.add_evidence(
        Evidence::new("breach", "addr")
            .with_attr("addr_state", "NSW")
            .with_attr("addr_country", "Australia")
            .with_attr("addr_iso", "AU"),
    );
    let d = analyse("sid", "name", "X", 100, &[c, a], &[]);
    assert_eq!(d.geo_precision.coordinates_count, 1);
    assert_eq!(d.geo_precision.coords_with_geohash, 1);
    assert_eq!(d.geo_precision.coords_with_timezone, 1);
    assert_eq!(d.geo_precision.address_count, 1);
    assert_eq!(d.geo_precision.addresses_with_iso, 1);
    assert!(d.geo_precision.iso_countries.contains(&"AU".to_string()));
}

#[test]
fn analyse_detects_cross_source_overlap() {
    let mut e1 = Entity::new(EntityKind::Email, "shared@x.com", 0.8, "sid");
    e1.add_evidence(Evidence::new("modA", "ev"));
    let mut e2 = Entity::new(EntityKind::Email, "shared@x.com", 0.8, "sid");
    e2.add_evidence(Evidence::new("modB", "ev"));
    let d = analyse("sid", "email", "x@y.com", 50, &[e1, e2], &[]);
    assert_eq!(d.cross_source_overlap.len(), 1);
    assert_eq!(d.cross_source_overlap[0].sources.len(), 2);
}

/// The unconditional fallback hint fires when no real hint condition is met —
/// an empty entity set with no events and a fast wall time exercises exactly that.
#[test]
fn analyse_falls_back_to_a_hint_when_nothing_else_fires() {
    let d = analyse("sid", "email", "x@y.com", 100, &[], &[]);
    assert!(!d.optimization_hints.is_empty());
}

/// T2.14: a slow scan (>60s) that ran modules which found nothing earns the
/// event-sourced slow-with-waste hint — the one signal the entity set can't carry
/// (an empty module emits no evidence, so it never appears in `modules_by_yield`).
#[test]
fn analyse_flags_slow_scan_with_zero_yield_modules() {
    use crate::core::event::{Event, EventKind};
    let events = vec![
        Event::new(
            "sid",
            EventKind::ModuleDone {
                module: "shodan".into(),
                found: 0,
            },
        ),
        Event::new(
            "sid",
            EventKind::ModuleDone {
                module: "censys".into(),
                found: 3,
            },
        ),
    ];
    // 61s wall time, one zero-yield module (shodan) → the hint fires and names it.
    let d = analyse("sid", "email", "x@y.com", 61_000, &[], &events);
    let hint = d
        .optimization_hints
        .iter()
        .find(|h| h.contains("zero-yield module"))
        .expect("slow scan with a zero-yield module must emit the hint");
    assert!(
        hint.contains("shodan"),
        "hint names the empty module: {hint}"
    );
    assert!(
        !hint.contains("censys"),
        "a module that DID find entities is not flagged: {hint}"
    );

    // Same events but a fast scan (<=60s) → no slow-scan hint (it is wall-gated).
    let fast = analyse("sid", "email", "x@y.com", 60_000, &[], &events);
    assert!(
        !fast
            .optimization_hints
            .iter()
            .any(|h| h.contains("zero-yield module")),
        "the hint is gated on a >60s wall time"
    );
}

#[test]
fn name_similarity_matches_partial_names() {
    let a = cluster::normalize_for_fuzzy("Jordan Meyer");
    let b = cluster::normalize_for_fuzzy("Jordan L Meyer");
    let c = cluster::normalize_for_fuzzy("J Meyer");
    // Jordan Meyer ↔ Jordan L Meyer should be > 0.6
    assert!(
        cluster::name_similarity(&a, &b) >= 0.6,
        "got {}",
        cluster::name_similarity(&a, &b)
    );
    // Both should match J Meyer at least via prefix bonus
    assert!(cluster::name_similarity(&a, &c) >= 0.4);
}

#[test]
fn name_similarity_rejects_unrelated() {
    let a = cluster::normalize_for_fuzzy("Jordan Meyer");
    let b = cluster::normalize_for_fuzzy("Sarah Connor");
    assert!(cluster::name_similarity(&a, &b) < 0.3);
}

#[test]
fn cluster_entities_collapses_name_variants() {
    let mut e1 = Entity::new(EntityKind::Person, "Jordan Meyer", 0.8, "sid");
    e1.add_evidence(Evidence::new("oathnet_pro", "ev"));
    let mut e2 = Entity::new(EntityKind::Person, "Jordan L Meyer", 0.75, "sid");
    e2.add_evidence(Evidence::new("see_know", "ev"));
    let mut e3 = Entity::new(EntityKind::Person, "Sarah Connor", 0.8, "sid");
    e3.add_evidence(Evidence::new("oathnet_pro", "ev"));
    let d = analyse("sid", "name", "Jordan Meyer", 100, &[e1, e2, e3], &[]);
    // First two should form a cluster; Sarah Connor stays singleton (skipped)
    assert!(!d.entity_clusters.is_empty());
    let cluster = &d.entity_clusters[0];
    assert_eq!(cluster.member_count, 2);
    assert_eq!(cluster.source_diversity, 2);
}

#[test]
fn cluster_coordinates_groups_nearby_points() {
    // Sydney Opera House + Sydney Harbour Bridge (~600m apart) should cluster.
    let mut e1 = Entity::new(EntityKind::Coordinates, "-33.8568,151.2153", 0.8, "sid");
    e1.add_evidence(
        Evidence::new("ip_geo", "ev")
            .with_attr("geohash", "r3gx2f7")
            .with_attr("timezone", "Australia/Sydney"),
    );
    let mut e2 = Entity::new(EntityKind::Coordinates, "-33.8523,151.2108", 0.7, "sid");
    e2.add_evidence(
        Evidence::new("ipinfo", "ev")
            .with_attr("geohash", "r3gx2f7")
            .with_attr("timezone", "Australia/Sydney"),
    );
    let d = analyse("sid", "ip", "1.1.1.1", 100, &[e1, e2], &[]);
    assert_eq!(d.coordinate_clusters.len(), 1);
    assert_eq!(d.coordinate_clusters[0].member_count, 2);
    assert!(d.coordinate_clusters[0].diameter_km < 1.0);
    assert_eq!(d.coordinate_clusters[0].country_iso.as_deref(), Some("AU"));
}

fn make_cluster(iso: &str, diversity: usize) -> CoordinateCluster {
    CoordinateCluster {
        centroid_lat: 0.0,
        centroid_lon: 0.0,
        centroid_geohash: String::new(),
        members: vec!["0.0,0.0".to_string()],
        member_count: 1,
        diameter_km: 0.0,
        country_iso: Some(iso.to_string()),
        timezone: String::new(),
        source_diversity: diversity,
        ..Default::default()
    }
}

#[test]
fn country_coherence_keeps_anchor_match_at_full_weight() {
    let c = make_cluster("AU", 1);
    assert_eq!(country_coherence_weight(&c, "AU"), 1.0);
}

#[test]
fn country_coherence_downweights_single_source_cross_border() {
    let c = make_cluster("US", 1);
    assert_eq!(country_coherence_weight(&c, "AU"), 0.05);
}

#[test]
fn country_coherence_partially_keeps_multi_source_cross_border() {
    assert_eq!(country_coherence_weight(&make_cluster("US", 2), "AU"), 0.30);
    assert_eq!(country_coherence_weight(&make_cluster("US", 3), "AU"), 0.60);
}

#[test]
fn country_coherence_neutralises_unknown_country() {
    let c = CoordinateCluster {
        centroid_lat: 0.0,
        centroid_lon: 0.0,
        centroid_geohash: String::new(),
        members: vec![],
        member_count: 0,
        diameter_km: 0.0,
        country_iso: None,
        timezone: String::new(),
        source_diversity: 1,
        ..Default::default()
    };
    assert_eq!(country_coherence_weight(&c, "AU"), 0.7);
}

#[test]
fn filter_country_coherent_drops_noise() {
    let clusters = vec![
        make_cluster("AU", 1), // 1.0 -> kept
        make_cluster("US", 1), // 0.05 -> dropped at threshold 0.5
        make_cluster("US", 3), // 0.60 -> kept at threshold 0.5
    ];
    let kept = filter_country_coherent(clusters, "AU", 0.5);
    assert_eq!(kept.len(), 2);
}

#[test]
fn fuzzy_cluster_drops_single_source_doublet() {
    // Two address entities, both from the same source. With the
    // diversity floor in place, this should NOT be reported as a
    // cluster (member_count=2, source_diversity=1).
    let mut e1 = Entity::new(EntityKind::Address, "Haigen Li", 0.3, "sid");
    e1.add_evidence(Evidence::new("oathnet_pro", "ev"));
    let mut e2 = Entity::new(EntityKind::Address, "Haigen Li, Pingan Asset", 0.3, "sid");
    e2.add_evidence(Evidence::new("oathnet_pro", "ev"));
    let d = analyse("sid", "name", "Haigen Bamford", 100, &[e1, e2], &[]);
    // Identity-pollution candidate filtered out.
    let polluted = d
        .entity_clusters
        .iter()
        .any(|c| c.canonical_value.contains("Pingan"));
    assert!(!polluted);
}

#[test]
fn fuzzy_cluster_keeps_triplet_from_single_source() {
    // Three same-source records is frequency-as-signal; kept.
    let mut e1 = Entity::new(EntityKind::Person, "Haigen Bamford", 0.5, "sid");
    e1.add_evidence(Evidence::new("oathnet_pro", "ev"));
    let mut e2 = Entity::new(EntityKind::Person, "HAIGEN BAMFORD", 0.5, "sid");
    e2.add_evidence(Evidence::new("oathnet_pro", "ev"));
    let mut e3 = Entity::new(EntityKind::Person, "haigen bamford", 0.5, "sid");
    e3.add_evidence(Evidence::new("oathnet_pro", "ev"));
    let d = analyse("sid", "name", "Haigen Bamford", 100, &[e1, e2, e3], &[]);
    let found = d
        .entity_clusters
        .iter()
        .any(|c| c.canonical_value.to_lowercase().contains("haigen"));
    assert!(found);
}
