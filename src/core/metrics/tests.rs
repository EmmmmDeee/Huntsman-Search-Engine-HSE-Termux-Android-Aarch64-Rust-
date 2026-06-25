use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::relation::{Relation, RelationKind};

    /// A single-source entity of `kind` at base `conf`. With no corroborating
    /// evidence, `source_count() == 1` and `c_effective() == conf`, so the tier
    /// is a direct function of `conf` (≥0.75 Verified, ≥0.40 Probable, else
    /// Candidate) — which keeps the expected values in these tests exact.
    fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
        Entity::new(kind, value, conf, "scan")
    }

    /// Add a distinct corroborating source so `source_count()` rises by one.
    fn with_sources(mut e: Entity, sources: &[&str]) -> Entity {
        for s in sources {
            e.add_evidence(Evidence::new(*s, "seen"));
        }
        e
    }

    #[test]
    fn empty_input_is_all_zero_and_never_nan() {
        let m = compute(&[], &[]);
        assert_eq!(m.total_entities, 0);
        assert_eq!(m.total_relations, 0);
        assert!(m.entities_by_kind.is_empty());
        assert!(m.relations_by_kind.is_empty());
        assert_eq!(
            m.tier_counts,
            TierCounts {
                verified: 0,
                probable: 0,
                candidate: 0
            }
        );
        // Statistics/fractions defined as 0.0 — explicitly NOT NaN.
        assert_eq!(m.mean_confidence, 0.0);
        assert_eq!(m.median_confidence, 0.0);
        assert!(!m.mean_confidence.is_nan());
        assert!(!m.median_confidence.is_nan());
        assert_eq!(m.corroborated_fraction, 0.0);
        assert_eq!(m.linked_entity_fraction, 0.0);
        assert_eq!(m.graph_density, 0.0);
        assert_eq!(m.graph_degeneracy, 0);
        assert_eq!(m.main_core_size, 0);
        assert_eq!(m.cross_scan_bridges, 0);
        assert_eq!(m.distinct_evidence_sources, 0);
    }

    #[test]
    fn single_entity_no_relations_has_zero_density_and_no_nan() {
        // n < 2 ⇒ density 0.0 (no possible undirected edge), no division by zero.
        let e = ent(EntityKind::Email, "a@example.com", 0.6);
        let m = compute(std::slice::from_ref(&e), &[]);
        assert_eq!(m.total_entities, 1);
        assert_eq!(m.graph_density, 0.0);
        assert_eq!(m.linked_entity_fraction, 0.0);
        // mean == median == the single c_effective (==confidence here).
        assert!((m.mean_confidence - 0.6).abs() < 1e-9);
        assert!((m.median_confidence - 0.6).abs() < 1e-9);
    }

    #[test]
    fn mixed_scan_produces_exact_counts_tiers_and_fractions() {
        // Four entities with KNOWN single-source confidences ⇒ known tiers:
        //   0.90 Verified, 0.80 Verified, 0.50 Probable, 0.20 Candidate.
        let entities = vec![
            ent(EntityKind::Person, "jane", 0.90),
            ent(EntityKind::Email, "jane@example.com", 0.80),
            ent(EntityKind::Domain, "example.com", 0.50),
            ent(EntityKind::Domain, "cdn.example.com", 0.20),
        ];
        let m = compute(&entities, &[]);

        assert_eq!(m.total_entities, 4);
        // Per-kind, sorted ascending by kind name: domain(2), email(1), person(1).
        assert_eq!(
            m.entities_by_kind,
            vec![
                ("domain".to_string(), 2),
                ("email".to_string(), 1),
                ("person".to_string(), 1),
            ]
        );
        assert_eq!(
            m.tier_counts,
            TierCounts {
                verified: 2,
                probable: 1,
                candidate: 1
            }
        );
        // Mean of {0.20,0.50,0.80,0.90} = 2.4/4 = 0.60; median = (0.50+0.80)/2 = 0.65.
        assert!((m.mean_confidence - 0.60).abs() < 1e-9, "{}", m.mean_confidence);
        assert!(
            (m.median_confidence - 0.65).abs() < 1e-9,
            "{}",
            m.median_confidence
        );
        // No entity has >=2 distinct sources here.
        assert_eq!(m.corroborated_fraction, 0.0);
    }

    #[test]
    fn corroborated_fraction_counts_multi_source_entities() {
        // Two of four entities have >=2 distinct corroborating sources.
        let entities = vec![
            with_sources(ent(EntityKind::Email, "a@x.com", 0.6), &["hibp", "dehashed"]),
            with_sources(ent(EntityKind::Email, "b@x.com", 0.6), &["hibp", "search", "whois"]),
            with_sources(ent(EntityKind::Email, "c@x.com", 0.6), &["hibp"]), // single source
            ent(EntityKind::Email, "d@x.com", 0.6),                          // no evidence
        ];
        let m = compute(&entities, &[]);
        assert_eq!(m.distinct_evidence_sources, 4); // hibp, dehashed, search, whois
        // 2 of 4 corroborated.
        assert!((m.corroborated_fraction - 0.5).abs() < 1e-9, "{}", m.corroborated_fraction);
    }

    #[test]
    fn graph_density_and_linked_fraction_on_a_known_graph() {
        // 4 entities, 2 edges among 3 of them: a—b and b—c (d is orphan).
        let a = ent(EntityKind::Email, "a@x.com", 0.6);
        let b = ent(EntityKind::Person, "b", 0.6);
        let c = ent(EntityKind::Phone, "+15551230000", 0.6);
        let d = ent(EntityKind::Domain, "orphan.example.com", 0.6);
        let rels = vec![
            Relation::new(a.uid.clone(), b.uid.clone(), RelationKind::IdentifiedBy, 0.6, "scan"),
            Relation::new(b.uid.clone(), c.uid.clone(), RelationKind::IdentifiedBy, 0.6, "scan"),
        ];
        let entities = vec![a, b, c, d];
        let m = compute(&entities, &rels);

        assert_eq!(m.total_relations, 2);
        // Possible undirected edges for n=4: 4*3/2 = 6; density = 2/6.
        assert!((m.graph_density - (2.0 / 6.0)).abs() < 1e-9, "{}", m.graph_density);
        // a,b,c are endpoints; d is not ⇒ 3/4 linked.
        assert!((m.linked_entity_fraction - 0.75).abs() < 1e-9, "{}", m.linked_entity_fraction);
        // relations_by_kind sorted by name (single kind here).
        assert_eq!(m.relations_by_kind, vec![("identified_by".to_string(), 2)]);
        // Cohesion: a—b—c is a path (a tree) ⇒ degeneracy 1, and its three connected
        // nodes form the 1-core; the orphan d (coreness 0) is excluded.
        assert_eq!(m.graph_degeneracy, 1);
        assert_eq!(m.main_core_size, 3);
    }

    #[test]
    fn cohesion_measures_capture_a_dense_core_amid_a_sparse_periphery() {
        // A triangle a-b-c (a 2-core) with a pendant tail c—d and an orphan e. Density is
        // diluted by the periphery, but degeneracy reports the cohesive heart exists and
        // the main core is exactly the three triangle members.
        let a = ent(EntityKind::Person, "a", 0.6);
        let b = ent(EntityKind::Person, "b", 0.6);
        let c = ent(EntityKind::Person, "c", 0.6);
        let d = ent(EntityKind::Person, "d", 0.6);
        let e = ent(EntityKind::Person, "e", 0.6); // orphan — coreness 0
        let mk = |x: &Entity, y: &Entity| {
            Relation::new(x.uid.clone(), y.uid.clone(), RelationKind::AssociatedWith, 0.6, "scan")
        };
        let rels = vec![mk(&a, &b), mk(&b, &c), mk(&a, &c), mk(&c, &d)];
        let m = compute(&[a, b, c, d, e], &rels);
        assert_eq!(m.graph_degeneracy, 2, "the triangle is a 2-core");
        assert_eq!(m.main_core_size, 3, "exactly the three triangle members are the main core");
    }

    #[test]
    fn graph_density_clamps_for_parallel_edges() {
        // Two entities, three parallel edges between them: raw 3 / (2*1/2)=3/1 → clamp 1.0.
        let a = ent(EntityKind::Email, "a@x.com", 0.6);
        let b = ent(EntityKind::Person, "b", 0.6);
        let mk = |k| Relation::new(a.uid.clone(), b.uid.clone(), k, 0.6, "scan");
        let rels = vec![
            mk(RelationKind::IdentifiedBy),
            mk(RelationKind::AliasOf),
            mk(RelationKind::AssociatedWith),
        ];
        let entities = vec![a, b];
        let m = compute(&entities, &rels);
        assert_eq!(m.graph_density, 1.0);
        assert!((m.linked_entity_fraction - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cross_scan_bridges_counts_tagged_entities() {
        let mut e1 = ent(EntityKind::Email, "a@x.com", 0.6);
        e1.tag("cross-scan");
        let mut e2 = ent(EntityKind::Email, "b@x.com", 0.6);
        e2.tag("cross-scan-cooccurrence");
        let mut e3 = ent(EntityKind::Email, "c@x.com", 0.6);
        e3.tag("cross-scan-relation");
        let mut e4 = ent(EntityKind::Email, "d@x.com", 0.6);
        e4.tag("unrelated"); // not a bridge tag
        let e5 = ent(EntityKind::Email, "e@x.com", 0.6); // untagged
        let entities = vec![e1, e2, e3, e4, e5];
        let m = compute(&entities, &[]);
        assert_eq!(m.cross_scan_bridges, 3);
    }

    #[test]
    fn metrics_are_independent_of_entity_and_relation_order() {
        // Build a non-trivial scan, compute, then shuffle both inputs and
        // re-compute. The two ScanMetrics must be byte-for-byte equal.
        let a = with_sources(ent(EntityKind::Person, "jane", 0.90), &["search", "whois"]);
        let b = ent(EntityKind::Email, "jane@example.com", 0.80);
        let c = ent(EntityKind::Domain, "example.com", 0.50);
        let mut d = ent(EntityKind::Domain, "cdn.example.com", 0.20);
        d.tag("cross-scan");
        let rels = vec![
            Relation::new(b.uid.clone(), c.uid.clone(), RelationKind::BelongsToDomain, 0.5, "scan"),
            Relation::new(a.uid.clone(), b.uid.clone(), RelationKind::IdentifiedBy, 0.8, "scan"),
        ];
        let entities = vec![a, b, c, d];

        let m1 = compute(&entities, &rels);

        // A different ordering of the same elements.
        let entities_shuffled: Vec<Entity> = {
            let mut v = entities.clone();
            v.reverse();
            v.rotate_left(1);
            v
        };
        let rels_shuffled: Vec<Relation> = {
            let mut v = rels.clone();
            v.reverse();
            v
        };
        let m2 = compute(&entities_shuffled, &rels_shuffled);

        assert_eq!(m1, m2, "ScanMetrics must be order-independent");
    }

    #[test]
    fn serialization_is_stable_and_ordered() {
        // The per-kind vectors must serialise in sorted-by-name order regardless
        // of insertion order, and the struct round-trips through serde_json.
        let entities = vec![
            ent(EntityKind::Person, "p", 0.9),
            ent(EntityKind::Domain, "d.example.com", 0.5),
            ent(EntityKind::Email, "e@x.com", 0.5),
        ];
        let m = compute(&entities, &[]);
        let json = serde_json::to_string(&m).expect("serialises");
        // domain appears before email before person in the kinds array.
        let kinds = json
            .split("\"entities_by_kind\":")
            .nth(1)
            .expect("has entities_by_kind");
        let di = kinds.find("domain").expect("domain present");
        let ei = kinds.find("email").expect("email present");
        let pi = kinds.find("person").expect("person present");
        assert!(di < ei && ei < pi, "kinds must be sorted ascending");
    }

    #[test]
    fn reachability_depth_profile_on_a_path() {
        // a — b — c — d, anchored at a: exactly one entity at each hop 0..=3.
        let a = ent(EntityKind::Person, "a", 0.6);
        let b = ent(EntityKind::Email, "b@x.com", 0.6);
        let c = ent(EntityKind::Phone, "+15551230000", 0.6);
        let d = ent(EntityKind::Domain, "d.example.com", 0.6);
        let rels = vec![
            Relation::new(a.uid.clone(), b.uid.clone(), RelationKind::IdentifiedBy, 0.6, "scan"),
            Relation::new(b.uid.clone(), c.uid.clone(), RelationKind::IdentifiedBy, 0.6, "scan"),
            Relation::new(c.uid.clone(), d.uid.clone(), RelationKind::IdentifiedBy, 0.6, "scan"),
        ];
        let entities = vec![a.clone(), b, c, d];
        let r = reachability(&entities, &rels, &a.uid);
        assert!(r.anchored);
        assert_eq!(r.reached_at_hop, vec![1, 1, 1, 1], "one entity per hop along the chain");
        assert_eq!(r.max_depth, 3);
        assert_eq!(r.reachable_total, 4);
        assert!((r.reachable_fraction - 1.0).abs() < 1e-9);
    }

    #[test]
    fn reachability_counts_only_the_connected_component() {
        // a — b, plus an orphan c not reachable from a.
        let a = ent(EntityKind::Person, "a", 0.6);
        let b = ent(EntityKind::Email, "b@x.com", 0.6);
        let c = ent(EntityKind::Domain, "orphan.example.com", 0.6);
        let rels = vec![Relation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::IdentifiedBy,
            0.6,
            "scan",
        )];
        let entities = vec![a.clone(), b, c];
        let r = reachability(&entities, &rels, &a.uid);
        assert_eq!(r.reachable_total, 2, "the orphan is unreachable from the seed");
        assert_eq!(r.max_depth, 1);
        assert!((r.reachable_fraction - (2.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn reachability_is_unanchored_for_an_absent_anchor() {
        let a = ent(EntityKind::Person, "a", 0.6);
        let r = reachability(std::slice::from_ref(&a), &[], "no-such-uid");
        assert!(!r.anchored);
        assert_eq!(r.reachable_total, 0);
        assert_eq!(r.reachable_fraction, 0.0);
        assert!(r.reached_at_hop.is_empty());
    }

    #[test]
    fn compute_anchors_seed_reach_on_the_subject_tag() {
        let mut subject = ent(EntityKind::Person, "subject", 0.85);
        subject.tag("subject");
        let relative = ent(EntityKind::Person, "relative", 0.5);
        let rels = vec![Relation::new(
            subject.uid.clone(),
            relative.uid.clone(),
            RelationKind::AssociatedWith,
            0.5,
            "scan",
        )];
        let entities = vec![subject, relative];
        let m = compute(&entities, &rels);
        assert!(m.seed_reach.anchored, "the subject-tagged entity anchors the reach");
        assert_eq!(m.seed_reach.max_depth, 1);
        assert_eq!(m.seed_reach.reachable_total, 2);
        // No subject/seed tag ⇒ unanchored.
        let m2 = compute(&[ent(EntityKind::Person, "lonely", 0.6)], &[]);
        assert!(!m2.seed_reach.anchored);
    }

    #[test]
    fn reachability_is_deterministic_under_input_shuffling() {
        let mut s = ent(EntityKind::Person, "s", 0.8);
        s.tag("subject");
        let leaves: Vec<Entity> = (0..5)
            .map(|i| ent(EntityKind::Email, &format!("l{i}@x.com"), 0.5))
            .collect();
        let rels: Vec<Relation> = leaves
            .iter()
            .map(|l| Relation::new(s.uid.clone(), l.uid.clone(), RelationKind::IdentifiedBy, 0.5, "scan"))
            .collect();
        let mut entities = vec![s.clone()];
        entities.extend(leaves.iter().cloned());

        let r1 = reachability(&entities, &rels, &s.uid);
        let mut e2 = entities.clone();
        e2.reverse();
        let mut rl2 = rels.clone();
        rl2.reverse();
        let r2 = reachability(&e2, &rl2, &s.uid);
        assert_eq!(r1, r2, "reach profile is order-independent");
        assert_eq!(r1.reached_at_hop, vec![1, 5], "star: the subject plus 5 at hop 1");
    }
