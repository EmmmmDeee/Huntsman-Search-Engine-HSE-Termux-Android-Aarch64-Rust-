//! Performance *regression* gate (runs in `cargo test --all`, so CI enforces it).
//!
//! Wall-time on a shared CI runner is too noisy to gate on a percentage, so the
//! hard assertions here are **deterministic complexity invariants** — the edge
//! counts that prove the graph builders stayed sub-quadratic — plus a single,
//! deliberately *generous* catastrophe ceiling that only trips on a real
//! algorithmic blow-up (O(n²)+), never on a slow runner. Precise timing is the
//! job of `benches/pipeline.rs` (`cargo bench --bench pipeline`), whose numbers
//! are tracked in `benches/BASELINE.md`.

use std::sync::Arc;
use std::time::Instant;

use huntsman_search_engine::core::correlator::Correlator;
use huntsman_search_engine::core::entity::{Entity, EntityKind, Evidence};
use huntsman_search_engine::core::port::StoragePort;
use huntsman_search_engine::core::relation::{self, RelationKind};
use huntsman_search_engine::core::scan::{Scan, Target, TargetKind};
use huntsman_search_engine::storage::Store;

/// A stealer-log cluster of N entities must produce a **star** (N-1 edges), not
/// a mesh (N·(N-1)/2). Guards `derive_stealer_cooccurrence`'s complexity.
#[test]
fn stealer_cooccurrence_is_star_not_mesh() {
    let mk = |v: &str| {
        let mut e = Entity::new(EntityKind::Email, v, 0.6, "p");
        e.tag("stealer");
        e.add_evidence(Evidence::new("x", "y").with_attr("log_id", "L"));
        e
    };
    let ents: Vec<Entity> = (0..6).map(|i| mk(&format!("u{i}@x.test"))).collect();
    let edges = relation::derive_stealer_cooccurrence(&ents, "p");
    assert_eq!(
        edges.len(),
        5,
        "6-member cluster must yield n-1=5 star edges, not a mesh"
    );
    assert!(
        edges
            .iter()
            .all(|e| e.kind == RelationKind::CompromisedWith)
    );
}

/// Structural edges link a subdomain to its **closest present parent only** —
/// a 3-level chain yields exactly 2 edges, never the transitive closure.
#[test]
fn structural_links_closest_parent_only() {
    let ents = vec![
        Entity::new(EntityKind::Domain, "example.com", 0.9, "p"),
        Entity::new(EntityKind::Domain, "a.example.com", 0.9, "p"),
        Entity::new(EntityKind::Domain, "b.a.example.com", 0.9, "p"),
    ];
    assert_eq!(relation::derive_structural(&ents, "p").len(), 2);
}

/// Catastrophe backstop: a 1 000-entity workload through every relation
/// builder + batched persistence + the correlator must finish well under a
/// generous ceiling. Loose by design (won't flake on a slow runner); it only
/// fires if something regresses to a super-linear hot path.
#[test]
fn full_pipeline_completes_within_generous_ceiling() {
    let entities = workload(1_000);

    let t = Instant::now();
    let mut rels = Vec::new();
    rels.extend(relation::derive_structural(&entities, "p"));
    rels.extend(relation::derive_colocation(&entities, "p"));
    rels.extend(relation::derive_resolution(&entities, "p"));
    rels.extend(relation::derive_registration(&entities, "p"));
    rels.extend(relation::derive_image_similarity(&entities, "p"));
    rels.extend(relation::derive_stealer_cooccurrence(&entities, "p"));

    let path = std::env::temp_dir().join(format!("hse-perftest-{}.db", std::process::id()));
    let p = path.to_string_lossy().into_owned();
    let store: Arc<dyn StoragePort> = Arc::new(Store::open(&p).expect("open temp db"));
    store
        .upsert_scan(&Scan::new(
            "p",
            Target::new(TargetKind::Domain, "example.com"),
        ))
        .unwrap();
    store.upsert_entities_batch(&entities).unwrap();
    store.upsert_relations_batch(&rels).unwrap();
    let _ = Correlator::new(Arc::clone(&store)).run("p").unwrap();
    let ms = t.elapsed().as_millis();

    drop(store);
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{p}{ext}"));
    }

    eprintln!(
        "[perf] 1000-entity full pipeline: {ms} ms, {} relations",
        rels.len()
    );
    assert!(
        ms < 30_000,
        "1000-entity pipeline took {ms} ms (> 30s) — likely an algorithmic regression"
    );
}

/// Deterministic synthetic workload (~`n`) touching every relation family.
fn workload(n: usize) -> Vec<Entity> {
    let mut out = Vec::with_capacity(n + 1);
    let q = (n / 5).max(1);

    out.push(Entity::new(EntityKind::Domain, "example.com", 0.9, "p"));
    for i in 0..q {
        out.push(Entity::new(
            EntityKind::Domain,
            format!("s{i}.example.com"),
            0.8,
            "p",
        ));
    }
    for i in 0..q {
        let mut e = Entity::new(
            EntityKind::IpAddress,
            format!("10.0.{}.{}", i / 256, i % 256),
            0.7,
            "p",
        );
        e.add_evidence(Evidence::new("p", format!("A record for s{i}.example.com")));
        out.push(e);
    }
    for i in 0..q {
        let mut e = Entity::new(EntityKind::Email, format!("u{i}@victim.test"), 0.6, "p");
        e.tag("stealer");
        e.add_evidence(Evidence::new("p", "stealer").with_attr("log_id", format!("L{}", i % 8)));
        out.push(e);
    }
    for i in 0..q {
        let mut e = Entity::new(
            EntityKind::Url,
            format!("https://img.test/{i}.jpg"),
            0.6,
            "p",
        );
        let h = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        e.add_evidence(Evidence::new("p", "image").with_attr("phash", format!("{h:016x}")));
        out.push(e);
    }
    let coords = (n / 10).min(40);
    for i in 0..coords {
        let (lat, lon) = if i % 2 == 0 {
            (-27.47, 153.02)
        } else {
            (-33.87, 151.21)
        };
        let j = (i as f64) * 0.0001;
        out.push(Entity::new(
            EntityKind::Coordinates,
            format!("{:.6},{:.6}", lat + j, lon + j),
            0.8,
            "p",
        ));
    }
    out
}
