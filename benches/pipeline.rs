//! Offline, deterministic performance benchmark for the graph data-fabric.
//!
//! Runs a synthetic workload through the **real** pipeline stages — relation
//! derivation (all builders), batched storage persistence, and the correlator
//! — and prints a per-stage timing table plus throughput and peak RSS. There
//! is **no network and no external data**: the workload is generated in-process
//! and deterministic, so numbers are comparable across runs on the same device
//! (the point being to track HSE's "low-overhead / high-velocity on aarch64"
//! claim with measurements, not assertions).
//!
//! Dependency-free (`harness = false`, our own `main`) to keep the build lean.
//!
//!   cargo bench --bench pipeline
//!   HSE_BENCH_N=2000 HSE_BENCH_ITERS=100 cargo bench --bench pipeline
//!
//! `HSE_BENCH_N` scales the entity count (default 500); `HSE_BENCH_ITERS` the
//! per-stage iteration count (default 50). The CI regression *gate* lives in
//! `tests/perf.rs` (deterministic invariants, not wall-time); this harness is
//! the human-facing measurement tool.

use std::sync::Arc;
use std::time::Instant;

use huntsman_search_engine::core::correlator::Correlator;
use huntsman_search_engine::core::entity::{Entity, EntityKind, Evidence};
use huntsman_search_engine::core::port::StoragePort;
use huntsman_search_engine::core::relation::{self, Relation};
use huntsman_search_engine::core::scan::{Scan, Target, TargetKind};
use huntsman_search_engine::storage::Store;

type Builder = fn(&[Entity], &str) -> Vec<Relation>;

fn main() {
    let n: usize = env_usize("HSE_BENCH_N", 500);
    let iters: usize = env_usize("HSE_BENCH_ITERS", 50);
    let io_iters = iters.min(20); // I/O stages are slower; fewer reps.

    let entities = workload(n);
    println!(
        "HSE pipeline benchmark — {} synthetic entities, {iters} iters (offline, deterministic)\n",
        entities.len()
    );
    println!("  {:<30} {:>10}   output", "stage", "median");
    println!("  {}", "─".repeat(60));

    // ── Relation builders (pure, no I/O) ───────────────────────────────────
    let builders: [(&str, Builder); 6] = [
        ("derive_structural", relation::derive_structural),
        ("derive_colocation", relation::derive_colocation),
        ("derive_resolution", relation::derive_resolution),
        ("derive_registration", relation::derive_registration),
        ("derive_image_similarity", relation::derive_image_similarity),
        (
            "derive_stealer_cooccurrence",
            relation::derive_stealer_cooccurrence,
        ),
    ];
    let mut all_rels: Vec<Relation> = Vec::new();
    let mut graph_build_ms = 0.0;
    for (name, f) in builders {
        let edges = f(&entities, "bench");
        let ms = bench(iters, || {
            std::hint::black_box(f(std::hint::black_box(&entities), "bench"));
        });
        graph_build_ms += ms;
        println!("  {name:<30} {ms:>8.3} ms   {} edges", edges.len());
        all_rels.extend(edges);
    }
    println!(
        "  {:<30} {graph_build_ms:>8.3} ms   {} edges total",
        "  ↳ full graph build",
        all_rels.len()
    );

    // ── Storage persistence (batched WAL upserts; temp DB) ──────────────────
    let dbpath = std::env::temp_dir().join(format!("hse-bench-{}.db", std::process::id()));
    let p = dbpath.to_string_lossy().into_owned();
    let store: Arc<dyn StoragePort> = Arc::new(Store::open(&p).expect("open temp db"));
    store
        .upsert_scan(&Scan::new(
            "bench",
            Target::new(TargetKind::Domain, "example.com"),
        ))
        .expect("upsert_scan");

    let pe = bench(io_iters, || {
        store.upsert_entities_batch(&entities).expect("entities");
    });
    println!(
        "  {:<30} {pe:>8.3} ms   {} entities (1 txn)",
        "upsert_entities_batch",
        entities.len()
    );
    let pr = bench(io_iters, || {
        store.upsert_relations_batch(&all_rels).expect("relations");
    });
    println!(
        "  {:<30} {pr:>8.3} ms   {} relations (1 txn)",
        "upsert_relations_batch",
        all_rels.len()
    );

    // ── Correlator (store-backed; reads what we persisted) ──────────────────
    let corr = Correlator::new(Arc::clone(&store));
    let fired = corr.run("bench").expect("correlator").len();
    let cm = bench(io_iters, || {
        std::hint::black_box(corr.run("bench").expect("correlator"));
    });
    println!(
        "  {:<30} {cm:>8.3} ms   {fired} correlations",
        "correlator.run (35 rules)"
    );

    drop(corr);
    drop(store);
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{p}{ext}"));
    }

    // ── Summary ─────────────────────────────────────────────────────────────
    println!("  {}", "─".repeat(60));
    let ent_per_s = (entities.len() as f64) / (graph_build_ms / 1000.0).max(1e-9);
    println!("  graph-build throughput: {ent_per_s:>10.0} entities/sec");
    if let Some(kb) = peak_rss_kb() {
        println!("  peak RSS:               {:>10.1} MiB", kb as f64 / 1024.0);
    }
}

/// Median wall-time in ms over `iters` runs (one warmup, discarded).
fn bench<F: FnMut()>(iters: usize, mut f: F) -> f64 {
    f();
    let mut samples = Vec::with_capacity(iters.max(1));
    for _ in 0..iters.max(1) {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    samples[samples.len() / 2]
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Peak resident set size (KiB) from `/proc/self/status` (Linux/Termux).
/// `None` off-Linux — the bench just omits the line there.
fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|l| {
        l.strip_prefix("VmHWM:")
            .and_then(|r| r.split_whitespace().next())
            .and_then(|kb| kb.parse().ok())
    })
}

/// Build a deterministic synthetic entity set (~`n`) exercising every relation
/// family: a subdomain tree (structural), co-located coordinates (colocation),
/// IPs with DNS evidence (resolution), stealer credentials sharing log ids
/// (co-occurrence), and image URLs with perceptual hashes (similarity).
fn workload(n: usize) -> Vec<Entity> {
    let mut out = Vec::with_capacity(n + 1);
    let q = (n / 5).max(1);

    // Domains: a root + subdomains → SubdomainOf edges to the root.
    out.push(Entity::new(EntityKind::Domain, "example.com", 0.9, "bench"));
    for i in 0..q {
        out.push(Entity::new(
            EntityKind::Domain,
            format!("s{i}.example.com"),
            0.8,
            "bench",
        ));
    }

    // IPs carrying DNS evidence that names a present domain → ResolvesTo.
    for i in 0..q {
        let mut e = Entity::new(
            EntityKind::IpAddress,
            format!("10.0.{}.{}", i / 256, i % 256),
            0.7,
            "bench",
        );
        e.add_evidence(
            Evidence::new("bench", format!("A record for s{i}.example.com"))
                .with_attr("domain", format!("s{i}.example.com")),
        );
        out.push(e);
    }

    // Stealer credentials bucketed into 8 logs → CompromisedWith stars.
    for i in 0..q {
        let mut e = Entity::new(EntityKind::Email, format!("u{i}@victim.test"), 0.6, "bench");
        e.tag("stealer");
        e.add_evidence(
            Evidence::new("bench", "stealer").with_attr("log_id", format!("L{}", i % 8)),
        );
        out.push(e);
    }

    // Image URLs with mostly-distinct pHashes + occasional duplicates.
    for i in 0..q {
        let mut e = Entity::new(
            EntityKind::Url,
            format!("https://img.test/{i}.jpg"),
            0.6,
            "bench",
        );
        let h = if i % 50 == 0 {
            0u64
        } else {
            (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        };
        e.add_evidence(Evidence::new("bench", "image").with_attr("phash", format!("{h:016x}")));
        out.push(e);
    }

    // Coordinates in two tight clusters (capped so colocation's O(k²) within a
    // cluster stays a bounded, representative cost rather than dominating).
    let coords = (n / 10).min(40);
    for i in 0..coords {
        let (base_lat, base_lon) = if i % 2 == 0 {
            (-27.47, 153.02)
        } else {
            (-33.87, 151.21)
        };
        let jitter = (i as f64) * 0.0001;
        out.push(Entity::new(
            EntityKind::Coordinates,
            format!("{:.6},{:.6}", base_lat + jitter, base_lon + jitter),
            0.8,
            "bench",
        ));
    }

    out
}
