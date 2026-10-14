//! Multi-hop analysis benchmark. Run with `cargo run --release --locked --example multihop_bench`.
//!
//! Three fixed workloads, each at a few sizes:
//! - `domain`: one domain and N addresses on it, the shape of a breach dump. Relation derivation
//!   ties every address to the domain, and the correlation rules then read the relations.
//! - `aliases`: one handle at N domains. Relation derivation makes every two addresses aliases,
//!   the densest identity cluster a scan produces.
//! - `graph`: N entities and 3N/2 random relations through the whole snapshot analysis: pivots,
//!   core numbers, metrics, gaps, intelligence and the correlation rules.
//!
//! Each line prints the relations derived, the median time over up to `RUNS` runs (fewer once a
//! workload has run for `BUDGET`), and a checksum of the result. The workloads are fixed, so a
//! changed checksum means a changed result. Sizes can be chosen per workload, as in
//! `multihop_bench domain=100,400 aliases=20 graph=2000`; a workload not named is skipped.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use huntsman_recon::analysis::analyze_snapshot;
use huntsman_recon::correlator::{Correlation, evaluate_rules};
use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use huntsman_recon::evidence_ancestry::EvidenceAncestryGraph;
use huntsman_recon::graph::{EntityRelation, RelationKind};
use huntsman_recon::pipeline::AnalysisSnapshot;
use huntsman_recon::relation::derive_all;

const RUNS: usize = 5;
const BUDGET: Duration = Duration::from_secs(30);
const SCAN: &str = "scan-bench";

/// An entity seen by two sources, so the rules treat it as corroborated.
fn entity(kind: EntityKind, value: String) -> Entity {
    let mut entity = Entity::new(kind, value, 0.9, SCAN);
    for source in ["dehashed", "hibp"] {
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan(source, SCAN),
            "row",
        ));
    }
    entity
}

fn domain_dump(size: usize) -> Vec<Entity> {
    let mut entities = vec![entity(EntityKind::Domain, "corp.example".into())];
    entities.extend((0..size).map(|n| entity(EntityKind::Email, format!("user{n}@corp.example"))));
    entities
}

fn one_handle(size: usize) -> Vec<Entity> {
    (0..size)
        .map(|n| entity(EntityKind::Email, format!("jsmith.alpha@site{n}.example")))
        .collect()
}

fn random_graph(size: usize) -> AnalysisSnapshot {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut draw = |bound: usize| -> usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % u64::try_from(bound).unwrap_or(1)).unwrap_or(0)
    };
    let entities = (0..size)
        .map(|n| match n % 4 {
            0 => entity(EntityKind::Email, format!("user{n}@mail{}.example", n % 7)),
            1 => entity(EntityKind::Username, format!("handle{n}")),
            2 => entity(EntityKind::Domain, format!("host{n}.example")),
            _ => entity(EntityKind::Url, format!("https://site{n}.example/p")),
        })
        .collect::<Vec<_>>();
    let relations = (0..size * 3 / 2)
        .map(|_| {
            EntityRelation::new(
                entities[draw(size)].uid.clone(),
                entities[draw(size)].uid.clone(),
                RelationKind::AssociatedWith,
                0.7,
            )
        })
        .collect();
    AnalysisSnapshot {
        entities,
        relations,
        coverage: Vec::new(),
        ancestry: EvidenceAncestryGraph::default(),
        truncated: false,
    }
}

/// FNV-1a over a sequence of strings, each followed by a separator.
fn fnv(parts: impl IntoIterator<Item = String>) -> u64 {
    parts.into_iter().fold(0xCBF2_9CE4_8422_2325, |acc, part| {
        part.bytes().chain([0]).fold(acc, |state, byte| {
            (state ^ u64::from(byte)).wrapping_mul(0x0100_0000_01B3)
        })
    })
}

/// A checksum of the correlations that ignores the order they come in and the order of the
/// uids within each, so that it compares runs that pair the same entities the other way round.
fn correlations_checksum(correlations: &[Correlation]) -> u64 {
    let mut lines = correlations
        .iter()
        .map(|correlation| {
            let mut uids = correlation.entity_uids.clone();
            uids.sort_unstable();
            format!(
                "{}|{}|{}",
                correlation.rule_id,
                correlation.description,
                uids.join(",")
            )
        })
        .collect::<Vec<_>>();
    lines.sort_unstable();
    fnv(lines)
}

fn by_rule(correlations: &[Correlation]) -> String {
    let mut counts = BTreeMap::<&str, usize>::new();
    for correlation in correlations {
        *counts.entry(correlation.rule_id.as_str()).or_default() += 1;
    }
    counts
        .iter()
        .map(|(rule, count)| format!("{rule}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Runs `work` up to `RUNS` times, or until `BUDGET` is spent, and prints the median time with
/// the checksum, which must not change from run to run.
fn measure(label: &str, size: usize, detail: &str, mut work: impl FnMut() -> (u64, String)) {
    let mut times = Vec::with_capacity(RUNS);
    let mut result = None;
    let started = Instant::now();
    while times.len() < RUNS && (times.is_empty() || started.elapsed() < BUDGET) {
        let run = Instant::now();
        let outcome = work();
        times.push(run.elapsed());
        if let Some(previous) = &result {
            assert_eq!(previous, &outcome, "{label} n={size} changed between runs");
        }
        result = Some(outcome);
    }
    times.sort_unstable();
    let (checksum, summary) = result.unwrap_or_default();
    println!(
        "{label}\tn={size}\t{detail}\tmedian_ms={:.1}\truns={}\tchecksum={checksum:016x}\t{summary}",
        times[times.len() / 2].as_secs_f64() * 1e3,
        times.len(),
    );
}

fn rules_over(label: &str, size: usize, entities: &[Entity]) {
    let relations = derive_all(entities, SCAN);
    let detail = format!("relations={}", relations.len());
    measure(label, size, &detail, || {
        let correlations = evaluate_rules(entities, &relations, SCAN);
        (correlations_checksum(&correlations), by_rule(&correlations))
    });
}

fn sizes(args: &[String], workload: &str, default: &[usize]) -> Vec<usize> {
    if args.is_empty() {
        return default.to_vec();
    }
    args.iter()
        .filter_map(|arg| arg.strip_prefix(workload)?.strip_prefix('='))
        .flat_map(|list| list.split(',').filter_map(|size| size.parse().ok()))
        .collect()
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    for size in sizes(&args, "domain", &[100, 400, 1000]) {
        rules_over("domain", size, &domain_dump(size));
    }
    for size in sizes(&args, "aliases", &[10, 20, 40]) {
        rules_over("aliases", size, &one_handle(size));
    }
    for size in sizes(&args, "graph", &[500, 2000, 5000]) {
        let snapshot = random_graph(size);
        let detail = format!("relations={}", snapshot.relations.len());
        measure("graph", size, &detail, || {
            let report = analyze_snapshot(&snapshot);
            let pivots = report.pivots.iter().map(|pivot| {
                format!(
                    "{}|{}|{}|{}",
                    pivot.uid,
                    pivot.reachable,
                    pivot.closeness.to_bits(),
                    pivot.articulation
                )
            });
            let metrics = serde_json::to_string(&report.metrics).unwrap_or_default();
            (
                fnv(pivots.chain([metrics])) ^ correlations_checksum(&report.correlations),
                format!(
                    "degeneracy={} pivots={}",
                    report.metrics.graph_degeneracy,
                    report.pivots.len()
                ),
            )
        });
    }
}
