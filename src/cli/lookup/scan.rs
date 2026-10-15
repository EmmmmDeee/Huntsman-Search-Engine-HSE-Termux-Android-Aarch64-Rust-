//! Scan routing and bounded batch orchestration.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

use crate::cli::{MAX_ARTIFACT_BYTES, fail};
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::scan_batch::parse_seed_list;
use huntsman_recon::scan_route::{
    ScanKind, canonical_selector, explicit_people_is_name, infer_kind, inferred_people_is_name,
    parse_kind,
};
use huntsman_recon::textnorm::escape_controls;

use super::profiles::{
    Refused, asn_cmd, collect, domain_cmd, email_cmd, exposure_cmd, ip_cmd, netblock_cmd,
    network_cmd, people_cmd, phone_cmd, username_cmd,
};
use huntsman_recon::analysis::{self, InvestigationReport};
use huntsman_recon::correlator::Correlation;
use huntsman_recon::pipeline::{self, PipelineLimits};
use huntsman_recon::recursion::{
    self, RecursionPolicy, RecursionReport, SelectorCollector, Step, Target,
};
use huntsman_recon::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub(in crate::cli) fn scan_cmd(args: &[String]) -> ExitCode {
    // --recurse is its own mode: it parses its own flags (--max-generations, --expand-floor) and
    // positional seeds, so detect it first rather than threading those flags through the single and
    // batch argument loop below.
    if args.iter().any(|arg| arg == "--recurse") {
        return recurse_scan(args);
    }

    let mut kind: Option<&str> = None;
    let mut input_file: Option<&str> = None;
    let mut save_dir: Option<&str> = None;
    let mut forwarded = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "-k" | "--kind" => {
                if kind.is_some() {
                    return fail(EX_USAGE, "scan accepts only one -k/--kind");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan -k/--kind needs a value");
                };
                kind = Some(value.as_str());
                index += 2;
            }
            "--input-file" => {
                if input_file.is_some() {
                    return fail(EX_USAGE, "scan accepts only one --input-file");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan --input-file needs a value");
                };
                if value.starts_with("--") {
                    return fail(EX_USAGE, "scan --input-file needs a file path");
                }
                input_file = Some(value.as_str());
                index += 2;
            }
            "--save-dir" => {
                if save_dir.is_some() {
                    return fail(EX_USAGE, "scan accepts only one --save-dir");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan --save-dir needs a value");
                };
                if value.starts_with("--") {
                    return fail(EX_USAGE, "scan --save-dir needs a directory path");
                }
                save_dir = Some(value.as_str());
                index += 2;
            }
            value => {
                forwarded.push(value.to_owned());
                index += 1;
            }
        }
    }

    if let Some(path) = input_file {
        if !forwarded.is_empty() {
            return fail(
                EX_USAGE,
                "scan --input-file does not accept a positional selector or --save; use --save-dir DIR to persist every seed",
            );
        }
        return scan_batch_file(path, kind, save_dir);
    }

    if save_dir.is_some() {
        return fail(
            EX_USAGE,
            "scan --save-dir applies only to --input-file batches; use --save FILE for a single selector",
        );
    }

    scan_one(&forwarded, kind)
}

fn scan_batch_file(path: &str, kind: Option<&str>, save_dir: Option<&str>) -> ExitCode {
    let bytes = match read_bounded(Path::new(path), MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(Error::Store(message)) => return fail(EX_NOINPUT, &message),
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    let Ok(body) = String::from_utf8(bytes) else {
        return fail(EX_DATAERR, "scan --input-file is not UTF-8");
    };
    let seeds = match parse_seed_list(&body) {
        Ok(seeds) => seeds,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };

    let total = seeds.len();
    eprintln!("batch: scanning {total} seed(s) from {path}");
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut first_failure = None;

    for (offset, seed) in seeds.iter().enumerate() {
        eprintln!("batch [{}/{}] {}", offset + 1, total, escape_controls(seed));
        // Each seed gets its own artifact path so concurrent persistence never
        // collides: a zero-padded 1-based index keeps names unique and ordered
        // even when two seeds sanitize to the same stem.
        let code = match save_dir {
            Some(dir) => {
                let target = per_seed_save_path(dir, offset + 1, seed);
                let forwarded = [
                    seed.clone(),
                    "--save".to_owned(),
                    target.to_string_lossy().into_owned(),
                ];
                scan_one(&forwarded, kind)
            }
            None => scan_one(std::slice::from_ref(seed), kind),
        };
        if code == ExitCode::SUCCESS {
            succeeded += 1;
        } else {
            failed += 1;
            first_failure.get_or_insert(code);
        }
    }

    eprintln!("batch complete: {succeeded} succeeded, {failed} failed, {total} total");
    first_failure.unwrap_or(ExitCode::SUCCESS)
}

/// The artifact path for the `index`-th seed (1-based) under `dir`.
///
/// The stem is `{index:04}-{sanitized}` so the ordinal alone guarantees a unique,
/// ordered name; the sanitized seed is a readability aid, never the uniqueness
/// guarantee. The seed is reduced to the session-id charset (ASCII alphanumeric
/// plus `.`, `_`, `-`), every other byte folded to `_`, and bounded to 60 bytes so
/// a long or adversarial seed cannot produce an unbounded or unsafe filename.
fn per_seed_save_path(dir: &str, index: usize, seed: &str) -> PathBuf {
    const MAX_STEM_BYTES: usize = 60;
    let mut stem = String::with_capacity(MAX_STEM_BYTES);
    for ch in seed.chars() {
        if stem.len() >= MAX_STEM_BYTES {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            stem.push(ch);
        } else {
            stem.push('_');
        }
    }
    let file = if stem.is_empty() {
        format!("{index:04}.json")
    } else {
        format!("{index:04}-{stem}.json")
    };
    Path::new(dir).join(file)
}

fn scan_one(forwarded: &[String], kind: Option<&str>) -> ExitCode {
    let Some(selector) = forwarded.first() else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon scan SELECTOR [-k people|email|exposure|username|phone|domain|ip|netblock|asn|network] [--save FILE] | scan --input-file FILE [-k KIND] [--save-dir DIR]",
        );
    };
    // A leading space must not hide an option from this check, or the selector would be judged
    // one name and the option passed on as part of it.
    if selector.trim_start().starts_with("--") {
        return fail(EX_USAGE, "scan needs SELECTOR before options");
    }

    let route = match kind {
        Some(value) => match parse_kind(value) {
            Ok(kind) => kind,
            Err(other) => return fail(EX_USAGE, &format!("unsupported scan kind: {other}")),
        },
        None => infer_kind(selector),
    };
    // A people route needs a name with two alphabetic tokens. The people command would skip one
    // and exit 0, which would report a refused lookup as a success, so the scan refuses it here.
    // An inferred route is a guess, so it is judged on the selector alone, as on main; an explicit
    // `-k people` is judged on the name it joins, as the people command reads it.
    if route == ScanKind::People {
        if kind.is_none() && !inferred_people_is_name(forwarded) {
            return fail(
                EX_DATAERR,
                "scan selector is not canonical: it is not a name, phone, email, or handle; pass -k people to look it up as a name",
            );
        }
        if kind.is_some() && !explicit_people_is_name(forwarded) {
            return fail(
                EX_DATAERR,
                "scan -k people needs a name: two alphabetic tokens, quoted or as separate words",
            );
        }
    }

    let Some(selector) = canonical_selector(route, selector) else {
        return fail(EX_DATAERR, "scan selector is not canonical");
    };
    let mut forwarded = forwarded.to_vec();
    forwarded[0] = selector;
    eprintln!("scan_route={}", route.command());
    match route {
        ScanKind::Email => email_cmd(&forwarded),
        ScanKind::Exposure => exposure_cmd(&forwarded),
        ScanKind::Username => username_cmd(&forwarded),
        ScanKind::Phone => phone_cmd(&forwarded),
        ScanKind::Domain => domain_cmd(&forwarded),
        ScanKind::Ip => ip_cmd(&forwarded),
        ScanKind::Netblock => netblock_cmd(&forwarded),
        ScanKind::Asn => asn_cmd(&forwarded),
        ScanKind::Network => network_cmd(&forwarded),
        ScanKind::People => people_cmd(&forwarded),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Live collector for `scan --recurse`: each target runs the real per-kind lookup through
/// `profiles::collect`, so the recursion fetches exactly what a single `scan` of that selector
/// would. A refused lookup becomes a recorded source outcome rather than a dropped dispatch, so
/// no source is silent and nothing is redacted on the way through.
struct LiveCollector;

impl SelectorCollector for LiveCollector {
    fn collect(&mut self, target: &Target) -> Step {
        match collect(target.kind, &target.selector) {
            Ok(collected) => Step {
                entities: collected.entities,
                outcomes: collected.outcomes,
            },
            Err(refused) => {
                let kind = match refused {
                    Refused::Network(_) => SourceOutcomeKind::ConnectFailure,
                    Refused::Unavailable(_) | Refused::Data(_) => SourceOutcomeKind::Inconclusive,
                };
                let outcome = SourceExecutionOutcome::failed(
                    target.kind.command(),
                    now_unix(),
                    kind,
                    None,
                    refused.message(),
                );
                Step {
                    entities: Vec::new(),
                    outcomes: vec![outcome],
                }
            }
        }
    }
}

/// `scan --recurse SELECTOR [SELECTOR ...]`: the bounded fetch → expand → fetch crawl. It parses its
/// own flags so the single and batch argument loop stays untouched. Each seed is routed by its
/// inferred kind, its identity-bearing findings are fed back as the next generation's seeds, and the
/// crawl stops at a fixed point or a shared bound. Output is the full, unredacted linkage: every
/// entity, every source outcome, the per-generation shape, and the stop reason.
fn recurse_scan(args: &[String]) -> ExitCode {
    const RECURSE_USAGE: &str = "usage: huntsman-recon scan --recurse SELECTOR [SELECTOR ...] [--max-generations N] [--expand-floor F] [--json]";
    let mut seeds: Vec<String> = Vec::new();
    let mut max_generations: Option<u32> = None;
    let mut expand_floor: Option<f64> = None;
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--recurse" => index += 1,
            "--json" => {
                json = true;
                index += 1;
            }
            "--max-generations" => {
                if max_generations.is_some() {
                    return fail(EX_USAGE, "scan accepts only one --max-generations");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan --max-generations needs a value");
                };
                let Ok(parsed) = value.parse::<u32>() else {
                    return fail(
                        EX_USAGE,
                        "scan --max-generations needs a non-negative integer",
                    );
                };
                max_generations = Some(parsed);
                index += 2;
            }
            "--expand-floor" => {
                if expand_floor.is_some() {
                    return fail(EX_USAGE, "scan accepts only one --expand-floor");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan --expand-floor needs a value");
                };
                let Ok(parsed) = value.parse::<f64>() else {
                    return fail(
                        EX_USAGE,
                        "scan --expand-floor needs a number between 0 and 1",
                    );
                };
                expand_floor = Some(parsed);
                index += 2;
            }
            "-k" | "--kind" => {
                return fail(
                    EX_USAGE,
                    "scan --recurse infers each seed's kind; drop -k/--kind",
                );
            }
            "--input-file" | "--save-dir" | "--save" => {
                return fail(
                    EX_USAGE,
                    "scan --recurse takes positional seeds only; --input-file, --save-dir, and --save are not supported with it",
                );
            }
            other if other.starts_with("--") => {
                return fail(EX_USAGE, &format!("scan --recurse: unknown option {other}"));
            }
            value => {
                seeds.push(value.to_owned());
                index += 1;
            }
        }
    }
    if seeds.is_empty() {
        return fail(EX_USAGE, RECURSE_USAGE);
    }
    let mut policy = RecursionPolicy::default();
    if let Some(generations) = max_generations {
        policy.max_generations = generations;
    }
    if let Some(floor) = expand_floor {
        if !(0.0..=1.0).contains(&floor) {
            return fail(EX_DATAERR, "scan --expand-floor must be between 0 and 1");
        }
        policy.expand_confidence_floor = floor;
    }
    let mut collector = LiveCollector;
    let report = recursion::run(&seeds, &policy, &mut collector);
    // Analyse everything the crawl reached with the shared spine once, and hand the result to
    // whichever renderer runs: the text and JSON outputs show the same analysis, never a different
    // one.
    let analysis = recursion_analysis(&report);
    if json {
        let view = recursion_json(seeds.len(), &report, &analysis);
        match serde_json::to_string_pretty(&view) {
            Ok(body) => println!("{body}"),
            Err(error) => return fail(EX_DATAERR, &format!("json: {error}")),
        }
    } else {
        print_recursion(seeds.len(), &report, &analysis);
    }
    if report.accepted_seeds.is_empty() {
        return fail(EX_DATAERR, "no actionable seeds");
    }
    ExitCode::SUCCESS
}

/// A machine-readable view of the whole crawl result: the same linkage, lineage, analysis and
/// source outcomes the text output carries, as one JSON object a downstream consumer can parse. A
/// seed's kind is its stable command word (not the internal variant name), matching the text
/// output; nothing is summarised or redacted away. `metrics`, `gaps` and `pivots` are the shared
/// analysis spine's by-kind summary, capability gaps and graph-pivot ranking over everything
/// reached. Borrows the report and its analysis, so building it is free.
#[derive(Serialize)]
struct RecursionJson<'a> {
    seeds: usize,
    accepted: Vec<SeedJson<'a>>,
    rejected: &'a [String],
    generations: &'a [huntsman_recon::recursion::GenerationStat],
    entities: &'a [huntsman_recon::entity::Entity],
    lineage: &'a [huntsman_recon::recursion::PivotEdge],
    correlations: &'a [Correlation],
    metrics: &'a huntsman_recon::metrics::ScanMetrics,
    gaps: &'a huntsman_recon::gap::GapReport,
    pivots: &'a [huntsman_recon::pivot::PivotScore],
    outcomes: &'a [SourceExecutionOutcome],
    dispatches: usize,
    visited: usize,
    termination: huntsman_recon::termination::TerminationReason,
    truncated: bool,
}

/// One accepted seed in the JSON view: the lookup kind as its command word and the canonical selector.
#[derive(Serialize)]
struct SeedJson<'a> {
    kind: &'a str,
    selector: &'a str,
}

/// Assemble the JSON view from the finished report and the analysis computed over it.
fn recursion_json<'a>(
    seed_count: usize,
    report: &'a RecursionReport,
    analysis: &'a InvestigationReport,
) -> RecursionJson<'a> {
    RecursionJson {
        seeds: seed_count,
        accepted: report
            .accepted_seeds
            .iter()
            .map(|target| SeedJson {
                kind: target.kind.command(),
                selector: &target.selector,
            })
            .collect(),
        rejected: &report.rejected_seeds,
        generations: &report.generations,
        entities: &report.entities,
        lineage: &report.edges,
        correlations: &analysis.correlations,
        metrics: &analysis.metrics,
        gaps: &analysis.gaps,
        pivots: &analysis.pivots,
        outcomes: &report.outcomes,
        dispatches: report.dispatches,
        visited: report.visited,
        termination: report.termination,
        truncated: report.truncated,
    }
}

/// Analyse everything the crawl reached with the shared analysis spine — the exact
/// [`analyze_snapshot`](analysis::analyze_snapshot) report `plan`, `serve` and `correlate` produce
/// — reused, not reinvented, so the recursive crawl surfaces the same cross-entity correlations
/// (shared identities, reused breach secrets, co-located hosts, …), by-kind summary, capability
/// gaps and graph-pivot ranking the way `SpiderFoot` does over a whole scan, rather than a bespoke
/// subset. The crawl engine yields merged entities directly, so the snapshot is reconstructed from
/// them with the relations they imply ([`pipeline::snapshot_from_entities`]); the scan id mirrors
/// the spine's own fallback. Nothing is redacted: analysis is additive over the already-collected
/// entities, never a filter on them.
fn recursion_analysis(report: &RecursionReport) -> InvestigationReport {
    let scan_id = report
        .entities
        .first()
        .map_or("recurse", |entity| entity.scan_id.as_str());
    let snapshot =
        pipeline::snapshot_from_entities(&report.entities, scan_id, &PipelineLimits::default());
    analysis::analyze_snapshot(&snapshot)
}

/// Print the crawl result in full: no uid masking, no counts in place of values — the real linkage
/// map, as the tool exists to produce. The analysis is computed once by the caller and shared with
/// the JSON renderer, so both outputs show the same report.
fn print_recursion(seed_count: usize, report: &RecursionReport, analysis: &InvestigationReport) {
    println!(
        "recurse seeds={seed_count} accepted={} rejected={}",
        report.accepted_seeds.len(),
        report.rejected_seeds.len()
    );
    for seed in &report.rejected_seeds {
        println!("rejected\t{}", escape_controls(seed));
    }
    for stat in &report.generations {
        println!(
            "generation={} dispatched={} entities={}",
            stat.generation, stat.dispatched, stat.entities_after
        );
    }
    println!("entities={}", report.entities.len());
    let mut entities: Vec<&huntsman_recon::entity::Entity> = report.entities.iter().collect();
    entities.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.value.cmp(&right.value))
    });
    for entity in entities {
        println!(
            "{}\t{}\t{:.2}\tgen={}\t{}",
            entity.kind.as_str(),
            escape_controls(&entity.value),
            entity.confidence,
            entity.generation,
            entity.tags.join(",")
        );
    }
    println!("lineage={}", report.edges.len());
    for edge in &report.edges {
        println!(
            "{}:{}\t->\t{}:{}\tgen={}",
            escape_controls(&edge.from_kind),
            escape_controls(&edge.from_selector),
            edge.to_kind,
            escape_controls(&edge.to_value),
            edge.generation
        );
    }
    print_recursion_analysis(&report.entities, analysis);
    println!("outcomes={}", report.outcomes.len());
    for outcome in &report.outcomes {
        let found = outcome
            .found
            .map_or_else(|| "-".to_owned(), |count| count.to_string());
        let detail = outcome.detail.as_deref().unwrap_or("");
        println!(
            "{}\t{:?}\tfound={found}\t{}",
            escape_controls(&outcome.module),
            outcome.kind,
            escape_controls(detail)
        );
    }
    println!(
        "dispatches={} visited={} generations={} termination={:?} truncated={}",
        report.dispatches,
        report.visited,
        report.generations.len(),
        report.termination,
        report.truncated
    );
}

/// Print the shared analysis spine's report over everything the crawl reached: the correlation
/// findings (each citing the real kind:value of every entity it links), the by-kind element and
/// relation summary `SpiderFoot` leads a scan with, the capability gaps (which seeds nothing linked
/// to), and the graph-pivot ranking (which discovered entity is the linkage linchpin). Every value
/// in full — no uid masking, no counts in place of values, nothing summarised away.
fn print_recursion_analysis(
    entities: &[huntsman_recon::entity::Entity],
    analysis: &InvestigationReport,
) {
    let by_uid: std::collections::HashMap<&str, &huntsman_recon::entity::Entity> = entities
        .iter()
        .map(|entity| (entity.uid.as_str(), entity))
        .collect();
    let label = |uid: &str| -> String {
        by_uid.get(uid).map_or_else(
            || escape_controls(uid),
            |entity| {
                format!(
                    "{}:{}",
                    entity.kind.as_str(),
                    escape_controls(&entity.value)
                )
            },
        )
    };
    println!("correlations={}", analysis.correlations.len());
    for correlation in &analysis.correlations {
        println!(
            "rule={} ({}) severity={:?} rank={:.2}\t{}",
            escape_controls(&correlation.rule_id),
            escape_controls(&correlation.rule_name),
            correlation.severity,
            correlation.rank,
            escape_controls(&correlation.description)
        );
        // Resolve every uid the correlation cites back to its real kind and value, so the finding
        // names the entities it links, not opaque ids.
        for uid in &correlation.entity_uids {
            println!("\t{}", label(uid));
        }
    }
    let metrics = &analysis.metrics;
    println!(
        "summary entities={} relations={} linked_fraction={:.2} sources={}",
        metrics.total_entities,
        metrics.total_relations,
        metrics.linked_entity_fraction,
        metrics.distinct_evidence_sources
    );
    for (kind, count) in &metrics.entities_by_kind {
        println!("kind\t{}\t{count}", escape_controls(kind));
    }
    for (kind, count) in &metrics.relations_by_kind {
        println!("relation\t{}\t{count}", escape_controls(kind));
    }
    let gaps = &analysis.gaps;
    println!(
        "gaps seeds={} linked={} isolated={} linked_fraction={:.2}",
        gaps.total_seeds, gaps.linked_seeds, gaps.isolated_seeds, gaps.linked_fraction
    );
    for orphan in &gaps.orphans {
        println!(
            "orphan\t{}:{}\t{}",
            escape_controls(&orphan.kind),
            escape_controls(&orphan.value),
            orphan.action
        );
    }
    println!("pivots={}", analysis.pivots.len());
    for pivot in &analysis.pivots {
        println!(
            "pivot\t{}\tdegree={} reachable={} closeness={:.2} articulation={}",
            label(&pivot.uid),
            pivot.degree,
            pivot.reachable,
            pivot.closeness,
            pivot.articulation
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{per_seed_save_path, recursion_analysis, recursion_json};
    use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use huntsman_recon::recursion::{RecursionReport, Target};
    use huntsman_recon::scan_route::ScanKind;
    use huntsman_recon::termination::TerminationReason;

    /// A report carrying only the entities a crawl would have reached, for driving the correlation
    /// wiring offline with no collector and no network.
    fn report_of(entities: Vec<Entity>) -> RecursionReport {
        RecursionReport {
            accepted_seeds: Vec::new(),
            rejected_seeds: Vec::new(),
            entities,
            edges: Vec::new(),
            outcomes: Vec::new(),
            generations: Vec::new(),
            dispatches: 0,
            visited: 0,
            termination: TerminationReason::FixedPoint,
            truncated: false,
        }
    }

    #[test]
    fn the_crawl_surfaces_the_shared_identity_cluster_correlation() {
        // An e-mail and a username reached by the crawl are one identity across two kinds. A flat
        // entity list leaves that linkage implicit; the recursion output must run the shared
        // correlation engine and surface it as the identity-cluster finding (AU-002), the way
        // SpiderFoot correlates a whole scan rather than listing disjoint findings.
        let report = report_of(vec![
            Entity::new(EntityKind::Email, "person@example.com", 0.9, "recurse"),
            Entity::new(EntityKind::Username, "person", 0.9, "recurse"),
        ]);
        let correlations = recursion_analysis(&report).correlations;
        assert!(
            correlations
                .iter()
                .any(|correlation| correlation.rule_id == "AU-002"),
            "the crawl did not surface the identity-cluster correlation: {correlations:?}"
        );
        // Every cited uid resolves to an entity actually in the report: the finding names real
        // entities, never an id the output cannot explain.
        let uids: std::collections::HashSet<&str> =
            report.entities.iter().map(|e| e.uid.as_str()).collect();
        for correlation in &correlations {
            for uid in &correlation.entity_uids {
                assert!(
                    uids.contains(uid.as_str()),
                    "correlation cited an entity not in the crawl: {uid}"
                );
            }
        }
    }

    #[test]
    fn a_crawl_with_no_cross_entity_pattern_surfaces_no_correlation() {
        // A single lone entity has nothing to correlate with: the engine must report an empty set,
        // not invent a finding.
        let report = report_of(vec![Entity::new(
            EntityKind::Email,
            "person@example.com",
            0.9,
            "recurse",
        )]);
        assert!(
            recursion_analysis(&report).correlations.is_empty(),
            "a lone entity should produce no correlation"
        );
    }

    #[test]
    fn the_json_view_carries_the_whole_crawl_result() {
        // The JSON output is the same analysis as the text output, machine-readable: it must carry
        // the entities, the accepted seeds (kind as the command word), the termination reason and
        // the correlations — not a reduced or redacted shape a consumer cannot act on.
        let mut report = report_of(vec![
            Entity::new(EntityKind::Email, "person@example.com", 0.9, "recurse"),
            Entity::new(EntityKind::Username, "person", 0.9, "recurse"),
        ]);
        report.accepted_seeds = vec![Target {
            kind: ScanKind::Email,
            selector: "person@example.com".to_owned(),
        }];
        let analysis = recursion_analysis(&report);
        let view = recursion_json(1, &report, &analysis);
        let value = serde_json::to_value(&view).expect("the view serialises");

        assert_eq!(value["seeds"], 1);
        assert_eq!(
            value["entities"].as_array().expect("entities array").len(),
            2
        );
        // The seed's kind is its stable command word, matching the text output, not the internal
        // enum variant name.
        assert_eq!(value["accepted"][0]["kind"], "email");
        assert_eq!(value["accepted"][0]["selector"], "person@example.com");
        // TerminationReason serialises in its snake_case contract form.
        assert_eq!(value["termination"], "fixed_point");
        // The correlations travel in the JSON too: the machine output is not a reduced one.
        let rules: Vec<&str> = value["correlations"]
            .as_array()
            .expect("correlations array")
            .iter()
            .filter_map(|correlation| correlation["rule_id"].as_str())
            .collect();
        assert!(
            rules.contains(&"AU-002"),
            "the json view dropped the identity-cluster correlation: {value}"
        );
        // The shared-spine analysis travels too: the by-kind summary, the capability gaps, and the
        // pivot ranking are all present as structured objects, one pivot per entity.
        assert_eq!(value["metrics"]["total_entities"], 2);
        assert!(value["gaps"].is_object(), "the json view dropped the gaps");
        assert_eq!(
            value["pivots"].as_array().expect("pivots array").len(),
            2,
            "a pivot score per entity should travel in the json: {value}"
        );
    }

    /// Builds a confirmed domain entity carrying the `ip` attribute that implies a hosting relation.
    fn hosted_on(domain: &str, ip: &str) -> Entity {
        let mut entity = Entity::new(EntityKind::Domain, domain, 0.9, "recurse");
        entity.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("dns", "recurse"), "A record")
                .with_attr("ip", ip),
        );
        entity
    }

    #[test]
    fn the_crawl_analysis_derives_the_graph_relations_its_entities_imply() {
        // Two domains the crawl reached resolve to one address: a hosting link the flat entity list
        // leaves implicit. Before, the recurse output ran only the correlation rules and surfaced no
        // graph metrics at all; now it runs the shared `analyze_snapshot` spine, so the derived
        // relations reach the metrics, gap and pivot analysis — the shared address shows up as a
        // relation and as a graph hub, not an edgeless list.
        let report = report_of(vec![
            hosted_on("alpha.example", "192.0.2.10"),
            hosted_on("beta.example", "192.0.2.10"),
            Entity::new(EntityKind::IpAddress, "192.0.2.10", 0.9, "recurse"),
        ]);
        let analysis = recursion_analysis(&report);
        assert!(
            analysis.metrics.total_relations >= 1,
            "the derived hosting relation never reached the metrics: {:?}",
            analysis.metrics
        );
        assert_eq!(
            analysis.metrics.total_entities, 3,
            "the by-kind summary must count every reached entity",
        );
        assert!(
            analysis.pivots.iter().any(|pivot| pivot.degree > 0),
            "no discovered entity became a graph pivot: {:?}",
            analysis.pivots
        );
        // The co-located-hosting correlation only fires when the relations the entities imply are
        // part of the analysis — proof the crawl now runs the full spine, not a correlation-only
        // subset.
        assert!(
            analysis
                .correlations
                .iter()
                .any(|correlation| correlation.rule_id == "AU-110"),
            "the shared-hosting correlation did not fire: {:?}",
            analysis.correlations
        );
    }

    #[test]
    fn index_prefix_is_zero_padded_and_keeps_a_safe_stem() {
        assert_eq!(
            per_seed_save_path("out", 1, "alice@example.org"),
            std::path::Path::new("out/0001-alice_example.org.json")
        );
        assert_eq!(
            per_seed_save_path("out", 42, "Bob.Jones"),
            std::path::Path::new("out/0042-Bob.Jones.json")
        );
    }

    #[test]
    fn separators_and_control_bytes_cannot_escape_the_directory() {
        let path = per_seed_save_path("out", 7, "../../etc/passwd");
        assert_eq!(path, std::path::Path::new("out/0007-.._.._etc_passwd.json"));
        // No real parent-directory component survives sanitization.
        assert!(
            !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        );
    }

    #[test]
    fn distinct_seeds_that_sanitize_alike_still_get_distinct_paths() {
        let a = per_seed_save_path("out", 1, "a/b");
        let b = per_seed_save_path("out", 2, "a b");
        assert_ne!(a, b);
        assert_eq!(a, std::path::Path::new("out/0001-a_b.json"));
        assert_eq!(b, std::path::Path::new("out/0002-a_b.json"));
    }

    #[test]
    fn an_empty_or_fully_stripped_seed_falls_back_to_the_index() {
        assert_eq!(
            per_seed_save_path("out", 3, ""),
            std::path::Path::new("out/0003.json")
        );
    }

    #[test]
    fn a_long_seed_is_bounded_to_sixty_stem_bytes() {
        let seed = "x".repeat(500);
        let path = per_seed_save_path("out", 9, &seed);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 name");
        // "0009-" (5) + 60 stem + ".json" (5) = 70.
        assert_eq!(name, format!("0009-{}.json", "x".repeat(60)));
        assert_eq!(name.len(), 70);
    }
}
