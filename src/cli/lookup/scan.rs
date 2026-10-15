//! Scan routing and bounded batch orchestration.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    Refused, collect, domain_cmd, email_cmd, exposure_cmd, ip_cmd, network_cmd, people_cmd,
    phone_cmd, username_cmd,
};
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
            "usage: huntsman-recon scan SELECTOR [-k people|email|exposure|username|phone|domain|ip|network] [--save FILE] | scan --input-file FILE [-k KIND] [--save-dir DIR]",
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
    const RECURSE_USAGE: &str = "usage: huntsman-recon scan --recurse SELECTOR [SELECTOR ...] [--max-generations N] [--expand-floor F]";
    let mut seeds: Vec<String> = Vec::new();
    let mut max_generations: Option<u32> = None;
    let mut expand_floor: Option<f64> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--recurse" => index += 1,
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
    print_recursion(seeds.len(), &report);
    if report.accepted_seeds.is_empty() {
        return fail(EX_DATAERR, "no actionable seeds");
    }
    ExitCode::SUCCESS
}

/// Print the crawl result in full: no uid masking, no counts in place of values — the real linkage
/// map, as the tool exists to produce.
fn print_recursion(seed_count: usize, report: &RecursionReport) {
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

#[cfg(test)]
mod tests {
    use super::per_seed_save_path;

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
