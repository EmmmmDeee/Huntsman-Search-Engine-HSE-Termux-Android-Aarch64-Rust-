//! `graph`: binary adapter over `huntsman_pipeline::run_dns_graph`. Argument parsing, the
//! resolver egress check, the default store location and rendering live here; traversal,
//! collection and persistence belong to the engine crates.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use super::fail;
use huntsman_pipeline::{DnsGraphRequest, PipelineError, run_dns_graph};
use huntsman_recon::egress::is_public_ip;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::textnorm::escape_controls;

pub(super) const GRAPH_USAGE: &str =
    "graph DOMAIN... [--depth N] [--resolver IP[:PORT]] [--store FILE] [--allow-private]
Walk the DNS topology from domain seeds: forward A/AAAA resolution and reverse PTR resolution,
alternating to --depth hops (0-4, default 2). Every distinct domain and address is persisted to a
redb graph store (default $HOME/.huntsman/graph.redb; re-runs append observations) and printed as
KIND<TAB>VALUE<TAB>HOP<TAB>SOURCE, then one summary line. Only the resolver is contacted (default
1.1.1.1:53, UDP); a non-public resolver needs --allow-private. Exits 69 when collectors failed and
nothing beyond the seeds was discovered.";

const MAX_DEPTH: u8 = 4;
const DEFAULT_DEPTH: u8 = 2;
const DEFAULT_RESOLVER: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53);

#[derive(Debug, PartialEq, Eq)]
struct GraphArgs {
    seeds: Vec<String>,
    depth: u8,
    resolver: SocketAddr,
    store: Option<PathBuf>,
    allow_private: bool,
}

fn parse(args: &[String]) -> Result<GraphArgs, String> {
    let mut parsed = GraphArgs {
        seeds: Vec::new(),
        depth: DEFAULT_DEPTH,
        resolver: DEFAULT_RESOLVER,
        store: None,
        allow_private: false,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--depth" => {
                let value = it.next().ok_or("--depth needs a value")?;
                parsed.depth = value
                    .parse::<u8>()
                    .ok()
                    .filter(|d| *d <= MAX_DEPTH)
                    .ok_or_else(|| format!("--depth must be 0-{MAX_DEPTH}"))?;
            }
            "--resolver" => {
                let value = it.next().ok_or("--resolver needs a value")?;
                parsed.resolver = value
                    .parse::<SocketAddr>()
                    .or_else(|_| value.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
                    .map_err(|_| "--resolver must be an IP address or IP:PORT".to_owned())?;
            }
            "--store" => {
                let value = it.next().ok_or("--store needs a file")?;
                parsed.store = Some(PathBuf::from(value));
            }
            "--allow-private" => parsed.allow_private = true,
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
            seed => parsed.seeds.push(seed.to_owned()),
        }
    }
    if parsed.seeds.is_empty() {
        return Err("at least one DOMAIN is required".to_owned());
    }
    Ok(parsed)
}

/// `$HOME/.huntsman/graph.redb`, creating `~/.huntsman` with mode 700 if it is absent.
fn default_store() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or("HOME is not an absolute path; pass --store FILE")?;
    let dir = home.join(".huntsman");
    if !dir.is_dir() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    Ok(dir.join("graph.redb"))
}

pub(super) fn graph_cmd(args: &[String]) -> ExitCode {
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            return fail(
                EX_USAGE,
                &format!("graph: {message}\nusage: huntsman-recon {GRAPH_USAGE}"),
            );
        }
    };
    if !parsed.allow_private && !is_public_ip(parsed.resolver.ip()) {
        return fail(
            EX_NOPERM,
            &format!(
                "graph: resolver {} is not a public address; pass --allow-private to use it",
                parsed.resolver
            ),
        );
    }
    let store_path = match parsed.store {
        Some(path) => path,
        None => match default_store() {
            Ok(path) => path,
            Err(message) => return fail(EX_IOERR, &format!("graph: {message}")),
        },
    };
    let observed_at_utc = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let seed_count = parsed.seeds.len();
    let request = DnsGraphRequest {
        seeds: parsed.seeds,
        resolver: parsed.resolver,
        max_depth: parsed.depth,
        store_path,
        observed_at_utc,
    };

    let report = run_dns_graph(&request, |entity| {
        println!(
            "{}\t{}\t{}\t{}",
            entity.kind.type_tag(),
            escape_controls(&entity.kind.canonical_value()),
            entity.hop_depth,
            escape_controls(&entity.provenance.source_module),
        );
    });
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            let code = match &error {
                PipelineError::InvalidSeed { .. } => EX_DATAERR,
                PipelineError::Store(_) => EX_IOERR,
                PipelineError::Engine(_) | PipelineError::Runtime(_) => EX_UNAVAILABLE,
            };
            return fail(code, &format!("graph: {error}"));
        }
    };
    let execution = report.execution;
    println!(
        "summary\temitted={} persisted={} expanded={} collector_failures={} depth_limited={} no_consumer={} overflow_unexpanded={} store={}",
        execution.emitted,
        report.persisted,
        execution.expanded,
        execution.collector_failures,
        execution.depth_limited,
        execution.no_consumer,
        execution.overflow_unexpanded,
        escape_controls(&request.store_path.display().to_string()),
    );
    if execution.collector_failures > 0 && report.persisted <= seed_count {
        return fail(
            EX_UNAVAILABLE,
            &format!(
                "graph: {} collector invocation(s) failed and nothing beyond the seeds was discovered (resolver {})",
                execution.collector_failures, request.resolver
            ),
        );
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_RESOLVER, GraphArgs, parse};

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn defaults_and_flags_parse() {
        let parsed = parse(&args(&[
            "a.example",
            "--depth",
            "4",
            "--resolver",
            "9.9.9.9",
            "b.example",
        ]));
        assert_eq!(
            parsed,
            Ok(GraphArgs {
                seeds: vec!["a.example".into(), "b.example".into()],
                depth: 4,
                resolver: "9.9.9.9:53".parse().unwrap_or(DEFAULT_RESOLVER),
                store: None,
                allow_private: false,
            })
        );
        let with_port = parse(&args(&[
            "a.example",
            "--resolver",
            "127.0.0.1:5353",
            "--allow-private",
        ]));
        assert!(
            matches!(with_port, Ok(GraphArgs { allow_private: true, resolver, .. }) if resolver.port() == 5353)
        );
    }

    #[test]
    fn bad_arguments_are_refused() {
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["a.example", "--depth", "5"])).is_err());
        assert!(parse(&args(&["a.example", "--resolver", "dns.google"])).is_err());
        assert!(parse(&args(&["a.example", "--store"])).is_err());
        assert!(parse(&args(&["a.example", "--bogus"])).is_err());
    }
}
