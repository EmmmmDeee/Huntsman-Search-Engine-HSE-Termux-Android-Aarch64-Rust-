//! Architecture audit — inventory the module graph and surface consolidation
//! and correctness risks **from the running binary**, not from reading
//! source.
//!
//! ## Why the binary and not the source
//!
//! `CLAUDE.md` makes the running software the source of truth for the module
//! and CLI reference, because a static doc drifts. The same argument applies
//! with more force to an architectural inventory: what matters is the graph
//! the *registry* actually exposes at runtime, which is what dispatch walks.
//! A grep over `src/modules` sees files; this sees the system.
//!
//! Inputs, in order of preference:
//!
//! * a live `hse serve` endpoint (`--base-url`), or
//! * a previously captured `modules.json` / `graph.json` pair (`--from-dir`),
//!   so the audit is reproducible in CI without binding a port.
//!
//! ## What it reports
//!
//! The capability graph is bipartite: modules produce and consume *entity
//! kinds*, and dispatch connects a producer to every consumer of the kinds
//! it emits. The findings below are all properties of that graph, and each
//! names a concrete architectural risk rather than a style preference:
//!
//! `orphan_kinds`
//! : Produced by some module, consumed by none. Every entity of that kind is
//!   a leaf: work is spent deriving a fact that can never be pivoted on.
//!   Either a consumer is missing or the production is dead weight.
//!
//! `ungrounded_kinds`
//! : Consumed by some module, produced by none. Those consumers can only
//!   ever be reached from an operator-supplied seed; on any derived path
//!   they are unreachable. Expected for true seed kinds, a defect otherwise.
//!
//! `sole_producers`
//! : A kind produced by exactly one module. That module is a single point of
//!   failure for every consumer downstream of the kind — a reliability
//!   property invisible from any one file.
//!
//! `duplicate_capabilities`
//! : Modules with an identical (accepts, produces, category) signature. The
//!   strongest consolidation signal the graph can give: two components
//!   claiming the same contract. Not automatically a defect (independent
//!   corroboration is deliberate in an OSINT tool) but always a question
//!   worth an answer.
//!
//! `fanout_hotspots`
//! : Modules whose output reaches an outsized share of the graph. These are
//!   the highest-blast-radius components: the places where a correctness
//!   bug propagates furthest, and so the places to spend review budget.
//!
//! Exit status: 0 on a normal report (regardless of findings), 1 if the
//! graph predates the `pivots_to` field (see [`build`]), 2 if the module
//! graph could not be loaded at all.
//!
//! ## Note on JSON object key order
//!
//! `--json` output orders map-shaped fields (`inventory`, `orphan_kinds`,
//! `ungrounded_kinds`, `sole_producers`, `duplicate_capabilities`)
//! alphabetically by key. That matches the original Python for every field
//! except `duplicate_capabilities`, which Python left in edges-encounter
//! order — a deliberate, scoped trade-off (see the equivalent note in
//! `src/bin/merge_state/main.rs`) rather than a functional difference: no
//! consumer of this report depends on JSON object key order.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use serde::Serialize;
use serde_json::Value;

/// Kinds an operator can legitimately supply as a scan seed. A consumer of
/// one of these is reachable even though nothing derives it, so they are
/// excluded from `ungrounded_kinds`. Sourced from the CLI's accepted seed
/// types.
const SEED_KINDS: &[&str] = &[
    "email",
    "username",
    "phone",
    "full_name",
    "domain",
    "ip_address",
    "url",
    "coordinates",
    "mac_address",
    "organisation",
    "address",
    "asn",
    "cidr",
    "crypto_address",
    "abn_acn",
    "api_key",
    "device_id",
    "ssid",
    "tracking_id",
];

#[derive(Parser)]
#[command(
    name = "architecture-audit",
    about = "Audit the live module capability graph"
)]
struct Args {
    /// Live `hse serve` base URL.
    #[arg(long)]
    base_url: Option<String>,
    /// Directory containing a captured `modules.json` + `graph.json` pair.
    #[arg(long)]
    from_dir: Option<PathBuf>,
    /// Emit the raw report as JSON instead of the human-readable text form.
    #[arg(long)]
    json: bool,
    /// Write the report to this path too.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    let (modules, graph) = match load(&args).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("architecture_audit: could not load the module graph: {e}");
            eprintln!("  start one with: hse serve --bind 127.0.0.1:8080");
            return ExitCode::from(2);
        }
    };
    let rep = match audit(&modules, &graph) {
        Ok(rep) => rep,
        Err(e) => {
            eprintln!("architecture_audit: {e}");
            return ExitCode::from(1);
        }
    };

    let text = if args.json {
        match serde_json::to_string_pretty(&rep) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("architecture_audit: serialising report: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        render(&rep)
    };
    println!("{text}");
    if let Some(out) = &args.out
        && let Err(e) = std::fs::write(out, format!("{text}\n"))
    {
        eprintln!("architecture_audit: writing {}: {e}", out.display());
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Return `(modules, graph)` from a live server or a captured directory.
async fn load(args: &Args) -> Result<(Vec<Value>, Value), String> {
    let (modules_raw, graph) = if let Some(dir) = &args.from_dir {
        (
            read_json(&dir.join("modules.json"))?,
            read_json(&dir.join("graph.json"))?,
        )
    } else {
        let base = args.base_url.as_deref().unwrap_or("http://127.0.0.1:8080");
        let base = base.trim_end_matches('/');
        let client = no_proxy_client()?;
        let modules = fetch_json(&client, &format!("{base}/api/v1/modules")).await?;
        let graph = fetch_json(&client, &format!("{base}/api/v1/modules/graph")).await?;
        (modules, graph)
    };
    // A `{"modules": [...]}` envelope unwraps; a bare array passes through.
    let modules = match modules_raw {
        Value::Object(mut map) => map.remove("modules").unwrap_or(Value::Array(Vec::new())),
        other => other,
    };
    let modules = modules
        .as_array()
        .cloned()
        .ok_or_else(|| "the modules response is not a JSON array".to_string())?;
    Ok((modules, graph))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

/// A client with the proxy explicitly disabled — mirrors the Python
/// original's `urllib.request.ProxyHandler({})`. The target is loopback by
/// default, and a configured `HTTPS_PROXY` would otherwise swallow this
/// request. Always fetches a caller-supplied `--base-url`, never
/// attacker-controlled input, so — unlike HSE's SSRF-hardened
/// `util::http::build_client` — there is no need for the shared SSRF-safe
/// resolver here, only the proxy bypass.
fn no_proxy_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("{url}: {e}"))?;
    resp.json::<Value>()
        .await
        .map_err(|e| format!("{url}: {e}"))
}

#[derive(Debug)]
struct Index {
    produced_by: BTreeMap<String, BTreeSet<String>>,
    consumed_by: BTreeMap<String, BTreeSet<String>>,
}

/// Index the bipartite module/kind graph into the lookups the findings need.
///
/// Producers are indexed by `pivots_to` — the emitted kinds already mapped
/// into the *dispatch* vocabulary — never by `produces`. The two fields use
/// different enums (`EntityKind` vs `TargetKind`) that agree on nearly every
/// spelling, so joining on `produces` looks correct and silently drops
/// `person`/`full_name`: dozens of modules, reported as feeding nothing.
/// This audit made exactly that mistake on its first run (as a Python
/// script; the lesson carries over unchanged to this port).
fn build(edges: &[Value]) -> Result<Index, String> {
    let mut produced_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut consumed_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for e in edges {
        let name = module_name(e)?;
        let pivots_to = e.get("pivots_to").ok_or_else(|| {
            "this graph predates `pivots_to`. Joining on `produces` crosses two vocabularies \
             and undercounts edges — refusing to emit a knowingly wrong graph. Rebuild `hse` \
             first."
                .to_string()
        })?;
        for k in string_list(pivots_to, "pivots_to")? {
            produced_by.entry(k).or_default().insert(name.to_string());
        }
        if let Some(consumes) = e.get("consumes") {
            for k in string_list(consumes, "consumes")? {
                consumed_by.entry(k).or_default().insert(name.to_string());
            }
        }
    }
    Ok(Index {
        produced_by,
        consumed_by,
    })
}

/// Modules reachable from `start` by following produced kinds to consumers.
///
/// This is the real blast radius of a module: dispatch hands each produced
/// entity to every consumer of that kind, transitively, until the depth
/// limit. Cycles are common and terminate naturally via the visited set.
fn reachable_modules(start: &str, by_name: &HashMap<&str, &Value>, idx: &Index) -> HashSet<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut frontier: Vec<String> = vec![start.to_string()];
    while let Some(cur) = frontier.pop() {
        let Some(kinds) = by_name
            .get(cur.as_str())
            .and_then(|e| e.get("pivots_to"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for kind in kinds.iter().filter_map(Value::as_str) {
            let Some(consumers) = idx.consumed_by.get(kind) else {
                continue;
            };
            for consumer in consumers {
                if consumer != start && !seen.contains(consumer) {
                    seen.insert(consumer.clone());
                    frontier.push(consumer.clone());
                }
            }
        }
    }
    seen
}

#[derive(Serialize)]
struct FanoutEntry {
    module: String,
    reaches: usize,
    pct: i64,
}

#[derive(Serialize)]
struct Report {
    module_count: usize,
    terminal_kinds: Vec<String>,
    kind_count: usize,
    inventory: BTreeMap<String, i64>,
    orphan_kinds: BTreeMap<String, Vec<String>>,
    ungrounded_kinds: BTreeMap<String, Vec<String>>,
    sole_producer_count: usize,
    sole_producers: BTreeMap<String, String>,
    duplicate_capabilities: BTreeMap<String, Vec<String>>,
    fanout_hotspots: Vec<FanoutEntry>,
}

fn audit(modules: &[Value], graph: &Value) -> Result<Report, String> {
    let edges: Vec<Value> = graph
        .get("edges")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Terminal kinds are excluded from `orphan_kinds`: they have no
    // TargetKind by design, so "consumed by nobody" is their definition, not
    // a defect.
    let terminal: BTreeSet<String> = graph
        .get("terminal_kinds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let idx = build(&edges)?;
    let by_name: HashMap<&str, &Value> = edges
        .iter()
        .map(|e| module_name(e).map(|n| (n, e)))
        .collect::<Result<_, _>>()?;

    let orphan_kinds: BTreeMap<String, Vec<String>> = idx
        .produced_by
        .iter()
        .filter(|(k, _)| !idx.consumed_by.contains_key(*k) && !terminal.contains(*k))
        .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
        .collect();
    let ungrounded_kinds: BTreeMap<String, Vec<String>> = idx
        .consumed_by
        .iter()
        .filter(|(k, _)| !idx.produced_by.contains_key(*k) && !SEED_KINDS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
        .collect();
    let sole_producers: BTreeMap<String, String> = idx
        .produced_by
        .iter()
        .filter(|(_, v)| v.len() == 1)
        .map(|(k, v)| {
            (
                k.clone(),
                v.iter().next().expect("len() == 1 checked above").clone(),
            )
        })
        .collect();

    // Identical contracts: the strongest consolidation signal available
    // here. Grouped by `(category, sorted consumes, sorted pivots_to)`.
    let mut sig: BTreeMap<(String, Vec<String>, Vec<String>), Vec<String>> = BTreeMap::new();
    for e in &edges {
        let name = module_name(e)?;
        let category = py_display(e.get("category"));
        let mut consumes = lenient_string_list(e.get("consumes"));
        consumes.sort();
        let mut produces = lenient_string_list(e.get("pivots_to"));
        produces.sort();
        sig.entry((category, consumes, produces))
            .or_default()
            .push(name.to_string());
    }
    let duplicate_capabilities: BTreeMap<String, Vec<String>> = sig
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|((category, consumes, produces), mut v)| {
            v.sort();
            let consumes_s = if consumes.is_empty() {
                "-".to_string()
            } else {
                consumes.join(",")
            };
            let produces_s = if produces.is_empty() {
                "-".to_string()
            } else {
                produces.join(",")
            };
            (format!("{category}: {consumes_s} -> {produces_s}"), v)
        })
        .collect();

    let total = edges.len();
    let mut blast: Vec<(String, usize)> = Vec::with_capacity(edges.len());
    for e in &edges {
        let name = module_name(e)?;
        blast.push((
            name.to_string(),
            reachable_modules(name, &by_name, &idx).len(),
        ));
    }
    // Stable sort: ties preserve `edges`' original order, matching Python's
    // `sorted()` (also stable) over the same encounter order.
    blast.sort_by_key(|(_, reach)| std::cmp::Reverse(*reach));
    let fanout_hotspots: Vec<FanoutEntry> = blast
        .into_iter()
        .take(12)
        .map(|(module, reaches)| {
            // `round_ties_even`, not `round`: Python's `round()` uses
            // round-half-to-even, which Rust's plain `f64::round()` does
            // NOT (it rounds half away from zero) — they disagree on an
            // exact `.5` percentage, which integer reach/total ratios reach
            // often enough on a ~170-module graph to matter.
            let pct = (100.0 * reaches as f64 / (total.max(1) as f64)).round_ties_even() as i64;
            FanoutEntry {
                module,
                reaches,
                pct,
            }
        })
        .collect();

    let mut inventory: BTreeMap<String, i64> = BTreeMap::new();
    for m in modules {
        *inventory
            .entry(format!("category:{}", py_display(m.get("category"))))
            .or_insert(0) += 1;
        *inventory
            .entry(format!("cost:{}", py_display(m.get("cost"))))
            .or_insert(0) += 1;
        if is_truthy(m.get("passive")) {
            *inventory.entry("passive".to_string()).or_insert(0) += 1;
        }
    }

    Ok(Report {
        module_count: total,
        terminal_kinds: terminal.into_iter().collect(),
        kind_count: idx
            .produced_by
            .keys()
            .chain(idx.consumed_by.keys())
            .collect::<BTreeSet<_>>()
            .len(),
        inventory,
        sole_producer_count: sole_producers.len(),
        orphan_kinds,
        ungrounded_kinds,
        sole_producers,
        duplicate_capabilities,
        fanout_hotspots,
    })
}

fn render(rep: &Report) -> String {
    let mut out: Vec<String> = vec![
        "HSE architecture audit".to_string(),
        "=".repeat(60),
        format!(
            "modules: {}   entity kinds in graph: {}",
            rep.module_count, rep.kind_count
        ),
        {
            let joined = rep.terminal_kinds.join(", ");
            format!(
                "terminal kinds (no TargetKind, always a leaf): {}",
                if joined.is_empty() { "none" } else { &joined }
            )
        },
        String::new(),
        "inventory:".to_string(),
    ];
    out.extend(rep.inventory.iter().map(|(k, v)| format!("  {k:<24} {v}")));

    out.push(String::new());
    out.push(format!(
        "orphan kinds (produced, never consumed): {}",
        rep.orphan_kinds.len()
    ));
    out.extend(
        rep.orphan_kinds
            .iter()
            .map(|(k, v)| format!("  {k:<18} produced by: {}", v.join(", "))),
    );

    out.push(String::new());
    out.push(format!(
        "ungrounded kinds (consumed, never produced, not a seed): {}",
        rep.ungrounded_kinds.len()
    ));
    out.extend(
        rep.ungrounded_kinds
            .iter()
            .map(|(k, v)| format!("  {k:<18} consumed by: {}", v.join(", "))),
    );

    out.push(String::new());
    out.push(format!(
        "sole producers (single point of failure for a kind): {}",
        rep.sole_producer_count
    ));
    out.extend(
        rep.sole_producers
            .iter()
            .map(|(k, v)| format!("  {k:<18} only from: {v}")),
    );

    out.push(String::new());
    out.push(format!(
        "duplicate capability signatures: {}",
        rep.duplicate_capabilities.len()
    ));
    out.extend(
        rep.duplicate_capabilities
            .iter()
            .map(|(k, v)| format!("  {}\n      {k}", v.join(", "))),
    );

    out.push(String::new());
    out.push("blast radius (modules reachable downstream):".to_string());
    out.extend(rep.fanout_hotspots.iter().map(|h| {
        format!(
            "  {:<22} {:>4} modules  ({}% of graph)",
            h.module, h.reaches, h.pct
        )
    }));

    out.join("\n")
}

fn module_name(e: &Value) -> Result<&str, String> {
    e.get("module")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("edge is missing a string \"module\" field: {e}"))
}

/// `v` must be a JSON array of strings, or this is a clear error — used for
/// `pivots_to`/`consumes`, which define the graph structure itself.
fn string_list(v: &Value, field: &str) -> Result<Vec<String>, String> {
    v.as_array()
        .ok_or_else(|| format!("`{field}` is not an array: {v}"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("`{field}` contains a non-string entry: {item}"))
        })
        .collect()
}

/// Like [`string_list`] but silently drops non-string / missing input rather
/// than erroring — used only for the secondary duplicate-capability
/// signature, where every real edge already has valid `pivots_to`/`consumes`
/// (validated by [`build`] before this ever runs) and a malformed one isn't
/// worth aborting the whole report over.
fn lenient_string_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Renders like Python's `str()` on the same JSON-decoded value: `None` for
/// missing/null, a string unquoted, a bool capitalised, anything else via
/// its JSON text. Used everywhere the original script interpolated a loose
/// `.get(...)` result into an f-string.
fn py_display(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => (if *b { "True" } else { "False" }).to_string(),
        Some(other) => other.to_string(),
    }
}

/// Python truthiness of a JSON-decoded value, for `m.get("passive")`-style
/// checks: `None`/`false`/`0`/empty string/empty array/empty object are
/// falsy, everything else is truthy.
fn is_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    include!("main_tests.rs");
}
