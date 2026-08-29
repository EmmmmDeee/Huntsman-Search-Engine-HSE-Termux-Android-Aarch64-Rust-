//! `architecture-audit` — inventory the module graph and surface
//! consolidation and correctness risks **from the running binary**, not from
//! reading source.
//!
//! ```text
//! hse serve --bind 127.0.0.1:8080 &          # start the binary to audit
//! cargo run --bin architecture-audit          # audit it (default base URL)
//! cargo run --bin architecture-audit -- --json --out audit.json
//! cargo run --bin architecture-audit -- --from-dir captured/   # reproducible in CI
//! ```
//!
//! Why the binary and not the source: `docs/AUTONOMY_CHARTER.md`'s SENSE
//! stage makes the running software the source of truth ("derive current
//! state from authoritative sources only, never from recall: build and query
//! the binary"), because a static doc — or a hand-copied vocabulary list —
//! drifts. The same argument applies with more force to an architectural
//! inventory: what matters is the graph the *registry* actually exposes at
//! runtime, which is what dispatch walks. A grep over `src/modules` sees
//! files; this sees the system.
//!
//! Replaces the former `scripts/architecture_audit.py` (tracked as an
//! accepted non-Rust exception in `docs/RUST_MIGRATION_AUDIT_2026-08-27.md`)
//! with an equivalent Rust tool, verified to produce identical JSON output
//! against the Python original on a real captured graph before it was
//! removed. See [`audit`] for the ported logic and exactly where this
//! deliberately diverges from the original: `SEED_KINDS` was a hand-copied
//! string literal there ([`audit::seed_kinds`] derives it from the crate's
//! own `TargetKind` enum instead), and the original's module docstring
//! promised a `--fail-on-regression` flag its `argparse` setup never
//! actually added — dropped here rather than ported, since a CLI's
//! documented behaviour should describe what it does.
//!
//! What it reports
//! ----------------
//! The capability graph is bipartite: modules produce and consume *entity
//! kinds*, and dispatch connects a producer to every consumer of the kinds it
//! emits.
//!
//! `orphan_kinds` — produced by some module, consumed by none. Every entity
//! of that kind is a leaf: work is spent deriving a fact that can never be
//! pivoted on.
//!
//! `ungrounded_kinds` — consumed by some module, produced by none. Those
//! consumers can only ever be reached from an operator-supplied seed.
//! Expected for true seed kinds, a defect otherwise.
//!
//! `sole_producers` — a kind produced by exactly one module. That module is a
//! single point of failure for every consumer downstream of the kind.
//!
//! `duplicate_capabilities` — modules with an identical (accepts, produces,
//! category) signature. The strongest consolidation signal the graph can
//! give.
//!
//! `fanout_hotspots` — modules whose output reaches an outsized share of the
//! graph: the highest-blast-radius components, where a correctness bug
//! propagates furthest.

mod audit;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use huntsman_search_engine::util::http::build_client;

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8080";

#[derive(Parser)]
#[command(
    name = "architecture-audit",
    about = "Inventory the hse module graph and surface consolidation/correctness risks"
)]
struct Args {
    /// Live `hse serve` base URL.
    #[arg(long)]
    base_url: Option<String>,
    /// Directory with a captured `modules.json` + `graph.json` pair, so the
    /// audit is reproducible without binding a port.
    #[arg(long)]
    from_dir: Option<PathBuf>,
    /// Emit the raw report as JSON instead of the formatted text report.
    #[arg(long)]
    json: bool,
    /// Also write the report to this path.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("architecture-audit: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &Args) -> Result<(), String> {
    let (modules, graph) = load(args).await.map_err(|e| {
        format!("could not load the module graph: {e}\n  start one with: hse serve --bind 127.0.0.1:8080")
    })?;

    let report = audit::audit(&modules, &graph)?;
    let text = if args.json {
        serde_json::to_string_pretty(&report).map_err(|e| format!("serialising report: {e}"))?
    } else {
        audit::render(&report)
    };
    println!("{text}");
    if let Some(out) = &args.out {
        std::fs::write(out, format!("{text}\n"))
            .map_err(|e| format!("writing {}: {e}", out.display()))?;
    }
    Ok(())
}

/// Load `(modules, graph)` from a captured directory or a live server —
/// `--from-dir` takes priority whenever given, matching the Python
/// original's precedence (`--base-url` is simply ignored if both are passed).
async fn load(args: &Args) -> Result<(Vec<audit::ModuleInfo>, audit::Graph), String> {
    if let Some(dir) = &args.from_dir {
        let modules_raw = std::fs::read_to_string(dir.join("modules.json"))
            .map_err(|e| format!("reading {}: {e}", dir.join("modules.json").display()))?;
        let graph_raw = std::fs::read_to_string(dir.join("graph.json"))
            .map_err(|e| format!("reading {}: {e}", dir.join("graph.json").display()))?;
        let modules: audit::ModulesPayload =
            serde_json::from_str(&modules_raw).map_err(|e| format!("parsing modules.json: {e}"))?;
        let graph: audit::Graph =
            serde_json::from_str(&graph_raw).map_err(|e| format!("parsing graph.json: {e}"))?;
        return Ok((modules.into_modules(), graph));
    }

    let base = args
        .base_url
        .as_deref()
        .unwrap_or(DEFAULT_BASE_URL)
        .trim_end_matches('/');
    let client = build_client();
    let modules: audit::ModulesPayload =
        get_json(&client, &format!("{base}/api/v1/modules")).await?;
    let graph: audit::Graph = get_json(&client, &format!("{base}/api/v1/modules/graph")).await?;
    Ok((modules.into_modules(), graph))
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetching {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("fetching {url}: HTTP {}", resp.status()));
    }
    resp.json::<T>()
        .await
        .map_err(|e| format!("parsing response from {url}: {e}"))
}
