//! CLI: scan / modules / doctor / serve / live / provision / set-key / keys.
//!
//! Surfaces every `ScanOptions` field as a flag so each scan is fully
//! customisable before launch. `serve` boots the HTTP server + SPA;
//! `live` re-runs the same scan on a fixed interval (v0.5+). See
//! `docs/USAGE.md` for the full reference.

mod audit;
mod config;
mod diagnostics;
mod diff;
mod doctor;
mod engines;
pub(crate) mod export;
mod keys_cmd;
mod live;
mod provision;
mod radar;
mod scan;
mod selftest;
mod serve;

use keys_cmd::KeysAction;

use std::io::IsTerminal;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::{
    core::{
        engine::ScanEngine,
        error::{Error, Result},
        module::ModuleCost,
        scan::{Target, TargetKind},
    },
    default_db_path,
    modules::registry,
    storage::Store,
    util::keys,
};

#[derive(Parser)]
#[command(
    name = "hse",
    version = crate::VERSION,
    about = "Huntsman Search Engine — Termux aarch64 OSINT / GEOINT prototype",
    long_about = "Pure-Rust OSINT scaffold for Termux on Android aarch64.\n\
                  80+ modules (most free, no key), autonomous depth-bounded expansion.\n\
                  Docs: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
// Scan has many fields (intentional — full ScanOptions surface as CLI flags).
// Boxing every field is uglier than the size disparity warrants.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Run a single scan and print the entities found.
    Scan {
        /// Target kind: email, username, phone, name, ip, domain, url, asn, coords,
        /// address, org, abn, mac, apikey. Omit (or pass `auto`) to auto-detect the
        /// kind from the value — the unified scan, e.g. `hse scan -v alice@example.com`.
        #[arg(short, long)]
        kind: Option<String>,
        /// Target value (e.g. example.com, foo@bar.com). Optional — omit to use
        /// the operator-local default seed (`HUNTSMAN_DEFAULT_SEED` in
        /// ~/.huntsman.env), so you can run a bare `hse scan` without retyping it.
        // allow_hyphen_values so a value that legitimately begins with `-`
        // (e.g. a southern-hemisphere coordinate `-33.86,151.20`) is taken as
        // the value, not parsed by clap as an unknown short flag.
        #[arg(short, long, allow_hyphen_values = true)]
        value: Option<String>,
        /// Comma-separated allowlist of module names.
        #[arg(short, long)]
        modules: Option<String>,
        /// Comma-separated exclude list.
        #[arg(long)]
        exclude: Option<String>,
        /// Delay between module dispatches, in milliseconds. Default 250 paces
        /// dispatch so a deep/everything scan doesn't flood the link or trip
        /// provider rate limits; set 0 for the fastest (burstier) behaviour.
        #[arg(short, long, default_value_t = 250)]
        throttle: u64,
        /// Drop entities whose base confidence is below this.
        #[arg(long)]
        min_confidence: Option<f64>,
        /// Skip key-gated and paid modules.
        #[arg(long)]
        free_only: bool,
        /// Skip non-passive modules (network-reaching).
        #[arg(long)]
        passive_only: bool,
        /// Per-module timeout override, in milliseconds.
        #[arg(long)]
        timeout: Option<u64>,
        /// Recursive expansion depth. 0 = single round; 1+ auto-feeds discovered
        /// entities back as new scan targets, up to N rounds deep. Omit to use
        /// the product default (2); `--auto`/`--recursive` override an omitted
        /// value.
        #[arg(short, long)]
        depth: Option<u32>,
        /// Shorthand for deep recursive expansion: sets depth to MAX_DEPTH (3)
        /// and min_expand_confidence=0.40. Overridden by an explicit --depth.
        #[arg(short = 'R', long)]
        recursive: bool,
        /// COMPLETE scan — the no-compromise preset. Auto-detects the seed kind,
        /// runs EVERY module (overrides --free-only/--passive-only/--modules),
        /// expands to MAX_DEPTH (3) at the Probable floor, and disables ROI
        /// pruning so nothing is skipped. The single "get everything" option.
        #[arg(
            short = 'F',
            long,
            visible_alias = "complete",
            visible_alias = "everything"
        )]
        full: bool,
        /// Automatically select optimal expansion depth based on seed type
        /// and available API keys. Uses expected-value analysis to determine
        /// the depth where marginal yield justifies the cost.
        #[arg(short = 'A', long)]
        auto: bool,
        /// Only expand entities whose C_eff is at least this. Default 0.50
        /// (Probable tier and above). Set 0.75 for strict Verified-only expansion.
        #[arg(long, default_value_t = 0.50)]
        min_expand_confidence: f64,
        /// Hard cap on total entities. Stops expansion when reached.
        #[arg(long)]
        max_entities: Option<usize>,
        /// Hard cap on total wall-time in seconds. Stops expansion when exceeded.
        #[arg(long)]
        max_wall_time: Option<u64>,
        /// Modules to run in parallel per round. Default 2 (gentle — avoids
        /// flooding the link / tripping rate limits). Raise it when the network
        /// can take it; set 0 for fully sequential dispatch (low-power devices).
        #[arg(long, default_value_t = 2)]
        max_concurrent: usize,
        /// Read ~/.huntsman/module_stats.json and skip modules with
        /// historical zero-yield rate ≥80% over ≥5 scans. Closes the
        /// self-optimization feedback loop — every scan informs the next.
        #[arg(long)]
        adaptive: bool,
        /// Maximise ROI per dispatch: skip already-saturated entities
        /// (≥2 corroborating sources, c_eff ≥ 0.85), keep only top-K
        /// candidates per round (K = 2×max_concurrent + 8), and
        /// terminate recursion when marginal yield falls below floor
        /// (default 0.75 new entities per dispatched target).
        #[arg(long)]
        max_roi: bool,
        /// Australian-focused regional searching is ON by default: the search
        /// module adds minimal `.au` / AU-directory dorks on top of the
        /// geolocation-neutral base (a seed with no region signal defaults to
        /// AU). Pass `--no-regional` for a purely global scan.
        #[arg(long = "no-regional", action = clap::ArgAction::SetTrue)]
        no_regional: bool,
        /// When `--max-roi` is set, override the default marginal-yield
        /// floor (0.75). Lower = recurse further before giving up.
        #[arg(long)]
        min_marginal_yield: Option<f64>,
        /// Expansion ordering strategy: `geo_converge` (default; legacy),
        /// `breadth_first`, `depth_first`, `richest_first`. Changes how
        /// the engine prioritises expansion candidates each round.
        #[arg(long, default_value = "geo_converge")]
        expansion_strategy: String,
        /// Per-scan SeekNow (see-know.eu) budget override. Caps the
        /// number of SeekNow API queries this scan may dispatch.
        /// Default (None) falls back to HUNTSMAN_SEEKNOW_SCAN_CAP env
        /// (160). Hard-clamped at 200 to preserve the daily session
        /// ceiling. Raise for investigative scans on high-value
        /// targets; lower for passive recces that shouldn't burn
        /// quota.
        #[arg(long)]
        seeknow_scan_cap: Option<u32>,
        /// Expand EVERY discovered username/person, including uncorroborated,
        /// single-source aliases that share no handle/name overlap with the
        /// subject. Disables the wrong-identity gate for maximum recall at the
        /// cost of pulling in unrelated footprints (prune by hand). Implied by
        /// `--full`. Default keeps the gate on; excluded aliases are logged.
        #[arg(long)]
        expand_all_identities: bool,
        /// Output format: table | json | dossier. "dossier" shows full intel grouped by category.
        #[arg(short, long, default_value = "table")]
        output: String,
    },
    /// List registered modules with their cost tier and accepted target kinds.
    ///
    /// Filter with `--category <cat>` (dns_recon / breach / infrastructure /
    /// search / geo / social / email / phone / corporate / threat / sensor
    /// / people / web / other) or `--json` to get the machine-readable
    /// shape that `/api/v1/modules` returns.
    Modules {
        /// Restrict listing to one module category.
        #[arg(short, long)]
        category: Option<String>,
        /// Output as JSON (same shape as `/api/v1/modules`).
        #[arg(long)]
        json: bool,
    },
    /// Liveness panel: probe every free search engine and report up/blocked/down
    /// + latency. Results also go to the unified debug log (structured events).
    Engines {
        /// Output as JSON instead of the status table.
        #[arg(long)]
        json: bool,
    },
    /// View or set persistent capability toggles (universal toggleability,
    /// SpiderFoot-style). No args lists all toggles; `hse config <key> <on|off>`
    /// sets one — e.g. `hse config engine.google off`.
    Config {
        /// Toggle key (e.g. `engine.google`). Omit to list all toggles.
        key: Option<String>,
        /// `on` / `off` to set the toggle; omit to just show its value.
        value: Option<String>,
    },
    /// Run ALL diagnostics in one pass: environment (doctor) + module/core
    /// self-test (selftest) + search-engine liveness (engines). Exits non-zero
    /// if any section fails. The one command to verify a fresh install.
    #[command(visible_alias = "diag", visible_alias = "check")]
    Diagnostics {
        /// Emit machine-readable JSON for the sections that support it
        /// (selftest, engines); doctor remains human-readable.
        #[arg(long)]
        json: bool,
    },
    /// Score and explain a scan's output quality: noise, infrastructure
    /// pollution, fragment values, missed PII, and source health, with
    /// actionable recommendations. Ingests a CSV export (`--csv`), a stored scan
    /// (`--scan-id`, `latest` allowed), and/or a debug log (`--log`, JSONL or
    /// tracing text). The self-audit the manifesto asks for: every scan becomes
    /// an opportunity to expose and eliminate weaknesses.
    #[command(visible_alias = "score")]
    Audit {
        /// CSV export to audit (`hse export --format csv`).
        #[arg(long)]
        csv: Option<String>,
        /// Stored scan id to audit (`latest` for the most recent completed scan).
        #[arg(long)]
        scan_id: Option<String>,
        /// Debug log / event stream to mine for source-health signals.
        #[arg(long)]
        log: Option<String>,
        /// Emit the machine-readable JSON report instead of the text scorecard.
        #[arg(long)]
        json: bool,
    },
    /// Verify environment: DB path, key file, Termux detection, module counts.
    /// (Subsumed by `hse diagnostics`; kept for focused use and the API/UI.)
    Doctor,
    /// Validate every module and core feature, then exit (non-zero on any
    /// failure). Runs the full suite automatically; the same report is served
    /// on demand at `GET /api/v1/selftest` and from the Web UI's Settings page.
    Selftest {
        /// Emit the machine-readable JSON report instead of the text table.
        #[arg(long)]
        json: bool,
    },
    /// Provision the local environment: write/merge `$HOME/.huntsman.env`
    /// from the canonical template and run a diagnostic smoke test.
    ///
    /// Replaces the post-install phases of the Termux bootstrap script:
    /// pre-build phases (toolchain / git clone / `cargo build`) still
    /// live in `install.sh` because they must run before this binary
    /// exists. After install, prefer `hse provision`.
    ///
    /// Idempotent: existing real key values are preserved across runs;
    /// the file is backed up to `<path>.env.bak.<epoch>` before any
    /// change.
    #[command(visible_alias = "setup")]
    Provision {
        /// Merge the env file but skip the diagnostic smoke test.
        #[arg(long, conflicts_with = "verify_only")]
        env_only: bool,
        /// Run the diagnostic smoke test but don't touch the env file.
        #[arg(long, conflicts_with = "env_only")]
        verify_only: bool,
        /// Show the merged env content without writing to disk.
        #[arg(long)]
        dry_run: bool,
    },

    /// Write a single `HUNTSMAN_*` key to `$HOME/.huntsman.env`.
    ///
    /// The file is created with mode 0600 if missing; existing entries
    /// for the same name are replaced in place. Other `HUNTSMAN_*`
    /// lines, comments, and unrelated entries are preserved verbatim.
    /// Same validation as the Settings HTTP endpoint — key names must
    /// start with `HUNTSMAN_` and values may not contain control
    /// characters or double-quotes.
    SetKey {
        /// Variable name, e.g. `HUNTSMAN_SHODAN_KEY`. Must start with `HUNTSMAN_`.
        name: String,
        /// Raw value to store. Quote in the shell to avoid mis-parsing.
        value: String,
    },
    /// Import an OathNet JSON export file. Extracts breach results,
    /// stealer metadata, IP geolocation, and Holehe platform checks
    /// into a new scan record with full entity extraction.
    Import {
        /// Path to the OathNet export JSON file.
        file: String,
        /// Output format: json, table, dossier.
        #[arg(short, long, default_value = "table")]
        output: String,
    },
    /// Start the HTTP server + SPA (browse to http://127.0.0.1:8080 from Chrome).
    Serve {
        /// Bind address. Localhost-only by default — change at your own risk.
        #[arg(short, long, default_value = crate::DEFAULT_BIND, env = "HSE_BIND")]
        bind: String,
        /// Disable the Settings page's key-write endpoint
        /// (`PUT /api/v1/settings/keys`). Key writes are ENABLED BY DEFAULT so
        /// the Settings page works out of the box on a personal device — and
        /// the endpoint *always* additionally requires the request to originate
        /// from a loopback peer, so a network-exposed bind still can't write
        /// keys. Pass this to lock writes down entirely for shared/hardened
        /// deployments.
        #[arg(long)]
        no_key_write: bool,
    },
    /// Manage the multi-key pool (add, list, validate, remove, status).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Run a target continuously, re-scanning on an interval. Streams events
    /// to stdout as compact JSON until Ctrl-C or `--iterations` is exhausted.
    Live {
        /// Target kind (same vocabulary as `scan --kind`). Omit (or pass `auto`)
        /// to auto-detect the kind from the value — the unified live scan.
        #[arg(short, long)]
        kind: Option<String>,
        /// Target value. Optional — omit to use the operator-local default seed
        /// (`HUNTSMAN_DEFAULT_SEED` in ~/.huntsman.env).
        // allow_hyphen_values so a value that legitimately begins with `-`
        // (e.g. a southern-hemisphere coordinate `-33.86,151.20`) is taken as
        // the value, not parsed by clap as an unknown short flag.
        #[arg(short, long, allow_hyphen_values = true)]
        value: Option<String>,
        /// Seconds between iterations.
        #[arg(short, long, default_value_t = crate::LIVE_DEFAULT_INTERVAL_SECS)]
        interval: u64,
        /// Stop after this many iterations. Omit for infinite.
        #[arg(long)]
        iterations: Option<u32>,
        /// Same as `scan --depth` — applies to each iteration.
        #[arg(short, long, default_value_t = 0)]
        depth: u32,
        /// Same as `scan --free-only`.
        #[arg(long)]
        free_only: bool,
        /// Same as `scan --passive-only`.
        #[arg(long)]
        passive_only: bool,
        /// Comma-separated module allowlist.
        #[arg(short, long)]
        modules: Option<String>,
        /// Radar mode: persist the keyed-module dispatch ledger across
        /// iterations so paid APIs are never re-queried on a seed an earlier
        /// sweep already covered — each sweep spends quota only on NEW seeds.
        #[arg(long)]
        radar: bool,
        /// Emit the raw newline-delimited JSON event stream (machine-readable)
        /// instead of the default human-readable, fully-unredacted structured
        /// view. Both carry identical data — the default just renders it for a
        /// human interpreter; `--json` is for piping into another tool.
        #[arg(long)]
        json: bool,
    },
    /// Radar mode: continuous Termux signal sweep → automatic pivoting.
    ///
    /// Sweeps device sensors (GPS, WiFi, cell towers, ARP, network interfaces)
    /// on a fast interval. Each newly discovered entity (coordinates, BSSIDs,
    /// IPs, cell tower IDs) is automatically fed into the full OSINT pivot
    /// pipeline at the configured depth. Only NEW discoveries trigger pivots —
    /// previously seen entities are skipped.
    ///
    /// Think of it as an intermittent radar that detects signals and
    /// automatically enriches them through all available modules.
    Radar {
        /// Seconds between sensor sweeps. Default 10.
        #[arg(short, long, default_value_t = 10)]
        interval: u64,
        /// Expansion depth for each discovered entity. Default 2.
        #[arg(short, long, default_value_t = 2)]
        depth: u32,
        /// Stop after this many sweeps. Omit for infinite (Ctrl-C to stop).
        #[arg(long)]
        sweeps: Option<u32>,
        /// Skip paid modules when pivoting.
        #[arg(long)]
        free_only: bool,
    },
    /// Export a previous scan's entities to JSON / CSV / GEXF / JSON-report / full.
    ///
    /// JSON           — `[{ kind, value, ... }, ...]` flat entity list
    /// CSV            — operator-friendly tabular form (same shape as
    ///                  the `/api/v1/scans/{id}/entities.csv` endpoint)
    /// GEXF           — Gephi/Cytoscape-importable graph with
    ///                  scan-id + observed_at on every node
    /// Report         — pretty-printed JSON dossier (scan + entities +
    ///                  correlations + counts; same shape as
    ///                  `/api/v1/scans/{id}/report.json`)
    /// Full           — Huntsman's STANDARD maximum-detail dossier: every
    ///                  entity (incl. candidates) with its full evidence
    ///                  chain — every raw field, the provenance
    ///                  (provider / api_key_origin / endpoint) and source
    ///                  website — nothing hashed, masked, or omitted
    ///
    /// Output goes to stdout by default; pass `--out <path>` to write
    /// to a file.
    Export {
        /// Scan ID (or `latest` for the most-recent completed scan).
        #[arg(short, long)]
        scan_id: String,
        /// Output format: json | csv | gexf | report | full. Default `json`.
        #[arg(short, long, default_value = "json")]
        format: String,
        /// File path to write to. Omit for stdout.
        #[arg(short, long)]
        out: Option<String>,
    },

    /// Compare two completed scans: entities added / removed / re-scored.
    Diff {
        /// Baseline scan ID (or `latest` for the most-recent completed scan).
        from: String,
        /// Later scan ID to compare against the baseline (or `latest`).
        to: String,
        /// Output format: text | json. Default `text`.
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

pub async fn run() -> Result<()> {
    // Raw logs by default (operator directive: the entire project outputs raw
    // logs). When `RUST_LOG` is unset we default to TRACE — the rawest level —
    // so every curl invocation, full endpoint payload, JSON-parse step, and
    // retry/backoff decision is emitted without the operator having to opt in.
    // An explicit `RUST_LOG` still wins (e.g. `RUST_LOG=warn` to quieten, or
    // `RUST_LOG=hyper=info,huntsman_search_engine=trace` to scope).
    //
    // Logs go to STDERR so stdout carries only the requested payload — without
    // this, log lines interleave into `--output json` (and live/export
    // streams), producing output downstream parsers cannot consume. `with_target`
    // and line numbers are on so each raw line shows its module-path + site.
    // Default filter: HSE's own crate at TRACE (raw logs for every module,
    // curl call, parse, retry), but the TLS/HTTP plumbing crates capped at
    // INFO — at TRACE, hyper/h2/rustls/reqwest emit per-frame/per-byte IO spam
    // that buries the project's own raw logs (observed ~160 dep lines vs ~260
    // HSE lines on a single IP lookup). This keeps "the entire project outputs
    // raw logs" meaningful: maximal verbosity for HSE, signal not framing noise
    // from its dependencies. An explicit `RUST_LOG` overrides this wholesale.
    const DEFAULT_RAW_LOG: &str = "trace,\
        hyper=info,hyper_util=info,h2=info,rustls=info,reqwest=info,\
        tokio_util=info,tower=info,want=info,mio=info";
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_RAW_LOG));
    // Two fmt layers behind one EnvFilter: the operator's stderr console
    // (ANSI auto-detected) and a clean no-ANSI tee into the in-memory ring
    // buffer, so the same raw-verbose stream is downloadable from the Web UI
    // (`GET /api/v1/logs`) / `hse logs` without polluting the console output.
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_line_number(true)
                .with_writer(std::io::stderr),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_line_number(true)
                .with_writer(crate::util::log_capture::RingMakeWriter),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            kind,
            value,
            modules,
            exclude,
            throttle,
            min_confidence,
            free_only,
            passive_only,
            timeout,
            depth,
            recursive,
            full,
            auto,
            min_expand_confidence,
            max_entities,
            max_wall_time,
            max_concurrent,
            adaptive,
            max_roi,
            no_regional,
            min_marginal_yield,
            expansion_strategy,
            seeknow_scan_cap,
            expand_all_identities,
            output,
        } => {
            let value = resolve_seed(value, keys::default_seed())?;
            // `--full` is the no-compromise preset: force every module on (drop
            // the free/passive filters and any allowlist), deep recursion, and
            // no ROI pruning. It composes by overriding the narrowing flags.
            scan::cmd_scan(scan::ScanCmd {
                kind,
                value,
                modules: if full { None } else { modules },
                exclude,
                throttle_ms: throttle,
                min_confidence,
                free_only: free_only && !full,
                passive_only: passive_only && !full,
                module_timeout_ms: timeout,
                depth,
                recursive: recursive || full,
                auto,
                min_expand_confidence,
                max_entities,
                max_wall_time_secs: max_wall_time,
                max_concurrent,
                adaptive,
                max_roi: max_roi && !full,
                // AU-focused regional searching is on unless explicitly disabled.
                regional_search: !no_regional,
                min_marginal_yield,
                expansion_strategy,
                seeknow_scan_cap,
                // `--full` is the no-compromise preset: maximise recall, so the
                // wrong-identity gate is lifted alongside the other narrowing
                // filters it already drops.
                expand_all_identities: expand_all_identities || full,
                output,
            })
            .await
        }
        Command::Modules { category, json } => cmd_modules(category, json),
        Command::Engines { json } => engines::cmd_engines(json).await,
        Command::Config { key, value } => config::cmd_config(key, value),
        Command::Diagnostics { json } => diagnostics::cmd_diagnostics(json).await,
        Command::Audit {
            csv,
            scan_id,
            log,
            json,
        } => audit::cmd_audit(csv, scan_id, log, json).await,
        Command::Doctor => doctor::cmd_doctor().await,
        Command::Selftest { json } => selftest::cmd_selftest(json).await,
        Command::Provision {
            env_only,
            verify_only,
            dry_run,
        } => cmd_provision(env_only, verify_only, dry_run).await,
        Command::SetKey { name, value } => cmd_set_key(name, value),
        Command::Keys { action } => keys_cmd::cmd_keys(action).await,
        Command::Import { file, output } => cmd_import(&file, &output).await,
        Command::Serve { bind, no_key_write } => serve::cmd_serve(bind, !no_key_write).await,
        Command::Live {
            kind,
            value,
            interval,
            iterations,
            depth,
            free_only,
            passive_only,
            modules,
            radar,
            json,
        } => {
            let value = resolve_seed(value, keys::default_seed())?;
            live::cmd_live(live::LiveCmd {
                kind,
                value,
                interval,
                iterations,
                depth,
                free_only,
                passive_only,
                modules,
                radar,
                json,
            })
            .await
        }
        Command::Radar {
            interval,
            depth,
            sweeps,
            free_only,
        } => radar::cmd_radar(interval, depth, sweeps, free_only).await,
        Command::Export {
            scan_id,
            format,
            out,
        } => export::cmd_export(scan_id, format, out).await,
        Command::Diff { from, to, format } => diff::cmd_diff(from, to, format),
    }
}

/// Resolve the effective `scan`/`live` target: the explicit CLI `--value` when
/// given (a blank value is treated as absent), otherwise the operator-local
/// default seed (`HUNTSMAN_DEFAULT_SEED`). Errors with actionable guidance when
/// neither is set. Pure over its inputs so the precedence is unit-testable and
/// the default-seed lookup stays a thin caller concern.
fn resolve_seed(cli_value: Option<String>, default_seed: Option<String>) -> Result<String> {
    cli_value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(default_seed)
        .ok_or_else(|| {
            Error::Other(
                "no target: pass --value <seed>, or set HUNTSMAN_DEFAULT_SEED in \
                 ~/.huntsman.env to your own default seed (kept local — never shipped)"
                    .to_string(),
            )
        })
}

// ─── Inline commands (small enough not to warrant their own file) ───────────

async fn cmd_provision(env_only: bool, verify_only: bool, dry_run: bool) -> Result<()> {
    println!("HSE v{} — provision", crate::VERSION);
    if !verify_only {
        provision::cmd_provision_env(dry_run)?;
    }
    if !env_only && !dry_run {
        provision::cmd_provision_verify().await?;
    } else if !env_only && dry_run {
        println!("==> Phase: verify (skipped under --dry-run)");
    }
    println!("\nDone.");
    Ok(())
}

fn cmd_set_key(name: String, value: String) -> Result<()> {
    use std::collections::BTreeMap;
    let mut updates = BTreeMap::new();
    updates.insert(name.clone(), value);
    keys::write_keys(&updates, &[]).map_err(|e| Error::Other(e.to_string()))?;
    println!("✓ {name} set in {}", keys::env_path());
    Ok(())
}

pub(crate) mod import;
use import::cmd_import;

fn cmd_modules(category_filter: Option<String>, as_json: bool) -> Result<()> {
    let mut mods = registry();
    mods.sort_by_key(|m| std::cmp::Reverse(m.priority()));

    // Optional category filter — case-insensitive exact match against
    // the snake_case category name (e.g. `--category geo`, `--category
    // dns_recon`). Pre-strip the operator's input to match the
    // canonical form ModuleCategory::as_str returns.
    let category_filter_lc = category_filter.as_ref().map(|s| s.to_lowercase());
    let filtered: Vec<_> = mods
        .iter()
        .filter(|m| match &category_filter_lc {
            Some(needle) => m.category().as_str() == needle.as_str(),
            None => true,
        })
        .collect();

    if as_json {
        // Same shape as /api/v1/modules — operators can `jq` the
        // output the same way they'd `jq` the HTTP endpoint.
        let infos: Vec<_> = filtered.iter().map(|m| m.info()).collect();
        let body = serde_json::to_string_pretty(&serde_json::json!({
            "modules": infos,
            "count": infos.len(),
        }))
        .map_err(|e| Error::Other(format!("json: {e}")))?;
        println!("{body}");
        return Ok(());
    }

    println!(
        "{:<26} {:>4}  {:<14} {:<10} {:<8} ACCEPTS",
        "MODULE", "PRI", "CATEGORY", "COST", "PASSIVE"
    );
    println!("{}", "-".repeat(96));

    let target_kinds = [
        ("email", TargetKind::Email),
        ("username", TargetKind::Username),
        ("phone", TargetKind::Phone),
        ("domain", TargetKind::Domain),
        ("url", TargetKind::Url),
        ("ip", TargetKind::IpAddress),
        ("cidr", TargetKind::Cidr),
        ("asn", TargetKind::Asn),
        ("name", TargetKind::FullName),
        ("coords", TargetKind::Coordinates),
        ("address", TargetKind::Address),
        ("org", TargetKind::Organisation),
        ("abn", TargetKind::AbnAcn),
        ("apikey", TargetKind::ApiKey),
    ];

    for m in &filtered {
        let accepts: Vec<&str> = target_kinds
            .iter()
            .filter(|(_, k)| m.accepts(&Target::new(*k, "")))
            .map(|(label, _)| *label)
            .collect();
        let cost = cost_label(m.cost());
        let passive = if m.is_passive() { "yes" } else { "no" };
        println!(
            "{:<26} {:>4}  {:<14} {:<10} {:<8} {}",
            m.name(),
            m.priority(),
            m.category().as_str(),
            cost,
            passive,
            accepts.join(",")
        );
    }
    if filtered.is_empty() {
        if let Some(f) = category_filter {
            eprintln!("\nNo modules in category '{f}'.");
            eprintln!(
                "Valid: dns_recon / breach / infrastructure / search / geo / social /\n       email / phone / corporate / threat / sensor / people / web / other"
            );
        }
    } else {
        println!("\n{} module(s) total.", filtered.len());
    }
    Ok(())
}

// ─── Shared helpers (used by subcommand files) ─────────────────────────────

pub(super) fn parse_target_kind(s: &str) -> Result<TargetKind> {
    match s.to_lowercase().trim() {
        "email" => Ok(TargetKind::Email),
        "username" => Ok(TargetKind::Username),
        "phone" => Ok(TargetKind::Phone),
        "fullname" | "name" => Ok(TargetKind::FullName),
        "ipaddress" | "ip" => Ok(TargetKind::IpAddress),
        "domain" => Ok(TargetKind::Domain),
        "url" => Ok(TargetKind::Url),
        "asn" => Ok(TargetKind::Asn),
        "cidr" | "netblock" | "netrange" => Ok(TargetKind::Cidr),
        "coordinates" | "coords" => Ok(TargetKind::Coordinates),
        "address" => Ok(TargetKind::Address),
        "organisation" | "org" => Ok(TargetKind::Organisation),
        "abn" | "acn" | "abn_acn" => Ok(TargetKind::AbnAcn),
        "apikey" | "api_key" | "key" => Ok(TargetKind::ApiKey),
        "mac" | "bssid" | "mac_address" => Ok(TargetKind::MacAddress),
        "crypto" | "crypto_address" | "wallet" | "btc" | "eth" => Ok(TargetKind::CryptoAddress),
        other => Err(Error::InvalidTarget(format!(
            "unknown target kind '{other}'. Valid: email, username, phone, name, ip, cidr, domain, url, asn, coords, address, org, abn, apikey, mac, crypto"
        ))),
    }
}

pub(super) fn cost_label(c: ModuleCost) -> &'static str {
    match c {
        ModuleCost::Free => "free",
        ModuleCost::KeyGated => "key-gated",
        ModuleCost::Paid => "paid",
    }
}

pub(super) fn split_csv(s: Option<String>) -> Option<Vec<String>> {
    s.map(|s| s.split(',').map(|m| m.trim().to_string()).collect())
}

pub(super) fn build_runtime(
    bus_capacity: usize,
) -> Result<(
    Arc<dyn crate::core::port::StoragePort>,
    crate::core::event::EventBus,
    Arc<ScanEngine>,
)> {
    let db = Store::open(&default_db_path())?;
    let _ = db.prune_events(
        crate::core::port::EVENTS_RETENTION_SECS,
        crate::core::port::EVENTS_MAX_ROWS,
    );
    let store: Arc<dyn crate::core::port::StoragePort> = Arc::new(db);
    let (bus, _rx) = tokio::sync::broadcast::channel(bus_capacity);
    let engine = Arc::new(ScanEngine::new(registry(), Arc::clone(&store), bus.clone()));
    Ok((store, bus, engine))
}

pub(super) fn use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

pub(super) fn color_confidence(c_eff: f64, text: &str, color: bool) -> String {
    if !color {
        return text.to_string();
    }
    if c_eff >= 0.75 {
        format!("\x1b[32m{text}\x1b[0m")
    } else if c_eff >= 0.40 {
        format!("\x1b[33m{text}\x1b[0m")
    } else {
        format!("\x1b[31m{text}\x1b[0m")
    }
}

pub(super) fn color_severity(severity: &str, color: bool) -> String {
    if !color {
        return severity.to_string();
    }
    match severity.trim() {
        "critical" => format!("\x1b[1;31m{severity}\x1b[0m"),
        "high" => format!("\x1b[31m{severity}\x1b[0m"),
        "medium" => format!("\x1b[33m{severity}\x1b[0m"),
        _ => format!("\x1b[2m{severity}\x1b[0m"),
    }
}

pub(super) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    // ── parse_target_kind ───────────────────────────────────────────────────

    #[test]
    fn parse_email() {
        assert_eq!(parse_target_kind("email").unwrap(), TargetKind::Email);
        assert_eq!(parse_target_kind("EMAIL").unwrap(), TargetKind::Email);
        assert_eq!(parse_target_kind(" Email ").unwrap(), TargetKind::Email);
    }

    #[test]
    fn parse_username() {
        assert_eq!(parse_target_kind("username").unwrap(), TargetKind::Username);
    }

    #[test]
    fn parse_phone() {
        assert_eq!(parse_target_kind("phone").unwrap(), TargetKind::Phone);
    }

    #[test]
    fn parse_name_aliases() {
        assert_eq!(parse_target_kind("name").unwrap(), TargetKind::FullName);
        assert_eq!(parse_target_kind("fullname").unwrap(), TargetKind::FullName);
    }

    #[test]
    fn parse_ip_aliases() {
        assert_eq!(parse_target_kind("ip").unwrap(), TargetKind::IpAddress);
        assert_eq!(
            parse_target_kind("ipaddress").unwrap(),
            TargetKind::IpAddress
        );
    }

    #[test]
    fn parse_domain() {
        assert_eq!(parse_target_kind("domain").unwrap(), TargetKind::Domain);
    }

    #[test]
    fn parse_asn() {
        assert_eq!(parse_target_kind("asn").unwrap(), TargetKind::Asn);
    }

    #[test]
    fn parse_coords_aliases() {
        assert_eq!(
            parse_target_kind("coords").unwrap(),
            TargetKind::Coordinates
        );
        assert_eq!(
            parse_target_kind("coordinates").unwrap(),
            TargetKind::Coordinates
        );
    }

    #[test]
    fn parse_address() {
        assert_eq!(parse_target_kind("address").unwrap(), TargetKind::Address);
    }

    #[test]
    fn parse_unknown_kind_is_err() {
        assert!(parse_target_kind("foobar").is_err());
        assert!(parse_target_kind("").is_err());
    }

    // ── split_csv ───────────────────────────────────────────────────────────

    #[test]
    fn split_csv_none_stays_none() {
        assert!(split_csv(None).is_none());
    }

    #[test]
    fn split_csv_single_entry() {
        let r = split_csv(Some("dns_resolver".into())).unwrap();
        assert_eq!(r, vec!["dns_resolver"]);
    }

    #[test]
    fn split_csv_multiple_entries() {
        let r = split_csv(Some("a, b ,c".into())).unwrap();
        assert_eq!(r, vec!["a", "b", "c"]);
    }

    #[test]
    fn split_csv_empty_string() {
        let r = split_csv(Some(String::new())).unwrap();
        assert_eq!(r, vec![""]);
    }

    // ── cost_label ──────────────────────────────────────────────────────────

    #[test]
    fn cost_labels() {
        assert_eq!(cost_label(ModuleCost::Free), "free");
        assert_eq!(cost_label(ModuleCost::KeyGated), "key-gated");
        assert_eq!(cost_label(ModuleCost::Paid), "paid");
    }

    // ── truncate ────────────────────────────────────────────────────────────

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        let r = truncate("hello world", 5);
        assert!(r.contains('…'));
        assert_eq!(r.chars().count(), 5);
    }

    #[test]
    fn truncate_unicode() {
        let r = truncate("café latte", 5);
        assert_eq!(r.chars().count(), 5);
        assert!(r.ends_with('…'));
    }

    // ── resolve_seed ────────────────────────────────────────────────────────

    #[test]
    fn resolve_seed_prefers_explicit_cli_value() {
        let got = resolve_seed(Some("alice".to_string()), Some("default".to_string())).unwrap();
        assert_eq!(got, "alice");
    }

    #[test]
    fn resolve_seed_falls_back_to_default_when_value_absent() {
        let got = resolve_seed(None, Some("default".to_string())).unwrap();
        assert_eq!(got, "default");
    }

    #[test]
    fn resolve_seed_blank_cli_value_falls_back_to_default() {
        // `-v "  "` is treated as absent, not as a blank target.
        let got = resolve_seed(Some("   ".to_string()), Some("default".to_string())).unwrap();
        assert_eq!(got, "default");
    }

    #[test]
    fn resolve_seed_trims_explicit_value() {
        let got = resolve_seed(Some("  bob  ".to_string()), None).unwrap();
        assert_eq!(got, "bob");
    }

    #[test]
    fn resolve_seed_errors_when_nothing_set() {
        let err = resolve_seed(None, None).unwrap_err().to_string();
        assert!(err.contains("--value"), "{err}");
        assert!(err.contains("HUNTSMAN_DEFAULT_SEED"), "{err}");
    }
}
