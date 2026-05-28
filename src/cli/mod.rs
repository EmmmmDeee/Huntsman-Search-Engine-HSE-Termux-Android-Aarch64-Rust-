//! CLI: scan / modules / doctor / serve / live / provision / set-key / keys.
//!
//! Surfaces every `ScanOptions` field as a flag so each scan is fully
//! customisable before launch. `serve` boots the HTTP server + SPA;
//! `live` re-runs the same scan on a fixed interval (v0.5+). See
//! `docs/USAGE.md` for the full reference.

mod doctor;
mod export;
mod keys_cmd;
mod live;
mod provision;
mod radar;
mod scan;
mod serve;

pub use keys_cmd::KeysAction;

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
                  Five free modules, autonomous depth-bounded expansion.\n\
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
        /// Target kind: email, username, phone, name, ip, domain, asn, coords, address.
        #[arg(short, long)]
        kind: String,
        /// Target value (e.g. example.com, foo@bar.com).
        #[arg(short, long)]
        value: String,
        /// Comma-separated allowlist of module names.
        #[arg(short, long)]
        modules: Option<String>,
        /// Comma-separated exclude list.
        #[arg(long)]
        exclude: Option<String>,
        /// Delay between module dispatches, in milliseconds.
        #[arg(short, long, default_value_t = 0)]
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
        /// entities back as new scan targets, up to N rounds deep.
        #[arg(short, long, default_value_t = 0)]
        depth: u32,
        /// Shorthand for deep recursive expansion: sets depth=5,
        /// min_expand_confidence=0.50, max_concurrent=4. Overridden by
        /// explicit --depth / --min-expand-confidence / --max-concurrent.
        #[arg(short = 'R', long)]
        recursive: bool,
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
        /// Modules to run in parallel per round. Default 4. Set 0 for
        /// sequential dispatch (v0.1 behaviour, best on low-power devices).
        #[arg(long, default_value_t = 4)]
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
        /// (24). Hard-clamped at 200 to preserve the daily session
        /// ceiling. Raise for investigative scans on high-value
        /// targets; lower for passive recces that shouldn't burn
        /// quota.
        #[arg(long)]
        seeknow_scan_cap: Option<u32>,
        /// Output format: table | json | dossier. "dossier" shows full intel grouped by category.
        #[arg(short, long, default_value = "table")]
        output: String,
    },
    /// List registered modules with their cost tier and accepted target kinds.
    Modules,
    /// Verify environment: DB path, key file, Termux detection, module counts.
    Doctor,
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
        /// Enable `PUT /api/v1/settings/keys` so the Settings page can write
        /// `~/.huntsman.env`. Even with this flag the endpoint additionally
        /// requires the request to originate from a loopback peer.
        #[arg(long)]
        allow_key_write: bool,
    },
    /// Manage the multi-key pool (add, list, validate, remove, status).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Run a target continuously, re-scanning on an interval. Streams events
    /// to stdout as compact JSON until Ctrl-C or `--iterations` is exhausted.
    Live {
        /// Target kind (same vocabulary as `scan --kind`).
        #[arg(short, long)]
        kind: String,
        /// Target value.
        #[arg(short, long)]
        value: String,
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
    /// Export a previous scan's entities to JSON / CSV / GEXF / JSON-report.
    ///
    /// JSON           — `[{ kind, value, ... }, ...]` flat entity list
    /// CSV            — operator-friendly tabular form (same shape as
    ///                  the `/api/v1/scans/{id}/entities.csv` endpoint)
    /// GEXF           — Gephi/Cytoscape-importable graph with
    ///                  scan-id + observed_at on every node
    /// Report         — pretty-printed JSON dossier (scan + entities +
    ///                  correlations + counts; same shape as
    ///                  `/api/v1/scans/{id}/report.json`)
    ///
    /// Output goes to stdout by default; pass `--out <path>` to write
    /// to a file.
    Export {
        /// Scan ID (or `latest` for the most-recent completed scan).
        #[arg(short, long)]
        scan_id: String,
        /// Output format: json | csv | gexf | report. Default `json`.
        #[arg(short, long, default_value = "json")]
        format: String,
        /// File path to write to. Omit for stdout.
        #[arg(short, long)]
        out: Option<String>,
    },
}

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
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
            auto,
            min_expand_confidence,
            max_entities,
            max_wall_time,
            max_concurrent,
            adaptive,
            max_roi,
            min_marginal_yield,
            expansion_strategy,
            seeknow_scan_cap,
            output,
        } => {
            scan::cmd_scan(scan::ScanCmd {
                kind,
                value,
                modules,
                exclude,
                throttle_ms: throttle,
                min_confidence,
                free_only,
                passive_only,
                module_timeout_ms: timeout,
                depth,
                recursive,
                auto,
                min_expand_confidence,
                max_entities,
                max_wall_time_secs: max_wall_time,
                max_concurrent,
                adaptive,
                max_roi,
                min_marginal_yield,
                expansion_strategy,
                seeknow_scan_cap,
                output,
            })
            .await
        }
        Command::Modules => cmd_modules(),
        Command::Doctor => doctor::cmd_doctor().await,
        Command::Provision {
            env_only,
            verify_only,
            dry_run,
        } => cmd_provision(env_only, verify_only, dry_run).await,
        Command::SetKey { name, value } => cmd_set_key(name, value),
        Command::Keys { action } => keys_cmd::cmd_keys(action).await,
        Command::Import { file, output } => cmd_import(&file, &output).await,
        Command::Serve {
            bind,
            allow_key_write,
        } => serve::cmd_serve(bind, allow_key_write).await,
        Command::Live {
            kind,
            value,
            interval,
            iterations,
            depth,
            free_only,
            passive_only,
            modules,
        } => {
            live::cmd_live(live::LiveCmd {
                kind,
                value,
                interval,
                iterations,
                depth,
                free_only,
                passive_only,
                modules,
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
    }
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

mod import;
use import::cmd_import;

fn cmd_modules() -> Result<()> {
    let mut mods = registry();
    mods.sort_by_key(|m| std::cmp::Reverse(m.priority()));

    println!(
        "{:<26} {:>4}  {:<10} {:<8} ACCEPTS",
        "MODULE", "PRI", "COST", "PASSIVE"
    );
    println!("{}", "-".repeat(80));

    let target_kinds = [
        ("email", TargetKind::Email),
        ("username", TargetKind::Username),
        ("phone", TargetKind::Phone),
        ("domain", TargetKind::Domain),
        ("url", TargetKind::Url),
        ("ip", TargetKind::IpAddress),
        ("asn", TargetKind::Asn),
        ("name", TargetKind::FullName),
        ("coords", TargetKind::Coordinates),
        ("address", TargetKind::Address),
        ("org", TargetKind::Organisation),
        ("abn", TargetKind::AbnAcn),
        ("apikey", TargetKind::ApiKey),
    ];

    for m in &mods {
        let accepts: Vec<&str> = target_kinds
            .iter()
            .filter(|(_, k)| m.accepts(&Target::new(*k, "")))
            .map(|(label, _)| *label)
            .collect();
        let cost = cost_label(m.cost());
        let passive = if m.is_passive() { "yes" } else { "no" };
        println!(
            "{:<26} {:>4}  {:<10} {:<8} {}",
            m.name(),
            m.priority(),
            cost,
            passive,
            accepts.join(",")
        );
    }
    Ok(())
}

// ─── Shared helpers (used by subcommand files) ─────────────────────────────

pub fn parse_target_kind(s: &str) -> Result<TargetKind> {
    match s.to_lowercase().trim() {
        "email" => Ok(TargetKind::Email),
        "username" => Ok(TargetKind::Username),
        "phone" => Ok(TargetKind::Phone),
        "fullname" | "name" => Ok(TargetKind::FullName),
        "ipaddress" | "ip" => Ok(TargetKind::IpAddress),
        "domain" => Ok(TargetKind::Domain),
        "url" => Ok(TargetKind::Url),
        "asn" => Ok(TargetKind::Asn),
        "coordinates" | "coords" => Ok(TargetKind::Coordinates),
        "address" => Ok(TargetKind::Address),
        "organisation" | "org" => Ok(TargetKind::Organisation),
        "abn" | "acn" | "abn_acn" => Ok(TargetKind::AbnAcn),
        "apikey" | "api_key" | "key" => Ok(TargetKind::ApiKey),
        "mac" | "bssid" | "mac_address" => Ok(TargetKind::MacAddress),
        other => Err(Error::InvalidTarget(format!(
            "unknown target kind '{other}'. Valid: email, username, phone, name, ip, domain, url, asn, coords, address, org, abn, apikey, mac"
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
    let _ = db.prune_events(7 * 86400, 100_000);
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
}
