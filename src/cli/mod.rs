//! CLI: scan / modules / doctor / serve / live / provision / set-key.
//!
//! Surfaces every `ScanOptions` field as a flag so each scan is fully
//! customisable before launch. `serve` boots the HTTP server + SPA;
//! `live` re-runs the same scan on a fixed interval (v0.5+). See
//! `docs/USAGE.md` for the full reference.

mod live;
mod provision;
mod scan;
mod serve;

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
    default_db_path, is_termux,
    modules::registry,
    storage::store::Store,
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
        /// Only expand entities whose C_eff is at least this. Default 0.75
        /// (Verified tier) — strong filter to keep expansion focused.
        #[arg(long, default_value_t = 0.75)]
        min_expand_confidence: f64,
        /// Hard cap on total entities. Stops expansion when reached.
        #[arg(long)]
        max_entities: Option<usize>,
        /// Hard cap on total wall-time in seconds. Stops expansion when exceeded.
        #[arg(long)]
        max_wall_time: Option<u64>,
        /// Modules to run in parallel per round (v0.8+). 0 = sequential
        /// (default). Higher values cut wall-time on modules that are
        /// I/O-bound — most useful with `--depth` for big expansion rounds.
        #[arg(long, default_value_t = 0)]
        max_concurrent: usize,
        /// Output format: table | json.
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
            min_expand_confidence,
            max_entities,
            max_wall_time,
            max_concurrent,
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
                min_expand_confidence,
                max_entities,
                max_wall_time_secs: max_wall_time,
                max_concurrent,
                output,
            })
            .await
        }
        Command::Modules => cmd_modules(),
        Command::Doctor => cmd_doctor(),
        Command::Provision {
            env_only,
            verify_only,
            dry_run,
        } => cmd_provision(env_only, verify_only, dry_run).await,
        Command::SetKey { name, value } => cmd_set_key(name, value),
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
        ("ip", TargetKind::IpAddress),
        ("asn", TargetKind::Asn),
        ("name", TargetKind::FullName),
        ("coords", TargetKind::Coordinates),
        ("address", TargetKind::Address),
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

fn cmd_doctor() -> Result<()> {
    let mods = registry();
    println!("HSE v{} — doctor\n", crate::VERSION);
    println!(
        "Termux:    {}",
        if is_termux() {
            "detected"
        } else {
            "not detected"
        }
    );
    println!("DB path:   {}", default_db_path());
    println!("Keys path: {}", keys::env_path());

    println!("\nStorage:");
    match Store::open(&default_db_path()) {
        Ok(_) => println!("  ok — database opens cleanly"),
        Err(e) => println!("  FAIL — {e}"),
    }

    println!("\nModules ({} registered):", mods.len());
    let mut by_cost = std::collections::BTreeMap::<&str, usize>::new();
    for m in &mods {
        *by_cost.entry(cost_label(m.cost())).or_default() += 1;
    }
    for (cost, count) in &by_cost {
        println!("  {cost:<10} {count}");
    }

    let loaded = keys::load();
    let huntsman_keys: Vec<_> = loaded
        .keys()
        .filter(|k| k.starts_with("HUNTSMAN_"))
        .collect();
    println!("\nHUNTSMAN_* keys loaded: {}", huntsman_keys.len());
    for k in &huntsman_keys {
        println!("  - {k}");
    }
    if huntsman_keys.is_empty() {
        println!("  (none set; all free modules still work)");
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
        "asn" => Ok(TargetKind::Asn),
        "coordinates" | "coords" => Ok(TargetKind::Coordinates),
        "address" => Ok(TargetKind::Address),
        other => Err(Error::InvalidTarget(format!(
            "unknown target kind '{other}'. Valid: email, username, phone, name, ip, domain, asn, coords, address"
        ))),
    }
}

fn cost_label(c: ModuleCost) -> &'static str {
    match c {
        ModuleCost::Free => "free",
        ModuleCost::KeyGated => "key-gated",
        ModuleCost::Paid => "paid",
    }
}

fn split_csv(s: Option<String>) -> Option<Vec<String>> {
    s.map(|s| s.split(',').map(|m| m.trim().to_string()).collect())
}

fn build_runtime(
    bus_capacity: usize,
) -> Result<(Arc<Store>, crate::core::event::EventBus, Arc<ScanEngine>)> {
    let store = Arc::new(Store::open(&default_db_path())?);
    let (bus, _rx) = tokio::sync::broadcast::channel(bus_capacity);
    let engine = Arc::new(ScanEngine::new(registry(), Arc::clone(&store), bus.clone()));
    Ok((store, bus, engine))
}

fn truncate(s: &str, max: usize) -> String {
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
