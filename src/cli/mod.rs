//! CLI: scan / modules / doctor / serve / live / provision / set-key / keys.
//!
//! Surfaces every `ScanOptions` field as a flag so each scan is fully
//! customisable before launch. `serve` boots the HTTP server + SPA;
//! `live` re-runs the same scan on a fixed interval (v0.5+). See
//! `docs/USAGE.md` for the full reference.

mod provision;

use std::io::IsTerminal;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::{
    core::{
        engine::ScanEngine,
        error::{Error, Result},
        module::{ModuleContext, ModuleCost},
        scan::{Scan, ScanOptions, Target, TargetKind},
    },
    default_db_path, is_termux,
    modules::registry,
    storage::Store,
    util::{http::build_client, keys, uid::scan_id},
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
}

#[derive(Subcommand)]
pub enum KeysAction {
    /// Add a key to the pool for a service.
    Add {
        /// Service name (shodan, intelx, dehashed, wigle, etc.)
        service: String,
        /// The API key value.
        key: String,
        /// Optional notes (e.g. "free tier", "expires 2026-12").
        #[arg(long)]
        notes: Option<String>,
    },
    /// List all keys in the pool.
    List {
        /// Filter by service name.
        service: Option<String>,
    },
    /// Validate keys against live endpoints.
    Validate {
        /// Validate only this service. Omit to validate all.
        service: Option<String>,
    },
    /// Remove a key from the pool.
    Remove {
        /// Service name.
        service: String,
        /// Key value to remove.
        key: String,
    },
    /// Show pool status summary.
    Status,
    /// List supported service names and their categories.
    Services,
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
            output,
        } => {
            cmd_scan(ScanCmd {
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
        Command::Keys { action } => cmd_keys(action).await,
        Command::Serve {
            bind,
            allow_key_write,
        } => cmd_serve(bind, allow_key_write).await,
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
            cmd_live(LiveCmd {
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
        } => cmd_radar(interval, depth, sweeps, free_only).await,
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

async fn cmd_keys(action: KeysAction) -> Result<()> {
    use crate::util::key_pool::{self, KeyEntry, KeyStatus};

    let pool = key_pool::global_pool();

    match action {
        KeysAction::Add {
            service,
            key,
            notes,
        } => {
            if key_pool::find_service(&service).is_none() {
                let names: Vec<&str> = key_pool::service_defs().iter().map(|s| s.name).collect();
                println!("Unknown service '{service}'. Known: {}", names.join(", "));
                println!("Adding anyway — key will be stored but not auto-validated.");
            }
            let mut entry = KeyEntry::new(&key);
            entry.notes = notes;
            if pool.add(&service, entry) {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
                println!(
                    "Added key to '{service}' pool ({} total)",
                    pool.service_count(&service)
                );
            } else {
                println!("Key already exists in '{service}' pool.");
            }
        }

        KeysAction::List { service } => {
            let snap = pool.snapshot();
            let services: Vec<(&String, &Vec<KeyEntry>)> = if let Some(ref s) = service {
                let lower = s.to_lowercase();
                snap.services.iter().filter(|(k, _)| **k == lower).collect()
            } else {
                snap.services.iter().collect()
            };

            if services.is_empty() {
                println!("No keys in pool.");
                return Ok(());
            }

            for (svc, entries) in &services {
                println!("\n[{svc}] ({} keys)", entries.len());
                for (i, e) in entries.iter().enumerate() {
                    let masked = if e.value.len() > 8 {
                        format!("{}…{}", &e.value[..4], &e.value[e.value.len() - 4..])
                    } else {
                        e.value.clone()
                    };
                    let notes = e.notes.as_deref().unwrap_or("");
                    println!(
                        "  {}: {} [{}] uses={} {}",
                        i + 1,
                        masked,
                        e.status.as_str(),
                        e.use_count,
                        notes
                    );
                }
            }
        }

        KeysAction::Validate { service } => {
            let snap = pool.snapshot();
            let targets: Vec<(String, Vec<KeyEntry>)> = if let Some(ref s) = service {
                let lower = s.to_lowercase();
                snap.services
                    .into_iter()
                    .filter(|(k, _)| *k == lower)
                    .collect()
            } else {
                snap.services.into_iter().collect()
            };

            if targets.is_empty() {
                println!("No keys to validate.");
                return Ok(());
            }

            let mut validated = 0u32;
            let mut active = 0u32;
            for (svc, entries) in &targets {
                for entry in entries {
                    print!(
                        "  {svc}: testing {}… ",
                        &entry.value[..entry.value.len().min(8)]
                    );
                    match key_pool::validate_key(svc, &entry.value).await {
                        Some(true) => {
                            pool.mark_validated(svc, &entry.value, true);
                            println!("ACTIVE");
                            active += 1;
                        }
                        Some(false) => {
                            pool.mark_validated(svc, &entry.value, false);
                            println!("INVALID");
                        }
                        None => {
                            println!("UNKNOWN (no validator for service)");
                        }
                    }
                    validated += 1;
                }
            }
            key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
            println!("\nValidated {validated} keys: {active} active.");
        }

        KeysAction::Remove { service, key } => {
            if pool.remove(&service, &key) {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
                println!("Removed key from '{service}' pool.");
            } else {
                println!("Key not found in '{service}' pool.");
            }
        }

        KeysAction::Status => {
            let snap = pool.snapshot();
            if snap.services.is_empty() {
                println!("Key pool is empty. Use `hse keys add <service> <key>` to add keys.");
                println!("\nPool file: {}", key_pool::pool_path().display());
                return Ok(());
            }

            println!(
                "{:<20} {:>5} {:>6} {:>7} {:>8}  CATEGORY",
                "SERVICE", "TOTAL", "ACTIVE", "INVALID", "USED"
            );
            println!("{}", "-".repeat(65));

            let mut sorted: Vec<_> = snap.services.iter().collect();
            sorted.sort_by_key(|(a, _)| *a);

            for (svc, entries) in &sorted {
                let active = entries.iter().filter(|e| e.is_usable()).count();
                let invalid = entries
                    .iter()
                    .filter(|e| e.status == KeyStatus::Invalid)
                    .count();
                let total_uses: u64 = entries.iter().map(|e| e.use_count).sum();
                let cat = key_pool::find_service(svc).map_or("custom", |d| d.category);
                println!(
                    "{:<20} {:>5} {:>6} {:>7} {:>8}  {cat}",
                    svc,
                    entries.len(),
                    active,
                    invalid,
                    total_uses
                );
            }
            println!(
                "\nTotal: {} keys ({} active) across {} services",
                pool.total_keys(),
                pool.total_active(),
                snap.services.len()
            );
            println!("Pool file: {}", key_pool::pool_path().display());
        }

        KeysAction::Services => {
            let defs = key_pool::service_defs();
            println!(
                "{:<18} {:<14} {:<26} ENV VAR",
                "SERVICE", "CATEGORY", "TEST ENDPOINT"
            );
            println!("{}", "-".repeat(85));
            for d in &defs {
                let short_url = if d.test_url.len() > 25 {
                    format!("{}…", &d.test_url[..24])
                } else {
                    d.test_url.to_string()
                };
                println!(
                    "{:<18} {:<14} {:<26} {}",
                    d.name, d.category, short_url, d.env_var
                );
            }
        }
    }
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
) -> Result<(
    Arc<dyn crate::core::port::StoragePort>,
    crate::core::event::EventBus,
    Arc<ScanEngine>,
)> {
    let store: Arc<dyn crate::core::port::StoragePort> = Arc::new(Store::open(&default_db_path())?);
    let (bus, _rx) = tokio::sync::broadcast::channel(bus_capacity);
    let engine = Arc::new(ScanEngine::new(registry(), Arc::clone(&store), bus.clone()));
    Ok((store, bus, engine))
}

fn use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

fn color_confidence(c_eff: f64, text: &str, color: bool) -> String {
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

fn color_severity(severity: &str, color: bool) -> String {
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

fn print_dossier(
    scan: &crate::core::scan::Scan,
    entities: &[crate::core::entity::Entity],
    correlations: &[crate::core::correlator::Correlation],
    kind: &str,
    value: &str,
    sid: &str,
) {
    use std::collections::BTreeMap;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  HUNTSMAN SEARCH ENGINE — INTELLIGENCE DOSSIER              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    {} = {}", kind, value);
    println!("  Scan ID:   {}", &sid[..16]);
    println!("  Status:    {}", scan.status.as_str());
    println!("  Entities:  {}", scan.entity_count);
    println!(
        "  Modules:   {} run, {} errored",
        scan.modules_run, scan.modules_errored
    );
    println!();

    // Group by kind
    let mut by_kind: BTreeMap<String, Vec<&crate::core::entity::Entity>> = BTreeMap::new();
    for e in entities {
        by_kind.entry(e.kind.to_string()).or_default().push(e);
    }

    // Priority order for dossier
    let kind_order = [
        "person",
        "email",
        "phone",
        "username",
        "credential",
        "address",
        "coordinates",
        "organisation",
        "abn_acn",
        "domain",
        "ip_address",
        "url",
        "mac_address",
        "device_id",
    ];

    for kind_name in &kind_order {
        let Some(group) = by_kind.get(*kind_name) else {
            continue;
        };
        let header = match *kind_name {
            "person" => "PERSONS",
            "email" => "EMAIL ADDRESSES",
            "phone" => "PHONE NUMBERS",
            "username" => "USERNAMES / HANDLES",
            "credential" => "CREDENTIALS (from breach/stealer data)",
            "address" => "PHYSICAL ADDRESSES / LOCATIONS",
            "coordinates" => "GPS COORDINATES",
            "organisation" => "ORGANISATIONS",
            "abn_acn" => "ABN / ACN (Australian Business Numbers)",
            "domain" => "DOMAINS",
            "ip_address" => "IP ADDRESSES",
            "url" => "URLS / PROFILES",
            "mac_address" => "MAC ADDRESSES (network devices)",
            "device_id" => "DEVICE IDENTIFIERS",
            other => other,
        };

        println!("━━━ {} ({}) ━━━", header, group.len());
        println!();

        let mut sorted = group.clone();
        sorted.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for e in &sorted {
            let c_eff = e.c_effective();
            let class = e.classify();
            println!(
                "  {} [{}]  conf={:.2}  c_eff={:.2}  corr={}",
                e.value, class, e.confidence, c_eff, e.corroboration
            );

            if !e.tags.is_empty() {
                println!("    tags: {}", e.tags.join(", "));
            }

            for ev in &e.evidence {
                println!("    ├─ {} — {}", ev.source, ev.summary);
                for (k, v) in &ev.attributes {
                    if !v.is_empty() && v.len() <= 120 {
                        println!("    │  {}: {}", k, v);
                    }
                }
            }
            println!();
        }
    }

    // Correlations
    if !correlations.is_empty() {
        println!("━━━ CORRELATIONS ({}) ━━━", correlations.len());
        println!();
        for c in correlations {
            let sev = match c.severity.to_string().as_str() {
                "CRITICAL" => "🔴 CRITICAL",
                "HIGH" => "🟠 HIGH",
                "MEDIUM" => "🟡 MEDIUM",
                _ => "🔵 LOW",
            };
            println!("  {} [{}] {}", c.rule_id, sev, c.rule_name);
            println!("    {}", c.description);
            println!();
        }
    }

    println!("━━━ END OF DOSSIER ━━━");
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

// ─── serve command ─────────────────────────────────────────────────────────

async fn cmd_serve(bind: String, allow_key_write: bool) -> Result<()> {
    use std::net::SocketAddr;

    use crate::api::{AppState, routes::router};
    use crate::core::live::LiveScanner;

    let (store, bus, engine) = build_runtime(1024)?;
    let http = build_client();
    let live = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        http.clone(),
        crate::util::keys::populate_and_load().await,
    );
    let state = Arc::new(AppState {
        store,
        engine,
        bus,
        live,
        http,
        allow_key_write,
        cancellations: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
            crate::api::MAX_CONCURRENT_SCANS,
        )),
    });

    let app = router(state, &bind);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| Error::Other(format!("bind {bind}: {e}")))?;

    tracing::info!("hse v{} — listening on http://{}", crate::VERSION, bind);
    tracing::info!("  open in Chrome / Firefox on this device");
    if allow_key_write {
        tracing::warn!("--allow-key-write: PUT /api/v1/settings/keys enabled (loopback only)");
    }
    tracing::info!("  Ctrl-C to stop");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| Error::Other(format!("serve: {e}")))?;

    tracing::info!("server stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

// ─── live command ──────────────────────────────────────────────────────────

struct LiveCmd {
    pub kind: String,
    pub value: String,
    pub interval: u64,
    pub iterations: Option<u32>,
    pub depth: u32,
    pub free_only: bool,
    pub passive_only: bool,
    pub modules: Option<String>,
}

async fn cmd_live(cmd: LiveCmd) -> Result<()> {
    use crate::core::live::{LiveOptions, LiveScanner};
    use tokio_stream::StreamExt;
    use tokio_stream::wrappers::BroadcastStream;

    let target_kind = parse_target_kind(&cmd.kind)?;
    let target = Target::new(target_kind, cmd.value.clone());

    let scan_options = ScanOptions {
        modules: split_csv(cmd.modules),
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth: cmd.depth,
        ..Default::default()
    };
    let live_options = LiveOptions {
        interval_secs: cmd.interval,
        iterations: cmd.iterations,
    };

    let (_store, bus, engine) = build_runtime(1024)?;
    let scanner = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        crate::util::http::build_client(),
        crate::util::keys::populate_and_load().await,
    );

    let live_id = scanner.start(target, scan_options, live_options);
    eprintln!("live session {live_id} — Ctrl-C to stop");

    let rx = bus.subscribe();
    let scanner_clone = scanner.clone();
    let target_lid = live_id.clone();
    let mut stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(event)
            if event.scan_id == target_lid
                || scanner_clone.session_owns_scan(&target_lid, &event.scan_id) =>
        {
            let is_terminator =
                matches!(event.kind, crate::core::event::EventKind::LiveStop { .. });
            let line = serde_json::to_string(&event.kind).unwrap_or_default();
            Some((line, is_terminator))
        }
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
            eprintln!("warning: event stream lagged, {n} event(s) dropped");
            None
        }
        _ => None,
    });

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nstopping live session…");
                scanner.stop(&live_id);
            }
            line = stream.next() => match line {
                Some((s, is_terminator)) => {
                    println!("{s}");
                    if is_terminator {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    Ok(())
}

// ─── scan command ──────────────────────────────────────────────────────────

struct ScanCmd {
    pub kind: String,
    pub value: String,
    pub modules: Option<String>,
    pub exclude: Option<String>,
    pub throttle_ms: u64,
    pub min_confidence: Option<f64>,
    pub free_only: bool,
    pub passive_only: bool,
    pub module_timeout_ms: Option<u64>,
    pub depth: u32,
    pub recursive: bool,
    pub auto: bool,
    pub min_expand_confidence: f64,
    pub max_entities: Option<usize>,
    pub max_wall_time_secs: Option<u64>,
    pub max_concurrent: usize,
    pub output: String,
}

async fn cmd_scan(cmd: ScanCmd) -> crate::core::error::Result<()> {
    let target_kind = parse_target_kind(&cmd.kind)?;
    let target = Target::new(target_kind, cmd.value.clone());

    let (depth, min_expand_confidence, max_concurrent) = if cmd.auto && cmd.depth == 0 {
        let has_paid = keys::load().contains_key("HUNTSMAN_OATHNET_KEY");
        let (auto_depth, auto_conf) = crate::core::scan::optimal_depth(target_kind, has_paid);
        eprintln!(
            "auto: depth={auto_depth} min_conf={auto_conf:.2} (paid_keys={})",
            has_paid
        );
        (auto_depth, auto_conf, cmd.max_concurrent.max(4))
    } else if cmd.recursive && cmd.depth == 0 {
        (
            7,
            cmd.min_expand_confidence.min(0.40),
            cmd.max_concurrent.max(4),
        )
    } else {
        (cmd.depth, cmd.min_expand_confidence, cmd.max_concurrent)
    };

    let options = ScanOptions {
        modules: split_csv(cmd.modules),
        exclude_modules: split_csv(cmd.exclude).unwrap_or_default(),
        throttle_ms: cmd.throttle_ms,
        max_concurrent,
        module_timeout_ms: cmd.module_timeout_ms,
        min_confidence: cmd.min_confidence,
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth,
        min_expand_confidence,
        max_entities: cmd.max_entities,
        max_wall_time_secs: cmd.max_wall_time_secs,
        scan_tags: Vec::new(),
        notes: None,
    };

    let sid = scan_id(target_kind.canonical_str(), &cmd.value);
    let (store, bus, engine) = build_runtime(64)?;

    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);
    let keys = keys::populate_and_load().await;
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys,
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    };

    let scan = engine.run(scan, target, ctx).await?;
    let entities = store.entities_for_scan(&sid)?;
    let correlations = store.correlations_for_scan(&sid)?;

    if cmd.output == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "scan": scan,
                "entities": entities,
                "correlations": correlations,
            }))?
        );
    } else if cmd.output == "dossier" {
        print_dossier(&scan, &entities, &correlations, &cmd.kind, &cmd.value, &sid);
    } else {
        let color = use_color();
        println!(
            "\nScan {} — {} entities for {}={}",
            &sid[..8],
            entities.len(),
            cmd.kind,
            cmd.value
        );
        if scan.modules_run > 0 {
            println!(
                "  modules: {} run, {} errored, {} timed out\n",
                scan.modules_run, scan.modules_errored, scan.modules_timed_out
            );
        } else {
            println!();
        }
        println!(
            "{:<16} {:<42} {:>6} {:>6}  {:<10} SRCS",
            "KIND", "VALUE", "CONF", "C_EFF", "CLASS"
        );
        println!("{}", "-".repeat(90));
        for e in &entities {
            let val = truncate(&e.value, 42);
            let c_eff = e.c_effective();
            let class = e.classify();
            let sources = e.evidence.len();
            let row = format!(
                "{:<16} {:<42} {:>6.3} {:>6.3}  {:<10} {}",
                e.kind, val, e.confidence, c_eff, class, sources
            );
            println!("{}", color_confidence(c_eff, &row, color));
        }
        if !correlations.is_empty() {
            println!("\n{} correlations:\n", correlations.len());
            println!(
                "{:<10} {:<10} {:<40} DESCRIPTION",
                "RULE", "SEVERITY", "NAME"
            );
            println!("{}", "-".repeat(86));
            for c in &correlations {
                let sev_padded = format!("{:<10}", c.severity);
                let sev_colored = color_severity(&sev_padded, color);
                println!(
                    "{:<10} {} {:<40} {}",
                    c.rule_id,
                    sev_colored,
                    truncate(&c.rule_name, 40),
                    c.description
                );
            }
        }
    }
    Ok(())
}

// ─── Radar command ───────────────────────────────────────────────────────────

const SENSOR_MODULES: &[&str] = &["device_sensors", "wifi_intel", "cell_intel", "local_net"];

async fn cmd_radar(interval: u64, depth: u32, sweeps: Option<u32>, free_only: bool) -> Result<()> {
    use std::collections::HashSet;

    let color = use_color();
    eprintln!(
        "{}",
        color_confidence(
            0.85,
            &format!("HSE radar — sweep every {interval}s, depth={depth}, Ctrl-C to stop"),
            color
        )
    );

    let (store, bus, engine) = build_runtime(1024)?;
    let mut seen_entities: HashSet<String> = HashSet::new();
    let mut sweep_num = 0u32;

    loop {
        sweep_num += 1;
        if let Some(max) = sweeps
            && sweep_num > max
        {
            break;
        }

        eprintln!(
            "\n{}",
            color_confidence(0.85, &format!("── sweep {sweep_num} ──"), color)
        );

        // Phase 1: Sensor sweep (passive modules only, any target, depth=0)
        let sweep_sid = scan_id("radar", &format!("sweep-{sweep_num}"));
        let sweep_target = Target::new(crate::core::scan::TargetKind::Domain, "radar.local");
        let sweep_opts = ScanOptions {
            modules: Some(SENSOR_MODULES.iter().map(|s| (*s).to_string()).collect()),
            passive_only: true,
            depth: 0,
            max_concurrent: 4,
            ..Default::default()
        };
        let sweep_scan =
            Scan::new(sweep_sid.clone(), sweep_target.clone()).with_options(sweep_opts);
        let sweep_keys = keys::load();
        let sweep_ctx = ModuleContext {
            scan_id: sweep_sid.clone(),
            bus: bus.clone(),
            http: crate::util::http::build_client(),
            keys: sweep_keys,
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: Arc::new(crate::util::proxy::ProxyPool::new()),
        };

        let sweep_result = engine.run(sweep_scan, sweep_target, sweep_ctx).await?;
        let sweep_entities = store.entities_for_scan(&sweep_sid)?;

        // Phase 2: Identify NEW entities (not seen in previous sweeps)
        let mut new_targets: Vec<(crate::core::scan::TargetKind, String)> = Vec::new();
        for entity in &sweep_entities {
            if seen_entities.insert(entity.uid.clone())
                && let Some(tk) = crate::core::scan::TargetKind::from_entity_kind(&entity.kind)
            {
                eprintln!(
                    "  {} new: {} = {}",
                    color_confidence(0.85, "◉", color),
                    entity.kind,
                    entity.value
                );
                new_targets.push((tk, entity.value.clone()));
            }
        }

        if new_targets.is_empty() {
            eprintln!(
                "  {} no new signals ({} entities, {} known)",
                color_confidence(0.3, "○", color),
                sweep_result.entity_count,
                seen_entities.len()
            );
        } else {
            eprintln!(
                "  {} {} new signal(s) → pivoting at depth {depth}",
                color_confidence(0.85, "▶", color),
                new_targets.len()
            );

            // Phase 3: Pivot on each new discovery through the full pipeline
            for (tk, value) in &new_targets {
                let pivot_sid = scan_id(tk.canonical_str(), value);
                let pivot_target = Target::new(*tk, value.clone());
                let pivot_opts = ScanOptions {
                    depth,
                    free_only,
                    max_concurrent: 4,
                    min_expand_confidence: 0.50,
                    ..Default::default()
                };
                let pivot_scan =
                    Scan::new(pivot_sid.clone(), pivot_target.clone()).with_options(pivot_opts);
                let pivot_keys = keys::load();
                let pivot_ctx = ModuleContext {
                    scan_id: pivot_sid.clone(),
                    bus: bus.clone(),
                    http: crate::util::http::build_client(),
                    keys: pivot_keys,
                    cancel: crate::core::cancel::CancelHandle::new(),
                    proxy_pool: Arc::new(crate::util::proxy::ProxyPool::new()),
                };

                let result = engine.run(pivot_scan, pivot_target, pivot_ctx).await?;
                let pivot_entities = store.entities_for_scan(&pivot_sid)?;

                // Add pivot results to seen set
                for e in &pivot_entities {
                    seen_entities.insert(e.uid.clone());
                }

                eprintln!(
                    "    {} {}={} → {} entities ({}run/{}err/{}to)",
                    color_confidence(0.7, "↳", color),
                    tk.canonical_str(),
                    truncate(value, 30),
                    result.entity_count,
                    result.modules_run,
                    result.modules_errored,
                    result.modules_timed_out,
                );

                // Stream key findings to stdout as JSON
                for e in &pivot_entities {
                    if e.c_effective() >= 0.50 {
                        let json = serde_json::json!({
                            "sweep": sweep_num,
                            "kind": e.kind.to_string(),
                            "value": e.value,
                            "confidence": e.confidence,
                            "c_eff": e.c_effective(),
                            "sources": e.evidence.len(),
                            "tags": e.tags,
                        });
                        println!("{}", serde_json::to_string(&json).unwrap_or_default());
                    }
                }
            }
        }

        // Wait for next sweep
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nradar stopped");
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
        }
    }

    eprintln!(
        "\n{} sweeps, {} unique entities discovered",
        sweep_num.min(sweeps.unwrap_or(sweep_num)),
        seen_entities.len()
    );
    Ok(())
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
