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
        Command::Import { file, output } => cmd_import(&file, &output).await,
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

async fn cmd_import(path: &str, output: &str) -> Result<()> {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("cannot read {path}: {e}")))?;

    let is_html = path.ends_with(".html") || body.trim_start().starts_with("<!") || body.trim_start().starts_with("<html");
    let is_txt = path.ends_with(".txt") && !is_html;

    if is_html {
        return cmd_import_html(&body, output);
    }
    if is_txt {
        return cmd_import_txt(&body, output);
    }

    let doc: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| Error::Other(format!("invalid JSON: {e}")))?;

    let export_info = doc.get("exportInfo").and_then(|v| v.as_object());
    let query = export_info
        .and_then(|ei| ei.get("query"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let date = export_info
        .and_then(|ei| ei.get("exportDate"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!("Importing OathNet JSON export: query=\"{query}\", date={date}");

    let sid = format!("import-{}", &crate::core::entity::unix_now().to_string());
    let mut entities: Vec<Entity> = Vec::new();
    let mut stats = ImportStats::default();

    // ── Parse breach results ──
    if let Some(breach) = doc
        .pointer("/searchResults/MULTI_SERVICE_RESULTS/breach/data/results")
        .and_then(|v| v.as_array())
    {
        for item in breach {
            stats.breach_records += 1;
            if let Some(email) = item.get("email").and_then(|v| v.as_str()) {
                if email.contains('@') && !email.contains("UPGRADE") {
                    let db = item
                        .get("dbname")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let mut e = Entity::new(EntityKind::Email, email, 0.75, &sid);
                    e.tag("breach");
                    e.tag("import");
                    e.add_evidence(
                        Evidence::new("import:oathnet", format!("Breach on {db}"))
                            .with_attr("dbname", db),
                    );
                    entities.push(e);
                    stats.emails += 1;
                }
            }
            if let Some(ip) = item.get("ip").and_then(|v| v.as_str()) {
                if ip.contains('.') && !ip.contains("UPGRADE") {
                    let mut e = Entity::new(EntityKind::IpAddress, ip, 0.65, &sid);
                    e.tag("breach");
                    e.tag("import");
                    entities.push(e);
                    stats.ips += 1;
                }
            }
        }
    }

    // ── Parse stealer victims — IPs, emails, HWIDs, Discord IDs, severity ──
    if let Some(victims) = doc
        .pointer("/stealerData/victims")
        .and_then(|v| v.as_array())
    {
        let mut seen_hwids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen_discord: std::collections::HashSet<String> = std::collections::HashSet::new();

        for victim in victims {
            stats.victim_records += 1;
            let total_docs = victim.get("total_docs").and_then(|v| v.as_u64()).unwrap_or(0);
            let log_id = victim.get("log_id").and_then(|v| v.as_str()).unwrap_or("");

            if let Some(ips) = victim.get("device_ips").and_then(|v| v.as_array()) {
                for ip_val in ips.iter().take(10) {
                    if let Some(ip) = ip_val.as_str() {
                        if ip.contains('.') && !ip.contains("UPGRADE") {
                            let mut e =
                                Entity::new(EntityKind::IpAddress, ip, 0.60, &sid);
                            e.tag("stealer-victim");
                            e.tag("import");
                            if total_docs > 100 {
                                e.tag("high-exposure");
                            }
                            e.add_evidence(
                                Evidence::new("import:oathnet", format!("Victim device IP ({total_docs} creds stolen)"))
                                    .with_attr("log_id", log_id)
                                    .with_attr("total_docs", total_docs.to_string()),
                            );
                            entities.push(e);
                            stats.ips += 1;
                        }
                    }
                }
            }
            if let Some(emails) = victim.get("device_emails").and_then(|v| v.as_array()) {
                for email_val in emails.iter().take(20) {
                    if let Some(email) = email_val.as_str() {
                        if email.contains('@') && !email.contains("UPGRADE") {
                            let mut e =
                                Entity::new(EntityKind::Email, email, 0.55, &sid);
                            e.tag("stealer-victim");
                            e.tag("import");
                            entities.push(e);
                            stats.emails += 1;
                        }
                    }
                }
            }
            // HWIDs — hardware identifiers for machine tracking
            if let Some(hwids) = victim.get("hwids").and_then(|v| v.as_array()) {
                for h in hwids.iter().take(5) {
                    if let Some(hwid) = h.as_str() {
                        if !hwid.is_empty() && seen_hwids.insert(hwid.to_string()) {
                            let mut e = Entity::new(EntityKind::DeviceId, hwid, 0.70, &sid);
                            e.tag("hwid");
                            e.tag("import");
                            e.add_evidence(
                                Evidence::new("import:oathnet", format!("Hardware ID from infected machine ({total_docs} creds)"))
                                    .with_attr("log_id", log_id),
                            );
                            entities.push(e);
                            stats.hwids += 1;
                        }
                    }
                }
            }
            // Discord IDs — identity pivots
            if let Some(dids) = victim.get("discord_ids").and_then(|v| v.as_array()) {
                for d in dids.iter().take(5) {
                    if let Some(did) = d.as_str() {
                        if !did.is_empty() && seen_discord.insert(did.to_string()) {
                            let mut e = Entity::new(EntityKind::Username, did, 0.60, &sid);
                            e.tag("discord-id");
                            e.tag("import");
                            entities.push(e);
                            stats.discord_ids += 1;
                        }
                    }
                }
            }
        }
    }

    // ── Parse stealer docs — domains, subdomains, URLs, usernames, timelines ──
    if let Some(docs) = doc
        .pointer("/stealerData/docs")
        .and_then(|v| v.as_array())
    {
        let mut seen_domains: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut seen_users: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut seen_urls: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut log_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut earliest_date: Option<String> = None;
        let mut latest_date: Option<String> = None;

        for doc_item in docs {
            stats.stealer_docs += 1;

            // Domains
            if let Some(domains) = doc_item.get("domain").and_then(|v| v.as_array()) {
                for d in domains {
                    if let Some(domain) = d.as_str() {
                        let lower = domain.to_lowercase();
                        if seen_domains.insert(lower.clone()) && domain.contains('.') {
                            let mut e =
                                Entity::new(EntityKind::Domain, &lower, 0.50, &sid);
                            e.tag("stealer-target");
                            e.tag("import");
                            entities.push(e);
                            stats.domains += 1;
                        }
                    }
                }
            }

            // Subdomains
            if let Some(subs) = doc_item.get("subdomain").and_then(|v| v.as_array()) {
                for s in subs {
                    if let Some(sub) = s.as_str() {
                        let lower = sub.to_lowercase();
                        if lower.contains('.') && seen_domains.insert(format!("sub:{lower}")) {
                            let mut e =
                                Entity::new(EntityKind::Domain, &lower, 0.55, &sid);
                            e.tag("subdomain");
                            e.tag("stealer-target");
                            e.tag("import");
                            entities.push(e);
                            stats.subdomains += 1;
                        }
                    }
                }
            }

            // URLs (compromised login/register pages)
            if let Some(url) = doc_item.get("url").and_then(|v| v.as_str()) {
                if url.starts_with("http") && seen_urls.insert(url.to_string()) {
                    let mut e = Entity::new(EntityKind::Url, url, 0.45, &sid);
                    e.tag("stealer-target");
                    e.tag("import");
                    entities.push(e);
                    stats.urls += 1;
                }
            }

            // Usernames (identity pivots)
            if let Some(username) = doc_item.get("username").and_then(|v| v.as_str()) {
                if !username.is_empty()
                    && username.len() >= 3
                    && seen_users.insert(username.to_lowercase())
                {
                    let conf = if username.contains('@') { 0.55 } else { 0.40 };
                    let kind = if username.contains('@') {
                        EntityKind::Email
                    } else {
                        EntityKind::Username
                    };
                    let mut e = Entity::new(kind, username, conf, &sid);
                    e.tag("stealer-username");
                    e.tag("import");
                    entities.push(e);
                    stats.usernames += 1;
                }
            }

            // Log IDs (unique infected machines) → DeviceId entities
            if let Some(lid) = doc_item.get("log_id").and_then(|v| v.as_str()) {
                if log_ids.insert(lid.to_string()) {
                    let mut e = Entity::new(EntityKind::DeviceId, lid, 0.50, &sid);
                    e.tag("log-id");
                    e.tag("import");
                    entities.push(e);
                }
            }

            // Paths (login/admin/API endpoints)
            if let Some(paths) = doc_item.get("path").and_then(|v| v.as_array()) {
                for p in paths {
                    if let Some(path) = p.as_str() {
                        let pl = path.to_lowercase();
                        if (pl.contains("admin") || pl.contains("api") || pl.contains("login")
                            || pl.contains("dashboard") || pl.contains("panel"))
                            && seen_urls.insert(format!("path:{path}"))
                        {
                            if let Some(doms) = doc_item.get("domain").and_then(|v| v.as_array()) {
                                if let Some(dom) = doms.first().and_then(|d| d.as_str()) {
                                    let full_url = format!("https://{dom}{path}");
                                    let mut e = Entity::new(EntityKind::Url, &full_url, 0.50, &sid);
                                    e.tag("admin-panel");
                                    e.tag("import");
                                    entities.push(e);
                                    stats.admin_paths += 1;
                                }
                            }
                        }
                    }
                }
            }

            // API key pattern scanning on password field
            if let Some(pw) = doc_item.get("password").and_then(|v| v.as_str()) {
                if !pw.is_empty() && pw.len() >= 20 {
                    let is_key = pw.starts_with("sk-") || pw.starts_with("pk_")
                        || pw.starts_with("ghp_") || pw.starts_with("gho_")
                        || pw.starts_with("SG.") || pw.starts_with("xoxb-")
                        || pw.starts_with("xoxp-") || pw.starts_with("AKIA")
                        || pw.starts_with("AIzaSy") || pw.starts_with("hf_")
                        || pw.starts_with("r8_") || pw.starts_with("npm_")
                        || pw.starts_with("sk_live_") || pw.starts_with("rk_live_")
                        || pw.starts_with("whsec_") || pw.starts_with("sntrys_")
                        || pw.starts_with("glc_") || pw.starts_with("NRAK-")
                        || pw.starts_with("dop_v1_") || pw.starts_with("ntn_")
                        || pw.starts_with("eyJ") || pw.starts_with("github_pat_")
                        || (pw.len() == 32 && pw.chars().all(|c| c.is_ascii_hexdigit()))
                        || (pw.len() == 64 && pw.chars().all(|c| c.is_ascii_hexdigit()));
                    if is_key {
                        let svc = if pw.starts_with("sk-ant-") { "anthropic" }
                            else if pw.starts_with("sk-proj-") { "openai" }
                            else if pw.starts_with("sk-") { "openai_or_stripe" }
                            else if pw.starts_with("ghp_") || pw.starts_with("github_pat_") { "github" }
                            else if pw.starts_with("AKIA") { "aws" }
                            else if pw.starts_with("AIzaSy") { "google" }
                            else if pw.starts_with("SG.") { "sendgrid" }
                            else if pw.starts_with("hf_") { "huggingface" }
                            else if pw.starts_with("sk_live_") { "stripe" }
                            else if pw.starts_with("xoxb-") { "slack" }
                            else if pw.starts_with("npm_") { "npm" }
                            else if pw.starts_with("dop_v1_") { "digitalocean" }
                            else { "generic_key" };

                        let display = format!("{}:{}...{}",
                            svc,
                            &pw[..pw.len().min(8)],
                            &pw[pw.len().saturating_sub(4)..]);
                        let mut e = Entity::new(EntityKind::ApiKey, &display, 0.80, &sid);
                        e.tag("api-key");
                        e.tag(format!("service:{svc}"));
                        e.tag("import");
                        e.add_evidence(
                            Evidence::new("import:oathnet", format!("API key pattern ({svc}) in stealer data"))
                                .with_attr("service", svc)
                                .with_attr("key_length", pw.len().to_string()),
                        );
                        entities.push(e);
                        stats.api_keys += 1;

                        // Store in key pool for automatic use
                        let pool = crate::util::key_pool::global_pool();
                        let mut entry = crate::util::key_pool::KeyEntry::new(pw);
                        entry.notes = Some(format!("Import: {svc} key from stealer data"));
                        pool.add(svc, entry);
                    }
                }
            }

            // Infection timeline
            if let Some(dt) = doc_item.get("pwned_at").and_then(|v| v.as_str()) {
                let date = &dt[..dt.len().min(10)];
                if earliest_date.as_deref().map_or(true, |e| date < e) {
                    earliest_date = Some(date.to_string());
                }
                if latest_date.as_deref().map_or(true, |l| date > l) {
                    latest_date = Some(date.to_string());
                }
            }
        }

        stats.machines = log_ids.len();
        stats.date_range = match (earliest_date, latest_date) {
            (Some(e), Some(l)) => format!("{e} to {l}"),
            _ => String::new(),
        };
    }

    // ── Parse victim device_users (OS account names) ──
    if let Some(victims) = doc
        .pointer("/stealerData/victims")
        .and_then(|v| v.as_array())
    {
        let mut seen_device_users: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for victim in victims {
            if let Some(users) = victim.get("device_users").and_then(|v| v.as_array()) {
                for u in users.iter().take(5) {
                    if let Some(name) = u.as_str() {
                        if !name.is_empty() && seen_device_users.insert(name.to_lowercase()) {
                            let mut e = Entity::new(EntityKind::Username, name, 0.35, &sid);
                            e.tag("device-user");
                            e.tag("import");
                            entities.push(e);
                            stats.device_users += 1;
                        }
                    }
                }
            }
        }
    }

    // ── Parse IP geolocation from osintData ──
    if let Some(ip_info) = doc.pointer("/osintData/ipInfo").and_then(|v| v.as_object()) {
        for (ip, info) in ip_info {
            let city = info.get("city").and_then(|v| v.as_str()).unwrap_or("");
            let region = info.get("regionName").and_then(|v| v.as_str()).unwrap_or("");
            let country = info.get("country").and_then(|v| v.as_str()).unwrap_or("");
            let lat = info.get("lat").and_then(|v| v.as_f64());
            let lon = info.get("lon").and_then(|v| v.as_f64());
            let isp = info.get("isp").and_then(|v| v.as_str()).unwrap_or("");

            if let (Some(lat), Some(lon)) = (lat, lon) {
                if lat.abs() > 0.01 && lon.abs() > 0.01 {
                    let coords = format!("{lat:.4},{lon:.4}");
                    let mut ce =
                        Entity::new(EntityKind::Coordinates, &coords, 0.70, &sid);
                    ce.tag("geoint");
                    ce.tag("import");
                    ce.add_evidence(
                        Evidence::new(
                            "import:oathnet",
                            format!("IP {ip}: {city}, {region}, {country} ({isp})"),
                        )
                        .with_attr("ip", ip)
                        .with_attr("isp", isp),
                    );
                    entities.push(ce);
                    stats.coordinates += 1;
                }
            }
            if !city.is_empty() {
                let addr = format!("{city}, {region}, {country}");
                let mut ae = Entity::new(EntityKind::Address, &addr, 0.65, &sid);
                ae.tag("import");
                entities.push(ae);
                stats.addresses += 1;
            }
        }
    }

    // ── Parse Holehe platform checks ──
    if let Some(holehe) = doc.pointer("/osintData/holehe").and_then(|v| v.as_object()) {
        for (email, data) in holehe {
            if let Some(domains) = data
                .pointer("/data/domains")
                .and_then(|v| v.as_array())
            {
                let platforms: Vec<&str> = domains
                    .iter()
                    .filter_map(|d| d.as_str())
                    .collect();
                if !platforms.is_empty() && !email.contains("UPGRADE") {
                    let mut e = Entity::new(EntityKind::Email, email, 0.85, &sid);
                    e.tag("holehe-verified");
                    e.tag("import");
                    e.add_evidence(
                        Evidence::new(
                            "import:oathnet",
                            format!(
                                "Holehe: registered on {} platform(s): {}",
                                platforms.len(),
                                platforms.join(", ")
                            ),
                        )
                        .with_attr("platforms", platforms.join(", "))
                        .with_attr("platform_count", platforms.len().to_string()),
                    );
                    entities.push(e);
                    stats.holehe += 1;
                }
            }
        }
    }

    // Dedup by UID
    let mut seen_uids: std::collections::HashSet<String> = std::collections::HashSet::new();
    entities.retain(|e| seen_uids.insert(e.uid.clone()));

    println!("Imported {} entities:", entities.len());
    println!(
        "  Identity:  {} emails, {} usernames, {} device users, {} Discord IDs",
        stats.emails, stats.usernames, stats.device_users, stats.discord_ids
    );
    println!(
        "  Network:   {} IPs, {} domains, {} subdomains, {} URLs, {} admin paths",
        stats.ips, stats.domains, stats.subdomains, stats.urls, stats.admin_paths
    );
    println!(
        "  Geo:       {} coordinates, {} addresses",
        stats.coordinates, stats.addresses
    );
    println!(
        "  Device:    {} HWIDs, {} machine log IDs",
        stats.hwids, stats.machines
    );
    println!(
        "  Keys:      {} API keys detected",
        stats.api_keys
    );
    println!("  Verified:  {} holehe platform checks", stats.holehe);
    println!(
        "  Source:    {} breach, {} stealer docs, {} victims",
        stats.breach_records, stats.stealer_docs, stats.victim_records
    );
    if !stats.date_range.is_empty() {
        println!("  Timeline:  {}", stats.date_range);
    }
    if stats.api_keys > 0 {
        println!("  Pool:      {} API keys stored in key pool for automatic use", stats.api_keys);
        let _ = crate::util::key_pool::save_pool(&crate::util::key_pool::global_pool());
    }

    match output {
        "json" => {
            let out = serde_json::json!({
                "import": { "query": query, "date": date, "file": path },
                "stats": {
                    "entities": entities.len(),
                    "emails": stats.emails,
                    "ips": stats.ips,
                    "domains": stats.domains,
                    "coordinates": stats.coordinates,
                },
                "entities": entities,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        }
        _ => {
            for e in &entities {
                println!(
                    "  [{:.2}] {:15} {}",
                    e.confidence,
                    e.kind.to_string(),
                    &e.value[..e.value.len().min(70)]
                );
            }
        }
    }

    Ok(())
}

fn cmd_import_html(body: &str, output: &str) -> Result<()> {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use std::collections::HashSet;

    println!("Importing OathNet HTML export...");
    let sid = format!("import-html-{}", crate::core::entity::unix_now());
    let mut entities: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let ip_re = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let email_re = regex::Regex::new(r"[\w.+-]+@[\w.-]+\.\w{2,}").unwrap();
    let domain_re =
        regex::Regex::new(r"(?:https?://)?([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)+)")
            .unwrap();

    let lower = body.to_lowercase();

    for cap in domain_re.captures_iter(&lower) {
        let dom = &cap[1];
        if dom.len() > 4 && seen.insert(format!("d:{dom}")) {
            let parts: Vec<&str> = dom.split('.').collect();
            let is_sub = parts.len() >= 3;
            let conf = if is_sub { 0.45 } else { 0.50 };
            let mut e = Entity::new(EntityKind::Domain, dom, conf, &sid);
            e.tag("import");
            if is_sub {
                e.tag("subdomain");
            }
            entities.push(e);
        }
    }

    for cap in ip_re.captures_iter(body) {
        let ip = cap[0].to_string();
        if seen.insert(format!("ip:{ip}"))
            && !ip.starts_with("0.")
            && !ip.starts_with("127.")
            && !ip.starts_with("255.")
        {
            let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.55, &sid);
            e.tag("import");
            entities.push(e);
        }
    }

    for cap in email_re.captures_iter(body) {
        let em = cap[0].to_lowercase();
        if em.len() >= 5 && seen.insert(format!("em:{em}")) {
            let mut e = Entity::new(EntityKind::Email, &em, 0.50, &sid);
            e.tag("import");
            entities.push(e);
        }
    }

    let mut uid_seen: HashSet<String> = HashSet::new();
    entities.retain(|e| uid_seen.insert(e.uid.clone()));

    let domains = entities.iter().filter(|e| e.kind == EntityKind::Domain).count();
    let ips = entities.iter().filter(|e| e.kind == EntityKind::IpAddress).count();
    let emails = entities.iter().filter(|e| e.kind == EntityKind::Email).count();

    println!(
        "Imported {} entities: {} domains, {} IPs, {} emails",
        entities.len(), domains, ips, emails
    );

    if output == "json" {
        let out = serde_json::json!({ "entities": entities });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for e in &entities {
            println!("  [{:.2}] {:15} {}", e.confidence, e.kind.to_string(), &e.value[..e.value.len().min(70)]);
        }
    }
    Ok(())
}

fn cmd_import_txt(body: &str, output: &str) -> Result<()> {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use std::collections::HashSet;

    println!("Importing OathNet TXT export...");
    let sid = format!("import-txt-{}", crate::core::entity::unix_now());
    let mut entities: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut stats = ImportStats::default();

    let ip_re = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let email_re = regex::Regex::new(r"[\w.+-]+@[\w.-]+\.\w{2,}").unwrap();
    let _url_re = regex::Regex::new(r#"https?://[^\s,<>"']+"#).unwrap();

    // ── Credential section: URLs, domains, usernames, API key scanning ──
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("URL: ") {
            let url = rest.trim();
            if url.starts_with("http") && seen.insert(format!("u:{url}")) {
                let mut e = Entity::new(EntityKind::Url, url, 0.45, &sid);
                e.tag("import");
                let pl = url.to_lowercase();
                if pl.contains("admin") || pl.contains("/api") || pl.contains("login") || pl.contains("dashboard") {
                    e.tag("admin-panel");
                    stats.admin_paths += 1;
                }
                entities.push(e);
                stats.urls += 1;
                if let Some(host) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) {
                    let domain = host.split('/').next().unwrap_or("").split(':').next().unwrap_or("");
                    if domain.contains('.') && seen.insert(format!("d:{domain}")) {
                        let parts: Vec<&str> = domain.split('.').collect();
                        let is_sub = parts.len() >= 3;
                        let mut de = Entity::new(EntityKind::Domain, domain, if is_sub { 0.45 } else { 0.50 }, &sid);
                        de.tag("import");
                        if is_sub { de.tag("subdomain"); stats.subdomains += 1; } else { stats.domains += 1; }
                        entities.push(de);
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("Username: ") {
            let uname = rest.trim();
            if uname.len() >= 2 && seen.insert(format!("un:{uname}")) {
                let kind = if uname.contains('@') { EntityKind::Email } else { EntityKind::Username };
                let mut e = Entity::new(kind, uname, 0.40, &sid);
                e.tag("import");
                e.tag("stealer-username");
                entities.push(e);
                stats.usernames += 1;
            }
        } else if let Some(rest) = line.strip_prefix("Password: ") {
            let pw = rest.trim();
            if pw.len() >= 20 {
                let is_key = pw.starts_with("sk-") || pw.starts_with("ghp_")
                    || pw.starts_with("SG.") || pw.starts_with("AKIA")
                    || pw.starts_with("AIzaSy") || pw.starts_with("hf_")
                    || pw.starts_with("sk_live_") || pw.starts_with("xoxb-")
                    || pw.starts_with("npm_") || pw.starts_with("dop_v1_")
                    || pw.starts_with("github_pat_") || pw.starts_with("r8_")
                    || pw.starts_with("eyJ") || pw.starts_with("ntn_")
                    || (pw.len() == 32 && pw.chars().all(|c| c.is_ascii_hexdigit()))
                    || (pw.len() == 64 && pw.chars().all(|c| c.is_ascii_hexdigit()));
                if is_key {
                    let svc = if pw.starts_with("sk-ant-") { "anthropic" }
                        else if pw.starts_with("sk-proj-") { "openai" }
                        else if pw.starts_with("ghp_") || pw.starts_with("github_pat_") { "github" }
                        else if pw.starts_with("AKIA") { "aws" }
                        else if pw.starts_with("SG.") { "sendgrid" }
                        else if pw.starts_with("sk_live_") { "stripe" }
                        else if pw.starts_with("hf_") { "huggingface" }
                        else { "generic_key" };
                    let display = format!("{}:{}...{}", svc, &pw[..pw.len().min(8)], &pw[pw.len().saturating_sub(4)..]);
                    let mut e = Entity::new(EntityKind::ApiKey, &display, 0.80, &sid);
                    e.tag("api-key");
                    e.tag(format!("service:{svc}"));
                    e.tag("import");
                    entities.push(e);
                    stats.api_keys += 1;
                    let pool = crate::util::key_pool::global_pool();
                    let mut entry = crate::util::key_pool::KeyEntry::new(pw);
                    entry.notes = Some(format!("TXT import: {svc} key"));
                    pool.add(svc, entry);
                }
            }
        }
    }

    // ── Victim section: IPs, emails, HWIDs, device users ──
    let victim_start = body.find("=== INFECTED MACHINES");
    let victim_end = body.find("=== OSINT ENRICHMENT").unwrap_or(body.len());
    if let Some(vs) = victim_start {
        let victim_section = &body[vs..victim_end];
        for line in victim_section.lines() {
            if let Some(rest) = line.strip_prefix("IPs: ") {
                for ip in rest.split(", ") {
                    let ip = ip.trim();
                    if ip.contains('.') && !ip.starts_with("0.") && seen.insert(format!("ip:{ip}")) {
                        let mut e = Entity::new(EntityKind::IpAddress, ip, 0.60, &sid);
                        e.tag("stealer-victim");
                        e.tag("import");
                        entities.push(e);
                        stats.ips += 1;
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Device Emails: ") {
                for em in rest.split(", ") {
                    let em = em.trim().to_lowercase();
                    if em.contains('@') && em.len() >= 5 && seen.insert(format!("em:{em}")) {
                        let mut e = Entity::new(EntityKind::Email, &em, 0.55, &sid);
                        e.tag("stealer-victim");
                        e.tag("import");
                        entities.push(e);
                        stats.emails += 1;
                    }
                }
            } else if let Some(rest) = line.strip_prefix("HWIDs: ") {
                for hwid in rest.split(", ") {
                    let hwid = hwid.trim();
                    if !hwid.is_empty() && seen.insert(format!("hw:{hwid}")) {
                        let mut e = Entity::new(EntityKind::DeviceId, hwid, 0.70, &sid);
                        e.tag("hwid");
                        e.tag("import");
                        entities.push(e);
                        stats.hwids += 1;
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Users: ") {
                for user in rest.split(", ") {
                    let user = user.trim();
                    if !user.is_empty() && seen.insert(format!("du:{user}")) {
                        let mut e = Entity::new(EntityKind::Username, user, 0.35, &sid);
                        e.tag("device-user");
                        e.tag("import");
                        entities.push(e);
                        stats.device_users += 1;
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Log ID: ") {
                let lid = rest.trim();
                if !lid.is_empty() && seen.insert(format!("lid:{lid}")) {
                    let mut e = Entity::new(EntityKind::DeviceId, lid, 0.50, &sid);
                    e.tag("log-id");
                    e.tag("import");
                    entities.push(e);
                    stats.machines += 1;
                }
            } else if let Some(rest) = line.strip_prefix("Discord IDs: ") {
                for did in rest.split(", ") {
                    let did = did.trim();
                    if !did.is_empty() && seen.insert(format!("dc:{did}")) {
                        let mut e = Entity::new(EntityKind::Username, did, 0.60, &sid);
                        e.tag("discord-id");
                        e.tag("import");
                        entities.push(e);
                        stats.discord_ids += 1;
                    }
                }
            }
        }
    }

    // ── OSINT section: IP geolocation ──
    let osint_start = body.find("=== OSINT ENRICHMENT");
    if let Some(os) = osint_start {
        let osint_section = &body[os..];
        let mut current_ip = String::new();
        let mut lat: Option<f64> = None;
        let mut lon: Option<f64> = None;
        let mut city = String::new();
        let mut region = String::new();
        let mut country = String::new();
        let mut isp = String::new();

        for line in osint_section.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("IP: ") {
                if !current_ip.is_empty() {
                    if let (Some(la), Some(lo)) = (lat, lon) {
                        if la.abs() > 0.01 && lo.abs() > 0.01 {
                            let coords = format!("{la:.4},{lo:.4}");
                            let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.70, &sid);
                            ce.tag("geoint");
                            ce.tag("import");
                            ce.add_evidence(Evidence::new("import:oathnet", format!("IP {current_ip}: {city}, {region}, {country} ({isp})")));
                            entities.push(ce);
                            stats.coordinates += 1;
                        }
                    }
                    if !city.is_empty() {
                        let addr = format!("{city}, {region}, {country}");
                        let mut ae = Entity::new(EntityKind::Address, &addr, 0.65, &sid);
                        ae.tag("import");
                        entities.push(ae);
                        stats.addresses += 1;
                    }
                }
                current_ip = rest.trim().to_string();
                lat = None; lon = None;
                city.clear(); region.clear(); country.clear(); isp.clear();
            } else if let Some(rest) = trimmed.strip_prefix("lat: ") {
                lat = rest.trim().parse().ok();
            } else if let Some(rest) = trimmed.strip_prefix("lon: ") {
                lon = rest.trim().parse().ok();
            } else if let Some(rest) = trimmed.strip_prefix("city: ") {
                city = rest.trim().to_string();
            } else if let Some(rest) = trimmed.strip_prefix("regionName: ") {
                region = rest.trim().to_string();
            } else if let Some(rest) = trimmed.strip_prefix("country: ") {
                country = rest.trim().to_string();
            } else if let Some(rest) = trimmed.strip_prefix("isp: ") {
                isp = rest.trim().to_string();
            }
        }
        if !current_ip.is_empty() {
            if let (Some(la), Some(lo)) = (lat, lon) {
                if la.abs() > 0.01 && lo.abs() > 0.01 {
                    let coords = format!("{la:.4},{lo:.4}");
                    let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.70, &sid);
                    ce.tag("geoint");
                    ce.tag("import");
                    entities.push(ce);
                    stats.coordinates += 1;
                }
            }
            if !city.is_empty() {
                let addr = format!("{city}, {region}, {country}");
                let mut ae = Entity::new(EntityKind::Address, &addr, 0.65, &sid);
                ae.tag("import");
                entities.push(ae);
                stats.addresses += 1;
            }
        }
    }

    let mut uid_seen: HashSet<String> = HashSet::new();
    entities.retain(|e| uid_seen.insert(e.uid.clone()));

    println!("Imported {} entities:", entities.len());
    println!("  Identity:  {} emails, {} usernames, {} device users, {} Discord IDs", stats.emails, stats.usernames, stats.device_users, stats.discord_ids);
    println!("  Network:   {} IPs, {} domains, {} subdomains, {} URLs, {} admin paths", stats.ips, stats.domains, stats.subdomains, stats.urls, stats.admin_paths);
    println!("  Geo:       {} coordinates, {} addresses", stats.coordinates, stats.addresses);
    println!("  Device:    {} HWIDs, {} machine log IDs", stats.hwids, stats.machines);
    println!("  Keys:      {} API keys detected", stats.api_keys);
    if stats.api_keys > 0 {
        println!("  Pool:      {} keys stored for automatic use", stats.api_keys);
        let _ = crate::util::key_pool::save_pool(&crate::util::key_pool::global_pool());
    }

    if output == "json" {
        let out = serde_json::json!({ "entities": entities });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for e in entities.iter().take(50) {
            println!("  [{:.2}] {:15} {}", e.confidence, e.kind.to_string(), &e.value[..e.value.len().min(70)]);
        }
        if entities.len() > 50 {
            println!("  ... and {} more", entities.len() - 50);
        }
    }
    Ok(())
}

#[derive(Default)]
struct ImportStats {
    breach_records: usize,
    stealer_docs: usize,
    victim_records: usize,
    emails: usize,
    ips: usize,
    domains: usize,
    subdomains: usize,
    urls: usize,
    usernames: usize,
    coordinates: usize,
    addresses: usize,
    holehe: usize,
    machines: usize,
    device_users: usize,
    hwids: usize,
    discord_ids: usize,
    admin_paths: usize,
    api_keys: usize,
    date_range: String,
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
