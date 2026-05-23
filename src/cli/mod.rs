//! CLI (v0.3): scan / modules / doctor / serve.
//!
//! Surfaces every `ScanOptions` field as a flag so each scan is fully
//! customisable before launch. `serve` boots the HTTP server + SPA. See
//! `docs/USAGE.md` for the full reference.

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
    storage::store::Store,
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
        /// Output format: table | json.
        #[arg(short, long, default_value = "table")]
        output: String,
    },
    /// List registered modules with their cost tier and accepted target kinds.
    Modules,
    /// Verify environment: DB path, key file, Termux detection, module counts.
    Doctor,
    /// Start the HTTP server + SPA (browse to http://127.0.0.1:8080 from Chrome).
    Serve {
        /// Bind address. Localhost-only by default — change at your own risk.
        #[arg(short, long, default_value = crate::DEFAULT_BIND, env = "HSE_BIND")]
        bind: String,
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
                min_expand_confidence,
                max_entities,
                max_wall_time_secs: max_wall_time,
                output,
            })
            .await
        }
        Command::Modules => cmd_modules(),
        Command::Doctor => cmd_doctor(),
        Command::Serve { bind } => cmd_serve(bind).await,
    }
}

async fn cmd_serve(bind: String) -> Result<()> {
    use crate::api::{AppState, routes::router};

    let store = Arc::new(Store::open(&default_db_path())?);
    let (bus, _rx) = tokio::sync::broadcast::channel(1024);
    let engine = Arc::new(ScanEngine::new(registry(), Arc::clone(&store), bus.clone()));
    let state = Arc::new(AppState { store, engine, bus });

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| Error::Other(format!("bind {bind}: {e}")))?;

    tracing::info!("hse v{} — listening on http://{}", crate::VERSION, bind);
    tracing::info!("  open in Chrome / Firefox on this device");
    tracing::info!("  Ctrl-C to stop");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| Error::Other(format!("serve: {e}")))?;

    tracing::info!("server stopped");
    Ok(())
}

/// Wait for SIGINT (Ctrl-C) or SIGTERM. Returns when either arrives.
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
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

struct ScanCmd {
    kind: String,
    value: String,
    modules: Option<String>,
    exclude: Option<String>,
    throttle_ms: u64,
    min_confidence: Option<f64>,
    free_only: bool,
    passive_only: bool,
    module_timeout_ms: Option<u64>,
    depth: u32,
    min_expand_confidence: f64,
    max_entities: Option<usize>,
    max_wall_time_secs: Option<u64>,
    output: String,
}

async fn cmd_scan(cmd: ScanCmd) -> Result<()> {
    let target_kind = parse_target_kind(&cmd.kind)?;
    let target = Target::new(target_kind, cmd.value.clone());

    let options = ScanOptions {
        modules: cmd
            .modules
            .map(|s| s.split(',').map(|m| m.trim().to_string()).collect()),
        exclude_modules: cmd
            .exclude
            .map(|s| s.split(',').map(|m| m.trim().to_string()).collect())
            .unwrap_or_default(),
        throttle_ms: cmd.throttle_ms,
        max_concurrent: 0,
        module_timeout_ms: cmd.module_timeout_ms,
        min_confidence: cmd.min_confidence,
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth: cmd.depth,
        min_expand_confidence: cmd.min_expand_confidence,
        max_entities: cmd.max_entities,
        max_wall_time_secs: cmd.max_wall_time_secs,
    };

    let sid = scan_id(&cmd.kind, &cmd.value);
    let store = Arc::new(Store::open(&default_db_path())?);
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::new(registry(), Arc::clone(&store), bus.clone());

    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: keys::load(),
    };

    let scan = engine.run(scan, target, ctx).await?;
    let entities = store.entities_for_scan(&sid)?;
    let correlations = store.correlations_for_scan(&sid)?;

    match cmd.output.as_str() {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "scan": scan,
                    "entities": entities,
                    "correlations": correlations,
                }))?
            );
        }
        _ => {
            println!(
                "\nScan {} — {} entities for {}={}\n",
                &sid[..8],
                entities.len(),
                cmd.kind,
                cmd.value
            );
            println!(
                "{:<16} {:<46} {:>6} {:>6}  CLASS",
                "KIND", "VALUE", "CONF", "C_EFF"
            );
            println!("{}", "-".repeat(86));
            for e in &entities {
                let val = truncate(&e.value, 46);
                println!(
                    "{:<16} {:<46} {:>6.3} {:>6.3}  {}",
                    e.kind.to_string(),
                    val,
                    e.confidence,
                    e.c_effective(),
                    e.classify()
                );
            }
            if !correlations.is_empty() {
                println!("\n{} correlations:\n", correlations.len());
                println!(
                    "{:<10} {:<10} {:<40} DESCRIPTION",
                    "RULE", "SEVERITY", "NAME"
                );
                println!("{}", "-".repeat(86));
                for c in &correlations {
                    println!(
                        "{:<10} {:<10} {:<40} {}",
                        c.rule_id,
                        c.severity.to_string(),
                        truncate(&c.rule_name, 40),
                        c.description
                    );
                }
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
        ("ip", TargetKind::IpAddress),
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

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
