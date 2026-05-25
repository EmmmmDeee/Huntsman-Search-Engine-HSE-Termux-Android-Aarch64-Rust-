mod provision;

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
        .with_writer(std::io::stderr)
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
    }
}

struct LiveCmd {
    kind: String,
    value: String,
    interval: u64,
    iterations: Option<u32>,
    depth: u32,
    free_only: bool,
    passive_only: bool,
    modules: Option<String>,
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

    let (store, bus, engine) = build_runtime(1024)?;
    let scanner = LiveScanner::new(Arc::clone(&engine), bus.clone(), Arc::clone(&store));

    let Some(live_id) = scanner.start(target, scan_options, live_options) else {
        return Err(Error::Other("too many concurrent live sessions".into()));
    };
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

async fn cmd_serve(bind: String, allow_key_write: bool) -> Result<()> {
    use std::net::SocketAddr;

    use crate::api::{AppState, routes::router};
    use crate::core::live::LiveScanner;

    let (store, bus, engine) = build_runtime(1024)?;
    let live = LiveScanner::new(Arc::clone(&engine), bus.clone(), Arc::clone(&store));
    let http = build_client();
    let state = Arc::new(AppState {
        store,
        engine,
        bus,
        live,
        http,
        allow_key_write,
        cancellations: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
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
    max_concurrent: usize,
    output: String,
}

async fn cmd_scan(cmd: ScanCmd) -> Result<()> {
    let target_kind = parse_target_kind(&cmd.kind)?;
    let target = Target::new(target_kind, cmd.value.clone());

    let options = ScanOptions {
        modules: split_csv(cmd.modules),
        exclude_modules: split_csv(cmd.exclude).unwrap_or_default(),
        throttle_ms: cmd.throttle_ms,
        max_concurrent: cmd.max_concurrent,
        module_timeout_ms: cmd.module_timeout_ms,
        min_confidence: cmd.min_confidence,
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth: cmd.depth,
        min_expand_confidence: cmd.min_expand_confidence,
        max_entities: cmd.max_entities,
        max_wall_time_secs: cmd.max_wall_time_secs,
        scan_tags: Vec::new(),
        notes: None,
    };

    let sid = scan_id(target_kind.canonical_str(), &cmd.value);
    let (store, bus, engine) = build_runtime(64)?;

    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: keys::load(),
        cancel: crate::core::cancel::CancelHandle::new(),
        store: Arc::clone(&store),
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
    } else if cmd.output == "report" {
        print_full_report(&scan, &entities, &correlations, &cmd.value, &cmd.kind);
    } else {
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
    Ok(())
}

fn print_full_report(
    scan: &crate::core::scan::Scan,
    entities: &[crate::core::entity::Entity],
    correlations: &[crate::core::correlator::Correlation],
    target_value: &str,
    target_kind: &str,
) {
    use std::collections::BTreeMap;

    let dur = scan
        .finished_at
        .unwrap_or(0)
        .saturating_sub(scan.started_at);

    println!("\n{}", "═".repeat(90));
    println!("  HUNTSMAN SEARCH ENGINE — INTELLIGENCE REPORT");
    println!("{}", "═".repeat(90));
    println!("  Target:   {} ({})", target_value, target_kind);
    println!(
        "  Status:   {} | Duration: {}s | Entities: {} | Correlations: {}",
        scan.status.as_str(),
        dur,
        entities.len(),
        correlations.len()
    );
    println!("{}", "═".repeat(90));

    // Group entities by kind
    let mut by_kind: BTreeMap<String, Vec<&crate::core::entity::Entity>> = BTreeMap::new();
    for e in entities {
        by_kind.entry(e.kind.to_string()).or_default().push(e);
    }

    // Print summary
    println!("\n  ┌─ ENTITY SUMMARY ─────────────────────────────────────────────");
    for (kind, group) in &by_kind {
        println!("  │  {:15} {:>4} found", kind, group.len());
    }
    println!(
        "  └────────────────────────────────────────────────────── total: {}\n",
        entities.len()
    );

    // Print HIGH severity correlations first
    let high_corr: Vec<_> = correlations
        .iter()
        .filter(|c| c.severity.as_canonical() == "high" || c.severity.as_canonical() == "critical")
        .collect();
    if !high_corr.is_empty() {
        println!("  ┌─ HIGH/CRITICAL ALERTS ──────────────────────────────────────");
        for c in &high_corr {
            println!(
                "  │  [{}] {} — {}",
                c.rule_id,
                c.severity.as_canonical().to_uppercase(),
                c.description
            );
        }
        println!("  └───────────────────────────────────────────────────────────────\n");
    }

    // Print each entity kind section with full evidence
    let kind_order = [
        "person",
        "email",
        "username",
        "phone",
        "credential",
        "password",
        "api_key",
        "url",
        "domain",
        "ip_address",
        "address",
        "coordinates",
        "organisation",
        "mac_address",
    ];
    for kind_name in kind_order {
        let group = match by_kind.get(kind_name) {
            Some(g) => g,
            None => continue,
        };
        println!(
            "  ╔═ {} ({}) ═══════════════════════════════════════════════",
            kind_name.to_uppercase(),
            group.len()
        );
        for (i, e) in group.iter().enumerate() {
            let srcs: Vec<&str> = e.evidence.iter().map(|ev| ev.source.as_str()).collect();
            let unique_srcs: std::collections::BTreeSet<&str> = srcs.into_iter().collect();
            println!("  ║");
            println!("  ║  [{}] {}", i + 1, e.value);
            println!(
                "  ║      Confidence: {:.3} | Corroboration: {} | Sources: {}",
                e.confidence,
                e.corroboration,
                unique_srcs.into_iter().collect::<Vec<_>>().join(", ")
            );
            if !e.tags.is_empty() {
                println!("  ║      Tags: {}", e.tags.join(", "));
            }
            for ev in &e.evidence {
                println!("  ║      ├── [{}] {}", ev.source, ev.summary);
                for (k, v) in &ev.attributes {
                    if k == "raw" {
                        println!("  ║      │   {}: <{} bytes>", k, v.len());
                    } else {
                        let display = if v.len() > 200 { &v[..200] } else { v.as_str() };
                        println!("  ║      │   {}: {}", k, display);
                    }
                }
            }
        }
        println!("  ╚═══════════════════════════════════════════════════════════════\n");
    }

    // Print all correlations
    if !correlations.is_empty() {
        println!(
            "  ┌─ ALL CORRELATIONS ({}) ────────────────────────────────────",
            correlations.len()
        );
        for (i, c) in correlations.iter().enumerate() {
            println!(
                "  │  [{}] {} — {} [{}]",
                i + 1,
                c.rule_id,
                c.rule_name,
                c.severity.as_canonical().to_uppercase()
            );
            println!("  │      {}", c.description);
        }
        println!("  └───────────────────────────────────────────────────────────────");
    }

    println!("\n{}", "═".repeat(90));
    println!(
        "  SCAN COMPLETE: {} entities, {} correlations, {}s",
        entities.len(),
        correlations.len(),
        dur
    );
    println!("{}\n", "═".repeat(90));
}

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

    println!("\nDiscovered Credentials Ledger:");
    println!("  path:    {}", crate::util::keyledger::ledger_file_path());
    println!("  entries: {}", crate::util::keyledger::ledger_count());

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
        "apikey" | "api_key" | "key" => Ok(TargetKind::ApiKey),
        "regex" | "re" | "pattern" => Ok(TargetKind::Regex),
        other => Err(Error::InvalidTarget(format!(
            "unknown target kind '{other}'. Valid: email, username, phone, name, ip, domain, asn, coords, address, apikey, regex"
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
