//! `hse-ai-daemon` — background poller: periodically checks for terminal scans
//! with no AI-daemon analysis yet and analyzes them via a locally-run Ollama
//! instance.
//!
//! Purely additive and best-effort: a scan is never blocked on this daemon,
//! and this binary never runs as part of `hse scan`/`hse serve`/`hse live` —
//! it must be started separately, and does nothing at all unless
//! `feature.ai_daemon` is armed (`hse config feature.ai_daemon on`). See
//! `src/ai/` and the `Runtime AI-independence` invariant in `src/lib.rs` for
//! why this binary is allowed to exist and how it stays isolated from the
//! deterministic scan/correlation core (it links the same library crate as
//! `hse`, but never the reverse).
//!
//! Reuses [`huntsman_search_engine::ai::analysis::analyze_scan`] — the exact
//! function `hse analyze` calls — so the two entry points can't drift on what
//! "analyzing a scan" means.

use clap::Parser;
use huntsman_search_engine::ai::analysis::analyze_scan;
use huntsman_search_engine::ai::ollama::{DEFAULT_BASE_URL, OllamaClient};
use huntsman_search_engine::storage::Store;
use huntsman_search_engine::{default_db_path, util::settings};
use std::process::ExitCode;
use std::time::Duration;

/// Floor for `HUNTSMAN_AI_POLL_INTERVAL_SECS` — below this, a busy loop of
/// mostly-empty `scans_pending_analysis` queries is not meaningfully more
/// responsive, just noisier.
const MIN_POLL_SECS: u64 = 15;
const DEFAULT_POLL_SECS: u64 = 60;
const MIN_GEN_TIMEOUT_MS: u64 = 1_000;
const DEFAULT_GEN_TIMEOUT_MS: u64 = 120_000;
/// Scans analyzed per poll cycle. Bounded so one cycle can't run unboundedly
/// long after a backlog builds up (e.g. the daemon was off for a while) —
/// the remainder is simply picked up on the next tick.
const SCANS_PER_CYCLE: usize = 5;

#[derive(Parser)]
#[command(
    name = "hse-ai-daemon",
    about = "Background AI-daemon scan analysis for Huntsman Search Engine (opt-in; requires a running Ollama instance)"
)]
struct Args {
    /// Ollama base URL (default `http://127.0.0.1:11434`).
    #[arg(long, env = "HUNTSMAN_OLLAMA_URL")]
    ollama_url: Option<String>,
    /// Ollama model tag to use; required — there is no default model, since a
    /// default would silently invoke whatever an operator happens to have
    /// pulled.
    #[arg(long, env = "HUNTSMAN_OLLAMA_MODEL")]
    model: Option<String>,
}

fn resolve_poll_interval() -> Duration {
    let secs = std::env::var("HUNTSMAN_AI_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n >= MIN_POLL_SECS)
        .unwrap_or(DEFAULT_POLL_SECS);
    Duration::from_secs(secs)
}

fn resolve_gen_timeout() -> Duration {
    let ms = std::env::var("HUNTSMAN_OLLAMA_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n >= MIN_GEN_TIMEOUT_MS)
        .unwrap_or(DEFAULT_GEN_TIMEOUT_MS);
    Duration::from_millis(ms)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();

    if !settings::ai_daemon_enabled() {
        eprintln!(
            "hse-ai-daemon: feature.ai_daemon is off — enable with \
             `hse config feature.ai_daemon on` (after installing and starting Ollama); exiting"
        );
        return ExitCode::FAILURE;
    }
    let Some(model) = args.model else {
        eprintln!(
            "hse-ai-daemon: no Ollama model configured — pass --model or set HUNTSMAN_OLLAMA_MODEL"
        );
        return ExitCode::FAILURE;
    };
    let base_url = args
        .ollama_url
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let client = OllamaClient::new(base_url, model);

    let store = match Store::open(&default_db_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hse-ai-daemon: could not open store: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Best-effort, not fatal: Ollama may simply not be up yet (e.g. this
    // daemon started before its own systemd/Termux boot-services unit did),
    // and each poll cycle already surfaces the same failure per scan. This is
    // purely a clearer first-run diagnostic than waiting for the first cycle.
    if let Err(e) = client.health_check().await {
        eprintln!(
            "hse-ai-daemon: startup health check failed ({e}); will keep retrying on each poll"
        );
    }

    let poll_interval = resolve_poll_interval();
    let gen_timeout = resolve_gen_timeout();
    println!(
        "hse-ai-daemon: polling every {poll_interval:?} for unanalyzed scans (model {})",
        client.model()
    );

    let mut tick = tokio::time::interval(poll_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tick.tick() => run_cycle(&store, &client, gen_timeout).await,
            () = shutdown_signal() => {
                println!("hse-ai-daemon: shutting down");
                return ExitCode::SUCCESS;
            }
        }
    }
}

/// One poll cycle: analyze up to [`SCANS_PER_CYCLE`] pending scans. A
/// per-scan failure (Ollama unreachable, a malformed response, a DB error) is
/// logged and the scan is simply retried on the next cycle — it never latches
/// a permanent "skipped" state and never stops the loop.
async fn run_cycle(store: &Store, client: &OllamaClient, timeout: Duration) {
    let pending = match store.scans_pending_analysis(SCANS_PER_CYCLE) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("hse-ai-daemon: could not list pending scans: {e}");
            return;
        }
    };
    for scan_id in pending {
        match analyze_scan(store, client, &scan_id, timeout).await {
            Ok(_) => println!("hse-ai-daemon: analyzed scan {scan_id}"),
            Err(e) => {
                eprintln!("hse-ai-daemon: scan {scan_id} failed ({e}); will retry next cycle");
            }
        }
    }
}

/// Degrade gracefully if a handler can't be installed (fall back to a
/// pending future rather than panicking), mirroring `cli::serve`'s
/// `shutdown_signal` — the same reasoning applies to a long-lived poll loop.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            eprintln!("hse-ai-daemon: Ctrl-C handler unavailable ({e}); use SIGTERM to stop");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                eprintln!("hse-ai-daemon: SIGTERM handler unavailable ({e})");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
