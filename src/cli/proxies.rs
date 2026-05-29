//! `hse proxies` — the proxy retriever surface.
//!
//! Activates `util::proxy`: retrieves free HTTP proxies from public sources,
//! validates each against a live test, and persists the fastest-first survivors
//! to `~/.huntsman/proxies.json`. Scans then route through them on demand with
//! `HUNTSMAN_PROXY=auto` (whole-client routing via `util::http::build_client`)
//! or `HUNTSMAN_SEARCH_PROXY` / the automatic pool fallback in the search
//! modules. Anti-blocking resilience for authorised OSINT collection — opt-in,
//! off by default.

use clap::Subcommand;

use crate::core::error::Result;
use crate::util::proxy::{self, Proxy};

#[derive(Subcommand)]
pub enum ProxiesAction {
    /// Retrieve fresh proxies from public sources, validate them live, and
    /// persist the working ones (fastest-first) to `~/.huntsman/proxies.json`.
    Refresh {
        /// Maximum candidates to validate in parallel.
        #[arg(long, default_value_t = 60)]
        max: usize,
    },
    /// Show the persisted, validated pool.
    List,
}

pub(super) async fn cmd_proxies(action: ProxiesAction) -> Result<()> {
    match action {
        ProxiesAction::Refresh { max } => refresh(max).await,
        ProxiesAction::List => {
            list();
            Ok(())
        }
    }
}

async fn refresh(max: usize) -> Result<()> {
    println!("Retrieving + validating proxies (up to {max} candidates, network-bound)…");
    let proxies = proxy::retrieve(max).await;
    if proxies.is_empty() {
        println!(
            "No live proxies validated (sources unreachable or all dead). Pool left unchanged."
        );
        return Ok(());
    }
    match proxy::save_pool(&proxies) {
        Ok(()) => println!(
            "✓ {} live proxies saved to {}",
            proxies.len(),
            proxy::pool_path().display()
        ),
        Err(e) => println!(
            "validated {} proxies but could not persist them: {e}",
            proxies.len()
        ),
    }
    print_table(&proxies);
    println!("\nRoute through them:  HUNTSMAN_PROXY=auto hse scan …   (uses the fastest)");
    Ok(())
}

fn list() {
    let proxies = proxy::load_pool();
    if proxies.is_empty() {
        println!("No persisted proxies. Run `hse proxies refresh` first.");
        return;
    }
    println!(
        "{} validated proxies in {}:",
        proxies.len(),
        proxy::pool_path().display()
    );
    print_table(&proxies);
}

fn print_table(proxies: &[Proxy]) {
    println!("  {:<24} {:<6} {:>10}", "addr", "proto", "latency");
    for p in proxies.iter().take(50) {
        println!("  {:<24} {:<6} {:>7} ms", p.addr, p.proto, p.latency_ms);
    }
    if proxies.len() > 50 {
        println!("  … and {} more", proxies.len() - 50);
    }
}
