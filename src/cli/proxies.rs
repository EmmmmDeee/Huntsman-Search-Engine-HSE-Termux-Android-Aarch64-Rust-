//! `hse proxies` — the proxy retriever surface.
//!
//! Activates `util::proxy`: retrieves free HTTP proxies from public sources,
//! validates each live, **grades anonymity** (elite/anonymous/transparent),
//! captures country where known, and persists the best-first survivors to
//! `~/.huntsman/proxies.json`. Scans route through them on demand with
//! `HUNTSMAN_PROXY=auto` (whole-client routing) or the search modules' pool
//! fallback. Anti-blocking resilience for authorised OSINT collection — opt-in,
//! off by default.

use clap::Subcommand;

use crate::core::error::Result;
use crate::util::proxy::{self, Grade, Proxy};

#[derive(Subcommand)]
pub enum ProxiesAction {
    /// Retrieve fresh proxies, validate + grade them live, and persist the
    /// best-first survivors to `~/.huntsman/proxies.json`.
    Refresh {
        /// Maximum candidates to validate in parallel.
        #[arg(long, default_value_t = 60)]
        max: usize,
        /// Keep only proxies of at least this anonymity grade.
        #[arg(long, value_parser = ["elite", "anonymous", "any"], default_value = "any")]
        grade: String,
        /// Keep only proxies from this ISO country code (e.g. `AU`, `US`).
        #[arg(long)]
        country: Option<String>,
    },
    /// Show the persisted, validated pool.
    List,
}

pub(super) async fn cmd_proxies(action: ProxiesAction) -> Result<()> {
    match action {
        ProxiesAction::Refresh {
            max,
            grade,
            country,
        } => refresh(max, &grade, country.as_deref()).await,
        ProxiesAction::List => {
            list();
            Ok(())
        }
    }
}

async fn refresh(max: usize, grade: &str, country: Option<&str>) -> Result<()> {
    println!("Retrieving + validating + grading proxies (up to {max} candidates, network-bound)…");
    let mut proxies = proxy::retrieve(max).await;
    let harvested = proxies.len();

    // High-yield filters: anonymity grade floor + optional country.
    if grade != "any" {
        proxies.retain(|p| meets_grade(p, grade));
    }
    if let Some(cc) = country {
        let cc = cc.to_uppercase();
        proxies.retain(|p| p.country.as_deref() == Some(cc.as_str()));
    }

    if proxies.is_empty() {
        println!(
            "No proxies passed (validated {harvested}, then grade='{grade}'{}). Pool left unchanged.",
            country
                .map(|c| format!(", country={c}"))
                .unwrap_or_default()
        );
        return Ok(());
    }
    match proxy::save_pool(&proxies) {
        Ok(()) => println!(
            "✓ {} proxies saved to {} (from {harvested} validated)",
            proxies.len(),
            proxy::pool_path().display()
        ),
        Err(e) => println!(
            "validated {} proxies but could not persist them: {e}",
            proxies.len()
        ),
    }
    print_table(&proxies);
    println!("\nRoute through them:  HUNTSMAN_PROXY=auto hse scan …   (uses the best-graded)");
    Ok(())
}

fn list() {
    let proxies = proxy::load_pool();
    if proxies.is_empty() {
        println!("No persisted proxies. Run `hse proxies refresh` first.");
        return;
    }
    println!(
        "{} validated proxies in {} (best-first):",
        proxies.len(),
        proxy::pool_path().display()
    );
    print_table(&proxies);
}

/// True if `p`'s grade clears the requested floor (`elite` ⇒ Elite only;
/// `anonymous` ⇒ Elite or Anonymous). Ungraded proxies never clear a floor.
fn meets_grade(p: &Proxy, floor: &str) -> bool {
    matches!(
        (floor, p.grade),
        ("elite", Some(Grade::Elite)) | ("anonymous", Some(Grade::Elite | Grade::Anonymous))
    )
}

fn print_table(proxies: &[Proxy]) {
    println!(
        "  {:<24} {:<6} {:<11} {:<7} {:>10}",
        "addr", "proto", "grade", "country", "latency"
    );
    for p in proxies.iter().take(50) {
        println!(
            "  {:<24} {:<6} {:<11} {:<7} {:>7} ms",
            p.addr,
            p.proto,
            p.grade.map(Grade::as_str).unwrap_or("?"),
            p.country.as_deref().unwrap_or("-"),
            p.latency_ms
        );
    }
    if proxies.len() > 50 {
        println!("  … and {} more", proxies.len() - 50);
    }
}
