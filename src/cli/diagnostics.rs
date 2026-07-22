//! `hse diagnostics` — one command that runs every diagnostic.
//!
//! Combines the three standalone health checks into a single pass so an operator
//! verifies the whole install with one invocation:
//!   1. `doctor`   — environment (DB, key file, Termux, module/cost counts);
//!   2. `selftest` — module registry + dispatch graph + core math + storage;
//!   3. `engines`  — live search-engine liveness sweep.
//!
//! Each section runs in turn under a banner; the command exits non-zero if any
//! underlying check fails, so it is CI/automation-friendly. The individual
//! commands remain available (and are what the Web UI / API call), this is the
//! convenience aggregate.

use crate::core::error::{Error, Result};

pub(super) async fn cmd_diagnostics(json: bool) -> Result<()> {
    let mut failed: Vec<&str> = Vec::new();

    banner("1/3", "Environment — doctor");
    // `diagnostics` stays offline/fast — the live capability preflight is an
    // explicit `hse doctor --live` opt-in, not part of the bundled check.
    if let Err(e) = super::doctor::cmd_doctor(false).await {
        eprintln!("  ✗ doctor failed: {e}");
        failed.push("doctor");
    }

    banner("2/3", "Module + core self-test");
    if let Err(e) = super::selftest::cmd_selftest(json).await {
        eprintln!("  ✗ selftest failed: {e}");
        failed.push("selftest");
    }

    banner("3/3", "Search-engine liveness");
    if let Err(e) = super::engines::cmd_engines(json).await {
        eprintln!("  ✗ engines failed: {e}");
        failed.push("engines");
    }

    println!();
    if failed.is_empty() {
        println!("==> diagnostics: ALL PASS (doctor, selftest, engines)");
        Ok(())
    } else {
        Err(Error::Other(format!(
            "diagnostics: {} section(s) failed: {}",
            failed.len(),
            failed.join(", ")
        )))
    }
}

fn banner(step: &str, title: &str) {
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  [{step}] {title}");
    println!("══════════════════════════════════════════════════════════════\n");
}
