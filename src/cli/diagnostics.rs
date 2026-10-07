//! `hse diagnostics` — one command that runs every diagnostic.
//!
//! Combines the three standalone health checks into a single pass so an operator
//! verifies the whole install with one invocation:
//!   1. `doctor`   — environment (DB, key file, Termux, module/cost counts);
//!   2. `selftest` — module registry + dispatch graph + core math + storage;
//!   3. `engines`  — live search-engine liveness sweep.
//!
//! Hard failures still make the command exit non-zero. A live subsystem that is
//! usable but impaired is reported as DEGRADED rather than being folded into
//! the previous false-green `ALL PASS` verdict.

use crate::core::error::{Error, Result};

pub(super) async fn cmd_diagnostics(json: bool) -> Result<()> {
    let mut failed: Vec<&str> = Vec::new();
    let mut degraded: Vec<&str> = Vec::new();

    banner("1/3", "Environment — doctor");
    // `diagnostics` stays offline/fast — the live capability preflight is an
    // explicit `hse doctor --live` opt-in, not part of the bundled check.
    if let Err(e) = crate::app::doctor::cmd_doctor(false).await {
        eprintln!("  ✗ doctor failed: {e}");
        failed.push("doctor");
    }

    banner("2/3", "Module + core self-test");
    if let Err(e) = super::selftest::cmd_selftest(json).await {
        eprintln!("  ✗ selftest failed: {e}");
        failed.push("selftest");
    }

    banner("3/3", "Search-engine liveness");
    match super::engines::cmd_engines_with_summary(json).await {
        Ok(summary) => match summary.state() {
            super::engines::EngineFleetState::Healthy => {}
            super::engines::EngineFleetState::Degraded => {
                eprintln!(
                    "  ⚠ engines degraded: {}/{} enabled engine(s) up; {} blocked, {} down",
                    summary.up, summary.enabled, summary.blocked, summary.down
                );
                degraded.push("engines");
            }
            super::engines::EngineFleetState::Failed => {
                eprintln!(
                    "  ✗ engines failed: {}/{} enabled engine(s) usable; {} blocked, {} down",
                    summary.up, summary.enabled, summary.blocked, summary.down
                );
                failed.push("engines");
            }
        },
        Err(e) => {
            eprintln!("  ✗ engines failed: {e}");
            failed.push("engines");
        }
    }

    println!();
    if !failed.is_empty() {
        Err(Error::Other(format!(
            "diagnostics: {} section(s) failed: {}{}",
            failed.len(),
            failed.join(", "),
            if degraded.is_empty() {
                String::new()
            } else {
                format!("; degraded: {}", degraded.join(", "))
            }
        )))
    } else if !degraded.is_empty() {
        println!(
            "==> diagnostics: DEGRADED ({}); core checks passed",
            degraded.join(", ")
        );
        Ok(())
    } else {
        println!("==> diagnostics: ALL PASS (doctor, selftest, engines)");
        Ok(())
    }
}

fn banner(step: &str, title: &str) {
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  [{step}] {title}");
    println!("══════════════════════════════════════════════════════════════\n");
}
