//! `hse attack <verb>` — MITRE ATT&CK views over HSE's existing, versioned
//! [`core::attack`](crate::core::attack) layer (Enterprise v17.1).
//!
//! HSE is a passive, authorised OSINT collector, so it honestly claims coverage
//! of exactly ONE tactic — Reconnaissance (TA0043). Every "covered" technique
//! here resolves to the registered modules that actually collect for it (its
//! evidence), and the gaps are the honest uncovered slice. No decorative score
//! is emitted: the coverage fraction is derived from real module capability, and
//! `ATT&CK COVERAGE ≠ DETECTION EFFECTIVENESS` — this reports collection reach,
//! not detection.
//!
//! Data authority: [`crate::modules::reconnaissance_coverage`] (registry-wide
//! coverage) and [`crate::modules::technique_module_index`] (technique →
//! evidence modules). This surface only renders them; it computes no coverage of
//! its own.

use clap::Subcommand;

use crate::core::attack::{self, navigator_layer};
use crate::core::error::{Error, Result};
use crate::modules::{reconnaissance_coverage, technique_module_index};

/// The `hse attack` sub-grammar. `--json` gives the machine-readable shape;
/// `navigator` always emits JSON (a Navigator layer file).
#[derive(Subcommand)]
pub enum AttackAction {
    /// ATT&CK posture summary: catalogue version, the tactic in scope, and how
    /// much of it HSE's registry covers.
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Reconnaissance (TA0043) coverage: each technique HSE collects for and the
    /// registered modules that are its evidence.
    Coverage {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Catalogued Reconnaissance techniques NO registered module collects for —
    /// the honest coverage gaps.
    Gaps {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Emit a MITRE ATT&CK Navigator layer (JSON) for HSE's static coverage,
    /// importable at the ATT&CK Navigator.
    Navigator,
}

/// Dispatch an `hse attack` verb.
pub(super) fn cmd_attack(action: AttackAction) -> Result<()> {
    match action {
        AttackAction::Status { json } => status(json),
        AttackAction::Coverage { json } => coverage(json),
        AttackAction::Gaps { json } => gaps(json),
        AttackAction::Navigator => navigator(),
    }
}

/// Emit a JSON value pretty-printed, or a serialise error.
fn print_json(value: &serde_json::Value) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value)
            .map_err(|e| Error::Other(format!("serialise attack output: {e}")))?
    );
    Ok(())
}

/// The registered modules that implement a technique, as a compact string. A
/// technique covered via an entity/relation-kind mapping rather than a dedicated
/// module is shown as such rather than as a false module claim.
fn modules_for(id: &str) -> String {
    match technique_module_index().get(id) {
        Some(mods) if !mods.is_empty() => mods.join(", "),
        _ => "— (entity/relation mapping)".to_string(),
    }
}

/// `hse attack status` — posture summary.
fn status(json: bool) -> Result<()> {
    let cov = reconnaissance_coverage();
    let total = cov.covered.len() + cov.uncovered.len();
    let modules_mapped = technique_module_index().len();

    if json {
        return print_json(&serde_json::json!({
            "attack_version": attack::ATTACK_VERSION,
            "tactic_id": cov.tactic_id,
            "tactic_name": cov.tactic_name,
            "techniques_total": total,
            "techniques_covered": cov.covered.len(),
            "coverage_fraction": cov.coverage_fraction,
            "techniques_with_module": modules_mapped,
        }));
    }

    println!("MITRE ATT&CK posture — HSE defensive-intelligence layer\n");
    println!(
        "Catalogue version : ATT&CK Enterprise v{}",
        attack::ATTACK_VERSION
    );
    println!(
        "Tactic in scope   : {} {} (the one tactic HSE performs collection for)",
        cov.tactic_id, cov.tactic_name
    );
    println!(
        "Recon coverage    : {}/{} techniques covered ({:.1}%)",
        cov.covered.len(),
        total,
        cov.coverage_fraction * 100.0
    );
    println!("Techniques w/ >=1 module : {modules_mapped}");
    println!(
        "\nCoverage is derived from real module capability, scoped to Reconnaissance \
         only — no other tactic is claimed, and no decorative score is emitted. \
         This reports collection reach, not detection effectiveness."
    );
    Ok(())
}

/// `hse attack coverage` — covered techniques and their evidence modules.
fn coverage(json: bool) -> Result<()> {
    let cov = reconnaissance_coverage();

    if json {
        let covered: Vec<serde_json::Value> = cov
            .covered
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.technique.id,
                    "name": c.technique.name,
                    "modules": technique_module_index().get(c.technique.id),
                })
            })
            .collect();
        return print_json(&serde_json::json!({
            "tactic_id": cov.tactic_id,
            "tactic_name": cov.tactic_name,
            "coverage_fraction": cov.coverage_fraction,
            "covered": covered,
        }));
    }

    println!("MITRE ATT&CK — HSE Reconnaissance (TA0043) coverage\n");
    if cov.covered.is_empty() {
        println!("No techniques covered.");
        return Ok(());
    }
    println!("{:<12}  {:<34}  MODULES (evidence)", "TECHNIQUE", "NAME");
    println!("{}", "─".repeat(96));
    for c in &cov.covered {
        println!(
            "{:<12}  {:<34}  {}",
            c.technique.id,
            c.technique.name,
            modules_for(c.technique.id)
        );
    }
    println!(
        "\n{}/{} techniques covered ({:.1}%).",
        cov.covered.len(),
        cov.covered.len() + cov.uncovered.len(),
        cov.coverage_fraction * 100.0
    );
    Ok(())
}

/// `hse attack gaps` — catalogued Reconnaissance techniques no module reaches.
fn gaps(json: bool) -> Result<()> {
    let cov = reconnaissance_coverage();

    if json {
        let gaps: Vec<serde_json::Value> = cov
            .uncovered
            .iter()
            .map(|t| serde_json::json!({ "id": t.id, "name": t.name }))
            .collect();
        return print_json(&serde_json::json!({ "gaps": gaps }));
    }

    println!("MITRE ATT&CK — HSE Reconnaissance (TA0043) coverage gaps\n");
    if cov.uncovered.is_empty() {
        println!("No gaps: every catalogued Reconnaissance technique is covered.");
        return Ok(());
    }
    println!("{:<12}  NAME", "TECHNIQUE");
    println!("{}", "─".repeat(60));
    for t in &cov.uncovered {
        println!("{:<12}  {}", t.id, t.name);
    }
    println!(
        "\n{} of {} Reconnaissance techniques are not collected for (honest gaps).",
        cov.uncovered.len(),
        cov.covered.len() + cov.uncovered.len()
    );
    Ok(())
}

/// `hse attack navigator` — a Navigator layer (JSON) for HSE's static coverage.
fn navigator() -> Result<()> {
    let cov = reconnaissance_coverage();
    let layer = navigator_layer(&cov, "HSE static Reconnaissance coverage");
    print_json(&layer)
}
