//! `hse attack <verb>` — MITRE ATT&CK views over HSE's existing, versioned
//! [`core::attack`](crate::core::attack) layer (Enterprise v19.2).
//!
//! Raw ATT&CK object claims (parents + sub-techniques) remain the provenance
//! authority and feed Navigator export. Human-facing coverage is projected onto
//! independent leaf capabilities by
//! [`core::attack_reporting`](crate::core::attack_reporting), so a parent with
//! children is a roll-up rather than a second scored unit.
//!
//! HSE honestly claims coverage of exactly ONE tactic — Reconnaissance (TA0043).
//! `ATT&CK COVERAGE ≠ DETECTION EFFECTIVENESS`: this reports collection reach,
//! not detection.

use clap::Subcommand;

use crate::core::attack::{self, navigator_layer};
use crate::core::attack_reporting::hierarchy_coverage;
use crate::core::error::{Error, Result};
use crate::modules::{reconnaissance_coverage, technique_module_index};

/// The `hse attack` sub-grammar. `--json` gives the machine-readable shape;
/// `navigator` always emits JSON (a Navigator layer file).
#[derive(Subcommand)]
pub enum AttackAction {
    /// ATT&CK posture summary: catalogue version, tactic, leaf capability reach,
    /// and the raw ATT&CK-object claims beneath it.
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Reconnaissance leaf capability coverage and its evidence modules.
    Coverage {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Uncovered leaf capabilities, separated into actionable gaps and
    /// deliberate exclusions.
    Gaps {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Emit a MITRE ATT&CK Navigator layer (JSON) for HSE's raw static claims,
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

/// `hse attack status` — hierarchy-aware posture summary.
fn status(json: bool) -> Result<()> {
    let raw = reconnaissance_coverage();
    let report = hierarchy_coverage(&raw);
    let modules_mapped = technique_module_index().len();

    if json {
        return print_json(&serde_json::json!({
            "attack_version": attack::ATTACK_VERSION,
            "tactic_id": raw.tactic_id,
            "tactic_name": raw.tactic_name,
            "coverage_basis": report.coverage_basis,
            "techniques_total": report.leaf_techniques_total,
            "techniques_covered": report.leaf_techniques_covered,
            "leaf_techniques_total": report.leaf_techniques_total,
            "leaf_techniques_covered": report.leaf_techniques_covered,
            "coverage_fraction": report.coverage_fraction,
            "attack_objects_total": report.attack_objects_total,
            "attack_objects_covered": report.attack_objects_covered,
            "raw_object_coverage_fraction": raw.coverage_fraction,
            "parent_rollups": report.parent_rollups,
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
        raw.tactic_id, raw.tactic_name
    );
    println!(
        "Leaf coverage     : {}/{} independent capabilities ({:.1}%)",
        report.leaf_techniques_covered,
        report.leaf_techniques_total,
        report.coverage_fraction * 100.0
    );
    println!(
        "Direct claims     : {}/{} ATT&CK objects (parents + sub-techniques; not scored)",
        report.attack_objects_covered, report.attack_objects_total
    );
    println!("Techniques w/ >=1 module : {modules_mapped}");
    println!(
        "\nParents with children are roll-ups, not extra scored units. Coverage is \
         scoped to Reconnaissance only; no other tactic is claimed. This reports \
         collection reach, not detection effectiveness."
    );
    Ok(())
}

/// `hse attack coverage` — covered leaf capabilities and their evidence modules.
fn coverage(json: bool) -> Result<()> {
    let raw = reconnaissance_coverage();
    let report = hierarchy_coverage(&raw);
    let idx = technique_module_index();

    if json {
        let covered: Vec<serde_json::Value> = report
            .covered_leaves
            .iter()
            .map(|technique| {
                serde_json::json!({
                    "id": technique.id,
                    "name": technique.name,
                    "modules": idx.get(technique.id),
                })
            })
            .collect();
        return print_json(&serde_json::json!({
            "tactic_id": raw.tactic_id,
            "tactic_name": raw.tactic_name,
            "coverage_basis": report.coverage_basis,
            "leaf_techniques_total": report.leaf_techniques_total,
            "leaf_techniques_covered": report.leaf_techniques_covered,
            "coverage_fraction": report.coverage_fraction,
            "attack_objects_total": report.attack_objects_total,
            "attack_objects_covered": report.attack_objects_covered,
            "covered": covered,
            "parent_rollups": report.parent_rollups,
        }));
    }

    println!("MITRE ATT&CK — HSE Reconnaissance (TA0043) leaf coverage\n");
    if report.covered_leaves.is_empty() {
        println!("No leaf capabilities covered.");
        return Ok(());
    }
    println!("{:<12}  {:<34}  MODULES (evidence)", "TECHNIQUE", "NAME");
    println!("{}", "─".repeat(96));
    for technique in &report.covered_leaves {
        println!(
            "{:<12}  {:<34}  {}",
            technique.id,
            technique.name,
            modules_for(technique.id)
        );
    }
    println!(
        "\n{}/{} independent leaf capabilities covered ({:.1}%).",
        report.leaf_techniques_covered,
        report.leaf_techniques_total,
        report.coverage_fraction * 100.0
    );
    println!(
        "Raw provenance remains {}/{} directly claimed ATT&CK objects.",
        report.attack_objects_covered, report.attack_objects_total
    );

    println!("\nParent family roll-ups:");
    println!("{:<12}  {:<34}  CHILDREN", "PARENT", "NAME");
    println!("{}", "─".repeat(66));
    for parent in &report.parent_rollups {
        println!(
            "{:<12}  {:<34}  {}/{}{}",
            parent.id,
            parent.name,
            parent.covered_children,
            parent.total_children,
            if parent.directly_covered {
                "  (parent directly claimed)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

/// `hse attack gaps` — uncovered leaf capabilities, classified by intent.
fn gaps(json: bool) -> Result<()> {
    let raw = reconnaissance_coverage();
    let report = hierarchy_coverage(&raw);

    if json {
        let all: Vec<serde_json::Value> = report
            .uncovered_leaves
            .iter()
            .map(|technique| serde_json::json!({ "id": technique.id, "name": technique.name }))
            .collect();
        let capability_gaps: Vec<serde_json::Value> = report
            .capability_gaps
            .iter()
            .map(|technique| serde_json::json!({ "id": technique.id, "name": technique.name }))
            .collect();
        let intentional_exclusions: Vec<serde_json::Value> = report
            .intentional_exclusions
            .iter()
            .map(|technique| serde_json::json!({ "id": technique.id, "name": technique.name }))
            .collect();
        return print_json(&serde_json::json!({
            "coverage_basis": report.coverage_basis,
            "uncovered_leaf_total": report.uncovered_leaves.len(),
            "gaps": all,
            "capability_gaps": capability_gaps,
            "intentional_exclusions": intentional_exclusions,
        }));
    }

    println!("MITRE ATT&CK — HSE Reconnaissance (TA0043) leaf gaps\n");

    println!("Capability gaps — collection capability not currently implemented:");
    if report.capability_gaps.is_empty() {
        println!("  None.");
    } else {
        for technique in &report.capability_gaps {
            println!("  {:<12}  {}", technique.id, technique.name);
        }
    }

    println!("\nIntentional exclusions — outside HSE's collection contract by design:");
    if report.intentional_exclusions.is_empty() {
        println!("  None.");
    } else {
        for technique in &report.intentional_exclusions {
            println!("  {:<12}  {}", technique.id, technique.name);
        }
    }

    println!(
        "\n{} of {} independent leaf capabilities are uncovered: {} actionable, {} deliberate.",
        report.uncovered_leaves.len(),
        report.leaf_techniques_total,
        report.capability_gaps.len(),
        report.intentional_exclusions.len()
    );
    Ok(())
}

/// `hse attack navigator` — raw ATT&CK object claims as a Navigator layer.
fn navigator() -> Result<()> {
    let cov = reconnaissance_coverage();
    let layer = navigator_layer(&cov, "HSE static Reconnaissance coverage");
    print_json(&layer)
}
