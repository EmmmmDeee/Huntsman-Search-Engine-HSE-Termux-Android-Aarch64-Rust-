//! Legacy-compatible ATT&CK CLI rendering over current reachable capability.
//!
//! This module renders the existing ATT&CK catalogue and hierarchy-aware coverage.
//! It does not infer execution from catalogue presence and does not duplicate module
//! reachability: module evidence comes from `module::reachable_modules`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::json;

use crate::attack::{self, Coverage};
use crate::attack_reporting::{HierarchyCoverage, hierarchy_coverage};
use crate::module::reachable_modules;
use crate::navigator;

pub const ATTACK_USAGE: &str =
    "usage: huntsman-recon attack status|coverage|gaps [--json] | attack navigator";

/// An `attack` invocation outside the grammar; it displays as [`ATTACK_USAGE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage;

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(ATTACK_USAGE)
    }
}

fn module_index() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut index = BTreeMap::<&'static str, Vec<&'static str>>::new();
    for module in reachable_modules().iter().filter(|module| module.network) {
        for id in module.attack_techniques {
            index.entry(id).or_default().push(module.name);
        }
    }
    for modules in index.values_mut() {
        modules.sort_unstable();
        modules.dedup();
    }
    index
}

fn coverage_state() -> (
    BTreeMap<&'static str, Vec<&'static str>>,
    Coverage,
    HierarchyCoverage,
) {
    let modules = module_index();
    let exercised = modules
        .iter()
        .map(|(id, evidence)| ((*id).to_owned(), evidence.len()))
        .collect::<BTreeMap<_, _>>();
    let raw = attack::coverage(&exercised);
    let hierarchy = hierarchy_coverage(&raw);
    (modules, raw, hierarchy)
}

fn json_line(value: &serde_json::Value) -> String {
    // A `Value` has string keys and no non-finite numbers, so it always serialises.
    let mut text = serde_json::to_string_pretty(value).expect("a JSON value serialises");
    text.push('\n');
    text
}

fn parse_json_flag(args: &[String]) -> Result<bool, Usage> {
    match args {
        [] => Ok(false),
        [flag] if flag == "--json" => Ok(true),
        _ => Err(Usage),
    }
}

fn modules_for<'a>(
    index: &'a BTreeMap<&'static str, Vec<&'static str>>,
    id: &str,
) -> &'a [&'static str] {
    index.get(id).map_or(&[], Vec::as_slice)
}

fn mapped_module_count(index: &BTreeMap<&'static str, Vec<&'static str>>) -> usize {
    index
        .values()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
}

fn status(json_output: bool) -> String {
    let (index, raw, hierarchy) = coverage_state();
    if json_output {
        return json_line(&json!({
            "attack_version": attack::RECONNAISSANCE_VERSION,
            "catalogue_source": attack::RECONNAISSANCE_SOURCE_URL,
            "version_source": attack::RECONNAISSANCE_VERSION_SOURCE_URL,
            "version_changelog": attack::RECONNAISSANCE_CHANGELOG_URL,
            "enterprise_baseline_version": attack::ATTACK_VERSION,
            "catalogue_scope": "reconnaissance",
            "evidence_basis": "reachable_network_modules",
            "tactic_id": raw.tactic_id,
            "tactic_name": raw.tactic_name,
            "coverage_basis": hierarchy.coverage_basis,
            "leaf_techniques_total": hierarchy.leaf_techniques_total,
            "leaf_techniques_covered": hierarchy.leaf_techniques_covered,
            "coverage_fraction": hierarchy.coverage_fraction,
            "attack_objects_total": hierarchy.attack_objects_total,
            "attack_objects_covered": hierarchy.attack_objects_covered,
            "techniques_with_module_evidence": index.len(),
            "mapped_network_modules": mapped_module_count(&index),
            "reachable_modules": reachable_modules().len(),
        }));
    }

    format!(
        "MITRE ATT&CK posture — Huntsman Recon\n\n\
Recon catalogue   : ATT&CK Enterprise TA0043 v{}\n\
Recon source      : {}\n\
Version source    : {}\n\
Version changelog : {}\n\
Enterprise base   : embedded full-matrix snapshot v{}\n\
Tactic in scope   : {} {}\n\
Coverage basis    : {} over reachable network modules\n\
Leaf coverage     : {}/{} ({:.1}%)\n\
ATT&CK objects    : {}/{} covered (parents retained as roll-ups)\n\
Mapped techniques : {} with reachable module evidence\n\
Mapped collectors : {} reachable network modules\n\
Reachable modules : {} total CLI-reachable modules\n\n\
Coverage reports reachable module mapping, not technique execution or detection effectiveness.\n",
        attack::RECONNAISSANCE_VERSION,
        attack::RECONNAISSANCE_SOURCE_URL,
        attack::RECONNAISSANCE_VERSION_SOURCE_URL,
        attack::RECONNAISSANCE_CHANGELOG_URL,
        attack::ATTACK_VERSION,
        raw.tactic_id,
        raw.tactic_name,
        hierarchy.coverage_basis,
        hierarchy.leaf_techniques_covered,
        hierarchy.leaf_techniques_total,
        hierarchy.coverage_fraction * 100.0,
        hierarchy.attack_objects_covered,
        hierarchy.attack_objects_total,
        index.len(),
        mapped_module_count(&index),
        reachable_modules().len(),
    )
}

fn coverage(json_output: bool) -> String {
    let (index, _raw, hierarchy) = coverage_state();
    if json_output {
        let covered = hierarchy
            .covered_leaves
            .iter()
            .map(|technique| {
                let modules = modules_for(&index, technique.id);
                json!({
                    "id": technique.id,
                    "name": technique.name,
                    "modules": modules,
                    "evidence_basis": "reachable_network_modules",
                })
            })
            .collect::<Vec<_>>();
        // A collector mapped to a parent technique (one with sub-techniques) names no leaf, so the
        // roll-up names it, as `attack status` counts it among the mapped collectors.
        let parent_rollups = hierarchy
            .parent_rollups
            .iter()
            .map(|rollup| {
                json!({
                    "id": rollup.id,
                    "name": rollup.name,
                    "directly_covered": rollup.directly_covered,
                    "covered_children": rollup.covered_children,
                    "total_children": rollup.total_children,
                    "modules": modules_for(&index, rollup.id),
                })
            })
            .collect::<Vec<_>>();
        return json_line(&json!({
            "tactic_id": attack::TACTIC_ID,
            "tactic_name": attack::TACTIC_NAME,
            "coverage_basis": hierarchy.coverage_basis,
            "coverage_fraction": hierarchy.coverage_fraction,
            "covered": covered,
            "parent_rollups": parent_rollups,
        }));
    }

    let mut output = String::from("MITRE ATT&CK — Huntsman Reconnaissance coverage\n\n");
    let _ = writeln!(
        &mut output,
        "{:<12}  {:<36}  MODULES (evidence)",
        "TECHNIQUE", "NAME"
    );
    let _ = writeln!(&mut output, "{}", "─".repeat(96));
    for technique in &hierarchy.covered_leaves {
        let modules = modules_for(&index, technique.id);
        let evidence = modules.join(", ");
        let _ = writeln!(
            &mut output,
            "{:<12}  {:<36}  {}",
            technique.id, technique.name, evidence
        );
    }
    let _ = writeln!(
        &mut output,
        "\n{}/{} independent leaf techniques covered ({:.1}%).",
        hierarchy.leaf_techniques_covered,
        hierarchy.leaf_techniques_total,
        hierarchy.coverage_fraction * 100.0
    );
    let _ = writeln!(
        &mut output,
        "\nParent roll-ups (not scored)\n{:<12}  {:<36}  {:<8}  MODULES (mapped to the parent)",
        "TECHNIQUE", "NAME", "CHILDREN"
    );
    let _ = writeln!(&mut output, "{}", "─".repeat(96));
    for rollup in &hierarchy.parent_rollups {
        let modules = modules_for(&index, rollup.id);
        let _ = writeln!(
            &mut output,
            "{:<12}  {:<36}  {:<8}  {}",
            rollup.id,
            rollup.name,
            format!("{}/{}", rollup.covered_children, rollup.total_children),
            if modules.is_empty() {
                "-".to_owned()
            } else {
                modules.join(", ")
            }
        );
    }
    output
}

fn gaps(json_output: bool) -> String {
    let (_index, _raw, hierarchy) = coverage_state();
    if json_output {
        let gaps = hierarchy
            .uncovered_leaves
            .iter()
            .map(|technique| json!({"id": technique.id, "name": technique.name}))
            .collect::<Vec<_>>();
        return json_line(&json!({
            "coverage_basis": hierarchy.coverage_basis,
            "gaps": gaps,
        }));
    }

    let mut output = String::from("MITRE ATT&CK — Huntsman Reconnaissance coverage gaps\n\n");
    let _ = writeln!(&mut output, "{:<12}  NAME", "TECHNIQUE");
    let _ = writeln!(&mut output, "{}", "─".repeat(60));
    for technique in &hierarchy.uncovered_leaves {
        let _ = writeln!(&mut output, "{:<12}  {}", technique.id, technique.name);
    }
    let _ = writeln!(
        &mut output,
        "\n{} of {} independent leaf techniques are uncovered.",
        hierarchy.uncovered_leaves.len(),
        hierarchy.leaf_techniques_total
    );
    output
}

fn navigator_layer() -> String {
    let (_index, raw, _hierarchy) = coverage_state();
    json_line(&navigator::coverage_layer(
        &raw,
        "reachable network-module capability",
    ))
}

/// Render one legacy-compatible `attack` subcommand.
///
/// # Errors
/// [`Usage`] for an unknown verb or flag.
pub fn render(args: &[String]) -> Result<String, Usage> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(Usage);
    };
    match verb.as_str() {
        "status" => Ok(status(parse_json_flag(rest)?)),
        "coverage" => Ok(coverage(parse_json_flag(rest)?)),
        "gaps" => Ok(gaps(parse_json_flag(rest)?)),
        "navigator" if rest.is_empty() => Ok(navigator_layer()),
        _ => Err(Usage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn legacy_verbs_and_json_flags_are_accepted() {
        for values in [
            &["status"][..],
            &["status", "--json"][..],
            &["coverage"][..],
            &["coverage", "--json"][..],
            &["gaps"][..],
            &["gaps", "--json"][..],
            &["navigator"][..],
        ] {
            assert!(render(&args(values)).is_ok(), "{values:?}");
        }
        for values in [
            &[][..],
            &["navigator", "--json"][..],
            &["status", "--json", "extra"][..],
            &["status", "--xml"][..],
            &["bogus"][..],
        ] {
            assert_eq!(render(&args(values)), Err(Usage), "{values:?}");
        }
        assert_eq!(Usage.to_string(), ATTACK_USAGE);
    }

    #[test]
    fn status_json_uses_leaf_coverage_and_current_catalogue_version() {
        let text = render(&args(&["status", "--json"])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["attack_version"], attack::RECONNAISSANCE_VERSION);
        assert_eq!(value["catalogue_source"], attack::RECONNAISSANCE_SOURCE_URL);
        assert_eq!(
            value["version_source"],
            attack::RECONNAISSANCE_VERSION_SOURCE_URL
        );
        assert_eq!(
            value["version_changelog"],
            attack::RECONNAISSANCE_CHANGELOG_URL
        );
        assert_eq!(value["enterprise_baseline_version"], attack::ATTACK_VERSION);
        assert_eq!(value["evidence_basis"], "reachable_network_modules");
        assert_eq!(value["tactic_id"], attack::TACTIC_ID);
        assert_eq!(
            value["coverage_basis"],
            crate::attack_reporting::COVERAGE_BASIS
        );
        assert!(value["leaf_techniques_total"].as_u64().unwrap() > 0);
        assert!(value["leaf_techniques_covered"].as_u64().unwrap() > 0);
        assert!(value["mapped_network_modules"].as_u64().unwrap() > 0);
        assert!(
            value["mapped_network_modules"].as_u64().unwrap()
                <= value["reachable_modules"].as_u64().unwrap()
        );
        assert!(
            value["leaf_techniques_covered"].as_u64().unwrap()
                <= value["leaf_techniques_total"].as_u64().unwrap()
        );
    }

    #[test]
    fn every_mapped_collector_is_named_by_a_coverage_row() {
        // `attack status` counts every network module with a mapping; `attack coverage` must
        // name each one somewhere, a leaf row or the roll-up of the parent it maps to.
        let value: serde_json::Value =
            serde_json::from_str(&render(&args(&["coverage", "--json"])).unwrap()).unwrap();
        let named = ["covered", "parent_rollups"]
            .iter()
            .flat_map(|key| value[*key].as_array().unwrap())
            .flat_map(|row| row["modules"].as_array().unwrap())
            .filter_map(serde_json::Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let mapped = module_index()
            .into_values()
            .flatten()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(named, mapped);
        let text = render(&args(&["coverage"])).unwrap();
        assert!(text.contains("Parent roll-ups (not scored)"), "{text}");
    }

    #[test]
    fn coverage_json_carries_reachable_module_evidence_without_claiming_every_mapping_has_a_module()
    {
        let text = render(&args(&["coverage", "--json"])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let covered = value["covered"].as_array().unwrap();
        let with_module = covered
            .iter()
            .filter(|row| !row["modules"].as_array().unwrap().is_empty())
            .count();
        assert!(with_module > 0);
        assert_eq!(with_module, covered.len());
        let github = covered
            .iter()
            .find(|row| row["id"] == "T1593.003")
            .expect("GitHub collector maps to Code Repositories");
        assert!(
            github["modules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m == "github_user")
        );
        assert!(
            !covered.iter().find(|row| row["id"] == "T1593.001").unwrap()["modules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m == "github_user")
        );
        assert!(
            covered
                .iter()
                .all(|row| row["evidence_basis"] == "reachable_network_modules")
        );

        let gaps = render(&args(&["gaps", "--json"])).unwrap();
        let gap_value: serde_json::Value = serde_json::from_str(&gaps).unwrap();
        let gap_ids = gap_value["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["id"].as_str())
            .collect::<BTreeSet<_>>();
        assert!(gap_ids.contains("T1681"));
        assert!(gap_ids.contains("T1682"));
    }

    #[test]
    fn navigator_is_reconnaissance_only_and_catalogue_complete() {
        let text = render(&args(&["navigator"])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["domain"], "enterprise-attack");
        assert_eq!(
            value["versions"]["attack"],
            attack::reconnaissance_spec_major()
        );
        assert_eq!(
            value["techniques"].as_array().unwrap().len(),
            attack::reconnaissance().len()
        );
    }
}
