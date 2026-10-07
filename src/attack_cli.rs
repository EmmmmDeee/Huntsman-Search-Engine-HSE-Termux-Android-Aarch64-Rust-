//! Legacy-compatible ATT&CK CLI rendering over current reachable capability.
//!
//! This module renders the existing ATT&CK catalogue and hierarchy-aware coverage.
//! It does not infer execution from catalogue presence and does not duplicate module
//! reachability: module evidence comes from `module::reachable_modules`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::json;

use crate::attack::{self, Coverage};
use crate::attack_reporting::{HierarchyCoverage, hierarchy_coverage};
use crate::module::reachable_modules;
use crate::navigator;

pub const ATTACK_USAGE: &str =
    "usage: huntsman-recon attack status|coverage|gaps [--json] | attack navigator";

fn module_index() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut index = BTreeMap::<&'static str, Vec<&'static str>>::new();
    for module in reachable_modules().iter().filter(|module| {
        module.network && module.category != crate::dependency::ModuleCategory::Other
    }) {
        for id in attack::techniques_for_category(module.category) {
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
    let raw = attack::static_reconnaissance_coverage(modules.keys().copied());
    let hierarchy = hierarchy_coverage(&raw);
    (modules, raw, hierarchy)
}

fn json_line(value: &serde_json::Value) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|mut text| {
            text.push('\n');
            text
        })
        .map_err(|error| format!("serialize ATT&CK output: {error}"))
}

fn parse_json_flag(args: &[String]) -> Result<bool, String> {
    match args {
        [] => Ok(false),
        [flag] if flag == "--json" => Ok(true),
        _ => Err(ATTACK_USAGE.to_string()),
    }
}

fn modules_for<'a>(
    index: &'a BTreeMap<&'static str, Vec<&'static str>>,
    id: &str,
) -> &'a [&'static str] {
    index.get(id).map_or(&[], Vec::as_slice)
}

fn status(json_output: bool) -> Result<String, String> {
    let (index, raw, hierarchy) = coverage_state();
    if json_output {
        return json_line(&json!({
            "attack_version": attack::ATTACK_VERSION,
            "tactic_id": raw.tactic_id,
            "tactic_name": raw.tactic_name,
            "coverage_basis": hierarchy.coverage_basis,
            "leaf_techniques_total": hierarchy.leaf_techniques_total,
            "leaf_techniques_covered": hierarchy.leaf_techniques_covered,
            "coverage_fraction": hierarchy.coverage_fraction,
            "attack_objects_total": hierarchy.attack_objects_total,
            "attack_objects_covered": hierarchy.attack_objects_covered,
            "techniques_with_module_evidence": index.len(),
            "reachable_modules": reachable_modules().len(),
        }));
    }

    Ok(format!(
        "MITRE ATT&CK posture — Huntsman Recon\n\n\
Catalogue version : ATT&CK Enterprise v{}\n\
Tactic in scope   : {} {}\n\
Coverage basis    : {}\n\
Leaf coverage     : {}/{} ({:.1}%)\n\
ATT&CK objects    : {}/{} covered (parents retained as roll-ups)\n\
Mapped techniques : {} with reachable module evidence\n\
Reachable modules : {}\n\n\
Coverage reports collection capability, not detection effectiveness.\n",
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
        reachable_modules().len(),
    ))
}

fn coverage(json_output: bool) -> Result<String, String> {
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
                    "structural_mapping": modules.is_empty(),
                })
            })
            .collect::<Vec<_>>();
        return json_line(&json!({
            "tactic_id": attack::TACTIC_ID,
            "tactic_name": attack::TACTIC_NAME,
            "coverage_basis": hierarchy.coverage_basis,
            "coverage_fraction": hierarchy.coverage_fraction,
            "covered": covered,
            "parent_rollups": hierarchy.parent_rollups,
        }));
    }

    let mut output = String::from("MITRE ATT&CK — Huntsman Reconnaissance coverage\n\n");
    writeln!(
        &mut output,
        "{:<12}  {:<36}  MODULES (evidence)",
        "TECHNIQUE", "NAME"
    )
    .map_err(|error| error.to_string())?;
    writeln!(&mut output, "{}", "─".repeat(96)).map_err(|error| error.to_string())?;
    for technique in &hierarchy.covered_leaves {
        let modules = modules_for(&index, technique.id);
        let evidence = if modules.is_empty() {
            "— (entity/relation mapping)".to_string()
        } else {
            modules.join(", ")
        };
        writeln!(
            &mut output,
            "{:<12}  {:<36}  {}",
            technique.id, technique.name, evidence
        )
        .map_err(|error| error.to_string())?;
    }
    writeln!(
        &mut output,
        "\n{}/{} independent leaf techniques covered ({:.1}%).",
        hierarchy.leaf_techniques_covered,
        hierarchy.leaf_techniques_total,
        hierarchy.coverage_fraction * 100.0
    )
    .map_err(|error| error.to_string())?;
    Ok(output)
}

fn gaps(json_output: bool) -> Result<String, String> {
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
    writeln!(&mut output, "{:<12}  NAME", "TECHNIQUE").map_err(|error| error.to_string())?;
    writeln!(&mut output, "{}", "─".repeat(60)).map_err(|error| error.to_string())?;
    for technique in &hierarchy.uncovered_leaves {
        writeln!(&mut output, "{:<12}  {}", technique.id, technique.name)
            .map_err(|error| error.to_string())?;
    }
    writeln!(
        &mut output,
        "\n{} of {} independent leaf techniques are uncovered.",
        hierarchy.uncovered_leaves.len(),
        hierarchy.leaf_techniques_total
    )
    .map_err(|error| error.to_string())?;
    Ok(output)
}

fn navigator_layer() -> Result<String, String> {
    let (_index, raw, _hierarchy) = coverage_state();
    json_line(&navigator::coverage_layer(
        &raw,
        "static reachable capability",
    ))
}

/// Render one legacy-compatible `attack` subcommand.
///
/// # Errors
/// Returns the usage contract for an invalid verb/flag or a serialization failure.
pub fn render(args: &[String]) -> Result<String, String> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(ATTACK_USAGE.to_string());
    };
    match verb.as_str() {
        "status" => status(parse_json_flag(rest)?),
        "coverage" => coverage(parse_json_flag(rest)?),
        "gaps" => gaps(parse_json_flag(rest)?),
        "navigator" if rest.is_empty() => navigator_layer(),
        _ => Err(ATTACK_USAGE.to_string()),
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
        assert_eq!(render(&[]).unwrap_err(), ATTACK_USAGE);
        assert_eq!(
            render(&args(&["navigator", "--json"])).unwrap_err(),
            ATTACK_USAGE
        );
    }

    #[test]
    fn status_json_uses_leaf_coverage_and_current_catalogue_version() {
        let text = render(&args(&["status", "--json"])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["attack_version"], attack::ATTACK_VERSION);
        assert_eq!(value["tactic_id"], attack::TACTIC_ID);
        assert_eq!(
            value["coverage_basis"],
            crate::attack_reporting::COVERAGE_BASIS
        );
        assert!(value["leaf_techniques_total"].as_u64().unwrap() > 0);
        assert!(value["leaf_techniques_covered"].as_u64().unwrap() > 0);
        assert!(
            value["leaf_techniques_covered"].as_u64().unwrap()
                <= value["leaf_techniques_total"].as_u64().unwrap()
        );
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
        let structural = covered
            .iter()
            .filter(|row| row["structural_mapping"] == true)
            .count();
        assert!(with_module > 0);
        assert!(structural > 0);
    }

    #[test]
    fn navigator_is_reconnaissance_only_and_catalogue_complete() {
        let text = render(&args(&["navigator"])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["domain"], "enterprise-attack");
        assert_eq!(value["versions"]["attack"], attack::attack_spec_major());
        assert_eq!(
            value["techniques"].as_array().unwrap().len(),
            attack::reconnaissance().len()
        );
    }
}
