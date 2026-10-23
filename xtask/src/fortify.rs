//! Evidence-gated engineering controller. Repository tooling only: no runtime dependencies,
//! network fetches, secret reads, unsolicited deployments, or financial transactions.
//!
//! `plan` describes the immutable responsibilities and phase contracts; `validate` checks
//! those contracts against the checkout; `status` observes its actual revision; `run` delegates
//! to the existing mutation-detecting gate; `score` calculates expected net value.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::error::{self, Error, Result};
use crate::gate;
use crate::proc::{git_stdout, repository_root};

const USAGE: &str = "usage: cargo run --locked -p xtask -- fortify <command>

commands:
  plan                        print the immutable roles and five phase contracts as JSON
  validate                    check contract topology and existing repository gates
  status                      print actual checkout revision and cleanliness as JSON
  run fast|msrv|full           validate, then execute the existing verification gate
  score UPSIDE COST LOSS OPPORTUNITY TIME
                              calculate expected net value (nonnegative integral units)

Deployment, branch merges, purchases, and live provider actions are not performed by fortify.";

#[derive(Clone, Copy)]
struct Role {
    id: &'static str,
    owner: &'static str,
    parent: Option<&'static str>,
    responsibility: &'static str,
}

#[derive(Clone, Copy)]
struct Phase {
    id: &'static str,
    owner: &'static str,
    predecessor: Option<&'static str>,
    contract: &'static str,
    verification: &'static str,
}

// This mirrors the repository's canonical functional council. Names identify responsibility,
// not separate agents, endorsements, or evidence that any person performed work.
const ROLES: &[Role] = &[
    Role {
        id: "strategy",
        owner: "JEFF DEAN",
        parent: None,
        responsibility: "objectives and acceptance criteria",
    },
    Role {
        id: "systems",
        owner: "JAMES HAMILTON",
        parent: Some("strategy"),
        responsibility: "architecture and execution coordination",
    },
    Role {
        id: "integration",
        owner: "DANIEL STENBERG",
        parent: Some("systems"),
        responsibility: "integration and core security",
    },
    Role {
        id: "research",
        owner: "JURE LESKOVEC",
        parent: Some("systems"),
        responsibility: "research and development",
    },
    Role {
        id: "production",
        owner: "JEZ HUMBLE",
        parent: Some("systems"),
        responsibility: "production scalability",
    },
    Role {
        id: "refactoring",
        owner: "MARTIN FOWLER",
        parent: Some("systems"),
        responsibility: "structural improvement",
    },
    Role {
        id: "distributed",
        owner: "LESLIE LAMPORT",
        parent: Some("systems"),
        responsibility: "distributed correctness and redundancy",
    },
    Role {
        id: "information",
        owner: "ELIOT HIGGINS",
        parent: Some("systems"),
        responsibility: "source verification and provenance",
    },
    Role {
        id: "operations",
        owner: "URS HÖLZLE",
        parent: Some("systems"),
        responsibility: "operational capacity and infrastructure",
    },
    Role {
        id: "platform",
        owner: "MITCHELL HASHIMOTO",
        parent: Some("systems"),
        responsibility: "platform and release engineering",
    },
    Role {
        id: "implementation",
        owner: "ANDREW GALLANT",
        parent: Some("systems"),
        responsibility: "Rust implementation",
    },
    Role {
        id: "performance",
        owner: "BRENDAN GREGG",
        parent: Some("systems"),
        responsibility: "profiling and performance measurement",
    },
    Role {
        id: "verification",
        owner: "RALF JUNG",
        parent: Some("systems"),
        responsibility: "independent correctness and tests",
    },
    Role {
        id: "security",
        owner: "TAVIS ORMANDY",
        parent: Some("systems"),
        responsibility: "independent defensive security gates",
    },
    Role {
        id: "resources",
        owner: "PATRICK COLLISON",
        parent: Some("systems"),
        responsibility: "cost and resource allocation",
    },
    Role {
        id: "economics",
        owner: "PIETER LEVELS",
        parent: Some("systems"),
        responsibility: "expected net value and self-funding analysis",
    },
];

const PHASES: &[Phase] = &[
    Phase {
        id: "design",
        owner: "strategy",
        predecessor: None,
        contract: "Record objectives, architecture, integration contracts and acceptance criteria",
        verification: "The role and phase dependency graph is complete and acyclic",
    },
    Phase {
        id: "research",
        owner: "research",
        predecessor: Some("design"),
        contract: "Ground proposed improvements in current, timestamped evidence and alternatives",
        verification: "Unverified claims and missing inputs are explicit; no invented observations",
    },
    Phase {
        id: "implement",
        owner: "implementation",
        predecessor: Some("research"),
        contract: "Implement minimal compatible Rust changes and enforce bounded resources",
        verification: "Formatting, build, tests, API contracts and platform checks are executed",
    },
    Phase {
        id: "optimize",
        owner: "performance",
        predecessor: Some("implement"),
        contract: "Measure correctness, cost, memory, latency and regression risk against a baseline",
        verification: "The existing gate verifies the checkout and rejects test-induced mutation",
    },
    Phase {
        id: "deploy",
        owner: "platform",
        predecessor: Some("optimize"),
        contract: "Require authorised delivery, independent security and test gates, health checks and rollback",
        verification: "CI and release workflows are present; promotion is never inferred from a plan",
    },
];

#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let root = repository_root();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["plan"] => output(plan()),
        ["validate"] => match validate(&root) {
            Ok(()) => {
                println!("fortify: PASS static contracts and repository gate wiring");
                ExitCode::SUCCESS
            }
            Err(problem) => error::report("fortify: FAIL", &problem),
        },
        ["status"] => match status(&root) {
            Ok(value) => output(value),
            Err(problem) => error::report("fortify: FAIL", &problem),
        },
        ["run", mode @ ("fast" | "msrv" | "full")] => match validate(&root) {
            Ok(()) => gate::run(&[(*mode).to_owned()]),
            Err(problem) => error::report("fortify: FAIL", &problem),
        },
        ["score", upside, cost, loss, opportunity, time] => {
            let values = [*upside, *cost, *loss, *opportunity, *time];
            match parse_amounts(values) {
                Ok([upside, cost, loss, opportunity, time]) => {
                    let value = net_value(upside, [cost, loss, opportunity, time]);
                    output(json!({
                        "expected_net_value_units": value.to_string(),
                        "decision": if value > 0 { "candidate" } else { "defer" },
                        "note": "Calculation only; neither expenditure nor deployment is authorised"
                    }))
                }
                Err(problem) => error::report("fortify: FAIL", &problem),
            }
        }
        ["-h" | "--help"] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => error::usage(USAGE),
    }
}

fn output(value: Value) -> ExitCode {
    println!("{value}");
    ExitCode::SUCCESS
}

fn plan() -> Value {
    let roles: Vec<Value> = ROLES
        .iter()
        .enumerate()
        .map(|(index, role)| json!({
            "rank": index + 1,
            "id": role.id,
            "owner": role.owner,
            "reports_to": role.parent,
            "responsibility": role.responsibility,
        }))
        .collect();
    let phases: Vec<Value> = PHASES
        .iter()
        .map(|phase| json!({
            "id": phase.id,
            "owner": phase.owner,
            "predecessor": phase.predecessor,
            "contract": phase.contract,
            "verification": phase.verification,
        }))
        .collect();
    json!({
        "schema": "huntsman.fortified-pipeline/1",
        "chain_of_command": ["strategy", "systems", "specialists"],
        "roles": roles,
        "phases": phases,
        "protocol": {
            "runtime": "pure Rust; rootless Android AArch64; no runtime LLM",
            "evidence": "provenance and freshness required for external conclusions",
            "security": "least privilege; no credential export; independent release gates",
            "quality": "strict gates; targets are not evidence of coverage achieved",
            "delivery": "explicit approval, health checks and recovery before promotion",
            "economics": "upside - direct cost - expected loss - opportunity cost - time cost",
        },
        "execution": "fortify run full invokes the existing verification gate; it does not deploy",
    })
}

/// Validate immutable order and edges; a dependency must appear before its dependent.
fn validate_model(roles: &[Role], phases: &[Phase]) -> Result<()> {
    if roles.len() != 16 || phases.len() != 5 {
        return Err(Error::Refused("unexpected role or phase count".to_owned()));
    }
    if roles[0].id != "strategy"
        || roles[0].parent.is_some()
        || roles[1].id != "systems"
        || roles[1].parent != Some("strategy")
    {
        return Err(Error::Refused("command authority changed".to_owned()));
    }
    let mut seen_roles = BTreeSet::new();
    for (index, role) in roles.iter().enumerate() {
        if role.id.is_empty() || role.owner.is_empty() || role.responsibility.is_empty()
            || !seen_roles.insert(role.id)
        {
            return Err(Error::Refused("duplicate or incomplete role".to_owned()));
        }
        if index > 1 && role.parent != Some("systems") {
            return Err(Error::Refused(format!("invalid parent for {}", role.id)));
        }
    }

    let mut seen_phases = BTreeSet::new();
    for (index, phase) in phases.iter().enumerate() {
        if !seen_roles.contains(phase.owner)
            || phase.id.is_empty()
            || phase.contract.is_empty()
            || phase.verification.is_empty()
            || !seen_phases.insert(phase.id)
        {
            return Err(Error::Refused(format!("incomplete phase {}", phase.id)));
        }
        if (index == 0 && phase.predecessor.is_some())
            || (index > 0 && phase.predecessor != Some(phases[index - 1].id))
        {
            return Err(Error::Refused(format!("invalid phase dependency {}", phase.id)));
        }
    }
    Ok(())
}

fn checked_text(root: &Path, name: &str) -> Result<String> {
    let path = root.join(name);
    fs::read_to_string(&path).map_err(|source| Error::Io { path, source })
}

fn contains_all(text: &str, required: &[&str], path: &str) -> Result<()> {
    for term in required {
        if !text.contains(*term) {
            return Err(Error::Refused(format!(
                "{path}: missing expected gate wiring {term:?}"
            )));
        }
    }
    Ok(())
}

/// Static gate wiring is a preflight, not proof that CI, Android or a deployment passed.
fn validate(root: &Path) -> Result<()> {
    validate_model(ROLES, PHASES)?;
    let manifest = checked_text(root, "Cargo.toml")?;
    contains_all(&manifest, &["members = [\"xtask\"]", "rust-version = \"1.87\""], "Cargo.toml")?;
    let ci = checked_text(root, ".github/workflows/ci.yml")?;
    contains_all(
        &ci,
        &["gate full", "gate msrv", "aarch64-linux-android", "pull_request:"],
        ".github/workflows/ci.yml",
    )?;
    let audit = checked_text(root, ".github/workflows/audit.yml")?;
    if audit.trim().is_empty() {
        return Err(Error::Refused("audit workflow is empty".to_owned()));
    }
    for path in [
        "AGENTS.md",
        "xtask/src/gate.rs",
        "xtask/src/proc.rs",
        "src/lib.rs",
        "src/main.rs",
        ".github/workflows/release.yml",
        "scripts/termux-runtime-acceptance.sh",
    ] {
        if !root.join(path).is_file() {
            return Err(Error::Refused(format!(
                "required integration file missing: {path}"
            )));
        }
    }
    Ok(())
}

fn status(root: &Path) -> Result<Value> {
    validate(root)?;
    let head = String::from_utf8_lossy(&git_stdout(root, &["rev-parse", "HEAD"])?)
        .trim()
        .to_owned();
    let branch = String::from_utf8_lossy(&git_stdout(root, &["branch", "--show-current"])?)
        .trim()
        .to_owned();
    let dirty = !git_stdout(root, &["status", "--porcelain", "--untracked-files=all"])?
        .is_empty();
    let checked_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|problem| Error::Refused(format!("invalid system clock: {problem}")))?
        .as_secs();
    Ok(json!({
        "schema": "huntsman.fortified-status/1",
        "checked_at_unix": checked_at,
        "commit": head,
        "branch": branch,
        "working_tree_clean": !dirty,
        "contracts": "passed static preflight",
        "verification": "not run by status",
        "deployment": "not performed",
    }))
}

fn parse_amounts(values: [&str; 5]) -> Result<[u64; 5]> {
    let mut result = [0_u64; 5];
    for (index, value) in values.iter().enumerate() {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Invalid(format!(
                "amount {} must be a nonnegative integer without signs or separators",
                index + 1
            )));
        }
        result[index] = value
            .parse()
            .map_err(|_| Error::Invalid(format!("amount {} exceeds u64", index + 1)))?;
    }
    Ok(result)
}

/// i128 retains exact u64 arithmetic even when four costs are each u64::MAX.
fn net_value(upside: u64, costs: [u64; 4]) -> i128 {
    let spend: i128 = costs.into_iter().map(i128::from).sum();
    i128::from(upside) - spend
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_and_phase_dependencies_are_valid() {
        validate_model(ROLES, PHASES).expect("canonical graph valid");
        assert_eq!(ROLES.len(), 16);
        assert_eq!(PHASES.len(), 5);
    }

    #[test]
    fn duplicate_role_is_refused() {
        let mut roles = ROLES.to_vec();
        roles[2].id = roles[1].id;
        assert!(validate_model(&roles, PHASES).is_err());
    }

    #[test]
    fn broken_predecessor_is_refused() {
        let mut phases = PHASES.to_vec();
        phases[3].predecessor = Some("design");
        assert!(validate_model(ROLES, &phases).is_err());
    }

    #[test]
    fn changed_authority_is_refused() {
        let mut roles = ROLES.to_vec();
        roles[1].parent = None;
        assert!(validate_model(&roles, PHASES).is_err());
    }

    #[test]
    fn huge_values_do_not_overflow() {
        assert_eq!(
            net_value(u64::MAX, [u64::MAX; 4]),
            -(3 * i128::from(u64::MAX))
        );
    }

    #[test]
    fn net_value_accounts_for_every_cost() {
        assert_eq!(net_value(100, [15, 10, 20, 5]), 50);
        assert_eq!(net_value(4, [2, 2, 1, 0]), -1);
    }

    #[test]
    fn amount_parser_refuses_negative_fractional_and_overflow() {
        for bad in ["-1", "1.5", "+1", "2,000", "18446744073709551616"] {
            assert!(parse_amounts(["100", bad, "0", "0", "0"]).is_err());
        }
    }

    #[test]
    fn plan_is_machine_readable_and_has_all_phases() {
        let value = plan();
        assert_eq!(value["schema"], "huntsman.fortified-pipeline/1");
        assert_eq!(value["roles"].as_array().map(Vec::len), Some(16));
        assert_eq!(value["phases"].as_array().map(Vec::len), Some(5));
    }

    #[test]
    fn checked_contracts_exist_in_real_checkout() {
        validate(&repository_root()).expect("repository contract");
    }
}
