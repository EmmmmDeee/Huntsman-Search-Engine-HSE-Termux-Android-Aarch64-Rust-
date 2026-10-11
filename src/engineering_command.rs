//! Executable engineering-command contract.
//!
//! The names are repository-internal codenames. This module makes the hierarchy
//! machine-readable so documentation, capability ownership, CLI output, and tests
//! share one canonical source of truth.

use std::fmt::Write as _;

pub const COMMAND_INVARIANT: &str =
    "CHIEF VISIONARY -> CHIEF SYSTEMS ARCHITECT -> ALL OTHER SYSTEMS";

pub const EXECUTION_PROTOCOLS: [&str; 7] = [
    "Zero deviation from command structure",
    "Immediate implementation without bureaucratic delay",
    "Aggressive optimization of all systems",
    "Investigative OSINT operations prioritized",
    "Resource allocation directed by hierarchy",
    "Performance metrics continuously monitored",
    "Economic self-sustainability enforced by ECONOMIC OPTIMIZATION LEAD",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Command,
    Technology,
    Information,
    Performance,
}

impl Phase {
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Command => 1,
            Self::Technology => 2,
            Self::Information => 3,
            Self::Performance => 4,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Command => "ESTABLISH COMMAND STRUCTURE",
            Self::Technology => "DEPLOY TECHNOLOGY TIER",
            Self::Information => "ACTIVATE INFORMATION TIER",
            Self::Performance => "SECURE PERFORMANCE TIER",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Role {
    pub rank: u8,
    pub name: &'static str,
    pub title: &'static str,
    pub phase: Phase,
}

pub const COMMAND_CHAIN: [Role; 16] = [
    Role {
        rank: 1,
        name: "CHIEF VISIONARY",
        title: "Chief Visionary & Strategic Architect",
        phase: Phase::Command,
    },
    Role {
        rank: 2,
        name: "CHIEF SYSTEMS ARCHITECT",
        title: "Chief Systems Architect",
        phase: Phase::Command,
    },
    Role {
        rank: 3,
        name: "INTEGRATION ENGINEER",
        title: "Integration Engineer",
        phase: Phase::Command,
    },
    Role {
        rank: 4,
        name: "ADVANCED TECHNOLOGY LEAD",
        title: "Advanced Technology & R&D Division",
        phase: Phase::Technology,
    },
    Role {
        rank: 5,
        name: "INDUSTRIAL SCALE LEAD",
        title: "Industrial Scale & Production Optimization",
        phase: Phase::Technology,
    },
    Role {
        rank: 6,
        name: "STRATEGIC REFACTORING LEAD",
        title: "Strategic Refactoring & Tactical Innovation",
        phase: Phase::Technology,
    },
    Role {
        rank: 7,
        name: "DISTRIBUTED SYSTEMS LEAD",
        title: "Distributed Systems Engineering",
        phase: Phase::Technology,
    },
    Role {
        rank: 8,
        name: "INFORMATION LEAD",
        title: "Information & Communications",
        phase: Phase::Information,
    },
    Role {
        rank: 9,
        name: "OPERATIONS LEAD",
        title: "Chief Operating Officer & Infrastructure",
        phase: Phase::Information,
    },
    Role {
        rank: 10,
        name: "PLATFORM LEAD",
        title: "Platform Engineering",
        phase: Phase::Information,
    },
    Role {
        rank: 11,
        name: "IMPLEMENTATION LEAD",
        title: "Implementation Engineer & Core Systems",
        phase: Phase::Information,
    },
    Role {
        rank: 12,
        name: "PERFORMANCE LEAD",
        title: "Performance Engineering & Optimization",
        phase: Phase::Performance,
    },
    Role {
        rank: 13,
        name: "VERIFICATION LEAD",
        title: "Verification Engineering & Performance Testing",
        phase: Phase::Performance,
    },
    Role {
        rank: 14,
        name: "SECURITY LEAD",
        title: "Security Engineering",
        phase: Phase::Performance,
    },
    Role {
        rank: 15,
        name: "RESOURCE LEAD",
        title: "Resource Acquisition & Economic Engine",
        phase: Phase::Performance,
    },
    Role {
        rank: 16,
        name: "ECONOMIC OPTIMIZATION LEAD",
        title: "Economic Optimization & Self-Funding Operations",
        phase: Phase::Performance,
    },
];

pub const CAPABILITY_OWNERS: [&str; 23] = [
    "IMPLEMENTATION LEAD",
    "IMPLEMENTATION LEAD",
    "IMPLEMENTATION LEAD",
    "INTEGRATION ENGINEER",
    "IMPLEMENTATION LEAD",
    "IMPLEMENTATION LEAD",
    "DISTRIBUTED SYSTEMS LEAD",
    "DISTRIBUTED SYSTEMS LEAD",
    "INTEGRATION ENGINEER",
    "PERFORMANCE LEAD",
    "OPERATIONS LEAD",
    "IMPLEMENTATION LEAD",
    "SECURITY LEAD",
    "SECURITY LEAD",
    "INFORMATION LEAD",
    "INFORMATION LEAD",
    "OPERATIONS LEAD",
    "ADVANCED TECHNOLOGY LEAD",
    "VERIFICATION LEAD",
    "VERIFICATION LEAD",
    "OPERATIONS LEAD",
    "INDUSTRIAL SCALE LEAD",
    "IMPLEMENTATION LEAD",
];

#[must_use]
pub fn role(name: &str) -> Option<&'static Role> {
    COMMAND_CHAIN.iter().find(|role| role.name == name)
}

#[must_use]
pub fn capability_owner(capability_number: usize) -> Option<&'static Role> {
    let name = CAPABILITY_OWNERS.get(capability_number.checked_sub(1)?)?;
    role(name)
}

/// Validate the executable hierarchy before presenting or using it.
///
/// # Errors
/// Returns a static diagnostic if rank continuity, uniqueness, phase order,
/// terminal placement, or capability ownership diverges from the contract.
pub fn validate() -> Result<(), &'static str> {
    if COMMAND_CHAIN.first().map(|role| role.name) != Some("CHIEF VISIONARY") {
        return Err("rank 1 changed");
    }
    if COMMAND_CHAIN.get(1).map(|role| role.name) != Some("CHIEF SYSTEMS ARCHITECT") {
        return Err("rank 2 changed");
    }
    if COMMAND_CHAIN.last().map(|role| role.name) != Some("ECONOMIC OPTIMIZATION LEAD") {
        return Err("ECONOMIC OPTIMIZATION LEAD is not terminal");
    }

    for (index, current) in COMMAND_CHAIN.iter().enumerate() {
        if usize::from(current.rank) != index + 1 {
            return Err("command ranks are not contiguous");
        }
        if COMMAND_CHAIN[..index]
            .iter()
            .any(|prior| prior.name == current.name)
        {
            return Err("duplicate command name");
        }
        if index > 0 && current.phase.number() < COMMAND_CHAIN[index - 1].phase.number() {
            return Err("phase order regressed");
        }
    }

    for owner in CAPABILITY_OWNERS {
        if role(owner).is_none() {
            return Err("capability owner is outside command hierarchy");
        }
    }
    Ok(())
}

/// Stable, human-readable rendering for the CLI and automation logs.
///
/// # Errors
/// Fails only if the executable contract itself is invalid.
pub fn render_json() -> Result<String, &'static str> {
    validate()?;
    let roles: Vec<serde_json::Value> = COMMAND_CHAIN
        .iter()
        .map(|role| {
            serde_json::json!({
                "rank": role.rank,
                "name": role.name,
                "title": role.title,
                "phase": {
                    "number": role.phase.number(),
                    "label": role.phase.label(),
                },
            })
        })
        .collect();
    let capability_owners: Vec<serde_json::Value> = CAPABILITY_OWNERS
        .iter()
        .enumerate()
        .map(|(index, owner)| {
            serde_json::json!({
                "capability": index + 1,
                "owner": owner,
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "invariant": COMMAND_INVARIANT,
        "execution_protocols": EXECUTION_PROTOCOLS,
        "roles": roles,
        "capability_owners": capability_owners,
    }))
    .map_err(|_| "failed to serialize command contract")
}

/// Stable, human-readable rendering for the CLI and automation logs.
///
/// # Errors
/// Fails only if the executable contract itself is invalid.
pub fn render() -> Result<String, &'static str> {
    validate()?;
    let mut out = String::new();
    writeln!(&mut out, "invariant={COMMAND_INVARIANT}").expect("writing to a String cannot fail");
    for (index, protocol) in EXECUTION_PROTOCOLS.iter().enumerate() {
        writeln!(&mut out, "protocol={}\t{protocol}", index + 1)
            .expect("writing to a String cannot fail");
    }

    let mut active_phase = None;
    for role in COMMAND_CHAIN {
        if active_phase != Some(role.phase) {
            active_phase = Some(role.phase);
            writeln!(
                &mut out,
                "phase={}\t{}",
                role.phase.number(),
                role.phase.label()
            )
            .expect("writing to a String cannot fail");
        }
        writeln!(&mut out, "{:02}\t{}\t{}", role.rank, role.name, role.title)
            .expect("writing to a String cannot fail");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_invariant_and_terminal_role_hold() {
        validate().unwrap();
        assert_eq!(
            COMMAND_INVARIANT,
            "CHIEF VISIONARY -> CHIEF SYSTEMS ARCHITECT -> ALL OTHER SYSTEMS"
        );
        assert_eq!(
            COMMAND_CHAIN.last().unwrap().name,
            "ECONOMIC OPTIMIZATION LEAD"
        );
        assert_eq!(EXECUTION_PROTOCOLS.len(), 7);
    }

    #[test]
    fn json_render_contains_complete_contract() {
        let rendered = render_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            value["invariant"],
            serde_json::Value::String(COMMAND_INVARIANT.to_owned())
        );
        assert_eq!(
            value["roles"].as_array().map(Vec::len),
            Some(COMMAND_CHAIN.len())
        );
        assert_eq!(
            value["capability_owners"].as_array().map(Vec::len),
            Some(CAPABILITY_OWNERS.len())
        );
        assert_eq!(
            value["roles"][15]["name"],
            serde_json::Value::String("ECONOMIC OPTIMIZATION LEAD".into())
        );
    }

    #[test]
    fn phase_boundaries_match_the_directive() {
        let phases: Vec<(u8, Phase)> = COMMAND_CHAIN
            .iter()
            .map(|role| (role.rank, role.phase))
            .collect();
        assert_eq!(
            phases,
            vec![
                (1, Phase::Command),
                (2, Phase::Command),
                (3, Phase::Command),
                (4, Phase::Technology),
                (5, Phase::Technology),
                (6, Phase::Technology),
                (7, Phase::Technology),
                (8, Phase::Information),
                (9, Phase::Information),
                (10, Phase::Information),
                (11, Phase::Information),
                (12, Phase::Performance),
                (13, Phase::Performance),
                (14, Phase::Performance),
                (15, Phase::Performance),
                (16, Phase::Performance),
            ]
        );
    }

    #[test]
    fn every_capability_owner_resolves_to_a_role() {
        for number in 1..=CAPABILITY_OWNERS.len() {
            assert!(capability_owner(number).is_some(), "capability {number}");
        }
        assert!(capability_owner(0).is_none());
        assert!(capability_owner(CAPABILITY_OWNERS.len() + 1).is_none());
    }
}
