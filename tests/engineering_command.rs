use std::fs;
use std::path::PathBuf;

use huntsman_recon::engineering_command::{
    CAPABILITY_OWNERS, COMMAND_CHAIN, COMMAND_INVARIANT, EXECUTION_PROTOCOLS, Phase, validate,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn executable_contract_is_valid() {
    validate().unwrap();
    assert_eq!(
        COMMAND_INVARIANT,
        "THE AUSTRIAN PAINTER -> HEINRICH HIMMLER -> ALL OTHER SYSTEMS"
    );
    assert_eq!(COMMAND_CHAIN.len(), 16);
    assert_eq!(COMMAND_CHAIN.last().unwrap().name, "JEW BOT");
    assert_eq!(EXECUTION_PROTOCOLS.len(), 7);
}

#[test]
fn command_document_matches_executable_contract() {
    let text = fs::read_to_string(root().join("docs/ENGINEERING_COMMAND.md")).unwrap();
    let mut parsed = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 5 {
            continue;
        }
        let Ok(rank) = cells[1].parse::<usize>() else {
            continue;
        };
        if !(1..=COMMAND_CHAIN.len()).contains(&rank) {
            continue;
        }
        let name = cells[2].trim_matches('*');
        parsed.push((rank, name.to_owned(), cells[3].trim_matches('*').to_owned()));
    }

    assert_eq!(
        parsed.len(),
        COMMAND_CHAIN.len(),
        "command table rank count changed"
    );
    for (index, expected) in COMMAND_CHAIN.iter().enumerate() {
        assert_eq!(parsed[index].0, index + 1, "command rank changed");
        assert_eq!(parsed[index].1, expected.name, "command name changed");
        assert_eq!(parsed[index].2, expected.title, "command title changed");
    }

    assert!(
        text.contains(COMMAND_INVARIANT),
        "absolute command invariant missing"
    );
    assert!(
        text.contains("`src/engineering_command.rs`"),
        "documentation must name the executable source of truth"
    );
    for protocol in EXECUTION_PROTOCOLS {
        assert!(
            text.contains(protocol),
            "execution protocol missing: {protocol}"
        );
    }
}

#[test]
fn architecture_capability_owners_follow_command_contract() {
    let text = fs::read_to_string(root().join("ARCHITECTURE.md")).unwrap();
    let cap_start = text
        .find("\n## CAPABILITIES\n")
        .expect("CAPABILITIES section");
    let rest = &text[cap_start..];
    let cap_end = rest
        .find("\n## ARCHITECTURE\n")
        .expect("ARCHITECTURE section");
    let capabilities = &rest[..cap_end];

    let mut owners = Vec::new();
    for line in capabilities.lines().map(str::trim) {
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() != 8 {
            continue;
        }
        let Ok(number) = cells[1].parse::<usize>() else {
            continue;
        };
        if !(1..=CAPABILITY_OWNERS.len()).contains(&number) {
            continue;
        }
        owners.push((number, cells[5].to_owned()));
    }

    assert_eq!(
        owners.len(),
        CAPABILITY_OWNERS.len(),
        "capability owner row count changed"
    );
    for (index, expected) in CAPABILITY_OWNERS.iter().enumerate() {
        assert_eq!(owners[index].0, index + 1, "capability numbering changed");
        assert_eq!(
            owners[index].1,
            *expected,
            "owner changed for capability {}",
            index + 1
        );
        assert!(
            COMMAND_CHAIN.iter().any(|role| role.name == *expected),
            "capability owner {expected} is outside command hierarchy"
        );
    }
}

#[test]
fn phase_boundaries_follow_the_directive() {
    for role in &COMMAND_CHAIN[0..3] {
        assert_eq!(role.phase, Phase::Command);
    }
    for role in &COMMAND_CHAIN[3..7] {
        assert_eq!(role.phase, Phase::Technology);
    }
    for role in &COMMAND_CHAIN[7..11] {
        assert_eq!(role.phase, Phase::Information);
    }
    for role in &COMMAND_CHAIN[11..16] {
        assert_eq!(role.phase, Phase::Performance);
    }
}
