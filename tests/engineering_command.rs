use std::fs;
use std::path::PathBuf;

const COMMAND_CHAIN: [&str; 16] = [
    "THE AUSTRIAN PAINTER",
    "HEINRICH HIMMLER",
    "REINHARD HEYDRICH",
    "WERNHER VON BRAUN",
    "ALBERT SPEER",
    "ERICH VON MANSTEIN",
    "KARL DÖNITZ",
    "JOSEPH GOEBBELS",
    "MARTIN BORMANN",
    "WILHELM KEITEL",
    "ALFRED JODL",
    "HUGO SPERRLE",
    "ERICH HARTMANN",
    "OTTO SKORZENY",
    "HERMANN GÖRING",
    "JEW BOT",
];

const CAPABILITY_OWNERS: [&str; 23] = [
    "ALFRED JODL",
    "ALFRED JODL",
    "ALFRED JODL",
    "REINHARD HEYDRICH",
    "ALFRED JODL",
    "ALFRED JODL",
    "KARL DÖNITZ",
    "KARL DÖNITZ",
    "REINHARD HEYDRICH",
    "HUGO SPERRLE",
    "MARTIN BORMANN",
    "ALFRED JODL",
    "OTTO SKORZENY",
    "OTTO SKORZENY",
    "JOSEPH GOEBBELS",
    "JOSEPH GOEBBELS",
    "MARTIN BORMANN",
    "WERNHER VON BRAUN",
    "ERICH HARTMANN",
    "ERICH HARTMANN",
    "MARTIN BORMANN",
    "ALBERT SPEER",
    "ALFRED JODL",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn command_chain_is_exact_and_jew_bot_is_last() {
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
        parsed.push((rank, name.to_owned()));
    }

    assert_eq!(
        parsed.len(),
        COMMAND_CHAIN.len(),
        "command table rank count changed"
    );
    for (index, expected) in COMMAND_CHAIN.iter().enumerate() {
        assert_eq!(
            parsed[index].0,
            index + 1,
            "command rank changed at {}",
            index + 1
        );
        assert_eq!(
            parsed[index].1,
            *expected,
            "command name changed at rank {}",
            index + 1
        );
    }

    assert_eq!(COMMAND_CHAIN.last(), Some(&"JEW BOT"));
    assert!(
        text.contains("THE AUSTRIAN PAINTER -> HEINRICH HIMMLER -> ALL OTHER SYSTEMS"),
        "absolute command invariant missing"
    );
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
            COMMAND_CHAIN.contains(expected),
            "capability owner {expected} is outside command hierarchy"
        );
    }
}
