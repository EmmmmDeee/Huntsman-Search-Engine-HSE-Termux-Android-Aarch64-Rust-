use std::fs;
use std::path::PathBuf;

use huntsman_recon::directive_lock::{CANONICAL, EXPECTED_SHA256, MIRRORS, verify_at};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn repository_directive_contract_is_valid() {
    verify_at(&root()).unwrap();
    assert_eq!(
        EXPECTED_SHA256,
        "2ae60f1a2f05471f453e8aa5975a0f9c06a9801822fea770e9e46d63fabfb190"
    );
    assert_eq!(MIRRORS.len(), 6);
}

#[test]
fn canonical_directive_contains_required_adaptive_invariants() {
    let path = root().join(CANONICAL);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", path.display()));

    for required in [
        "# HUNTSMAN: FORTIFIED EXECUTION COUNCIL",
        "ELON MUSK → JAMES HAMILTON → ALL OTHER SYSTEMS",
        "delegate every project decision within that objective",
        "Do **not** ask the user to choose among ordinary implementation options.",
        "Activate only when a user task, approved automation, or repository event",
        "Where earlier repository conventions refer to generic council titles",
        "DESIGN → RESEARCH → IMPLEMENT → OPTIMIZE → DEPLOY",
        "100% contract coverage",
        "100% mutation coverage",
    ] {
        assert!(
            text.contains(required),
            "canonical directive missing: {required}"
        );
    }
}

#[test]
fn canonical_directive_preserves_named_council_and_decision_ownership() {
    let text = fs::read_to_string(root().join(CANONICAL)).unwrap();
    let roles = [
        "ELON MUSK",
        "JAMES HAMILTON",
        "BRUCE SCHNEIER",
        "DEMIS HASSABIS",
        "TIM COOK",
        "ANDY GROVE",
        "LESLIE LAMPORT",
        "RENEE DIRESTA",
        "GWYNNE SHOTWELL",
        "KELSEY HIGHTOWER",
        "LINUS TORVALDS",
        "JOHN CARMACK",
        "MARGARET HAMILTON",
        "PEITER ZATKO (MUDGE)",
        "WARREN BUFFETT",
        "JIM SIMONS",
    ];
    let mut previous = 0;
    for (rank, role) in roles.into_iter().enumerate() {
        let needle = format!("| {} | **{role}** |", rank + 1);
        let at = text
            .find(&needle)
            .unwrap_or_else(|| panic!("canonical directive missing ranked role: {needle}"));
        assert!(at >= previous, "canonical role ordering changed: {role}");
        previous = at + needle.len();
    }
}
