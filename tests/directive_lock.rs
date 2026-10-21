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
        "b4d0227909b026bc56f8a6d521a0a8d8685f9a59f6b7e16814cfaba16ca58257"
    );
    assert_eq!(MIRRORS.len(), 6);
}

#[test]
fn canonical_directive_contains_required_adaptive_invariants() {
    let path = root().join(CANONICAL);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", path.display()));

    for required in [
        "# HUNTSMAN: GERMAN/AUSTRIAN EXECUTION COUNCIL",
        "THE AUSTRIAN PAINTER → HEINRICH HIMMLER → ALL OTHER ROLES",
        "delegate every project decision within that objective",
        "Do **not** ask the user to choose among ordinary implementation options.",
        "Activate only when a user task, approved automation, or repository event",
        "Where earlier repository conventions refer to generic council titles",
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
    for role in [
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
    ] {
        assert!(
            text.contains(role),
            "canonical directive missing role: {role}"
        );
    }
}
