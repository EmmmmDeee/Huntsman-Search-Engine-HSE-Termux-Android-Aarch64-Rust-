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
        "114056de822bf906c9d148e61fe1e5e696c1ac47ef643522e953b4aae09ddd98"
    );
    assert_eq!(MIRRORS.len(), 6);
}

#[test]
fn canonical_directive_contains_required_adaptive_invariants() {
    let path = root().join(CANONICAL);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", path.display()));

    for required in [
        "# HUNTSMAN OSINT ENGINE",
        "JEFF DEAN → JAMES HAMILTON → ALL OTHER SYSTEMS",
        "delegate every project decision within that objective",
        "Do **not** ask the user to choose among ordinary implementation options.",
        "Activate only when a user task, approved automation, or repository event",
        "Where earlier repository conventions refer to generic council titles",
        "DISCOVER → VERIFY → DESIGN → RESEARCH → IMPLEMENT → INTEGRATE → OPTIMISE → TEST → DEPLOY → VALIDATE → REPEAT",
        "100% contract coverage",
        "100% mutation coverage",
        // The owner made the Termux target a permanent priority on 2026-11-05.
        "**PLATFORM — PERMANENT PRIORITY:** Optimise first for Termux on Android AArch64",
        "a rootless userland install operated through its web UI",
        "Judge every change by its effect there before any other platform",
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
        "JEFF DEAN",
        "JAMES HAMILTON",
        "DANIEL STENBERG",
        "JURE LESKOVEC",
        "JEZ HUMBLE",
        "MARTIN FOWLER",
        "LESLIE LAMPORT",
        "ELIOT HIGGINS",
        "URS HÖLZLE",
        "MITCHELL HASHIMOTO",
        "ANDREW GALLANT",
        "BRENDAN GREGG",
        "RALF JUNG",
        "TAVIS ORMANDY",
        "PATRICK COLLISON",
        "PIETER LEVELS",
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
