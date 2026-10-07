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
        "5bdd9777d9a8046d2d4a6bf645ee6201b6e1d004b1a6a1fc7a99eb246a687584"
    );
    assert_eq!(MIRRORS.len(), 6);
}

#[test]
fn canonical_directive_contains_required_adaptive_invariants() {
    let path = root().join(CANONICAL);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", path.display()));

    for required in [
        "THE AUSTRIAN PAINTER → HIMMLER → ALL OTHER SYSTEMS",
        "# PERMANENT ADAPTIVE DEFAULT OVERRIDE",
        "permanent standing default conceptual team",
        "Do not rename **JEW BOT**.",
        "Activate only roles that can materially improve that objective; leave unnecessary roles idle.",
        "Where any earlier local team, persona, or hierarchy convention conflicts with this directive, this directive supersedes it.",
    ] {
        assert!(text.contains(required), "canonical directive missing: {required}");
    }
}
