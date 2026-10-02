//! Repository-level architectural invariant gate.
//!
//! This test intentionally inspects the checked-out source/configuration tree.
//! It complements unit tests of the detector itself by requiring the actual
//! repository state under test to satisfy every active invariant.

use std::path::Path;

use huntsman_search_engine::core::architectural_invariants::audit_repository;

#[test]
fn repository_architectural_invariants_hold() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let report = audit_repository(root);

    assert!(
        !report.has_violations(),
        "repository architectural invariant violation(s): {:#?}",
        report.reports
    );
    assert!(
        !report.has_blockers(),
        "repository architectural invariant blocker(s): {:#?}",
        report.reports
    );
}
