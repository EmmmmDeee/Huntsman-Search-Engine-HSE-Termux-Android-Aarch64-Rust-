//! A workflow that reads the built package from `cargo metadata` must select it by id. Cargo lists
//! the packages of a workspace in name order, so the first entry is not the product: once xtask
//! became a workspace member, `.packages[0]` named xtask and the aarch64 identity check failed.

use std::fs;

#[test]
fn no_workflow_selects_a_package_by_its_position_in_the_metadata() {
    let mut checked = 0;
    for entry in fs::read_dir(".github/workflows").expect("the workflows directory") {
        let path = entry.expect("a workflow entry").path();
        let text = fs::read_to_string(&path).expect("a readable workflow");
        assert!(
            !text.contains(".packages[0]"),
            "{} selects a package by position; select workspace_default_members[0] by id",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "no workflows were checked");
}

#[test]
fn the_release_identity_check_selects_the_default_member_by_id() {
    let release = fs::read_to_string(".github/workflows/release.yml").expect("release workflow");
    assert!(
        release.contains("$m.workspace_default_members[0]"),
        "the aarch64 identity check must select the default member by id"
    );
}
