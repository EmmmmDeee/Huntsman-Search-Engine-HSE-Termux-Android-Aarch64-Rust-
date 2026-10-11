//! The container image builds from an allow-listed context, and cargo must be able to load
//! every workspace member from it. A member missing from the Dockerfile or the ignore file
//! breaks the image build with "failed to load manifest for workspace member".

use std::fs;

/// The workspace members the root manifest declares, from its `members = [...]` line.
fn workspace_members() -> Vec<String> {
    let manifest = fs::read_to_string("Cargo.toml").expect("root manifest");
    let line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("members = ["))
        .expect("the root manifest declares workspace members");
    line.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_workspace_member_is_in_the_image_build_context() {
    let members = workspace_members();
    assert!(
        members.contains(&"xtask".to_owned()),
        "the xtask crate must be a declared member: {members:?}"
    );
    let dockerfile = fs::read_to_string("Dockerfile").expect("Dockerfile");
    let ignore = fs::read_to_string(".dockerignore").expect(".dockerignore");
    for member in &members {
        assert!(
            dockerfile.contains(&format!("COPY {member}/Cargo.toml")),
            "the Dockerfile must copy the manifest of workspace member {member}"
        );
        assert!(
            dockerfile.contains(&format!("COPY {member}/src")),
            "the Dockerfile must copy the source of workspace member {member}"
        );
        assert!(
            ignore
                .lines()
                .any(|line| line == format!("!{member}/Cargo.toml")),
            ".dockerignore must allow {member}/Cargo.toml into the build context"
        );
        assert!(
            ignore
                .lines()
                .any(|line| line == format!("!{member}/src/**")),
            ".dockerignore must allow {member}/src into the build context"
        );
    }
}
