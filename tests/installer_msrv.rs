use std::fs;

#[test]
fn installer_minimum_rust_matches_package_msrv() {
    let cargo = fs::read_to_string("Cargo.toml").expect("Cargo.toml");
    let msrv = cargo
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let value = line.strip_prefix("rust-version")?.split_once('=')?.1.trim();
            Some(value.trim_matches('"').to_string())
        })
        .expect("package rust-version");

    let installer = fs::read_to_string("install.sh").expect("install.sh");
    let expected = format!("RUST_MIN_VERSION=\"{msrv}\"");
    assert!(
        installer.contains(&expected),
        "install.sh must reject Rust older than Cargo.toml rust-version {msrv}"
    );
}
