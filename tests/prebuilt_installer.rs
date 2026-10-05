use std::path::PathBuf;
use std::process::Command;

#[test]
fn prebuilt_installer_accepts_runtime_before_replacing_existing_binary() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("bash")
        .arg(root.join("tests/prebuilt_installer.sh"))
        .output()
        .expect("prebuilt installer regression must execute");
    assert!(
        output.status.success(),
        "prebuilt installer regression failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
