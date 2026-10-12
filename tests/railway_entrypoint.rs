//! The Railway entrypoint must not print a token it generates. The value is stored in the data
//! directory, and the log names that file instead. Unix only: the entrypoint is POSIX sh.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[test]
fn a_generated_token_is_stored_and_never_printed() {
    let root = std::env::temp_dir().join(format!("huntsman-entrypoint-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let data = root.join("data");
    fs::create_dir_all(&data).unwrap();

    // A stub stands in for the binary, so the entrypoint's final exec runs nothing that serves.
    let stub = root.join("huntsman-recon");
    fs::write(&stub, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new("sh")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/railway-entrypoint.sh"))
        .env_remove("HSE_AUTH_TOKEN")
        .env("RAILWAY_VOLUME_MOUNT_PATH", &data)
        .env("HUNTSMAN_BIN", &stub)
        .env("HUNTSMAN_STARTUP_CHECK", "0")
        .env("PORT", "8080")
        .output()
        .unwrap();

    let stored = fs::read_to_string(data.join(".huntsman").join("railway-auth-token")).unwrap();
    let token = stored.trim();
    assert_eq!(token.len(), 64, "a 256-bit token, hex encoded");

    // A host logs both streams, so neither may carry the token. The messages leave the output out:
    // on failure it would print the token.
    for (name, stream) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        assert!(
            !String::from_utf8_lossy(stream).contains(token),
            "the generated token reached {name}"
        );
    }
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("railway-auth-token"),
        "stderr does not name the stored file"
    );
    let _ = fs::remove_dir_all(&root);
}
