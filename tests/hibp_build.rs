//! Run the dedicated embedder with fake keys, without mutating process environment.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn embedding_is_optional_release_safe_and_runtime_sources_are_not_required() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scratch = root
        .join("target")
        .join(format!("hibp-build-{}", std::process::id()));
    let out = scratch.join("out");
    let home = scratch.join("home");
    let key_file = home.join(".config/hibp/api_key");
    fs::create_dir_all(&out).unwrap();
    fs::create_dir_all(key_file.parent().unwrap()).unwrap();
    let binary = scratch.join("embedder");
    assert!(
        Command::new("rustc")
            .arg(root.join("build.rs"))
            .args(["--edition=2024", "-o"])
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    for (env_key, file_key, disable, expected) in [
        (None, None, None, ""),
        (Some("fake-env-key"), None, None, "fake-env-key"),
        (None, Some(" fake-file-key \n"), None, "fake-file-key"),
        (
            Some("fake-env-key"),
            Some("fake-file-key"),
            None,
            "fake-env-key",
        ),
        (
            Some("changeme"),
            Some("fake-file-key"),
            None,
            "fake-file-key",
        ),
        (
            Some("insert_key_here"),
            Some("fake-file-key"),
            None,
            "fake-file-key",
        ),
        (Some("fake-env-key"), Some("fake-file-key"), Some("CI"), ""),
        (
            Some("fake-env-key"),
            Some("fake-file-key"),
            Some("HSE_RELEASE"),
            "",
        ),
        (
            Some("fake-env-key"),
            Some("fake-file-key"),
            Some("HUNTSMAN_HIBP_NO_EMBED"),
            "",
        ),
    ] {
        if let Some(value) = file_key {
            fs::write(&key_file, value).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
            }
        } else {
            let _ = fs::remove_file(&key_file);
        }
        let mut command = Command::new(&binary);
        for name in [
            "HIBP_API_KEY",
            "CI",
            "HSE_RELEASE",
            "HUNTSMAN_HIBP_NO_EMBED",
        ] {
            command.env_remove(name);
        }
        command.env("OUT_DIR", &out).env("HOME", &home);
        if let Some(value) = env_key {
            command.env("HIBP_API_KEY", value);
        }
        if let Some(name) = disable {
            command.env(name, "1");
        }
        let result = command.output().unwrap();
        assert!(result.status.success());
        assert_eq!(
            fs::read_to_string(out.join("hibp_embedded_key.txt")).unwrap(),
            expected
        );
        let output = String::from_utf8(result.stdout).unwrap();
        assert!(!output.contains("fake-env-key") && !output.contains("fake-file-key"));
        assert!(output.contains("rerun-if-env-changed=HIBP_API_KEY"));
        assert!(output.contains("rerun-if-changed="));
    }
    fs::remove_dir_all(scratch).unwrap();
}
