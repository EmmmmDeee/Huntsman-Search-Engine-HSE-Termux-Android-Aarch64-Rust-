use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "huntsman-provider-credentials-{tag}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("scratch");
    path
}

#[test]
fn credential_status_reads_runtime_keys_without_rendering_values() {
    let dir = scratch("status");
    let keys = dir.join("keys.env");
    let secret = "0123456789abcdef0123456789abcdef";
    fs::write(
        &keys,
        format!("HIBP_API_KEY={secret}\nHUNTSMAN_BRAVE_KEY=brave-secret\n"),
    )
    .expect("write keys");
    #[cfg(unix)]
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).expect("chmod");

    let output = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["credential-status", keys.to_str().expect("utf8 path")])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(stdout.contains("provider=HIBP\tstate=configured"));
    assert!(stdout.contains("provider=Brave Search\tstate=configured"));
    assert!(!stdout.contains(secret));
    assert!(!stdout.contains("brave-secret"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn credential_status_rejects_ambiguous_arguments_before_network() {
    let output = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["credential-status", "--probe", "--probe"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(64));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("usage: huntsman-recon credential-status [--probe] [FILE]")
    );
}

/// `DeHashed`'s legacy private key file, `~/.config/dehashed/api_key`, sets
/// `HUNTSMAN_DEHASHED_KEY` for every path: `credential-status` reports the key a search would
/// use. A file the private-file gate refuses is named on stderr, with the fix, and its key is
/// neither used nor shown.
#[cfg(unix)]
#[test]
fn credential_status_reports_the_key_dehashed_s_own_file_gives_every_search() {
    let home = scratch("dehashed-file");
    let dir = home.join(".config").join("dehashed");
    fs::create_dir_all(&dir).expect("dir");
    let file = dir.join("api_key");
    let secret = "TEST_ONLY_DEHASHED_FILE_KEY_51c3";
    fs::write(&file, format!("{secret}\n")).expect("write key");
    let run = || {
        let output = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
            .arg("credential-status")
            .env("HOME", &home)
            .env_remove("HUNTSMAN_DEHASHED_KEY")
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).expect("stdout");
        let stderr = String::from_utf8(output.stderr).expect("stderr");
        assert!(!stdout.contains(secret) && !stderr.contains(secret));
        (stdout, stderr)
    };

    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");
    let (stdout, stderr) = run();
    assert!(
        stdout.contains("provider=DeHashed\tstate=configured"),
        "{stdout}"
    );
    assert!(stderr.is_empty(), "{stderr}");

    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod");
    let (stdout, stderr) = run();
    assert!(
        stdout.contains("provider=DeHashed\tstate=incomplete\tHUNTSMAN_DEHASHED_KEY=unset"),
        "{stdout}"
    );
    assert!(
        stderr.contains(&format!("warning: not loading {}", file.display())),
        "{stderr}"
    );

    let _ = fs::remove_dir_all(home);
}
