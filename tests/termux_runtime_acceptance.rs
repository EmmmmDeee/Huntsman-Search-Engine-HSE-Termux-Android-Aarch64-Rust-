use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};

const HARNESS: &str = "scripts/termux-runtime-acceptance.sh";

#[test]
fn termux_runtime_harness_targets_current_binary_and_api_contract() {
    let text = fs::read_to_string(HARNESS).expect("Termux acceptance harness must exist");

    for required in [
        "command -v huntsman-recon",
        "umask 077",
        "chmod 600 \"$REPORT\" \"$SERVER_LOG\"",
        r#"ORIGINAL_PWD="$(pwd -P)""#,
        r#"HSE_BIN="$ORIGINAL_PWD/$HSE_BIN""#,
        r#"STATE_DIR="$(anchor_path "${HUNTSMAN_HOME:-$HOME/.huntsman}")""#,
        "HSE_ACCEPTANCE_TIMEOUT must be positive",
        "HSE_ACCEPTANCE_SERVER_TIMEOUT must be positive",
        "HSE_ACCEPTANCE_PORT must be in 1..65535",
        r#"cd "$WORK_DIR" &&"#,
        r#""$HSE_BIN" check"#,
        r#""$HSE_BIN" verify var/ledger.json"#,
        "unset HSE_AUTH_TOKEN",
        r#"exec "$HSE_BIN" serve --bind"#,
        // The lookup is kept as a saved scan, in the disposable directory, and read back.
        r#"export HUNTSMAN_HOME="$WORK_DIR/home""#,
        r#""$base/api/scans/$scan""#,
        "/api/health",
        "/api/modules",
        "/api/command",
        "verify_idle_connections",
        "verify_web_ui",
        r#""$HSE_BIN" doctor serve --bind "$bind""#,
        "serve=healthy",
        "idle connections do not delay a request",
        "TERMUX_RUNTIME_ACCEPTANCE",
        "server lifecycle pass=2 (restart)",
        "saved scan survives server restart",
        "aarch64|arm64",
        "/data/data/com.termux/files/usr",
    ] {
        assert!(
            text.contains(required),
            "{HARNESS} must contain current runtime probe {required:?}"
        );
    }

    for stale in [
        "/api/v1/health",
        "/api/v1/modules",
        "command -v hse || true",
        "  cd \"$WORK_DIR\"\n  timeout",
        // The web UI probe lives in `doctor serve`; the harness must not keep a second copy.
        "/api/analyze?seeds=",
        "content-security-policy",
    ] {
        assert!(
            !text.contains(stale),
            "{HARNESS} must not retain stale runtime probe {stale:?}"
        );
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("huntsman-acceptance-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Whether every command the harness needs is on PATH. CI must have them all.
fn harness_tools_present() -> bool {
    let present = [
        "bash", "timeout", "curl", "date", "grep", "mktemp", "rm", "tee", "tail", "sleep", "uname",
    ]
    .iter()
    .all(|tool| {
        Command::new("bash")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .is_ok_and(|out| out.status.success())
    });
    assert!(
        present || std::env::var_os("CI").is_none(),
        "CI must have every command the acceptance harness uses"
    );
    present
}

/// A free loopback port below 32768. Linux and Android hand out ephemeral ports from 32768 up,
/// so no test that binds port 0 can take this one between this check and the harness's two binds.
fn free_port_below_the_ephemeral_range() -> u16 {
    let start = 20_000 + u16::try_from(std::process::id() % 10_000).unwrap();
    (start..32_000)
        .chain(20_000..start)
        .find(|port| TcpListener::bind(("127.0.0.1", *port)).is_ok())
        .expect("a free loopback port below 32768")
}

/// Runs the harness with `extra` environment, `HOME` in a scratch directory and no inherited
/// Huntsman settings. Returns the process output and the report it wrote.
fn run_harness(tag: &str, extra: &[(&str, &str)]) -> (Output, String) {
    let home = scratch(tag);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let state = home.join(".huntsman");
        fs::create_dir_all(&state).unwrap();
        for name in ["termux-acceptance.txt", "termux-acceptance-server.log"] {
            let path = state.join(name);
            fs::write(&path, b"previous run\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        }
    }
    let mut command = Command::new("bash");
    command
        // Emulate a permissive caller; the harness must establish its own privacy.
        .args(["-c", "umask 000; exec bash \"$1\"", "harness-test"])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(HARNESS))
        .current_dir(&home)
        .env("HOME", &home)
        .env("HSE_BIN", env!("CARGO_BIN_EXE_huntsman-recon"));
    for name in [
        "HUNTSMAN_HOME",
        "HSE_ACCEPTANCE_REPORT",
        "HSE_ACCEPTANCE_SERVER_LOG",
        "HSE_ACCEPTANCE_HOST",
        "HSE_ACCEPTANCE_PORT",
        "HSE_AUTH_TOKEN",
        "HSE_BIND",
        "PORT",
    ] {
        command.env_remove(name);
    }
    command.envs(extra.iter().copied());
    let out = command.output().expect("bash runs the harness");
    let report =
        fs::read_to_string(home.join(".huntsman/termux-acceptance.txt")).unwrap_or_default();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["termux-acceptance.txt", "termux-acceptance-server.log"] {
            let file = home.join(".huntsman").join(name);
            let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must stay private", file.display());
        }
    }
    let _ = fs::remove_dir_all(&home);
    (out, report)
}

/// The harness run as CI runs it: every check against the binary this build produced, with only
/// the two device checks skipped, so the harness cannot drift from the binary or its API before
/// someone runs it on a handset.
#[test]
fn the_harness_passes_against_the_built_binary_in_host_mode() {
    if !harness_tools_present() {
        return;
    }
    let port = free_port_below_the_ephemeral_range().to_string();
    let (out, report) = run_harness(
        "host",
        &[("HSE_ACCEPTANCE_HOST", "1"), ("HSE_ACCEPTANCE_PORT", &port)],
    );
    assert!(
        out.status.success(),
        "{report}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for line in [
        "INFO  host run on ",
        "PASS  huntsman-recon --version executes",
        "PASS  offline check and ledger verification execute in a disposable directory",
        "PASS  module and command APIs return current structured state",
        "PASS  web UI page loads under its policy and its offline analysis answers",
        "PASS  idle connections do not delay a request",
        "PASS  saved scan survives server restart",
        "PASS  server lifecycle pass=2 (restart)",
        "PASS  HOST_RUNTIME_ACCEPTANCE (not a handset pass)",
    ] {
        assert!(report.contains(line), "missing {line:?} in:\n{report}");
    }
    for device_only in [
        "TERMUX_RUNTIME_ACCEPTANCE",
        "runtime architecture is ARM64",
        "Termux PREFIX detected",
    ] {
        assert!(
            !report.contains(device_only),
            "a host run must not claim {device_only:?}:\n{report}"
        );
    }
}

#[test]
fn without_host_mode_the_harness_still_refuses_a_host_that_is_not_a_handset() {
    if !harness_tools_present() {
        return;
    }
    let arch = Command::new("uname").arg("-m").output().unwrap();
    if matches!(
        String::from_utf8_lossy(&arch.stdout).trim(),
        "aarch64" | "arm64"
    ) {
        return;
    }
    let (out, report) = run_harness("device-guard", &[]);
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert!(
        report.contains("FAIL  unexpected runtime architecture: "),
        "{report}"
    );
    let (out, report) = run_harness("bad-host-flag", &[("HSE_ACCEPTANCE_HOST", "yes")]);
    assert_eq!(out.status.code(), Some(1), "{report}");
    assert!(
        report.contains("FAIL  HSE_ACCEPTANCE_HOST must be 1 or unset, got 'yes'"),
        "{report}"
    );
}

/// The handset needs no checkout: the documented command fetches the harness from its real path.
#[test]
fn install_doc_fetches_the_harness_from_its_real_path() {
    let url = format!(
        "https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/{HARNESS}"
    );
    let doc = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/INSTALL.md"))
        .unwrap();
    let section = doc
        .split("## Real-device Termux acceptance")
        .nth(1)
        .expect("docs/INSTALL.md keeps its real-device acceptance section");
    assert!(
        section.contains(&format!(
            "curl -fsSL {url} -o \"$TMPDIR/termux-runtime-acceptance.sh\""
        )),
        "the handset command must fetch {url}"
    );
    assert!(section.contains("bash \"$TMPDIR/termux-runtime-acceptance.sh\""));
    let script = fs::read_to_string(HARNESS).unwrap();
    assert!(
        script.contains(&url),
        "the harness header names the same URL"
    );
}

#[test]
fn termux_runtime_harness_is_valid_bash() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("bash")
        .arg("-n")
        .arg(root.join(HARNESS))
        .status()
        .expect("bash must execute in CI");
    assert!(status.success(), "{HARNESS} must parse as bash");
}
