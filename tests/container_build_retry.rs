//! Docker build retrier: recover transient registry failures but fail closed
//! for permanent build errors and exhausted attempts. No network or Docker needed.
#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn check(scenario: &str, expected_code: i32, expected_attempts: usize) {
    let root = std::env::temp_dir().join(format!(
        "huntsman-container-retry-{}-{scenario}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("scratch directory");
    let docker = root.join("docker");
    let sleep = root.join("sleep");
    let calls = root.join("calls");
    fs::write(
        &docker,
        r#"#!/bin/sh
set -eu
[ "$1" = build ] || exit 40
printf x >> "$CALLS"
n="$(wc -c < "$CALLS")"
case "$SCENARIO" in
  transient_then_pass)
    if [ "$n" -eq 1 ]; then
      echo 'unexpected status code https://registry-1.docker.io/v2/foo: 500 Internal Server Error'
      exit 23
    fi
    ;;
  rate_limited_then_pass)
    if [ "$n" -eq 1 ]; then
      echo 'unexpected status code https://registry-1.docker.io/v2/foo: 429 Too Many Requests'
      exit 23
    fi
    ;;
  permanent)
    echo 'error: Rust source does not compile'
    exit 23
    ;;
  transient_forever)
    echo 'unexpected status code https://registry-1.docker.io/v2/foo: 500 Internal Server Error'
    exit 23
    ;;
  success) ;;
  *) exit 40 ;;
esac
echo "build-ok $*"
"#,
    )
    .expect("mock docker");
    fs::write(&sleep, "#!/bin/sh\nexit 0\n").expect("mock sleep");
    for path in [&docker, &sleep] {
        let mut mode = fs::metadata(path).expect("mock metadata").permissions();
        mode.set_mode(0o755);
        fs::set_permissions(path, mode).expect("make mock executable");
    }

    let mut path = OsString::from(root.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/container-build-retry.sh");
    let output = Command::new("bash")
        .arg(script)
        .args(["--pull", "-f", "Dockerfile", "."])
        .env("PATH", path)
        .env("TMPDIR", &root)
        .env("CALLS", &calls)
        .env("SCENARIO", scenario)
        .output()
        .expect("retry wrapper executes");

    assert_eq!(
        output.status.code(),
        Some(expected_code),
        "scenario {scenario}: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let attempts = fs::read(&calls).expect("mock was called").len();
    assert_eq!(attempts, expected_attempts, "scenario {scenario}");
    let leaked_logs = fs::read_dir(&root)
        .expect("scratch files")
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("huntsman-docker-retry.")
        });
    assert!(!leaked_logs, "temporary logs must be removed");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn transient_registry_failure_recovers_on_second_attempt() {
    check("transient_then_pass", 0, 2);
}

#[test]
fn registry_rate_limit_recovers_on_second_attempt() {
    check("rate_limited_then_pass", 0, 2);
}

#[test]
fn normal_build_does_not_retry() {
    check("success", 0, 1);
}

#[test]
fn permanent_build_error_fails_without_retry() {
    check("permanent", 23, 1);
}

#[test]
fn exhausted_transient_registry_errors_remain_failures() {
    check("transient_forever", 23, 3);
}
