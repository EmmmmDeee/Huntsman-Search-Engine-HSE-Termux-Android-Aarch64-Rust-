//! Bounded apt install for CI runners: a stalled mirror costs one bounded attempt, not the job.
//! Packages install only after every download completed, from the cache, and an exhausted retry
//! remains a failure. No network, root or apt needed: a fake `sudo` and `apt-get` act out each
//! scenario, and coreutils' `timeout` does the bounding as it does on the runner.
#![cfg(unix)]

#[path = "support/executable.rs"]
mod executable;

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const PACKAGES: [&str; 2] = ["gcc-aarch64-linux-gnu", "qemu-user"];

/// A bound no healthy fake call comes near, so only a stall can reach it.
const GENEROUS: &str = "60";
/// A bound short enough to keep stall scenarios quick, still far above a healthy fake call.
const SHORT: &str = "2";

/// The fake `apt-get`: it records each call as `<step> <arguments>`, then succeeds, fails or
/// stalls as `$SCENARIO` says for that step's `n`th call. A stall execs a process that never
/// ends, so only the script's bound can end it.
const APT_GET: &str = r#"#!/bin/sh
set -eu
case " $* " in
  *" update "*) step=update ;;
  *" --download-only "*) step=download ;;
  *" install "*) step=install ;;
  *) exit 40 ;;
esac
echo "$step $*" >> "$CALLS"
n="$(grep -c "^$step " "$CALLS")"
case "$SCENARIO:$step:$n" in
  stall_then_pass:download:1 | stall_forever:download:*) exec tail -f /dev/null ;;
  update_fails_then_pass:update:1 | install_fails:install:*) exit 100 ;;
esac
"#;

struct Run {
    code: Option<i32>,
    /// Each `apt-get` call: its step, then its arguments.
    calls: Vec<String>,
    stderr: String,
}

impl Run {
    fn steps(&self) -> Vec<&str> {
        self.calls
            .iter()
            .map(|call| call.split(' ').next().expect("a recorded step"))
            .collect()
    }
}

/// Run the script for PACKAGES with BOUND seconds per step, against fakes acting out SCENARIO.
fn run(scenario: &str, packages: &[&str], bound: &str) -> Run {
    // Tests run on parallel threads, and two may act out one scenario: each run gets its own
    // directory, so no run reads another's calls.
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "huntsman-apt-retry-{}-{}",
        std::process::id(),
        RUNS.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("scratch directory");
    executable::write_executable(&root.join("sudo"), "#!/bin/sh\nexec \"$@\"\n", 0o755);
    executable::write_executable(&root.join("apt-get"), APT_GET, 0o755);
    let calls = root.join("calls");

    let mut path = OsString::from(root.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/apt-install-retry.sh");
    let output = Command::new("bash")
        .arg(script)
        .args(packages)
        .env("PATH", path)
        .env("CALLS", &calls)
        .env("SCENARIO", scenario)
        .env("HUNTSMAN_APT_BOUND_SECONDS", bound)
        .output()
        .expect("the installer runs");
    let run = Run {
        code: output.status.code(),
        calls: fs::read_to_string(&calls)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    let _ = fs::remove_dir_all(&root);
    run
}

#[test]
fn a_healthy_mirror_installs_on_the_first_attempt_from_the_downloaded_packages() {
    let run = run("success", &PACKAGES, GENEROUS);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.steps(), ["update", "download", "install"]);
    assert_eq!(
        run.calls[1],
        "download -o Acquire::Retries=3 install -y --no-install-recommends --download-only \
         gcc-aarch64-linux-gnu qemu-user"
    );
    assert_eq!(
        run.calls[2],
        "install -o Acquire::Retries=3 install -y --no-install-recommends \
         gcc-aarch64-linux-gnu qemu-user"
    );
}

#[test]
fn a_stalled_download_is_cut_off_and_the_next_attempt_installs() {
    let run = run("stall_then_pass", &PACKAGES, SHORT);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        run.steps(),
        ["update", "download", "update", "download", "install"]
    );
    assert!(
        run.stderr.contains("apt attempt 1 failed (exit 124"),
        "{}",
        run.stderr
    );
}

#[test]
fn a_failed_list_refresh_is_retried_before_anything_downloads() {
    let run = run("update_fails_then_pass", &PACKAGES, GENEROUS);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.steps(), ["update", "update", "download", "install"]);
}

#[test]
fn a_mirror_that_never_delivers_fails_after_three_bounded_attempts_and_installs_nothing() {
    let run = run("stall_forever", &PACKAGES, SHORT);
    assert_eq!(run.code, Some(124), "{}", run.stderr);
    assert_eq!(
        run.steps(),
        [
            "update", "download", "update", "download", "update", "download"
        ]
    );
    assert!(
        run.stderr
            .contains("apt could not fetch gcc-aarch64-linux-gnu qemu-user in three attempts"),
        "{}",
        run.stderr
    );
}

#[test]
fn a_failed_install_from_the_cache_is_real_and_not_retried() {
    let run = run("install_fails", &PACKAGES, GENEROUS);
    assert_eq!(run.code, Some(100), "{}", run.stderr);
    assert_eq!(run.steps(), ["update", "download", "install"]);
}

#[test]
fn no_package_or_a_bad_bound_is_a_usage_error_that_runs_nothing() {
    let run_without_packages = run("success", &[], GENEROUS);
    assert_eq!(
        run_without_packages.code,
        Some(64),
        "{}",
        run_without_packages.stderr
    );
    assert!(run_without_packages.calls.is_empty());
    for bad in ["0", "-5", "ten", "1.5", "60s"] {
        let refused = run("success", &PACKAGES, bad);
        assert_eq!(refused.code, Some(64), "bound {bad:?}: {}", refused.stderr);
        assert!(refused.calls.is_empty(), "bound {bad:?} ran apt-get");
    }
}
