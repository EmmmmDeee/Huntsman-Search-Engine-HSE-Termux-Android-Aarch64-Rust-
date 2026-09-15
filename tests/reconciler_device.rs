//! The capability reconciler's device phase (`scripts/reconcile.sh
//! --device-only`), driven against a stubbed Termux on this host: every
//! `termux-*` tool, `pm` and `pkg` on PATH is a script under a temp dir,
//! `TERMUX_VERSION` marks the host as Termux and `PREFIX` points at a temp
//! dpkg database. The repository half is covered by
//! `tests/install_invariants.rs`.
//!
//! These lock the invariants the device side exists for:
//!   * INSTALLED ≠ READY and ATTEMPT ≠ SUCCESS — an install is judged by
//!     re-probing the same tool set, never by `pkg` exiting 0;
//!   * PRESENCE ≠ RESPONSIVENESS — the CLI, the companion app and the bridge
//!     are three facts, each proven on its own;
//!   * UNAVAILABLE ≠ EMPTY and FAILED ≠ NEGATIVE — a sensor that answered
//!     `[]` is a valid empty read, a sensor that errored is unknown state;
//!   * Bluetooth is an optional provider, never a readiness condition;
//!   * a radar process whose absent-tool cache predates the package install
//!     is stale until restarted, and is only ever stopped when authorised.
//!
//! Every test holds one lock: the reconciler scans this host's process table
//! for `hse radar`, so the test that spawns a fake radar must not overlap the
//! others.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

const APK: &str = "package:com.termux.api";

struct Device {
    dir: tempfile::TempDir,
}

impl Device {
    /// A stubbed device whose stock tools all answer: the four core sensors
    /// (Wi-Fi scan legitimately empty), the bridge probe, a `pm` that lists
    /// the companion app, and a `pkg` that "installs" the location tool and
    /// stamps the dpkg list. `termux-location` is the tool tests remove to
    /// exercise the install path.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        for sub in ["bin", "prefix/var/lib/dpkg/info", "home"] {
            fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        let d = Self { dir };
        d.stub(
            "pm",
            &format!("printf 'package:com.android.settings\\n{APK}\\n'"),
        );
        d.stub("termux-battery-status", r#"echo '{"percentage": 81}'"#);
        d.stub(
            "termux-location",
            r#"echo '{"latitude": 10.8, "longitude": 106.6, "provider": "gps"}'"#,
        );
        d.stub(
            "termux-wifi-connectioninfo",
            r#"echo '{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "lab"}'"#,
        );
        d.stub("termux-wifi-scaninfo", "echo '[]'");
        d.stub("termux-telephony-cellinfo", r#"echo '[{"type": "lte"}]'"#);
        d.stub(
            "pkg",
            r#"d="$(dirname "$0")"
printf '#!/usr/bin/env bash\necho %s\n' "'{\"latitude\": 10.8, \"longitude\": 106.6}'" > "$d/termux-location"
chmod +x "$d/termux-location"
touch "$PREFIX/var/lib/dpkg/info/termux-api.list"
echo "stub pkg: $*""#,
        );
        d
    }

    fn bin(&self) -> PathBuf {
        self.dir.path().join("bin")
    }

    fn stub(&self, name: &str, body: &str) {
        let p = self.bin().join(name);
        fs::write(&p, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn remove(&self, name: &str) {
        fs::remove_file(self.bin().join(name)).unwrap();
    }

    fn dpkg_list(&self) -> PathBuf {
        self.dir
            .path()
            .join("prefix/var/lib/dpkg/info/termux-api.list")
    }

    /// Stamp the dpkg list with an install time `offset` from now.
    fn set_install_time(&self, offset_secs: i64) {
        let list = self.dpkg_list();
        if !list.exists() {
            fs::write(&list, "").unwrap();
        }
        let when = if offset_secs >= 0 {
            SystemTime::now() + Duration::from_secs(offset_secs as u64)
        } else {
            SystemTime::now() - Duration::from_secs((-offset_secs) as u64)
        };
        fs::File::options()
            .write(true)
            .open(&list)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

    /// Run `scripts/reconcile.sh --device-only --json` (plus `extra`) against
    /// this device; returns the exit code and the parsed final state.
    fn reconcile(&self, extra: &[&str]) -> (i32, serde_json::Value) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/reconcile.sh");
        let host_path = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.bin()).chain(std::env::split_paths(&host_path)),
        )
        .unwrap();
        let out = Command::new("bash")
            .arg(&script)
            .args(["--device-only", "--json"])
            .args(extra)
            .current_dir(self.dir.path())
            .env("PATH", path)
            .env("TERMUX_VERSION", "stub")
            .env("PREFIX", self.dir.path().join("prefix"))
            .env("HOME", self.dir.path().join("home"))
            .output()
            .expect("bash");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let json = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "reconciler emitted non-JSON ({e}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().unwrap_or(-1), json)
    }
}

fn sensors(json: &serde_json::Value) -> Vec<(&str, &str)> {
    ["gnss", "wifi_connection", "wifi_scan", "cell", "ble"]
        .into_iter()
        .map(|k| (k, json["sensors"][k].as_str().unwrap_or("?")))
        .collect()
}

#[test]
fn a_missing_core_tool_is_installed_and_judged_by_re_probing_not_by_pkg() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dev = Device::new();
    dev.remove("termux-location");

    // Dry run: the decision is shown, nothing is installed, nothing downstream
    // is claimed for a substrate that is not there.
    let (code, json) = dev.reconcile(&["--dry-run"]);
    assert_eq!(code, 5, "{json}");
    assert_eq!(json["termux"]["state"], "cli_partial", "{json}");
    assert_eq!(json["termux"]["package_action"], "would_install", "{json}");
    assert_eq!(json["termux"]["cli"], "fail", "{json}");
    assert_eq!(
        json["termux"]["cli_missing"],
        serde_json::json!(["termux-location"])
    );
    assert_eq!(
        json["termux"]["bridge"], "skipped",
        "no bridge claim without the CLI"
    );
    assert!(
        sensors(&json).iter().all(|(_, v)| *v == "skipped"),
        "no sensor may be probed, let alone reported, over a missing CLI: {json}"
    );
    assert!(
        !dev.bin().join("termux-location").exists(),
        "dry-run must not install"
    );

    // Converge: the stub `pkg` delivers the tool; the re-probe is what makes
    // it `installed`, and only then are the app, bridge and sensors probed.
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["termux"]["package_action"], "installed", "{json}");
    assert_eq!(json["termux"]["state"], "ready", "{json}");
    for fact in ["cli", "apk", "bridge"] {
        assert_eq!(json["termux"][fact], "pass", "{fact}: {json}");
    }
    assert_eq!(
        sensors(&json),
        vec![
            ("gnss", "executed_valid"),
            ("wifi_connection", "executed_valid"),
            ("wifi_scan", "executed_empty"),
            ("cell", "executed_valid"),
            ("ble", "unavailable"),
        ],
        "{json}"
    );
    assert_eq!(json["radar"]["evidence"], "core_ready", "{json}");

    // Idempotent: nothing to install, nothing reinstalled.
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["termux"]["package_action"], "unchanged", "{json}");
    assert_eq!(json["termux"]["state"], "ready", "{json}");
}

#[test]
fn pkg_exiting_zero_without_delivering_the_tools_is_not_an_install() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dev = Device::new();
    dev.remove("termux-location");
    dev.stub("pkg", "exit 0");
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 5, "{json}");
    assert_eq!(json["termux"]["package_action"], "install_failed", "{json}");
    assert_eq!(json["termux"]["cli"], "fail", "{json}");
    assert_eq!(
        json["termux"]["cli_missing"],
        serde_json::json!(["termux-location"])
    );
    let reason = json["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("still missing"),
        "the verdict must say the postcondition failed, not that pkg succeeded: {reason}"
    );
}

#[test]
fn a_failed_probe_is_unknown_state_that_degrades_readiness_and_an_empty_answer_is_not() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dev = Device::new();
    // Termux:API's own error shape, exit 0: the tool ran, the sensor did not answer.
    dev.stub(
        "termux-telephony-cellinfo",
        r#"echo '{"API_ERROR": "Missing permission"}'"#,
    );
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 2, "{json}");
    assert_eq!(
        json["termux"]["state"], "ready",
        "the substrate itself is fine: {json}"
    );
    assert_eq!(json["sensors"]["cell"], "failed", "{json}");
    assert_eq!(
        json["sensors"]["wifi_scan"], "executed_empty",
        "`[]` is a valid empty read"
    );
    assert_eq!(
        json["radar"]["evidence"], "degraded",
        "one unknown sensor degrades the whole"
    );
    let reason = json["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("not negative evidence"), "{reason}");

    // A non-zero exit is the same unknown state.
    dev.stub("termux-telephony-cellinfo", "exit 1");
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 2, "{json}");
    assert_eq!(json["sensors"]["cell"], "failed", "{json}");
}

#[test]
fn bluetooth_is_an_optional_provider_and_never_a_readiness_condition() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dev = Device::new();
    // No provider at all: unavailable, and the core substrate is still ready.
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["sensors"]["ble"], "unavailable", "{json}");
    assert_eq!(json["radar"]["evidence"], "core_ready", "{json}");

    // A provider that answers (even with nothing nearby) upgrades to full.
    dev.stub("termux-bluetooth-scaninfo", "echo '[]'");
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["sensors"]["ble"], "available", "{json}");
    assert_eq!(json["radar"]["evidence"], "full_ready", "{json}");

    // A provider that fails must not invalidate the core readiness.
    dev.stub("termux-bluetooth-scaninfo", "exit 1");
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["sensors"]["ble"], "failed", "{json}");
    assert_eq!(json["radar"]["evidence"], "core_ready", "{json}");
}

#[test]
fn the_companion_app_and_the_bridge_are_separate_facts_that_fail_closed() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dev = Device::new();
    // The package manager ran and did not list the app: final, no bridge attempt.
    dev.stub("pm", "printf 'package:com.android.settings\\n'");
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 5, "{json}");
    assert_eq!(json["termux"]["state"], "apk_missing", "{json}");
    assert_eq!(json["termux"]["cli"], "pass", "{json}");
    assert_eq!(json["termux"]["apk"], "fail", "{json}");
    assert_eq!(json["termux"]["bridge"], "skipped", "{json}");
    assert!(
        sensors(&json).iter().all(|(_, v)| *v == "skipped"),
        "{json}"
    );

    // The query itself could not run: the one case the bridge may settle,
    // because it cannot answer without the app.
    dev.stub("pm", "exit 1");
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["termux"]["state"], "ready", "{json}");
    assert_eq!(json["termux"]["apk"], "pass", "{json}");
    assert_eq!(json["termux"]["bridge"], "pass", "{json}");
    assert!(
        json["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("proven present by the bridge"),
        "{json}"
    );

    // App listed, CLI present, bridge dead: installed is not ready.
    dev.stub("pm", &format!("printf '{APK}\\n'"));
    dev.stub("termux-battery-status", "exit 1");
    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 5, "{json}");
    assert_eq!(json["termux"]["state"], "bridge_failed", "{json}");
    assert_eq!(json["termux"]["apk"], "pass", "{json}");
    assert_eq!(json["termux"]["bridge"], "fail", "{json}");
    assert!(
        sensors(&json).iter().all(|(_, v)| *v == "skipped"),
        "{json}"
    );
}

/// A fake `hse radar`: `cat` on a FIFO nobody writes, exec'd under argv[0]
/// `hse` so its command line is exactly `hse radar`. Killed on drop.
struct FakeRadar {
    child: std::process::Child,
}

impl FakeRadar {
    fn spawn(dir: &Path) -> Self {
        let fifo = dir.join("radar");
        if !fifo.exists() {
            assert!(
                Command::new("mkfifo")
                    .arg(&fifo)
                    .status()
                    .unwrap()
                    .success(),
                "mkfifo"
            );
        }
        let child = Command::new("bash")
            .args(["-c", "exec -a hse cat radar"])
            .current_dir(dir)
            .spawn()
            .expect("spawn fake radar");
        // Give exec a moment so the process table shows `hse radar`.
        std::thread::sleep(Duration::from_millis(300));
        Self { child }
    }

    fn pid(&self) -> String {
        self.child.id().to_string()
    }

    fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }
}

impl Drop for FakeRadar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_radar_older_than_the_package_install_is_stale_and_only_stopped_when_authorised() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let dev = Device::new();
    let mut radar = FakeRadar::spawn(dev.dir.path());
    // The package was (re)installed AFTER this radar started: its absent-tool
    // cache cannot know the tools exist.
    dev.set_install_time(120);

    let (code, json) = dev.reconcile(&[]);
    assert_eq!(code, 8, "a stale process is the sole blocker: {json}");
    assert_eq!(json["radar"]["process"], "stale_restart_required", "{json}");
    assert_eq!(
        json["radar"]["process_pids"],
        serde_json::json!([radar.pid()])
    );
    assert_eq!(
        json["radar"]["process_action"], "none",
        "not authorised: never touched"
    );
    assert_eq!(
        json["radar"]["evidence"], "degraded",
        "every sensor read, but nothing is admissible until a fresh radar runs: {json}"
    );
    assert!(
        radar.alive(),
        "an unauthorised run must not stop the process"
    );

    // A dry run is never authorised to mutate, flag or not.
    let (code, json) = dev.reconcile(&["--dry-run", "--allow-process-restart"]);
    assert_eq!(code, 8, "{json}");
    assert_eq!(json["radar"]["process_action"], "none", "{json}");
    assert!(radar.alive());

    // Authorised: stopped through SIGINT, exit proven, re-observed.
    let (code, json) = dev.reconcile(&["--allow-process-restart"]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["radar"]["process_action"], "stopped", "{json}");
    assert_eq!(json["radar"]["process"], "not_running", "{json}");
    assert_eq!(json["radar"]["evidence"], "core_ready", "{json}");
    assert!(!radar.alive(), "the stale radar must have exited");

    // A radar started AFTER the install is current, and left alone.
    dev.set_install_time(-120);
    let mut fresh = FakeRadar::spawn(dev.dir.path());
    let (code, json) = dev.reconcile(&["--allow-process-restart"]);
    assert_eq!(code, 0, "{json}");
    assert_eq!(json["radar"]["process"], "current", "{json}");
    assert_eq!(json["radar"]["process_action"], "none", "{json}");
    assert!(fresh.alive(), "a current radar is never stopped");
}
