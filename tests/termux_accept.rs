//! `scripts/termux-accept.sh`, the on-device acceptance runner
//! (REQ-ACCEPT-001), driven in a throwaway git repository with `cargo`,
//! `uname` and the built `hse` replaced by stubs on `PATH`. Every verdict it
//! can reach is reached here without a phone and without a real build. The
//! environment that decides "is this Termux on aarch64" (`uname -m`,
//! `TERMUX_VERSION`, `PREFIX`) is set by each test, so the suite gives the
//! same answers when it runs on a Termux device.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn write_exec(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// `cargo`: `build --profile P` writes a stub `hse` into `target/<dir>/`,
/// and `test` passes unless told otherwise. Each run of either leaves a marker,
/// so a test can prove cargo was never reached.
const CARGO_STUB: &str = r#"#!/bin/sh
touch "$STUB_MARKERS/cargo-$1"
case "$1" in
build)
    [ -n "${STUB_BUILD_FAIL:-}" ] && exit 101
    prof=dev
    while [ $# -gt 0 ]; do [ "$1" = --profile ] && prof="$2"; shift; done
    case "$prof" in dev) d=debug ;; *) d="$prof" ;; esac
    sha="${STUB_SHA:-$(git rev-parse HEAD)}"
    mkdir -p "target/$d"
    sed "s/@SHA@/$sha/" "$STUB_HSE" > "target/$d/hse"
    chmod +x "target/$d/hse" ;;
test)
    [ -n "${STUB_TEST_FAIL:-}" ] && exit 101 ;;
esac
exit 0
"#;

/// The built binary: `build-sha --json` and a `config` that persists under
/// `$HOME/.huntsman`, unless `STUB_NO_PERSIST` makes writes vanish.
const HSE_STUB: &str = r#"#!/bin/sh
case "$1" in
build-sha)
    v=true
    [ -n "${STUB_UNVERIFIABLE:-}" ] && v=false
    printf '{"sha":"@SHA@","dirty":false,"version":"0","verifiable":%s}\n' "$v" ;;
config)
    f="$HOME/.huntsman/settings"
    mkdir -p "$HOME/.huntsman"
    if [ $# -ge 3 ]; then
        [ -n "${STUB_NO_PERSIST:-}" ] || printf '%s=%s\n' "$2" "$3" > "$f"
        printf '%s = %s\n' "$2" "$3"
    else
        v=$(sed -n "s/^$2=//p" "$f" 2>/dev/null)
        printf '%s = %s\n' "$2" "${v:-on}"
    fi ;;
esac
"#;

struct Fixture {
    dir: tempfile::TempDir,
    home: tempfile::TempDir,
    stubs: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fx = Self {
            dir: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
            stubs: tempfile::tempdir().unwrap(),
        };
        let script = fx.dir.path().join("scripts/termux-accept.sh");
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::copy(root().join("scripts/termux-accept.sh"), &script).unwrap();
        assert!(
            fs::metadata(&script).unwrap().permissions().mode() & 0o111 != 0,
            "scripts/termux-accept.sh must be committed executable"
        );
        fs::write(fx.dir.path().join(".gitignore"), "target/\n").unwrap();
        fs::write(fx.dir.path().join("README.md"), "fixture\n").unwrap();
        write_exec(&fx.stubs.path().join("bin/cargo"), CARGO_STUB);
        fs::write(fx.stubs.path().join("hse.in"), HSE_STUB).unwrap();
        fs::create_dir_all(fx.stubs.path().join("markers")).unwrap();
        fx.git(&["init", "-q", "-b", "main"]);
        fx.git(&["add", "-A"]);
        fx.git(&["commit", "-q", "-m", "fixture"]);
        fx
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(self.dir.path())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}: {}", text(&out.stderr));
        text(&out.stdout).trim().to_string()
    }

    /// `uname -m` answers `arch`.
    fn arch(&self, arch: &str) {
        write_exec(
            &self.stubs.path().join("bin/uname"),
            &format!("#!/bin/sh\necho {arch}\n"),
        );
    }

    fn ran_cargo(&self) -> bool {
        fs::read_dir(self.stubs.path().join("markers"))
            .unwrap()
            .next()
            .is_some()
    }

    /// Run the runner with `args`, as Termux when `termux` is set, plus `envs`.
    fn run(&self, args: &[&str], termux: bool, envs: &[(&str, &str)]) -> Output {
        let host_path = std::env::var_os("PATH").unwrap_or_default();
        let mut path = std::ffi::OsString::from(self.stubs.path().join("bin"));
        path.push(":");
        path.push(host_path);
        let mut c = Command::new("bash");
        c.arg(self.dir.path().join("scripts/termux-accept.sh"))
            .args(args)
            .current_dir(self.dir.path())
            .env("PATH", path)
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("STUB_MARKERS", self.stubs.path().join("markers"))
            .env("STUB_HSE", self.stubs.path().join("hse.in"))
            .env_remove("TERMUX_VERSION")
            .env_remove("PREFIX")
            .env_remove("HSE_BUILD_PROFILE");
        if termux {
            c.env("TERMUX_VERSION", "0.118.0")
                .env("PREFIX", "/data/data/com.termux/files/usr");
        }
        for (k, v) in envs {
            c.env(k, v);
        }
        c.output().expect("bash")
    }

    fn head(&self) -> String {
        self.git(&["rev-parse", "HEAD"])
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The record printed on stdout, parsed, after checking it is the same record
/// the runner stored at `$HOME/.huntsman/acceptance/<sha>.json`.
fn record(fx: &Fixture, out: &Output) -> serde_json::Value {
    let printed: serde_json::Value =
        serde_json::from_str(text(&out.stdout).trim()).unwrap_or_else(|e| {
            panic!(
                "stdout is not the JSON record ({e}):\n{}\n{}",
                text(&out.stdout),
                text(&out.stderr)
            )
        });
    let stored = fx
        .home
        .path()
        .join(".huntsman/acceptance")
        .join(format!("{}.json", fx.head()));
    let stored: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&stored).expect("the record is stored")).unwrap();
    assert_eq!(printed, stored, "the stored record is the printed one");
    assert_eq!(
        printed["sha"],
        fx.head(),
        "the record names the commit under test"
    );
    printed
}

fn stage<'a>(rec: &'a serde_json::Value, name: &str) -> &'a str {
    rec["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"] == name)
        .and_then(|s| s["result"].as_str())
        .unwrap_or_else(|| panic!("no `{name}` stage in {rec}"))
}

#[test]
fn a_checkout_with_uncommitted_changes_is_refused_before_anything_runs() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    fs::write(fx.dir.path().join("local-only.txt"), "x").unwrap();
    let out = fx.run(&[], true, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("uncommitted changes"));
    assert!(!fx.ran_cargo(), "nothing may be built from local state");
    assert!(!fx.home.path().join(".huntsman/acceptance").exists());
}

#[test]
fn a_host_that_is_not_termux_on_aarch64_is_refused_unless_it_says_so() {
    let fx = Fixture::new();
    for (arch, termux) in [("x86_64", false), ("aarch64", false), ("x86_64", true)] {
        fx.arch(arch);
        let out = fx.run(&[], termux, &[]);
        assert_eq!(out.status.code(), Some(2), "{arch} termux={termux}");
        assert!(
            text(&out.stderr).contains("--host"),
            "names the way to run it anyway"
        );
    }
    assert!(!fx.ran_cargo());

    fx.arch("x86_64");
    let out = fx.run(&["--host"], false, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(
        rec["verdict"], "HOST-ONLY",
        "a host run is never device evidence"
    );
    assert_eq!(rec["kind"], "host");
}

#[test]
fn a_device_run_where_every_stage_passes_is_accepted() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    // The operator's own state, which the run must leave exactly as it was.
    let theirs = fx.home.path().join(".huntsman/settings");
    fs::create_dir_all(theirs.parent().unwrap()).unwrap();
    fs::write(&theirs, "feature.auto_update=theirs\n").unwrap();
    let out = fx.run(&[], true, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(rec["verdict"], "ACCEPTED");
    assert_eq!(rec["kind"], "device");
    assert_eq!(rec["arch"], "aarch64");
    assert_eq!(rec["termux"], "0.118.0");
    for s in [
        "checkout", "platform", "build", "identity", "tests", "restart",
    ] {
        assert_eq!(stage(&rec, s), "PASS", "{s}");
    }
    assert!(rec["binary_bytes"].as_u64().unwrap() > 0);
    // The restart check wrote and read a setting in a scratch HOME. The
    // operator's own settings are untouched.
    assert_eq!(
        fs::read_to_string(&theirs).ok().as_deref(),
        Some("feature.auto_update=theirs\n"),
        "the restart check must not touch the operator's settings"
    );
}

#[test]
fn skipped_tests_make_a_device_run_partial_not_accepted() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&["--skip-tests"], true, &[]);
    assert!(out.status.success());
    let rec = record(&fx, &out);
    assert_eq!(rec["verdict"], "PARTIAL");
    assert_eq!(stage(&rec, "tests"), "SKIP");
}

#[test]
fn a_binary_that_is_not_head_is_rejected() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let wrong = "0".repeat(40);
    let out = fx.run(&[], true, &[("STUB_SHA", &wrong)]);
    assert_eq!(out.status.code(), Some(1));
    let rec = record(&fx, &out);
    assert_eq!(rec["verdict"], "REJECTED");
    assert_eq!(stage(&rec, "identity"), "FAIL");

    // The right sha is not enough: a binary that cannot prove it (a dirty
    // build) is the failure `hse build-sha` exists to expose.
    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&[], true, &[("STUB_UNVERIFIABLE", "1")]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stage(&record(&fx, &out), "identity"), "FAIL");
}

#[test]
fn a_setting_that_does_not_survive_a_new_process_is_rejected() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&[], true, &[("STUB_NO_PERSIST", "1")]);
    assert_eq!(out.status.code(), Some(1));
    let rec = record(&fx, &out);
    assert_eq!(rec["verdict"], "REJECTED");
    assert_eq!(stage(&rec, "restart"), "FAIL");
    assert!(
        !fx.home.path().join(".huntsman/settings").exists(),
        "the check runs in a scratch HOME, never the operator's"
    );
}

#[test]
fn a_failed_build_or_failed_tests_is_rejected() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&[], true, &[("STUB_BUILD_FAIL", "1")]);
    assert_eq!(out.status.code(), Some(1));
    let rec = record(&fx, &out);
    assert_eq!(stage(&rec, "build"), "FAIL");
    assert_eq!(
        stage(&rec, "identity"),
        "FAIL",
        "no binary, so nothing proves HEAD"
    );
    assert_eq!(rec["verdict"], "REJECTED");

    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&[], true, &[("STUB_TEST_FAIL", "1")]);
    assert_eq!(out.status.code(), Some(1));
    let rec = record(&fx, &out);
    assert_eq!(stage(&rec, "tests"), "FAIL");
    assert_eq!(rec["verdict"], "REJECTED");
}

#[test]
fn each_profile_is_looked_for_where_cargo_puts_it() {
    for profile in ["fast", "release", "dev"] {
        let fx = Fixture::new();
        fx.arch("aarch64");
        let out = fx.run(&["--profile", profile, "--skip-tests"], true, &[]);
        assert!(out.status.success(), "{profile}: {}", text(&out.stderr));
        let rec = record(&fx, &out);
        assert_eq!(stage(&rec, "identity"), "PASS", "{profile}");
        assert_eq!(rec["profile"], profile);
    }
    let fx = Fixture::new();
    fx.arch("aarch64");
    assert_eq!(
        fx.run(&["--profile", "debug"], true, &[]).status.code(),
        Some(2)
    );
}

#[test]
fn the_record_goes_where_out_says() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let elsewhere = fx.home.path().join("evidence/run.json");
    let out = fx.run(
        &["--skip-tests", "--out", elsewhere.to_str().unwrap()],
        true,
        &[],
    );
    assert!(out.status.success());
    let stored: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&elsewhere).unwrap()).unwrap();
    assert_eq!(stored["sha"], fx.head());
}
