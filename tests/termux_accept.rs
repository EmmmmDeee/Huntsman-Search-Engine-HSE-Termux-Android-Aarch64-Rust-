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

/// `cargo`: `build --profile P` writes a stub `hse` into `<target>/<dir>/`,
/// `metadata` names `<target>`, and `test` passes unless told otherwise.
/// `<target>` is `CARGO_TARGET_DIR` (relative to the working directory) or
/// `target`, as for the real cargo. Each run leaves a marker, so a test can
/// prove cargo was never reached.
const CARGO_STUB: &str = r#"#!/bin/sh
touch "$STUB_MARKERS/cargo-$1"
pwd -P > "$STUB_MARKERS/pwd-$1"
t="${CARGO_TARGET_DIR:-target}"
case "$t" in /*) ;; *) t="$PWD/$t" ;; esac
case "$1" in
metadata)
    printf '{"packages":[],"target_directory":"%s","version":1}\n' "$t" ;;
build)
    [ -n "${STUB_BUILD_FAIL:-}" ] && exit 101
    prof=dev
    while [ $# -gt 0 ]; do [ "$1" = --profile ] && prof="$2"; shift; done
    case "$prof" in dev) d=debug ;; *) d="$prof" ;; esac
    sha="${STUB_SHA:-$(git rev-parse HEAD)}"
    mkdir -p "$t/$d"
    sed "s/@SHA@/$sha/" "$STUB_HSE" > "$t/$d/hse"
    chmod +x "$t/$d/hse" ;;
test)
    # A suite that sees anything but the commit fails: a hidden edit to the
    # README, or an ignored local file.
    if [ -n "${STUB_TEST_REQUIRES_PRISTINE:-}" ]; then
        [ "$(cat README.md)" = fixture ] && [ ! -e local.cfg ] || exit 101
    fi
    # A test run that edits a file (relative: the tree it runs in), or moves
    # HEAD, under the runner.
    [ -n "${STUB_TEST_EDITS:-}" ] && echo edited >> "$STUB_TEST_EDITS"
    [ -n "${STUB_TEST_COMMITS:-}" ] \
        && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q --allow-empty -m moved
    [ -n "${STUB_TEST_REPOINTS:-}" ] && git remote set-url origin "$STUB_TEST_REPOINTS"
    [ -n "${STUB_TEST_FAIL:-}" ] && exit 101 ;;
esac
exit 0
"#;

/// The built binary: `build-sha [--json]` and a `config` that persists under
/// `$HOME/.huntsman`, unless `STUB_NO_PERSIST` makes writes vanish.
///
/// Like the real one, every command but `build-sha` first checks for an update
/// and, unless this `HOME` turned automatic updates off, installs it into the
/// source tree the binary sits in (`target/<profile>/../..`): the checkout
/// under test (REQ-UPDATE-001). Here the "update" is a line added to its
/// README, which the runner must never let happen. With update notices on it
/// still checks, which leaves a marker. The switch is read as the real `hse`
/// reads its one settings file: a value `config` stored wins over the one the
/// file started with.
const HSE_STUB: &str = r#"#!/bin/sh
updates_off() {
    case "$(sed -n 's/^feature\.auto_update=//p' "$HOME/.huntsman/settings" 2>/dev/null)" in
        off) return 0 ;;
        on) return 1 ;;
    esac
    grep -Eq '"feature\.auto_update": *false' "$HOME/.huntsman/settings.json" 2>/dev/null
}
if [ "$1" != build-sha ] && ! updates_off; then
    echo "updated by hse" >> "$(dirname "$0")/../../README.md"
fi
# With update notices on, it still fetches upstream into that checkout's refs.
if [ "$1" != build-sha ] \
    && ! grep -Eq '"feature\.update_notify": *false' "$HOME/.huntsman/settings.json" 2>/dev/null; then
    touch "$STUB_MARKERS/hse-checked-for-updates"
fi
case "$1" in
build-sha)
    if [ "${2:-}" = --json ]; then
        v=true
        [ -n "${STUB_UNVERIFIABLE:-}" ] && v=false
        printf '{"sha":"@SHA@","dirty":false,"version":"0","verifiable":%s}\n' "$v"
    else
        echo @SHA@
    fi ;;
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
        // Android's answer, which a device must give. Stubbed rather than
        // absent, so a real getprop on a Termux host cannot answer instead.
        write_exec(
            &fx.stubs.path().join("bin/getprop"),
            "#!/bin/sh\n[ -n \"${STUB_NO_ANDROID:-}\" ] && { echo; exit 0; }\n\
             case \"$1\" in ro.build.version.release) echo 14 ;; ro.product.model) echo Pixel ;; esac\n",
        );
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
        self.run_in(self.dir.path(), args, termux, envs)
    }

    /// [`Fixture::run`], started from `cwd` inside the checkout.
    fn run_in(&self, cwd: &Path, args: &[&str], termux: bool, envs: &[(&str, &str)]) -> Output {
        let host_path = std::env::var_os("PATH").unwrap_or_default();
        let mut path = std::ffi::OsString::from(self.stubs.path().join("bin"));
        path.push(":");
        path.push(host_path);
        let mut c = Command::new("bash");
        c.arg(self.dir.path().join("scripts/termux-accept.sh"))
            .args(args)
            .current_dir(cwd)
            .env("PATH", path)
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("STUB_MARKERS", self.stubs.path().join("markers"))
            .env("STUB_HSE", self.stubs.path().join("hse.in"))
            .env_remove("TERMUX_VERSION")
            .env_remove("PREFIX")
            .env_remove("HSE_BUILD_PROFILE")
            .env_remove("HSE_INSTALL_DIR")
            .env_remove("CARGO_TARGET_DIR");
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

    // An edit to a tracked file, unstaged and then staged, with nothing
    // untracked: a check that only sees new files would pass both.
    let fx = Fixture::new();
    fx.arch("aarch64");
    fs::write(fx.dir.path().join("README.md"), "fixture\nlocal\n").unwrap();
    for staged in [false, true] {
        if staged {
            fx.git(&["add", "README.md"]);
        }
        let out = fx.run(&[], true, &[]);
        assert_eq!(out.status.code(), Some(2), "staged={staged}");
        assert!(
            text(&out.stderr).contains("uncommitted changes"),
            "staged={staged}"
        );
    }
    assert!(!fx.ran_cargo());

    // A `git status` that cannot run is not a clean checkout.
    let fx = Fixture::new();
    fx.arch("aarch64");
    fs::write(fx.dir.path().join(".git/index"), "not an index").unwrap();
    let out = fx.run(&[], true, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("git status failed"));
    assert!(!fx.ran_cargo());
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

    // Termux on aarch64 without Android is the arm64 termux-docker image on a
    // cloud host: the Termux variables and `uname` alone do not make a device.
    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&[], true, &[("STUB_NO_ANDROID", "1")]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("no Android version"),
        "{}",
        text(&out.stderr)
    );
    assert!(!fx.ran_cargo());
    let out = fx.run(&["--host"], true, &[("STUB_NO_ANDROID", "1")]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(record(&fx, &out)["verdict"], "HOST-ONLY");
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
    assert_eq!(rec["android"], "14", "a device names its Android version");
    for s in [
        "checkout",
        "platform",
        "build",
        "identity",
        "tests",
        "restart",
        "unchanged",
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

/// The binary is where cargo put it. With `CARGO_TARGET_DIR` set, as
/// docs/INSTALL.md suggests (`~/.cache/hse-build`), the runner looked in the
/// checkout's `target/`, found no binary, and rejected a good build. A
/// relative value is resolved as cargo resolves it.
#[test]
fn the_binary_is_found_wherever_cargo_target_dir_puts_it() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let elsewhere = fx.home.path().join(".cache/hse-build");
    for dir in [
        elsewhere.to_str().unwrap().to_string(),
        "../outside-target".to_string(),
    ] {
        let out = fx.run(&["--skip-tests"], true, &[("CARGO_TARGET_DIR", &dir)]);
        assert!(out.status.success(), "{dir}: {}", text(&out.stderr));
        let rec = record(&fx, &out);
        assert_eq!(stage(&rec, "identity"), "PASS", "{dir}");
        assert_eq!(stage(&rec, "restart"), "PASS", "{dir}");
        assert!(
            !fx.dir.path().join("target").exists(),
            "{dir}: nothing was built into the checkout"
        );
    }
    assert!(elsewhere.join("fast/hse").exists());
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

/// REQ-UPDATE-001. `hse config` checks for an update before it runs, and run
/// from inside the checkout it installs one there, replacing the commit under
/// test. The restart stage runs `hse config` four times, and toggled
/// `feature.auto_update` itself, so the last read ran with updates on.
#[test]
fn the_runner_never_lets_hse_update_the_checkout_under_test() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let readme = fx.dir.path().join("README.md");
    let out = fx.run(&["--skip-tests"], true, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(stage(&rec, "restart"), "PASS");
    assert_eq!(stage(&rec, "unchanged"), "PASS");
    assert_eq!(fs::read_to_string(&readme).unwrap(), "fixture\n");
    assert!(
        !fx.stubs
            .path()
            .join("markers/hse-checked-for-updates")
            .exists(),
        "update notices are off too, so no fetch reaches the checkout's refs"
    );

    // Control: the same binary with updates left on does edit the checkout,
    // so the PASS above is the runner's doing, not an inert stub.
    let scratch = tempfile::tempdir().unwrap();
    let status = Command::new(fx.dir.path().join("target/fast/hse"))
        .args(["config", "feature.map_tiles"])
        .env("HOME", scratch.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        fs::read_to_string(&readme).unwrap(),
        "fixture\nupdated by hse\n",
        "the stub models the update, so the runner is what prevented it"
    );
}

/// The record speaks for one commit only if, at the end, both the tree that
/// was built and the operator's checkout are still that commit: edited, or
/// moved to another HEAD, either one makes the run REJECTED.
#[test]
fn a_checkout_that_changes_during_the_run_is_rejected() {
    // The tree being built, edited by the tests (a relative path: where they run).
    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&[], true, &[("STUB_TEST_EDITS", "README.md")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(rec["verdict"], "REJECTED");
    assert_eq!(stage(&rec, "tests"), "PASS");
    assert_eq!(stage(&rec, "unchanged"), "FAIL");

    // A new, untracked file in the tree being built.
    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&[], true, &[("STUB_TEST_EDITS", "stray.txt")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(stage(&record(&fx, &out), "unchanged"), "FAIL");

    // The operator's checkout, edited while the run builds.
    let fx = Fixture::new();
    fx.arch("aarch64");
    let theirs = fx.dir.path().join("README.md");
    let out = fx.run(&[], true, &[("STUB_TEST_EDITS", theirs.to_str().unwrap())]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(rec["verdict"], "REJECTED");
    assert_eq!(stage(&rec, "unchanged"), "FAIL");

    // The tree being built, moved to another commit. The next run starts from
    // the commit again: the kept worktree is reset, not reused as it was left.
    let fx = Fixture::new();
    fx.arch("aarch64");
    let out = fx.run(&[], true, &[("STUB_TEST_COMMITS", "1")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(rec["verdict"], "REJECTED");
    assert_eq!(stage(&rec, "unchanged"), "FAIL");
    let out = fx.run(&[], true, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(record(&fx, &out)["verdict"], "ACCEPTED");

    // Same commit, clean tree, but origin re-pointed: what the installer did
    // to a checkout it was started inside.
    let fx = Fixture::new();
    fx.arch("aarch64");
    fx.git(&["remote", "add", "origin", "https://example.invalid/hse.git"]);
    let out = fx.run(&[], true, &[("STUB_TEST_REPOINTS", "/elsewhere")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(rec["verdict"], "REJECTED");
    assert_eq!(stage(&rec, "unchanged"), "FAIL");
}

/// A stub `install.sh`, committed into the fixture. It logs what it was asked
/// to do and puts a stub `hse` on `PATH`: for the commit it was asked for,
/// unless `STUB_INSTALL_SHA` names another; one that cannot prove its commit
/// with `STUB_INSTALL_UNVERIFIABLE`; or none at all with `STUB_INSTALL_NOOP`.
/// `STUB_INSTALL_FAIL` makes it fail.
const INSTALL_STUB: &str = r#"#!/bin/sh
{ echo "dir=$HSE_INSTALL_DIR"; echo "from=$HSE_REPO_URL"; echo "sha=$HSE_REQUIRE_SHA"; echo "ref=${HSE_REF:-}"; } > "$STUB_INSTALL_LOG"
[ -n "${STUB_INSTALL_FAIL:-}" ] && exit 1
[ -n "${STUB_INSTALL_NOOP:-}" ] && exit 0
sed "s/@SHA@/${STUB_INSTALL_SHA:-$HSE_REQUIRE_SHA}/" "$STUB_HSE" > "$STUB_BIN/hse"
[ -n "${STUB_INSTALL_UNVERIFIABLE:-}" ] && sed -i 's/v=true/v=false/' "$STUB_BIN/hse"
chmod +x "$STUB_BIN/hse"
"#;

/// A fixture with `origin` set and the stub installer committed, and the
/// paths the stub writes to: its log, and the `bin` directory on `PATH`.
fn install_fixture(origin: &str) -> (Fixture, std::path::PathBuf, std::path::PathBuf) {
    let fx = Fixture::new();
    fx.arch("aarch64");
    fx.git(&["remote", "add", "origin", origin]);
    fs::write(fx.dir.path().join("install.sh"), INSTALL_STUB).unwrap();
    fx.git(&["add", "install.sh"]);
    fx.git(&["commit", "-q", "-m", "installer"]);
    let log = fx.stubs.path().join("install.log");
    let bin = fx.stubs.path().join("bin");
    (fx, log, bin)
}

/// `--install` runs the real installer, which upgrades in place a clone it is
/// started inside. Started from the checkout under test, it pointed the
/// checkout's origin at itself and switched it to a branch named after HEAD.
/// It installs where it installs for an operator, from the checkout's origin,
/// and never into the checkout. The commit is pinned with `HSE_REQUIRE_SHA`
/// alone: as `HSE_REF`, it named the install's branch after the commit, which
/// then followed nothing and never updated again.
#[test]
fn the_install_stage_installs_elsewhere_and_never_into_the_checkout() {
    let origin = "https://example.invalid/hse.git";
    let (fx, log, bin) = install_fixture(origin);
    let envs = [
        ("STUB_INSTALL_LOG", log.to_str().unwrap()),
        ("STUB_BIN", bin.to_str().unwrap()),
    ];

    let out = fx.run(&["--install", "--skip-tests"], true, &envs);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(stage(&rec, "install"), "PASS");
    assert_eq!(stage(&rec, "unchanged"), "PASS");
    let ran = fs::read_to_string(&log).expect("the installer ran");
    let default_dir = fx.home.path().join(".local/share/hse");
    assert!(
        ran.contains(&format!("dir={}\n", default_dir.display())),
        "the installer's own default, not the checkout: {ran}"
    );
    assert!(ran.contains(&format!("from={origin}\n")), "{ran}");
    assert!(ran.contains(&format!("sha={}\n", fx.head())), "{ran}");
    assert!(
        ran.contains("ref=\n"),
        "the branch is the installer's: {ran}"
    );
    assert_eq!(fx.git(&["remote", "get-url", "origin"]), origin);

    // Pointed at the checkout itself, the stage refuses and never starts it.
    fs::remove_file(&log).unwrap();
    let here = fx.dir.path().to_str().unwrap();
    let out = fx.run(
        &["--install", "--skip-tests"],
        true,
        &[envs[0], envs[1], ("HSE_INSTALL_DIR", here)],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(stage(&rec, "install"), "FAIL");
    assert_eq!(rec["verdict"], "REJECTED");
    assert!(!log.exists(), "the installer never ran");
}

/// The install stage passes only on what the installer put on `PATH`: a HEAD
/// that can prove it. An installer that installed another commit fails. One
/// that did nothing, with an `hse` for HEAD already on `PATH`, passed before;
/// that run proves nothing about the installer, and says so (PARTIAL).
#[test]
fn the_install_stage_passes_only_what_the_installer_installed() {
    let zeros = "0".repeat(40);
    let (fx, log, bin) = install_fixture("https://example.invalid/hse.git");
    let out = fx.run(
        &["--install"],
        true,
        &[
            ("STUB_INSTALL_LOG", log.to_str().unwrap()),
            ("STUB_BIN", bin.to_str().unwrap()),
            ("STUB_INSTALL_SHA", &zeros),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(stage(&rec, "install"), "FAIL");
    assert_eq!(rec["verdict"], "REJECTED");

    let (fx, log, bin) = install_fixture("https://example.invalid/hse.git");
    let before = fs::read_to_string(fx.stubs.path().join("hse.in"))
        .unwrap()
        .replace("@SHA@", &fx.head());
    write_exec(&bin.join("hse"), &before);
    let out = fx.run(
        &["--install"],
        true,
        &[
            ("STUB_INSTALL_LOG", log.to_str().unwrap()),
            ("STUB_BIN", bin.to_str().unwrap()),
            ("STUB_INSTALL_NOOP", "1"),
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(stage(&rec, "install"), "SKIP");
    assert_eq!(
        rec["verdict"], "PARTIAL",
        "an hse that was there before shows nothing about the installer"
    );
    assert!(!log.exists(), "it is not run when it can prove nothing");

    // The right commit is not enough: an installed binary that cannot prove
    // it (a dirty build) fails, as it does at the identity stage.
    let (fx, log, bin) = install_fixture("https://example.invalid/hse.git");
    let out = fx.run(
        &["--install", "--skip-tests"],
        true,
        &[
            ("STUB_INSTALL_LOG", log.to_str().unwrap()),
            ("STUB_BIN", bin.to_str().unwrap()),
            ("STUB_INSTALL_UNVERIFIABLE", "1"),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(stage(&record(&fx, &out), "install"), "FAIL");

    // The installer that runs is the commit's. The checkout's copy, edited
    // behind git status's back, is not it.
    let (fx, log, bin) = install_fixture("https://example.invalid/hse.git");
    fx.git(&["update-index", "--assume-unchanged", "install.sh"]);
    fs::write(fx.dir.path().join("install.sh"), "#!/bin/sh\nexit 1\n").unwrap();
    let out = fx.run(
        &["--install", "--skip-tests"],
        true,
        &[
            ("STUB_INSTALL_LOG", log.to_str().unwrap()),
            ("STUB_BIN", bin.to_str().unwrap()),
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(stage(&record(&fx, &out), "install"), "PASS");
    assert!(log.exists(), "the commit's installer ran");
}

/// The build and the tests run on the commit, not on the operator's working
/// tree. `git status` cannot see an edit to a path marked assume-unchanged or
/// skip-worktree, nor an ignored file the build reads, so all three passed the
/// checkout stage and were built and tested as if they were HEAD. The stub
/// suite fails if it sees any of them.
#[test]
fn hidden_edits_and_ignored_files_are_never_what_gets_tested() {
    for flag in ["--assume-unchanged", "--skip-worktree"] {
        let fx = Fixture::new();
        fx.arch("aarch64");
        fx.git(&["update-index", flag, "README.md"]);
        fs::write(fx.dir.path().join("README.md"), "a local edit\n").unwrap();
        fs::write(fx.dir.path().join(".git/info/exclude"), "local.cfg\n").unwrap();
        fs::write(fx.dir.path().join("local.cfg"), "local only\n").unwrap();
        assert_eq!(
            fx.git(&["status", "--porcelain"]),
            "",
            "precondition: {flag} hides it"
        );

        let out = fx.run(&[], true, &[("STUB_TEST_REQUIRES_PRISTINE", "1")]);
        assert!(out.status.success(), "{flag}: {}", text(&out.stderr));
        let rec = record(&fx, &out);
        assert_eq!(rec["verdict"], "ACCEPTED", "{flag}");
        assert_eq!(stage(&rec, "tests"), "PASS", "{flag}");
        let built_in = fs::read_to_string(fx.stubs.path().join("markers/pwd-build")).unwrap();
        let checkout = fx.dir.path().canonicalize().unwrap();
        assert_ne!(
            Path::new(built_in.trim()),
            checkout,
            "{flag}: built in a worktree of the commit, not the checkout"
        );
        assert_eq!(
            fs::read_to_string(fx.dir.path().join("README.md")).unwrap(),
            "a local edit\n",
            "{flag}: the operator's own edit is left alone"
        );
    }
}

/// Termux:API can hang when its app is missing or asleep. The battery probe
/// had no limit, so a run whose every stage passed hung and wrote no record.
#[test]
fn a_hanging_battery_probe_cannot_stop_the_record() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let probe = fx.stubs.path().join("bin/termux-battery-status");
    write_exec(&probe, "#!/bin/sh\nexec sleep 60\n");
    let started = std::time::Instant::now();
    let out = fx.run(&["--skip-tests"], true, &[("HSE_ACCEPT_API_TIMEOUT", "1")]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "the probe was not cut off: {:?}",
        started.elapsed()
    );
    assert_eq!(record(&fx, &out)["battery_percent"], "");

    // Control: a probe that answers is read.
    write_exec(
        &probe,
        "#!/bin/sh\necho '{\"health\": \"GOOD\", \"percentage\": 87}'\n",
    );
    let out = fx.run(&["--skip-tests"], true, &[]);
    assert_eq!(record(&fx, &out)["battery_percent"], "87");
}

/// A relative `--out` is the operator's path, from where they ran the script.
/// The runner changes directory (to the checkout's top, then to the commit's
/// worktree); the record must not follow it. Started from a subdirectory, so
/// "where it was started" and "the checkout's top" are different answers.
#[test]
fn a_relative_out_is_relative_to_where_the_runner_was_started() {
    let fx = Fixture::new();
    fx.arch("aarch64");
    let started_in = fx.dir.path().join("scripts");
    let out = fx.run_in(
        &started_in,
        &["--skip-tests", "--out", "run.json"],
        true,
        &[],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stored: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(started_in.join("run.json")).unwrap()).unwrap();
    assert_eq!(stored["sha"], fx.head());
}

/// The record is pasted into PRs. An origin URL can carry a token
/// (`https://TOKEN@host/…`, as install.sh suggests for a private repository),
/// and a failed install, or an origin changed during the run, wrote it there.
#[test]
fn credentials_in_an_origin_url_never_reach_the_record() {
    let token = "ghp_FAKEtoken0123456789";
    let secret_origin = format!("https://{token}@example.invalid/owner/private.git");
    let (fx, log, bin) = install_fixture(&secret_origin);
    let out = fx.run(
        &["--install", "--skip-tests"],
        true,
        &[
            ("STUB_INSTALL_LOG", log.to_str().unwrap()),
            ("STUB_BIN", bin.to_str().unwrap()),
            ("STUB_INSTALL_FAIL", "1"),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let rec = record(&fx, &out);
    assert_eq!(stage(&rec, "install"), "FAIL");
    let printed = text(&out.stdout);
    assert!(
        !printed.contains(token),
        "the token is in the record: {printed}"
    );
    assert!(
        printed.contains("https://***@example.invalid/owner/private.git"),
        "{printed}"
    );
    assert!(
        fs::read_to_string(&log).unwrap().contains(&secret_origin),
        "the installer itself still gets the real URL"
    );

    let fx = Fixture::new();
    fx.arch("aarch64");
    fx.git(&["remote", "add", "origin", &secret_origin]);
    let moved = format!("https://{token}@example.invalid/elsewhere.git");
    let out = fx.run(&[], true, &[("STUB_TEST_REPOINTS", &moved)]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(stage(&record(&fx, &out), "unchanged"), "FAIL");
    assert!(!text(&out.stdout).contains(token), "{}", text(&out.stdout));
}
