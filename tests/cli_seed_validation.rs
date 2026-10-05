//! CLI contract guards (spawn the real binary — the faithful test of the wiring
//! that a unit test can't reach):
//!   - seed validation: `hse scan` / `hse live` must reject reserved/placeholder
//!     targets at the boundary, so an "example anything" can never be dispatched.
//!   - `-o json` output discipline: stdout must be a single JSON document, with
//!     all human-readable progress/summary on stderr, so `| jq` works.
//!   - a settings file that does not parse stops `hse` and is kept.
//!   - an image `hse ingest` cannot read fails with the reason, and its file
//!     path is never mined for findings.
//!   - the hint printed after a scan is stored is a command that reads it back.
//!   - automatic updates never touch the source tree a build runs from.

mod common;

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_hse");

/// Run `hse <args>` with logging off; return (success, stderr).
///
/// `HOME` is pointed at a per-process scratch dir: even a run that is rejected
/// at the seed boundary opens the store / key pool at startup, and without this
/// those writes landed in the developer's real `~/.huntsman` (the same isolation
/// `run_streams` and the diff tests below already apply).
fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "off")
        .env("HOME", common::tmp_dir("seed-run"))
        .output()
        .expect("spawn hse");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// REQ-SCANNAME-001: `hse scan --name` stores the scan's name, cleaned as a
/// request body's is, and a name that is not one line is refused before
/// anything runs.
#[test]
fn scan_name_is_stored_cleaned_and_a_broken_one_refused() {
    let dir = common::tmp_dir("scan-name");
    let scan = |name: &str| {
        Command::new(BIN)
            .args([
                "scan",
                "-v",
                "Jane Smith",
                "-k",
                "name",
                "--modules",
                "name_intel",
                "--throttle",
                "0",
                "--name",
                name,
                "-o",
                "json",
            ])
            .env("RUST_LOG", "off")
            .env("HOME", &dir)
            .output()
            .expect("spawn hse scan")
    };
    let named = scan("  Q3\taudit ");
    assert!(
        named.status.success(),
        "{}",
        String::from_utf8_lossy(&named.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&named.stdout).expect("one JSON document on stdout");
    assert_eq!(report["scan"]["options"]["name"], "Q3 audit", "{report}");

    let broken = scan("two\nlines");
    assert!(!broken.status.success(), "a two-line name must be refused");
    let stderr = String::from_utf8_lossy(&broken.stderr);
    assert!(
        stderr.contains("--name: name contains control characters or a line break"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// REQ-INGEST-001: `hse ingest` of an image with no OCR on the host exits
/// non-zero, says why and how to fix it, and prints no findings. It used to
/// exit 0 and print three, all read from the sentence "OCR unavailable for
/// <path>": the email in the folder's name at 0.85, that email's domain, and
/// the file name as a domain. With `--auto-scan` it stored them as a scan.
/// With `--extract-geolocation` on an image with no EXIF, nothing is found
/// either, so that fails the same way.
///
/// `PATH` is an empty directory, so the host has no `tesseract`, whatever the
/// machine running the test has installed.
#[test]
fn ingest_of_an_image_it_cannot_read_says_why_and_finds_nothing() {
    let dir = common::tmp_dir("ingest-ocr");
    let no_tools = dir.join("empty-path");
    let folder = dir.join("case-jane.doe@contoso-files.net");
    std::fs::create_dir_all(&no_tools).expect("empty PATH dir");
    std::fs::create_dir_all(&folder).expect("folder");
    let image = folder.join("scan-of-id.png");
    std::fs::write(&image, b"\x89PNG\r\n\x1a\n").expect("image");
    let image = image.to_str().expect("utf-8 temp path");

    for extra in [
        &[][..],
        &["--auto-scan"][..],
        &["--extract-geolocation"][..],
    ] {
        let out = Command::new(BIN)
            .args(["ingest", "-f", image])
            .args(extra)
            .env("RUST_LOG", "off")
            .env("HOME", &dir)
            .env("PATH", &no_tools)
            .output()
            .expect("spawn hse ingest");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{extra:?}: must fail: {stdout}");
        assert!(
            stderr.contains("OCR not available: tesseract is not installed")
                && stderr.contains("pkg install tesseract"),
            "{extra:?}: the reason and the fix: {stderr}"
        );
        assert!(
            !stdout.contains("contoso") && !stdout.contains("scan-of-id"),
            "{extra:?}: the file's path is not a finding: {stdout}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_wiring_self_compare_is_rejected_with_diagnostic() {
    // The diff *logic* is unit-tested in core::diff; this guards the CLI WIRING a
    // unit test can't reach: `latest` resolution, same-scan detection, and the
    // footgun-rejection exit code. Comparing a scan to itself is a user mistake
    // (scan ids are deterministic SHA-256, so re-scanning overwrites the row rather
    // than creating a second one — the diff is always empty). The correct behaviour
    // is to exit non-zero and print a diagnostic pointing at the snapshot workflow.
    let dir = common::tmp_dir("diff");

    // One offline scan so there's a `latest` to compare against itself.
    let scan = Command::new(BIN)
        .args([
            "scan",
            "-v",
            "Jane Smith",
            "-k",
            "name",
            "--modules",
            "name_intel",
            "--throttle",
            "0",
        ])
        .env("RUST_LOG", "off")
        .env("HOME", &dir)
        .output()
        .expect("spawn hse scan");
    assert!(scan.status.success(), "seed scan must succeed");

    let out = Command::new(BIN)
        .args(["diff", "latest", "latest", "-f", "json"])
        .env("RUST_LOG", "off")
        .env("HOME", &dir)
        .output()
        .expect("spawn hse diff");
    assert!(
        !out.status.success(),
        "self-compare must exit non-zero — footgun rejected, not silently allowed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("both sides resolve to the same scan"),
        "expected same-scan diagnostic on stderr, got:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_rejects_placeholder_domain() {
    let (ok, err) = run(&["scan", "--kind", "domain", "--value", "example.com"]);
    assert!(!ok, "example.com must be rejected, not scanned");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "expected a placeholder-rejection message, got: {err}"
    );
}

#[test]
fn scan_rejects_placeholder_email_host() {
    let (ok, err) = run(&["scan", "--kind", "email", "--value", "jordan@example.com"]);
    assert!(!ok, "jordan@example.com must be rejected");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "{err}"
    );
}

#[test]
fn live_rejects_placeholder_domain() {
    let (ok, err) = run(&["live", "--kind", "domain", "--value", "test.example"]);
    assert!(!ok, "test.example must be rejected");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "{err}"
    );
}

#[test]
fn scan_json_stdout_is_pure_json() {
    // The `-o json` contract for the most-used command: stdout is a single JSON
    // document (scan + entities + correlations + diagnostics), with all progress
    // and the "full dossier:" notice on stderr. Offline modules only (no network)
    // so the test is hermetic. Guards the same stdout/stderr discipline the import
    // fix established, across the command an operator is most likely to pipe.
    let dir = common::tmp_dir("scan-json");

    let out = Command::new(BIN)
        .args([
            "scan",
            "-v",
            "Jane Smith",
            "-k",
            "name",
            "--modules",
            "name_intel",
            "--throttle",
            "0",
            "-o",
            "json",
        ])
        .env("RUST_LOG", "off")
        .env("HOME", &dir)
        .output()
        .expect("spawn hse scan");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("scan -o json stdout is not pure JSON ({e}):\n{stdout}"));
    for key in ["scan", "entities", "correlations"] {
        assert!(
            parsed.get(key).is_some(),
            "scan JSON must carry `{key}`: {parsed}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_json_stdout_is_pure_json_summary_on_stderr() {
    // `hse import … -o json` must emit ONLY JSON on stdout so `| jq` works; the
    // human-readable "Imported N entities" summary belongs on stderr. The summary
    // used to be println!'d to stdout ahead of the JSON, so a consumer parsing
    // stdout failed. Spawn the real binary and prove the contract end-to-end.
    let dir = common::tmp_dir("import-json");
    let file = dir.join("dossier.txt");
    std::fs::write(
        &file,
        "Entry #1\n\u{2022} name: Isaac Frost\n\u{2022} email: isaac@frostcorp.io\n\
         \u{2022} ip: 8.8.8.8\n\u{2022} phone: +61412345678\n",
    )
    .unwrap();

    let out = Command::new(BIN)
        .args(["import", file.to_str().unwrap(), "-o", "json"])
        .env("RUST_LOG", "off")
        .env("HOME", &dir) // isolate the DB/key pool from the developer's $HOME
        .output()
        .expect("spawn hse import");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Stdout parses as JSON in full — nothing else is interleaved.
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not pure JSON ({e}):\n{stdout}"));
    assert!(
        parsed.get("entities").and_then(|e| e.as_array()).is_some(),
        "JSON must carry an entities array: {parsed}"
    );
    // The human summary went to stderr, not stdout.
    assert!(
        stderr.contains("Imported") && !stdout.contains("Imported"),
        "summary must be on stderr only; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// REQ-SETTINGS-001: a settings file that does not parse stops `hse` with the
/// reason, before the self-update reads a switch, and is left as it is. It was
/// read as no overrides, so one trailing comma turned auto-update, the
/// map-tile fetch and the live radar back on without a word, and the next
/// `hse config` replaced the file. The two commands install.sh runs that read
/// no switch, `hse build-sha` and `hse provision --env-only`, still work.
#[test]
fn a_settings_file_that_does_not_parse_stops_hse_and_is_kept() {
    let dir = common::tmp_dir("settings-broken");
    std::fs::create_dir_all(dir.join(".huntsman")).expect("data dir");
    let path = dir.join(".huntsman").join("settings.json");
    let stamp = dir.join(".cache").join("hse-autoupdate.stamp");
    let _ = std::fs::remove_dir_all(dir.join(".cache"));
    // Run a copy of the binary from the scratch dir, not the one in the build
    // tree: the self-update this test proves never ran would otherwise find
    // that source tree, and a regression could start a real install from it.
    let bin = dir.join("hse");
    if std::fs::hard_link(BIN, &bin).is_err() {
        std::fs::copy(BIN, &bin).expect("copy hse");
    }
    let run_in = |home: &std::path::Path, args: &[&str]| {
        Command::new(&bin)
            .args(args)
            .env("RUST_LOG", "off")
            .env("HOME", home)
            .env_remove("HUNTSMAN_INSTALL_DIR")
            .output()
            .expect("spawn hse")
    };
    let hse = |args: &[&str]| run_in(&dir, args);

    let broken =
        r#"{"feature.auto_update":false,"feature.map_tiles":false,"feature.live_radar":false,}"#;
    std::fs::write(&path, broken).expect("settings");
    for args in [&["config"][..], &["config", "feature.regional", "off"][..]] {
        let out = hse(args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} must refuse: {stdout}");
        assert!(
            stderr.contains("settings.json") && stderr.contains("move it aside"),
            "{args:?}: the file and the fix: {stderr}"
        );
        assert!(
            !stdout.contains("● on"),
            "{args:?}: nothing reset is shown: {stdout}"
        );
    }
    assert_eq!(std::fs::read_to_string(&path).expect("kept"), broken);
    // Stopped before the self-update, which reads `feature.auto_update` and
    // stamps its check: read as no overrides, the file turned it back on.
    assert!(
        !stamp.exists(),
        "the self-update ran on a settings file that does not parse"
    );

    let fresh = common::tmp_dir("settings-none");
    let (with_broken, without) = (hse(&["build-sha"]), run_in(&fresh, &["build-sha"]));
    assert_eq!(
        (with_broken.status.code(), &with_broken.stdout),
        (without.status.code(), &without.stdout),
        "build-sha reads no switch: {}",
        String::from_utf8_lossy(&with_broken.stderr)
    );
    let _ = std::fs::remove_dir_all(&fresh);
    let out = hse(&["provision", "--env-only", "--dry-run"]);
    assert!(
        out.status.success(),
        "provision --env-only reads no switch: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Repaired, the same switches are read and shown off.
    std::fs::write(&path, broken.replace(",}", "}")).expect("repaired");
    let out = hse(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for key in [
        "feature.auto_update",
        "feature.map_tiles",
        "feature.live_radar",
    ] {
        assert!(
            stdout
                .lines()
                .any(|l| l.contains(key) && l.contains("○ off")),
            "{key} reads off: {stdout}"
        );
    }
    // The control for the stamp check above: once the file parses, the same
    // command reaches the self-update, which stamps its check (update notices
    // are still on).
    assert!(
        stamp.exists(),
        "the self-update check did not run: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// REQ-UPDATE-002. `hse` run from a build (`<tree>/target/debug/hse`) found
/// `<tree>` by walking up from its own path, and when that tree was behind its
/// origin, updated it in the background. The installer, started in a clone,
/// upgrades it to `main` in place and installs over the system `hse`. Every
/// test that runs the built binary did that to the checkout it tested
/// (REQ-UPDATE-001). Automatic updates now look only for an installation. An
/// explicit `hse update` still finds the build tree. The real binary runs in a
/// fixture tree one commit behind a local origin, whose `install.sh` only
/// leaves a mark.
#[cfg(unix)]
#[test]
fn automatic_updates_never_touch_the_tree_a_build_runs_from() {
    use std::path::Path;
    let git = |dir: &Path, args: &[&str]| {
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
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let base = common::tmp_dir("update-scope");
    let _ = std::fs::remove_dir_all(&base);
    let origin = base.join("origin");
    let tree = base.join("tree");
    let mark = base.join("installer-ran");
    std::fs::create_dir_all(&origin).expect("origin dir");
    git(&origin, &["init", "-q", "-b", "main"]);
    std::fs::write(
        origin.join("Cargo.toml"),
        "[package]\nname = \"huntsman-search-engine\"\n",
    )
    .expect("Cargo.toml");
    std::fs::write(
        origin.join("install.sh"),
        "#!/bin/sh\ntouch \"$HSE_TEST_INSTALL_MARK\"\n",
    )
    .expect("install.sh");
    git(&origin, &["add", "-A"]);
    git(&origin, &["commit", "-q", "-m", "one"]);
    git(
        &base,
        &[
            "clone",
            "-q",
            origin.to_str().unwrap(),
            tree.to_str().unwrap(),
        ],
    );
    git(&origin, &["commit", "-q", "--allow-empty", "-m", "two"]);

    // The binary where a build puts it.
    let bin = tree.join("target/debug/hse");
    std::fs::create_dir_all(bin.parent().unwrap()).expect("target dir");
    if std::fs::hard_link(BIN, &bin).is_err() {
        std::fs::copy(BIN, &bin).expect("copy hse");
    }
    let hse = |home: &Path, args: &[&str], installation: Option<&Path>| {
        std::fs::create_dir_all(home).expect("home");
        let mut c = Command::new(&bin);
        c.args(args)
            .current_dir(&tree)
            .env("HOME", home)
            .env("RUST_LOG", "off")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HSE_TEST_INSTALL_MARK", &mark)
            .env_remove("HUNTSMAN_INSTALL_DIR")
            .env_remove("HSE_REF");
        if let Some(dir) = installation {
            c.env("HUNTSMAN_INSTALL_DIR", dir);
        }
        c.output().expect("spawn hse")
    };
    // The installer is started detached, so it is waited for.
    let installer_ran = || {
        for _ in 0..100 {
            if mark.exists() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    };

    // A build, with no installation recorded: not updated automatically.
    let as_build = base.join("home-build");
    let out = hse(&as_build, &["config"], None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !installer_ran(),
        "the tree a build runs from was updated in the background"
    );
    // An explicit check still finds the build tree, and the commit waiting.
    let out = hse(&as_build, &["update", "--check"], None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 commit(s) available"), "{stdout}");

    // Control: the same tree recorded as the installation is updated, so the
    // silence above is the rule and not a dead mechanism.
    let out = hse(&base.join("home-installed"), &["config"], Some(&tree));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        installer_ran(),
        "an installation behind its origin is updated"
    );

    // Detached: pinned to one commit, and `update --check` says so
    // (REQ-UPDATE-001), where it used to say "offline?".
    git(&tree, &["checkout", "-q", "--detach"]);
    let out = hse(&as_build, &["update", "--check"], None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("HEAD is detached"), "{stdout}");

    let _ = std::fs::remove_dir_all(&base);
}

/// REQ-INGEST-001: when tesseract runs and refuses an image, its own reason
/// reaches the operator, not just its exit code. A stand-in `tesseract` on
/// `PATH` exits 1 with tesseract's usual complaint on stderr.
#[cfg(unix)]
#[test]
fn ingest_reports_tesseracts_own_reason_for_refusing_an_image() {
    use std::os::unix::fs::PermissionsExt;
    // The stand-in's interpreter by absolute path: `/bin/sh` is not where it
    // lives on every host (Termux), and the stand-in runs with a bare `PATH`.
    let sh = std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("sh"))
                .find(|c| c.is_file())
        })
        .expect("a POSIX sh on PATH");
    let dir = common::tmp_dir("ingest-ocr-refusal");
    let tools = dir.join("tools");
    std::fs::create_dir_all(&tools).expect("tools dir");
    let fake = tools.join("tesseract");
    std::fs::write(
        &fake,
        format!(
            "#!{}\necho 'Error in pixReadStream: Unknown format: no pix returned' >&2\nexit 1\n",
            sh.display()
        ),
    )
    .expect("stand-in tesseract");
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let image = dir.join("scan.png");
    std::fs::write(&image, b"\x89PNG\r\n\x1a\n").expect("image");

    let out = Command::new(BIN)
        .args(["ingest", "-f", image.to_str().expect("utf-8 temp path")])
        .env("RUST_LOG", "off")
        .env("HOME", &dir)
        .env("PATH", &tools)
        .output()
        .expect("spawn hse ingest");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "tesseract exited with 1: Error in pixReadStream: Unknown format: no pix returned"
        ),
        "tesseract's own reason: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The scan id a summary says it stored, and the command it says views it,
/// from a line of the form "scan <id> (N entities, ...) — view with `<command>`".
fn stored_and_hint(said: &str) -> (String, String) {
    const LEAD: &str = "view with `";
    let at = said
        .find(LEAD)
        .unwrap_or_else(|| panic!("no hint in: {said}"));
    let hint = said[at + LEAD.len()..]
        .split('`')
        .next()
        .unwrap_or_default()
        .to_string();
    let stored = said[..at]
        .rsplit("scan ")
        .next()
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_default()
        .to_string();
    (stored, hint)
}

/// REQ-CLI-HINTS-001: each command that stores a scan without running one
/// (`hse import`, `hse investigate --auto-scan`, `hse ingest --auto-scan`) ends
/// with a hint, and the command the hint names runs and reads that scan back.
/// All three named a list command `hse` does not have, which exited 2 as an
/// unrecognized subcommand.
#[test]
fn every_stored_scan_hint_reads_that_scan_back() {
    let dir = common::tmp_dir("stored-hint");
    let dossier = dir.join("dossier.txt");
    std::fs::write(
        &dossier,
        "Entry #1\n\u{2022} name: Isaac Frost\n\u{2022} email: isaac@frostcorp.io\n",
    )
    .expect("dossier");
    let notes = dir.join("notes.txt");
    std::fs::write(&notes, "Contact qa-hint@hse-hint-test.dev for the files.\n").expect("notes");
    let dossier = dossier.to_str().expect("utf-8 temp path");
    let notes = notes.to_str().expect("utf-8 temp path");
    // Logging off: the hint must reach the operator whatever the log level.
    let hse = |args: &[&str]| {
        Command::new(BIN)
            .args(args)
            .env("RUST_LOG", "off")
            .env("HOME", &dir)
            .output()
            .expect("spawn hse")
    };

    for args in [
        vec!["import", dossier],
        vec![
            "investigate",
            "what is linked to qa-hint@hse-hint-test.dev",
            "--auto-scan",
        ],
        vec!["ingest", "-f", notes, "--auto-scan"],
    ] {
        let run = hse(&args);
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(run.status.success(), "{args:?}: {said}");
        let (stored, hint) = stored_and_hint(&said);
        let view_args: Vec<&str> = hint.split_whitespace().collect();
        assert_eq!(view_args.first(), Some(&"hse"), "{args:?}: {hint}");
        let view = hse(&view_args[1..]);
        assert!(
            view.status.success(),
            "{args:?}: `{hint}` must run: {}",
            String::from_utf8_lossy(&view.stderr)
        );
        // The full dossier: its header names the scan and counts what is in it.
        let read_back = String::from_utf8_lossy(&view.stdout);
        let field = |name: &str| {
            read_back
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .map(|v| v.trim_start_matches([' ', ':']).trim().to_string())
                .unwrap_or_default()
        };
        assert_eq!(
            field("scan id"),
            stored,
            "{args:?}: `{hint}` reads the scan it stored: {read_back}"
        );
        assert!(
            field("entities").parse::<usize>().is_ok_and(|n| n > 0),
            "{args:?}: with its entities: {read_back}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── stream discipline: a command's primary output belongs on stdout ─────────

/// Every status marker the self-test can render, read from the source of truth
/// rather than copied. A hand-written subset is how `[fail]` (lowercase) got in
/// here — a branch that could never match the rendered `[FAIL]`, silently
/// weakening the assertion it appeared in.
///
/// The variant list is still written out here; adding a fourth `Status` means
/// adding it below. The marker STRINGS, which is what actually drifted, are no
/// longer duplicated.
fn markers() -> [&'static str; 3] {
    use huntsman_search_engine::selftest::Status;
    [Status::Pass, Status::Warn, Status::Fail].map(Status::marker)
}

/// Count rendered self-test check lines, whatever their outcome.
///
/// Counting only `[ok]` would make these tests depend on every check PASSING,
/// which is not what they are about: they assert WHICH STREAM the report lands
/// on. A warn or a fail is still a check line that must appear on stdout.
fn check_line_count(text: &str) -> usize {
    text.lines()
        .filter(|l| markers().iter().any(|m| l.contains(m)))
        .count()
}

/// Run `hse <args>` with an isolated `HOME`; return (stdout, stderr).
///
/// `hse selftest` reads `~/.huntsman.env` and writes under `~/.huntsman`, so
/// without this the result would depend on the developer's or runner's real home
/// directory — and the run would leave state in it. The temp dir lives until the
/// child has exited and its output is collected.
fn run_streams(args: &[&str]) -> (String, String) {
    let home = tempfile::tempdir().expect("temp HOME");
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "off")
        .env("HOME", home.path())
        .output()
        .expect("spawn hse");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn selftest_text_report_goes_to_stdout_so_it_can_be_redirected() {
    // Regression: the table was printed with `eprintln!` "so stdout stays clean
    // for piping the `--json` form" — but the two branches are mutually
    // exclusive, so the table never shared a stream with that JSON. The cost was
    // that `hse selftest > report.txt` produced an EMPTY file and
    // `hse selftest | grep` matched nothing, on a command whose help calls it
    // "kept for scripting".
    let (stdout, _stderr) = run_streams(&["selftest"]);
    assert!(
        stdout.contains("self-test"),
        "the self-test report must be on stdout so it survives redirection; \
         stdout was:\n{stdout}"
    );
    assert!(
        check_line_count(&stdout) > 0,
        "stdout must carry the individual check lines, not just a header:\n{stdout}"
    );
}

#[test]
fn selftest_json_mode_keeps_stdout_a_single_parseable_document() {
    // The counterpart guarantee: moving the TEXT table to stdout must not have
    // leaked it into `--json`, whose stdout has to stay machine-readable.
    let (stdout, _stderr) = run_streams(&["selftest", "--json"]);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
    assert!(
        parsed.is_ok(),
        "`selftest --json` stdout must parse as one JSON document; got:\n{stdout}"
    );
    assert!(
        check_line_count(&stdout) == 0,
        "the human table must not appear in --json stdout:\n{stdout}"
    );
}

#[test]
fn diagnostics_text_report_carries_its_selftest_section_on_stdout() {
    // The aggregate command prints its other sections to stdout and invokes
    // `cmd_selftest`. With the table on stderr, `hse diagnostics > report.txt`
    // captured the self-test section's HEADER and none of its check lines — a
    // report that reads as complete while an entire section's body is missing.
    let (stdout, _stderr) = run_streams(&["diagnostics"]);
    assert!(
        stdout.contains("self-test"),
        "diagnostics stdout must contain the self-test section:\n{stdout}"
    );
    let check_lines = check_line_count(&stdout);
    assert!(
        check_lines >= 5,
        "diagnostics stdout must carry the self-test CHECK LINES, not just the \
         section header — found {check_lines}"
    );
}
