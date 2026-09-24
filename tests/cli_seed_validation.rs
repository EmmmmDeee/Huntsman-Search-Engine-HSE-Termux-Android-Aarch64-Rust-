//! CLI contract guards (spawn the real binary — the faithful test of the wiring
//! that a unit test can't reach):
//!   - seed validation: `hse scan` / `hse live` must reject reserved/placeholder
//!     targets at the boundary, so an "example anything" can never be dispatched.
//!   - `-o json` output discipline: stdout must be a single JSON document, with
//!     all human-readable progress/summary on stderr, so `| jq` works.
//!   - a settings file that does not parse stops `hse` and is kept.

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
