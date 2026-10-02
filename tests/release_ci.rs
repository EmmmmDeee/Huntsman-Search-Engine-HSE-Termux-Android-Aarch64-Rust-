//! Contract for the live release workflow. GitHub only runs workflows under the
//! root `.github/workflows/`; the copy under `legacy/` is inert. Deleting the
//! root file (f0a1c64) silently stopped every main-channel pre-release.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const RELEASE: &str = ".github/workflows/release.yml";
const SCAN: &str = ".github/scripts/scan-for-keys.sh";
const INSTALL: &str = ".github/scripts/install-termux.sh";

fn release() -> String {
    fs::read_to_string(RELEASE)
        .expect("the live release workflow must exist at the repository root")
}

/// The text of job `name`: from its `  name:` line to the next job key.
fn job(wf: &str, name: &str) -> String {
    let header = format!("  {name}:");
    let mut lines = wf.lines().skip_while(|l| *l != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("{RELEASE} must define job {name}"));
    let body: Vec<&str> = lines
        .take_while(|l| l.is_empty() || l.starts_with("   ") || l.starts_with("  #"))
        .collect();
    format!("{first}\n{}", body.join("\n"))
}

#[test]
fn main_pushes_publish_main_channel_pre_releases_only() {
    let wf = release();
    for required in [
        "branches:\n      - main",
        "workflow_dispatch:",
        "refs/heads/main",
        "main-${GITHUB_SHA:0:7}",
        "gh release create \"$TAG\"",
        "gh release create latest",
        "is NOT a pre-release; refusing",
        "Cannot run person lookups yet.",
        "queue: max",
        "ASSET: huntsman-recon-aarch64-linux-android",
        "usage: huntsman-recon \\[check",
        "dist/install-termux.sh",
    ] {
        assert!(wf.contains(required), "{RELEASE} must contain {required:?}");
    }
    assert_eq!(
        wf.matches("--prerelease --latest=false").count(),
        2,
        "both releases must be pre-releases that never become Latest"
    );
    for forbidden in [
        "tags:",
        "make_latest: true",
        "--latest=true",
        "--latest \\",
        "@master",
        "@main",
        "ASSET: hse",
        "dist/hse",
    ] {
        assert!(
            !wf.contains(forbidden),
            "{RELEASE} must not contain {forbidden:?}"
        );
    }
}

#[test]
fn rolling_latest_moves_only_behind_an_explicit_opt_in() {
    let wf = release();
    let step = wf
        .split("      - name: ")
        .find(|s| s.starts_with("Move the rolling `latest`"))
        .expect("latest step must exist");
    assert!(
        step.contains(
            "        if: vars.PROMOTE_RECON_TO_LATEST == 'true' && steps.existing.outputs.exists == 'false'\n"
        ),
        "moving `latest` must be gated on PROMOTE_RECON_TO_LATEST == 'true'"
    );
    for required in [
        "compare/${cur}...${GITHUB_SHA}",
        "ahead)",
        "identical | behind)",
        "never moving it backwards",
        "refusing to move latest",
    ] {
        assert!(
            step.contains(required),
            "`latest` must only move forward along main: missing {required:?}"
        );
    }
    assert_eq!(
        wf.matches("gh release delete").count(),
        1,
        "only the gated latest step may delete a release"
    );
    assert!(
        step.contains("gh release delete latest"),
        "the only delete must be in the gated latest step"
    );
    assert!(wf.contains("latest moved to this build without PROMOTE_RECON_TO_LATEST"));
}

#[test]
fn cargo_never_runs_with_a_write_token() {
    let wf = release();
    let build = job(&wf, "build");
    let publish = job(&wf, "publish");
    assert!(build.contains("cargo build"), "build job must build");
    assert!(
        build.contains("    permissions:\n      contents: read\n    env:"),
        "build job must be read-only"
    );
    assert!(build.contains("persist-credentials: false"));
    assert!(build.contains("checkout persisted git credentials"));
    for forbidden in ["write", "GH_TOKEN:", "github.token", "secrets."] {
        assert!(
            !build.contains(forbidden),
            "build job must not contain {forbidden:?}"
        );
    }
    assert!(publish.contains(
        "    permissions:\n      contents: write     # create the tags and pre-releases\n      id-token: write     # Sigstore-backed provenance\n      attestations: write # record the attestation\n"
    ));
    assert!(publish.contains(
        "    if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main' && needs.resolve.outputs.publish == 'true'\n"
    ));
    for forbidden in [
        "actions/checkout",
        "uses: ./",
        "cargo ",
        "bash .github/",
        "bash ./",
        "rust-toolchain",
    ] {
        assert!(
            !publish.contains(forbidden),
            "publish job must check out and run no repository code: found {forbidden:?}"
        );
    }
    // GH_TOKEN only on the steps that call the API, never job-wide.
    assert!(
        !publish
            .contains("\n    env:\n      TAG: ${{ needs.resolve.outputs.tag }}\n      GH_TOKEN"),
        "publish must not set GH_TOKEN at job level"
    );
    for line in publish.lines().filter(|l| l.contains("GH_TOKEN:")) {
        assert_eq!(
            line, "          GH_TOKEN: ${{ github.token }}",
            "GH_TOKEN must be step-scoped"
        );
    }
    for step in publish.split("      - name: ") {
        let calls_api = step.contains("gh api") || step.contains("gh release");
        assert_eq!(
            calls_api,
            step.contains("GH_TOKEN:"),
            "GH_TOKEN must be given exactly to the API-calling steps:\n{step}"
        );
    }
    // Only these jobs exist, and only `publish` asks for any write scope.
    assert_eq!(wf.matches(": write").count(), 3);
    assert_eq!(publish.matches(": write").count(), 3);
}

#[test]
fn publish_rechecks_the_build_jobs_digests_and_rescans_the_downloaded_bytes() {
    let wf = release();
    let build = job(&wf, "build");
    let publish = job(&wf, "publish");
    for required in [
        "asset_sha256: ${{ steps.digests.outputs.asset_sha256 }}",
        "dist_sha256: ${{ steps.digests.outputs.dist_sha256 }}",
        "actions/upload-artifact@",
    ] {
        assert!(
            build.contains(required),
            "build job must contain {required:?}"
        );
    }
    for required in [
        "ASSET_SHA256: ${{ needs.build.outputs.asset_sha256 }}",
        "DIST_SHA256: ${{ needs.build.outputs.dist_sha256 }}",
        "actions/download-artifact@",
        "recorded by the build job",
        "downloaded files differ from the ones the build job scanned",
        "sha256sum --strict -c",
        "bash \"$scanner\" dist",
    ] {
        assert!(
            publish.contains(required),
            "publish job must contain {required:?}"
        );
    }
    let rescan = publish.find("bash \"$scanner\" dist").unwrap();
    for later in ["actions/attest-build-provenance@", "gh release create"] {
        assert!(
            publish.find(later).unwrap() > rescan,
            "{later} must come after the re-scan"
        );
    }
}

#[test]
fn publish_scans_with_a_byte_identical_inlined_scanner() {
    let wf = release();
    let start = "          cat > \"$scanner\" <<'SCAN_FOR_KEYS'\n";
    let end = "\n          SCAN_FOR_KEYS\n";
    let from = wf.find(start).expect("publish must inline the scanner") + start.len();
    let to = from
        + wf[from..]
            .find(end)
            .expect("inlined scanner must be terminated");
    let inlined: String = wf[from..to]
        .lines()
        .map(|l| {
            assert!(
                l.is_empty() || l.starts_with("          "),
                "inlined scanner line is not indented: {l:?}"
            );
            l.get(10..).unwrap_or("")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let file = fs::read_to_string(SCAN).expect("key scanner must exist");
    assert_eq!(
        inlined, file,
        "the scanner inlined in {RELEASE} must be byte-identical to {SCAN}"
    );
    assert!(
        !file.contains("${{"),
        "{SCAN} must not contain an Actions expression"
    );
    assert_eq!(wf.matches("<<'SCAN_FOR_KEYS'").count(), 1);
}

#[test]
fn main_publishes_are_serialised_not_coalesced() {
    let wf = release();
    let publish = job(&wf, "publish");
    assert!(publish.contains(
        "    concurrency:\n      group: release-publish-main\n      cancel-in-progress: false\n      queue: max\n"
    ));
    assert_eq!(
        wf.lines().filter(|l| l.trim() == "queue: max").count(),
        1,
        "only the publish job queues"
    );
    // Main runs never share a workflow-level group, so none is replaced there.
    assert!(wf.contains(
        "  group: release-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}\n"
    ));
    assert!(wf.contains(
        "https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#concurrency"
    ));
    // Idempotent: an existing complete main-<sha7> at this commit is verified,
    // never replaced, and a tag at another commit is refused.
    for required in [
        "id: existing",
        "verifying it, not replacing it",
        "not ${GITHUB_SHA}; refusing",
        "is missing or has no digest",
        "if: steps.existing.outputs.exists == 'false'",
    ] {
        assert!(
            publish.contains(required),
            "publish job must contain {required:?}"
        );
    }
}

#[test]
fn post_publish_check_requires_a_matching_non_empty_digest() {
    let wf = release();
    let step = wf
        .split("      - name: ")
        .find(|s| s.starts_with("Verify published pre-releases"))
        .expect("verify step must exist");
    for required in [
        "[ -n \"$d\" ] || fail \"${t} has no digest for asset ${a}\"",
        "[[ \"$d\" =~ ^sha256:[0-9a-f]{64}$ ]]",
        "[ \"$d\" = \"$want\" ] || fail",
        "if length == 1 then (.[0].digest // \"\") else \"\" end",
    ] {
        assert!(
            step.contains(required),
            "verify step must contain {required:?}"
        );
    }
    assert!(
        !step.contains("if [ -n \"$got\" ]"),
        "a missing digest must never be skipped"
    );
}

#[test]
fn every_remote_action_is_pinned_to_a_full_commit_sha_with_a_version_comment() {
    let wf = release();
    let mut remote = 0;
    for line in wf
        .lines()
        .filter(|l| l.trim_start().starts_with("- uses: ") || l.trim_start().starts_with("uses: "))
    {
        let spec = line.split("uses: ").nth(1).unwrap();
        if spec.starts_with("./") {
            continue;
        }
        remote += 1;
        let (_, rest) = spec.split_once('@').expect("action must have a ref");
        let (sha, comment) = rest.split_once(" # ").expect("pin needs a version comment");
        assert!(
            sha.len() == 40
                && sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{line}: must pin a full commit SHA"
        );
        assert!(
            !comment.trim().is_empty(),
            "{line}: needs a version comment"
        );
    }
    assert!(
        remote >= 5,
        "expected the pinned remote actions, found {remote}"
    );
}

#[test]
fn publishing_requires_release_build_and_zero_finding_key_scan() {
    let wf = release();
    for required in [
        "HSE_RELEASE: \"1\"",
        "HUNTSMAN_HIBP_NO_EMBED: \"1\"",
        "hibp_embedded_key.txt",
        "bash .github/scripts/scan-for-keys.sh dist",
        "grep -qx \"result: PASS (0 findings)\" key-scan-report.txt",
        "dist/key-scan-report.txt",
        "has no digest for asset",
    ] {
        assert!(wf.contains(required), "{RELEASE} must contain {required:?}");
    }
    let install = fs::read_to_string(INSTALL).expect("Termux installer must exist");
    for required in [
        "CHANNEL=\"${HUNTSMAN_CHANNEL:-hse}\"",
        "TAG=\"${HSE_TAG:-main-7dca720}\"",
        "RECON_TAG_DEFAULT=\"@RECON_TAG@\"",
        "releases/download/${TAG}",
        "sha256sum -c",
        "$PREFIX/bin/$DEST_NAME",
    ] {
        assert!(
            install.contains(required),
            "{INSTALL} must contain {required:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Behavioural tests: run the real scanner on temporary fixtures. Every planted
// value is synthetic and assembled at runtime, so no key-shaped literal sits
// in the source tree.

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hse-release-ci-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Absolute path of `name` on PATH, if any.
fn tool(name: &str) -> Option<PathBuf> {
    let out = Command::new("bash")
        .args(["-c", &format!("command -v {name}")])
        .output()
        .ok()?;
    let path = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (out.status.success() && path.starts_with('/')).then(|| PathBuf::from(path))
}

/// The scanner needs `strings` and `python3`; CI runners have both. Elsewhere
/// the behavioural tests are skipped rather than run without them.
fn scanner_tools_present() -> bool {
    let present = tool("strings").is_some() && tool("python3").is_some();
    assert!(
        present || std::env::var_os("CI").is_none(),
        "CI must have strings and python3 for the scanner tests"
    );
    if !present {
        eprintln!("skipping: strings or python3 not installed");
    }
    present
}

fn run_scan(dir: &Path, path_env: Option<&Path>) -> (Option<i32>, String) {
    let bash = tool("bash").expect("bash must be available");
    let mut cmd = Command::new(bash);
    cmd.arg(SCAN).arg(dir);
    if let Some(p) = path_env {
        cmd.env("PATH", p);
    }
    let out = cmd.output().expect("bash must run");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code(), text)
}

fn scan(dir: &Path) -> (Option<i32>, String) {
    run_scan(dir, None)
}

fn fake(prefix: &str, unit: &str, n: usize) -> String {
    format!("{prefix}{}", unit.repeat(n))
}

/// A synthetic 32-lowercase-hex value (the HIBP key shape).
fn fake_hex32() -> String {
    fake("", "0a1b2c3d", 4)
}

/// A synthetic GitHub classic token shape.
fn fake_ghp() -> String {
    fake("ghp_", "Ab3", 13)
}

fn assert_redacted(text: &str, value: &str, ctx: &str) {
    assert!(
        !text.contains(value),
        "{ctx}: scanner output must not contain the planted value"
    );
    let half = &value[..value.len() / 2];
    assert!(
        !text.contains(half),
        "{ctx}: scanner output must not contain part of the planted value"
    );
}

fn clean_fixture(dir: &Path) {
    fs::write(
        dir.join("p.json"),
        format!(
            "{{\"commit\":\"{}\",\"sha256\":\"{}\",\"upper\":\"{}\"}}\n",
            "a1".repeat(20),
            "b2".repeat(32),
            "AB".repeat(16)
        ),
    )
    .unwrap();
    fs::write(
        dir.join("bin"),
        [
            b"\x00\x7fELF usage: huntsman-recon [check]\x00".as_slice(),
            // 31 and 33 hex: one short and one long of the key shape.
            fake("", "c", 31).as_bytes(),
            b"\x00\x01".as_slice(),
            fake("", "d", 33).as_bytes(),
            b"\x00".as_slice(),
        ]
        .concat(),
    )
    .unwrap();
}

#[test]
fn scanner_passes_clean_fixtures_with_no_findings() {
    if !scanner_tools_present() {
        return;
    }
    let clean = scratch("clean");
    clean_fixture(&clean);
    let (code, text) = scan(&clean);
    assert_eq!(code, Some(0), "clean fixtures must pass:\n{text}");
    assert!(text.contains("files scanned: 2"), "{text}");
    assert!(text.contains("key scan: 0 finding(s)"), "{text}");
    assert!(!text.contains("FINDING"), "{text}");
    let _ = fs::remove_dir_all(&clean);
}

#[test]
fn scanner_fails_on_planted_synthetic_keys_without_printing_them() {
    if !scanner_tools_present() {
        return;
    }
    let hex = fake_hex32();
    let ghp = fake_ghp();
    let cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "hex.bin",
            [b"\x00\x01 k=".as_slice(), hex.as_bytes(), b" \x00\xff"].concat(),
            "hibp-key-hex",
            &hex,
        ),
        (
            "bare-hex.bin",
            [b"\x00\x02".as_slice(), hex.as_bytes(), b"\x00\x03"].concat(),
            "hibp-key-hex",
            &hex,
        ),
        (
            "hex.json",
            format!("{{\"v\":\"{hex}\"}}\n").into_bytes(),
            "hibp-key-hex",
            &hex,
        ),
        (
            "hex.txt",
            format!("{hex}\n").into_bytes(),
            "hibp-key-hex",
            &hex,
        ),
        (
            "gh.bin",
            [b"\x00 t=".as_slice(), ghp.as_bytes(), b" \x00\xfe"].concat(),
            "github-token",
            &ghp,
        ),
        (
            "gh.txt",
            format!("token={ghp}\n").into_bytes(),
            "github-token",
            &ghp,
        ),
    ];
    for (file, bytes, rule, value) in cases {
        let dir = scratch(file);
        clean_fixture(&dir);
        fs::write(dir.join(file), &bytes).unwrap();
        let (code, text) = scan(&dir);
        assert_eq!(code, Some(1), "{file} must fail the scan:\n{text}");
        assert!(
            text.contains(&format!("rule={rule} (value withheld)")),
            "{file}: {text}"
        );
        assert!(text.contains("key scan: 1 finding(s)"), "{file}: {text}");
        assert_redacted(&text, value, file);
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn scanner_fails_closed_when_a_tool_is_missing() {
    if !scanner_tools_present() {
        return;
    }
    let needed = [
        "strings", "python3", "grep", "find", "sort", "cat", "mktemp", "rm",
    ];
    let fixture = scratch("tools-fixture");
    clean_fixture(&fixture);
    let ghp = fake_ghp();
    fs::write(
        fixture.join("gh.bin"),
        [b"\x00 t=".as_slice(), ghp.as_bytes(), b" \x00\xfe"].concat(),
    )
    .unwrap();
    for missing in [None, Some("strings"), Some("python3")] {
        let bin = scratch(&format!("path-{}", missing.unwrap_or("all")));
        for name in needed.iter().filter(|n| Some(**n) != missing) {
            let src = tool(name).unwrap_or_else(|| panic!("{name} must be installed"));
            std::os::unix::fs::symlink(src, bin.join(name)).unwrap();
        }
        let (code, text) = run_scan(&fixture, Some(&bin));
        assert_ne!(code, Some(0), "scan must not pass:\n{text}");
        assert_redacted(&text, &ghp, "restricted PATH");
        match missing {
            // Positive control: the restricted PATH is enough to find the token.
            None => assert!(
                text.contains("rule=github-token (value withheld)"),
                "{text}"
            ),
            Some(name) => assert!(
                text.contains(&format!("scanner dependency missing: {name}")),
                "missing {name} must fail closed:\n{text}"
            ),
        }
        let _ = fs::remove_dir_all(&bin);
    }
    let _ = fs::remove_dir_all(&fixture);
}

#[test]
fn scanner_fails_closed_on_a_missing_or_empty_path() {
    if !scanner_tools_present() {
        return;
    }
    let empty = scratch("empty");
    let (code, text) = scan(&empty);
    assert_eq!(code, Some(1), "an empty tree must not pass:\n{text}");
    assert!(text.contains("nothing scanned"), "{text}");
    let missing = empty.join("does-not-exist");
    let (code, text) = scan(&missing);
    assert_eq!(code, Some(1), "a missing path must not pass:\n{text}");
    assert!(text.contains("scan path does not exist"), "{text}");
    let _ = fs::remove_dir_all(&empty);
}

#[test]
fn an_existing_release_is_verified_by_publish_not_skipped_by_resolve() {
    let wf = release();
    let resolve = job(&wf, "resolve");
    let build = job(&wf, "build");
    for forbidden in [
        "gh api",
        "GH_TOKEN",
        "build=false",
        "publish=false\n            echo \"Release",
    ] {
        assert!(
            !resolve.contains(forbidden),
            "resolve must not skip an existing release: found {forbidden:?}"
        );
    }
    assert!(
        !build.contains("    if:"),
        "build must run on every main push so publish can verify or refuse an existing release"
    );
    assert!(!wf.contains("needs.resolve.outputs.build"));
    let publish = job(&wf, "publish");
    assert!(publish.contains("    if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main' && needs.resolve.outputs.publish == 'true'\n"));
    for required in [
        "not ${GITHUB_SHA}; refusing",
        "exists and is NOT a pre-release; refusing",
        "is missing or has no digest",
        "verifying it, not replacing it",
    ] {
        assert!(
            publish.contains(required),
            "publish must contain {required:?}"
        );
    }
}

#[test]
fn attestation_warning_does_not_promise_a_retry() {
    let wf = release();
    assert!(!wf.contains("Re-run to retry"));
    assert!(wf.contains("A re-run will not add it"));
}
