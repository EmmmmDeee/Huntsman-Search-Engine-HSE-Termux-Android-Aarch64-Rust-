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
        wf.lines()
            .filter(|l| l.trim_start().starts_with("gh release delete"))
            .count(),
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
    run_script(Path::new(SCAN), dir, path_env.map(Path::as_os_str))
}

fn run_script(
    script: &Path,
    dir: &Path,
    path_env: Option<&std::ffi::OsStr>,
) -> (Option<i32>, String) {
    let envs: Vec<(&str, &std::ffi::OsStr)> = path_env.map(|p| ("PATH", p)).into_iter().collect();
    run_script_with(script, dir, &envs)
}

fn run_script_with(
    script: &Path,
    dir: &Path,
    envs: &[(&str, &std::ffi::OsStr)],
) -> (Option<i32>, String) {
    let bash = tool("bash").expect("bash must be available");
    let mut cmd = Command::new(bash);
    cmd.arg(script).arg(dir);
    for (k, v) in envs {
        cmd.env(k, v);
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
    // The 00..ff hex byte table and a decimal digit-pair table, as std links
    // them into every Rust binary: long hex runs that are not keys.
    let hex_table: String = (0..=255u8).map(|b| format!("{b:02x}")).collect();
    let digit_table: String = (0..100).map(|n| format!("{n:02}")).collect();
    fs::write(
        dir.join("bin"),
        [
            b"\x00\x7fELF usage: huntsman-recon [check]\x00".as_slice(),
            // 31 hex is one short of the key shape; 40 (git SHA-1) and 64
            // (sha256) are the two allowed hex-run lengths.
            fake("", "c", 31).as_bytes(),
            b"\x00\x01".as_slice(),
            fake("", "d", 40).as_bytes(),
            b"\x00\x01".as_slice(),
            fake("", "e", 64).as_bytes(),
            b"\x00".as_slice(),
            hex_table.as_bytes(),
            b"\x00".as_slice(),
            digit_table.as_bytes(),
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
    assert_eq!(code, Some(2), "an empty tree must not pass:\n{text}");
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
fn attestation_is_a_required_step_before_publishing() {
    let wf = release();
    let publish = job(&wf, "publish");
    assert!(
        !wf.contains("continue-on-error"),
        "no release step may be optional, the attestation least of all"
    );
    assert!(!wf.contains("Warn when attestation failed"));
    let steps: Vec<&str> = publish.split("      - name: ").collect();
    let pos = |prefix: &str| {
        steps
            .iter()
            .position(|s| s.starts_with(prefix))
            .unwrap_or_else(|| panic!("publish must have a step {prefix:?}"))
    };
    let (attest, require, create) = (
        pos("Attest build provenance"),
        pos("Require a build provenance attestation"),
        pos("Publish pre-release"),
    );
    assert!(
        attest < require && require < create,
        "attest, then require, then publish"
    );
    assert!(steps[attest].contains("        if: steps.existing.outputs.exists == 'false'\n"));
    assert!(
        !steps[require].contains("        if:"),
        "the attestation requirement must run for new and existing releases"
    );
    for required in [
        "ATTESTATION_ID: ${{ steps.attest.outputs.attestation-id }}",
        "attestations/${d}",
    ] {
        assert!(steps[require].contains(required), "missing {required:?}");
    }
    // The publish job's permissions already allow attesting; nothing new.
    assert!(publish.contains("      attestations: write # record the attestation\n"));
}

/// One synthetic positive per pattern rule, assembled at runtime.
fn rule_fixtures() -> Vec<(&'static str, String)> {
    vec![
        ("openai-style-sk", format!("sk-{}", "Ab1_".repeat(6))),
        ("anthropic", format!("sk-ant-{}", "Zz9-".repeat(6))),
        ("google-api-key", format!("AIza{}", "Q7x-".repeat(9))),
        ("github-token", fake_ghp()),
        ("github-pat", format!("github_pat_{}", "11AB_".repeat(13))),
        ("slack-token", format!("xoxb-{}", "12ab-".repeat(4))),
        ("aws-access-key-id", format!("AKIA{}", "Q2W3E4R5T6Y7U8I9")),
        (
            "private-key-block",
            format!("-----BEGIN {} PRIVATE KEY-----", "EC"),
        ),
        ("bearer-token", format!("Bearer {}", "Ab3.".repeat(7))),
        ("hibp-key-hex", fake_hex32()),
        (
            "credential-assignment",
            format!("HIBP_API_KEY={}", "Zq8.".repeat(4)),
        ),
    ]
}

/// The rule names declared in the scanner's RULES array.
fn scanner_rule_names() -> Vec<String> {
    fs::read_to_string(SCAN)
        .expect("key scanner must exist")
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("$'"))
        .filter_map(|l| l.split_once("\\t").map(|(name, _)| name.to_owned()))
        .collect()
}

#[test]
fn every_scanner_rule_has_a_synthetic_positive_fixture() {
    let mut declared = scanner_rule_names();
    let mut covered: Vec<String> = rule_fixtures()
        .into_iter()
        .map(|(name, _)| name.to_owned())
        .collect();
    declared.sort();
    covered.sort();
    assert_eq!(declared.len(), 11, "unexpected rule count: {declared:?}");
    assert_eq!(
        declared, covered,
        "every rule in {SCAN} needs a behavioural fixture"
    );
}

#[test]
fn scanner_detects_every_rule_in_binaries_and_text_without_printing_values() {
    if !scanner_tools_present() {
        return;
    }
    for (rule, value) in rule_fixtures() {
        for (ext, bytes) in [
            (
                "bin",
                [b"\x00\x01 k=".as_slice(), value.as_bytes(), b" \x00\xff"].concat(),
            ),
            ("txt", format!("k = {value}\n").into_bytes()),
        ] {
            let dir = scratch(&format!("rule-{rule}-{ext}"));
            clean_fixture(&dir);
            let file = format!("planted.{ext}");
            fs::write(dir.join(&file), &bytes).unwrap();
            let (code, text) = scan(&dir);
            assert_eq!(code, Some(1), "{rule} ({ext}) must fail the scan:\n{text}");
            assert!(
                text.contains(&format!("rule={rule} (value withheld)")),
                "{rule} ({ext}) must be reported by its own rule:\n{text}"
            );
            assert_redacted(&text, &value, &format!("{rule} ({ext})"));
            let _ = fs::remove_dir_all(&dir);
        }
    }
}

#[test]
fn scanner_flags_a_high_entropy_string_in_text_without_printing_it() {
    if !scanner_tools_present() {
        return;
    }
    // 32 distinct base58 characters mixing upper, lower and digits: 5 bits/char.
    let alphabet: Vec<char> = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        .chars()
        .collect();
    let value: String = (0..32)
        .map(|i| alphabet[(i * 7) % alphabet.len()])
        .collect();
    let dir = scratch("entropy");
    clean_fixture(&dir);
    fs::write(dir.join("e.json"), format!("{{\"v\":\"{value}\"}}\n")).unwrap();
    let (code, text) = scan(&dir);
    assert_eq!(code, Some(1), "a high-entropy string must fail:\n{text}");
    assert!(
        text.contains("rule=high-entropy-string (value withheld)"),
        "{text}"
    );
    assert!(text.contains("key scan: 1 finding(s)"), "{text}");
    assert_redacted(&text, &value, "high-entropy");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// install-termux.sh: run it offline against a fake `curl` and `uname`.

fn write_exec(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Runs the installer for the recon channel with the given release assets.
/// Returns (exit code, output, `$PREFIX/bin` entries).
fn run_installer(name: &str, binary: &[u8], sha_line: &str) -> (Option<i32>, String, PathBuf) {
    run_installer_with(name, binary, sha_line, false)
}

/// As `run_installer`; with `dest_is_dir` the destination path is a directory.
fn run_installer_with(
    name: &str,
    binary: &[u8],
    sha_line: &str,
    dest_is_dir: bool,
) -> (Option<i32>, String, PathBuf) {
    let root = scratch(&format!("install-{name}"));
    let assets = root.join("assets");
    let fakes = root.join("fakes");
    let prefix = root.join("prefix");
    for d in [&assets, &fakes, &prefix.join("bin"), &root.join("tmp")] {
        fs::create_dir_all(d).unwrap();
    }
    let asset = "huntsman-recon-aarch64-linux-android";
    fs::write(assets.join(asset), binary).unwrap();
    fs::write(assets.join(format!("{asset}.sha256")), sha_line).unwrap();
    if dest_is_dir {
        fs::create_dir_all(prefix.join("bin/huntsman-recon")).unwrap();
    } else {
        fs::write(prefix.join("bin/huntsman-recon"), b"old build\n").unwrap();
    }
    write_exec(
        &fakes.join("curl"),
        "#!/usr/bin/env bash\nout=\"\"; url=\"\"\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -o) out=\"$2\"; shift 2 ;;\n    --proto) shift 2 ;;\n    -*) shift ;;\n    *) url=\"$1\"; shift ;;\n  esac\ndone\ncp \"$FAKE_ASSETS/${url##*/}\" \"$out\"\n",
    );
    write_exec(&fakes.join("uname"), "#!/usr/bin/env bash\necho aarch64\n");
    let path = format!(
        "{}:{}",
        fakes.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new(tool("bash").expect("bash must be available"))
        .arg(INSTALL)
        .env("PATH", path)
        .env("PREFIX", &prefix)
        .env("TMPDIR", root.join("tmp"))
        .env("FAKE_ASSETS", &assets)
        .env("HUNTSMAN_CHANNEL", "recon")
        .env("HUNTSMAN_RELEASE_TAG", "main-0a1b2c3")
        .output()
        .expect("bash must run");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code(), text, root)
}

fn sha256_hex(path: &Path) -> String {
    let out = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8(out.stdout).unwrap()[..64].to_owned()
}

fn bin_entries(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root.join("prefix/bin"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn installer_replaces_the_binary_atomically_and_only_after_verification() {
    let tools = ["sha256sum", "install", "mktemp", "mv", "cut", "cp"];
    if tools.iter().any(|t| tool(t).is_none()) {
        assert!(std::env::var_os("CI").is_none(), "CI must have coreutils");
        eprintln!("skipping: coreutils missing");
        return;
    }
    let asset = "huntsman-recon-aarch64-linux-android";
    let new_build = b"\x7fELF new recon build\n";
    let probe = scratch("install-probe");
    fs::write(probe.join("b"), new_build).unwrap();
    let good = format!("{}  {asset}\n", sha256_hex(&probe.join("b")));
    let _ = fs::remove_dir_all(&probe);

    // Verified: replaced in place, mode 0755, no staging file left behind.
    let (code, text, root) = run_installer("ok", new_build, &good);
    assert_eq!(code, Some(0), "{text}");
    let dest = root.join("prefix/bin/huntsman-recon");
    assert_eq!(fs::read(&dest).unwrap(), new_build);
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    assert_eq!(
        bin_entries(&root),
        ["huntsman-recon"],
        "no staging leftovers"
    );
    let _ = fs::remove_dir_all(&root);

    // Mismatch: the existing binary is untouched and nothing is staged.
    let bad = format!("{}  {asset}\n", "0".repeat(64));
    let (code, text, root) = run_installer("bad", new_build, &bad);
    assert_ne!(code, Some(0), "a sha256 mismatch must fail:\n{text}");
    assert_eq!(
        fs::read(root.join("prefix/bin/huntsman-recon")).unwrap(),
        b"old build\n"
    );
    assert_eq!(
        bin_entries(&root),
        ["huntsman-recon"],
        "no staging leftovers"
    );
    let _ = fs::remove_dir_all(&root);

    let src = fs::read_to_string(INSTALL).unwrap();
    for required in [
        "stage=\"$PREFIX/bin/.${DEST_NAME}.install.$$\"",
        "install -m 0755 \"$tmp/$ASSET\" \"$stage\"",
        "mv -fT \"$stage\" \"$dest\"",
    ] {
        assert!(
            src.contains(required),
            "{INSTALL} must contain {required:?}"
        );
    }
    assert!(
        !src.contains("install -m 0755 \"$tmp/$ASSET\" \"$PREFIX/bin/$DEST_NAME\""),
        "must not write straight onto the live binary"
    );
}

/// The scanner copy inlined in the publish job, de-indented.
fn inlined_scanner() -> String {
    let wf = release();
    let start = "          cat > \"$scanner\" <<'SCAN_FOR_KEYS'\n";
    let end = "\n          SCAN_FOR_KEYS\n";
    let from = wf.find(start).expect("publish must inline the scanner") + start.len();
    let to = from
        + wf[from..]
            .find(end)
            .expect("inlined scanner must be terminated");
    wf[from..to]
        .lines()
        .map(|l| l.get(10..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn both_scanner_copies_fail_closed_when_find_or_sort_fails_or_truncates() {
    if !scanner_tools_present() {
        return;
    }
    let real_sort = tool("sort").expect("sort must be installed");
    let real_find = tool("find").expect("find must be installed");
    let root = scratch("partial-list");
    // `a-clean.json` sorts first, so a one-entry prefix omits the planted file.
    let fixture = root.join("dist");
    fs::create_dir_all(&fixture).unwrap();
    fs::write(fixture.join("a-clean.json"), "{\"ok\":true}\n").unwrap();
    let ghp = fake_ghp();
    fs::write(
        fixture.join("z-secret.bin"),
        [b"\x00 t=".as_slice(), ghp.as_bytes(), b" \x00\xfe"].concat(),
    )
    .unwrap();
    let inline = root.join("inlined-scan-for-keys.sh");
    fs::write(&inline, inlined_scanner()).unwrap();
    let real_path = std::env::var("PATH").unwrap_or_default();
    let scripts = [PathBuf::from(SCAN), inline];

    // Positive control: with the real tools both copies find the planted token.
    for script in &scripts {
        let (code, text) = run_script(script, &fixture, None);
        assert_eq!(
            code,
            Some(1),
            "{}: control must find the token:\n{text}",
            script.display()
        );
        assert!(
            text.contains("rule=github-token (value withheld)"),
            "{text}"
        );
    }

    // Each fake prints only the first NUL-terminated entry of the real output.
    let cases = [
        (
            "sort",
            &real_sort,
            1,
            "sort failed; refusing to scan a partial file list",
        ),
        (
            "sort",
            &real_sort,
            0,
            "sort returned 1 of 2 files; refusing to scan a partial file list",
        ),
        ("find", &real_find, 1, "find failed on:"),
    ];
    for (name, real, exit, message) in cases {
        let fakes = root.join(format!("fake-{name}-{exit}"));
        fs::create_dir_all(&fakes).unwrap();
        write_exec(
            &fakes.join(name),
            &format!(
                "#!/usr/bin/env bash\n\"{}\" \"$@\" | head -z -n 1\nexit {exit}\n",
                real.display()
            ),
        );
        let path = std::ffi::OsString::from(format!("{}:{real_path}", fakes.display()));
        for script in &scripts {
            let ctx = format!("{} with fake {name} exiting {exit}", script.display());
            let (code, text) = run_script(script, &fixture, Some(&path));
            assert_eq!(code, Some(2), "{ctx} must fail closed with exit 2:\n{text}");
            assert!(
                text.contains(message),
                "{ctx}: expected {message:?}:\n{text}"
            );
            assert!(
                !text.contains("key scan: 0 finding(s)"),
                "{ctx} must not report a clean scan:\n{text}"
            );
            assert!(
                !text.contains("files scanned:"),
                "{ctx} must not scan a prefix:\n{text}"
            );
            assert_redacted(&text, &ghp, &ctx);
        }
    }
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Scanner hardening, follow-up to #672 (Security S1 and hex-run rule, FTBB
// N1-N7, REFACTOR R1). Every planted value is synthetic and built at runtime.

/// A random 32-lowercase-hex value, fresh per run, never a real key. It always
/// holds a letter, so it is never mistaken for a decimal lookup table.
fn random_hex32() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    loop {
        let words: Vec<u64> = (0..2)
            .map(|i| {
                let mut h = RandomState::new().build_hasher();
                h.write_u64(i);
                h.finish()
            })
            .collect();
        let hex = format!("{:016x}{:016x}", words[0], words[1]);
        if hex.bytes().any(|b| b.is_ascii_lowercase()) {
            return hex;
        }
    }
}

/// Fixture for the file-list tests: `a-clean.json` sorts before the planted
/// `z-secret.bin`. Returns (root, fixture dir, both scanner copies, token).
fn list_fixture(name: &str) -> (PathBuf, PathBuf, [PathBuf; 2], String) {
    let root = scratch(name);
    let fixture = root.join("dist");
    fs::create_dir_all(&fixture).unwrap();
    fs::write(fixture.join("a-clean.json"), "{\"ok\":true}\n").unwrap();
    let ghp = fake_ghp();
    fs::write(
        fixture.join("z-secret.bin"),
        [b"\x00 t=".as_slice(), ghp.as_bytes(), b" \x00\xfe"].concat(),
    )
    .unwrap();
    let inline = root.join("inlined-scan-for-keys.sh");
    fs::write(&inline, inlined_scanner()).unwrap();
    (root, fixture, [PathBuf::from(SCAN), inline], ghp)
}

fn path_with(fakes: &Path) -> std::ffi::OsString {
    std::ffi::OsString::from(format!(
        "{}:{}",
        fakes.display(),
        std::env::var("PATH").unwrap_or_default()
    ))
}

/// Security S1: a `sort` that keeps the count but swaps one name for a
/// duplicate of another must not shorten the scan.
#[test]
fn both_scanner_copies_refuse_a_sort_that_swaps_a_name_for_a_duplicate() {
    if !scanner_tools_present() {
        return;
    }
    let real_sort = tool("sort").expect("sort must be installed");
    let (root, fixture, scripts, ghp) = list_fixture("swap-sort");
    let fakes = root.join("fakes");
    fs::create_dir_all(&fakes).unwrap();
    write_exec(
        &fakes.join("sort"),
        &format!(
            "#!/usr/bin/env bash\nmapfile -d '' -t l < <(\"{}\" \"$@\")\nl[${{#l[@]}}-1]=${{l[0]}}\nprintf '%s\\0' \"${{l[@]}}\"\n",
            real_sort.display()
        ),
    );
    let path = path_with(&fakes);
    for script in &scripts {
        let ctx = format!("{} with a name-swapping sort", script.display());
        let (code, text) = run_script(script, &fixture, Some(&path));
        assert_eq!(code, Some(2), "{ctx} must fail closed with exit 2:\n{text}");
        assert!(
            text.contains(
                "sort dropped or rewrote a listed file; refusing to scan a tampered file list"
            ),
            "{ctx}:\n{text}"
        );
        assert!(
            !text.contains("files scanned:"),
            "{ctx} must not scan:\n{text}"
        );
        assert_redacted(&text, &ghp, &ctx);
    }
    let _ = fs::remove_dir_all(&root);
}

/// FTBB N5: the scan loop runs over the checked array. A loop that re-reads
/// `sort` (process substitution or pipe) would scan a second, unchecked list;
/// this sort is real on its first call and truncates on every later one.
#[test]
fn both_scanner_copies_scan_the_checked_list_not_a_second_sort() {
    if !scanner_tools_present() {
        return;
    }
    let real_sort = tool("sort").expect("sort must be installed");
    let (root, fixture, scripts, ghp) = list_fixture("stateful-sort");
    let fakes = root.join("fakes");
    fs::create_dir_all(&fakes).unwrap();
    let count = root.join("sort-calls");
    write_exec(
        &fakes.join("sort"),
        &format!(
            "#!/usr/bin/env bash\nn=$(( $(cat \"{c}\" 2>/dev/null || echo 0) + 1 ))\necho \"$n\" > \"{c}\"\nif [ \"$n\" -eq 1 ]; then exec \"{s}\" \"$@\"; fi\n\"{s}\" \"$@\" | head -z -n 1\n",
            c = count.display(),
            s = real_sort.display()
        ),
    );
    let path = path_with(&fakes);
    for script in &scripts {
        let _ = fs::remove_file(&count);
        let ctx = format!("{} with a stateful sort", script.display());
        let (code, text) = run_script(script, &fixture, Some(&path));
        assert_eq!(code, Some(1), "{ctx} must find the token:\n{text}");
        assert!(
            text.contains("rule=github-token (value withheld)"),
            "{ctx}:\n{text}"
        );
        assert!(text.contains("files scanned: 2"), "{ctx}:\n{text}");
        assert_eq!(
            fs::read_to_string(&count).unwrap().trim(),
            "1",
            "{ctx}: sort must run exactly once"
        );
        assert_redacted(&text, &ghp, &ctx);
    }
    let src = fs::read_to_string(SCAN).unwrap();
    assert!(src.contains("for f in \"${files[@]}\"; do\n  scanned=$((scanned + 1))"));
    for forbidden in ["< <(sort", "< <(find", "sort -z \"$list\" |", "| while"] {
        assert!(
            !src.contains(forbidden),
            "{SCAN} must not contain {forbidden:?}"
        );
    }
    let _ = fs::remove_dir_all(&root);
}

/// Security's hex-run rule: any lowercase hex run of 32+ characters whose
/// length is not exactly 40 or 64 is a finding, so a key packed right after
/// "password" (which ends in the hex letter `d`) is caught.
#[test]
fn hex_run_rule_catches_a_key_packed_against_other_hex() {
    if !scanner_tools_present() {
        return;
    }
    let hex = random_hex32();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "password.bin",
            [
                b"\x00\x01password".as_slice(),
                hex.as_bytes(),
                b"ZZZ\x00\x02",
            ]
            .concat(),
        ),
        ("password.txt", format!("password{hex}\n").into_bytes()),
        (
            "hex-after.bin",
            [b"\x00\x01".as_slice(), hex.as_bytes(), b"cafe\x00"].concat(),
        ),
        ("run48.txt", format!("v={hex}{}\n", &hex[..16]).into_bytes()),
        ("run128.txt", format!("v={}\n", hex.repeat(4)).into_bytes()),
    ];
    for (file, bytes) in cases {
        let dir = scratch(&format!("hexrun-{file}"));
        clean_fixture(&dir);
        fs::write(dir.join(file), &bytes).unwrap();
        let (code, text) = scan(&dir);
        assert_eq!(code, Some(1), "{file} must fail the scan:\n{text}");
        assert!(
            text.contains(&format!(
                "FINDING file={}/{file} rule=hibp-key-hex (value withheld)",
                dir.display()
            )),
            "{file}:\n{text}"
        );
        assert!(text.contains("key scan: 1 finding(s)"), "{file}:\n{text}");
        assert_redacted(&text, &hex, file);
        let _ = fs::remove_dir_all(&dir);
    }
}

/// FTBB N1: matching is byte-wise even when the caller runs a UTF-8 locale,
/// where a bracket expression does not match an invalid byte such as \xff.
#[test]
fn scanner_matches_byte_wise_under_a_utf8_locale() {
    if !scanner_tools_present() {
        return;
    }
    let hex = fake_hex32();
    let sk = format!("sk-{}", "Ab1_".repeat(6));
    let cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "hex-ff.txt",
            [b"k=".as_slice(), hex.as_bytes(), b"\xff\n"].concat(),
            "hibp-key-hex",
            &hex,
        ),
        (
            "ff-sk.txt",
            [b"x\xff".as_slice(), sk.as_bytes(), b"\n"].concat(),
            "openai-style-sk",
            &sk,
        ),
    ];
    let utf8 = std::ffi::OsStr::new("C.UTF-8");
    for (file, bytes, rule, value) in cases {
        let dir = scratch(&format!("locale-{file}"));
        clean_fixture(&dir);
        fs::write(dir.join(file), &bytes).unwrap();
        let (code, text) =
            run_script_with(Path::new(SCAN), &dir, &[("LC_ALL", utf8), ("LANG", utf8)]);
        assert_eq!(
            code,
            Some(1),
            "{file} under C.UTF-8 must fail the scan:\n{text}"
        );
        assert!(
            text.contains(&format!("rule={rule} (value withheld)")),
            "{file}:\n{text}"
        );
        assert_redacted(&text, value, file);
        let _ = fs::remove_dir_all(&dir);
    }
    assert!(
        fs::read_to_string(SCAN)
            .unwrap()
            .contains("\nexport LC_ALL=C\n")
    );
}

/// FTBB N7 / REFACTOR R2: `find -type f` does not list symlinks, so a
/// symlink in the artifact would be skipped unscanned. It is refused.
#[test]
fn scanner_refuses_a_symlink_instead_of_skipping_it() {
    if !scanner_tools_present() {
        return;
    }
    let root = scratch("symlink");
    let dir = root.join("dist");
    fs::create_dir_all(&dir).unwrap();
    clean_fixture(&dir);
    let ghp = fake_ghp();
    let outside = root.join("outside.bin");
    fs::write(
        &outside,
        [b"\x00 t=".as_slice(), ghp.as_bytes(), b" \x00"].concat(),
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("link.bin")).unwrap();
    let inline = root.join("inlined-scan-for-keys.sh");
    fs::write(&inline, inlined_scanner()).unwrap();
    for script in [PathBuf::from(SCAN), inline] {
        let ctx = format!("{} with a symlink", script.display());
        let (code, text) = run_script(&script, &dir, None);
        assert_eq!(code, Some(2), "{ctx} must fail closed with exit 2:\n{text}");
        assert!(
            text.contains("1 non-regular entries under")
                && text.contains("link.bin::not a regular file"),
            "{ctx}:\n{text}"
        );
        assert!(
            !text.contains("files scanned:"),
            "{ctx} must not scan:\n{text}"
        );
        assert_redacted(&text, &ghp, &ctx);
    }
    let _ = fs::remove_dir_all(&root);
}

/// UTF-16LE little-endian encoding of `s` (ASCII only).
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// REFACTOR R1 (BLE #55): binaries also get a UTF-16LE `strings` pass, so a
/// wide-char literal holding a key is not invisible.
#[test]
fn scanner_reads_utf16le_strings_in_binaries() {
    if !scanner_tools_present() {
        return;
    }
    for (rule, value) in [
        ("github-token", fake_ghp()),
        ("hibp-key-hex", random_hex32()),
    ] {
        let dir = scratch(&format!("utf16-{rule}"));
        clean_fixture(&dir);
        let bytes = [
            b"\x7fELF\x00\x01\x02".as_slice(),
            &utf16le(&format!("key={value};")),
            b"\x00\x00\x03",
        ]
        .concat();
        fs::write(dir.join("wide.bin"), &bytes).unwrap();
        let (code, text) = scan(&dir);
        assert_eq!(code, Some(1), "UTF-16LE {rule} must fail the scan:\n{text}");
        assert!(
            text.contains(&format!("wide.bin rule={rule} (value withheld)")),
            "UTF-16LE {rule}:\n{text}"
        );
        assert_redacted(&text, &value, rule);
        let _ = fs::remove_dir_all(&dir);
    }
    assert!(fs::read_to_string(SCAN)
        .unwrap()
        .contains("wide=$(strings -a -e l -n 8 \"$f\") || { echo \"::error::strings -e l failed on $f\"; exit 1; }"));
}

/// FTBB N6: if the destination is a directory, `mv -f` would move the binary
/// into it and report success. `mv -fT` refuses.
#[test]
fn installer_refuses_a_directory_at_the_destination() {
    let tools = ["sha256sum", "install", "mktemp", "mv", "cut", "cp"];
    if tools.iter().any(|t| tool(t).is_none()) {
        assert!(std::env::var_os("CI").is_none(), "CI must have coreutils");
        return;
    }
    let asset = "huntsman-recon-aarch64-linux-android";
    let new_build = b"\x7fELF new recon build\n";
    let probe = scratch("install-dir-probe");
    fs::write(probe.join("b"), new_build).unwrap();
    let good = format!("{}  {asset}\n", sha256_hex(&probe.join("b")));
    let _ = fs::remove_dir_all(&probe);
    let (code, text, root) = run_installer_with("dest-dir", new_build, &good, true);
    assert_ne!(
        code,
        Some(0),
        "a directory at the destination must fail:\n{text}"
    );
    assert!(!text.contains("Installed"), "{text}");
    assert!(text.contains("could not move"), "{text}");
    let dest = root.join("prefix/bin/huntsman-recon");
    assert!(dest.is_dir());
    assert_eq!(
        fs::read_dir(&dest).unwrap().count(),
        0,
        "nothing moved into it"
    );
    assert_eq!(
        bin_entries(&root),
        ["huntsman-recon"],
        "no staging leftovers"
    );
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Publish job: run the extracted steps against a fake `gh` (FTBB N2, N3, N4).

/// The `run: |` script of the step whose name starts with `prefix`, de-indented.
fn step_script(prefix: &str) -> String {
    let wf = release();
    let step = wf
        .split("      - name: ")
        .find(|s| s.starts_with(prefix))
        .unwrap_or_else(|| panic!("{RELEASE} must have a step {prefix:?}"));
    let marker = "        run: |\n";
    let from = step.find(marker).expect("step must have a run script") + marker.len();
    let script = step[from..]
        .lines()
        .take_while(|l| l.is_empty() || l.starts_with("          "))
        .map(|l| l.get(10..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert!(
        !script.contains("${{"),
        "{prefix}: script must take inputs from env"
    );
    script
}

const FAKE_GH: &str = r#"#!/usr/bin/env bash
# Fake `gh api PATH [--jq EXPR]`: answers from $FAKE_GH/<key>.json, where key
# is PATH without repos/<repo>/ and with / as _. <key>.status overrides the
# HTTP status; a missing fixture is a 404.
[ "${1:-}" = api ] || { echo "fake gh: unexpected: $*" >&2; exit 99; }
shift
path="" jq=""
while [ $# -gt 0 ]; do
  case "$1" in
    --jq) jq="$2"; shift 2 ;;
    -*) echo "fake gh: unexpected flag $1" >&2; exit 99 ;;
    *) path="$1"; shift ;;
  esac
done
key="${path#repos/"$GITHUB_REPOSITORY"/}"
key="${key//\//_}"
echo "$path" >> "$FAKE_GH/calls"
status=404
body='{"message":"Not Found"}'
if [ -f "$FAKE_GH/$key.json" ]; then status=200; body="$(cat "$FAKE_GH/$key.json")"; fi
if [ -f "$FAKE_GH/$key.status" ]; then status="$(cat "$FAKE_GH/$key.status")"; fi
if [ "$status" != 200 ]; then printf '%s' "$body"; echo "gh: Fake (HTTP $status)" >&2; exit 1; fi
if [ -n "$jq" ]; then jq -r "$jq" <<<"$body"; else printf '%s\n' "$body"; fi
"#;

const STEP_TAG: &str = "main-0a1b2c3";
const STEP_ASSET: &str = "huntsman-recon-aarch64-linux-android";

fn step_sha() -> String {
    format!("0a1b2c3{}", "d".repeat(33))
}

fn digest(c: &str) -> String {
    format!("sha256:{}", c.repeat(64))
}

fn release_json(prerelease: bool, assets: &[(String, Option<String>)]) -> String {
    let assets: Vec<String> = assets
        .iter()
        .map(|(n, d)| match d {
            Some(d) => format!("{{\"name\":\"{n}\",\"digest\":\"{d}\"}}"),
            None => format!("{{\"name\":\"{n}\",\"digest\":null}}"),
        })
        .collect();
    format!(
        "{{\"prerelease\":{prerelease},\"draft\":false,\"assets\":[{}]}}",
        assets.join(",")
    )
}

fn complete_assets() -> Vec<(String, Option<String>)> {
    [
        STEP_ASSET.to_owned(),
        format!("{STEP_ASSET}.sha256"),
        format!("{STEP_ASSET}.provenance.json"),
        "key-scan-report.txt".to_owned(),
        "install-termux.sh".to_owned(),
    ]
    .into_iter()
    .zip(["a", "b", "c", "e", "f"])
    .map(|(n, c)| (n, Some(digest(c))))
    .collect()
}

struct StepRun {
    code: Option<i32>,
    text: String,
    output: String,
}

/// Runs `script` with the fake `gh`; `fixtures` are (key, status, body).
fn run_step(
    name: &str,
    script: &str,
    fixtures: &[(&str, u16, String)],
    envs: &[(&str, &str)],
) -> StepRun {
    let root = scratch(&format!("step-{name}"));
    let (fakes, data, tmp) = (root.join("fakes"), root.join("gh"), root.join("tmp"));
    for d in [&fakes, &data, &tmp] {
        fs::create_dir_all(d).unwrap();
    }
    write_exec(&fakes.join("gh"), FAKE_GH);
    for (key, status, body) in fixtures {
        fs::write(data.join(format!("{key}.json")), body).unwrap();
        if *status != 200 {
            fs::write(data.join(format!("{key}.status")), status.to_string()).unwrap();
        }
    }
    let file = root.join("step.sh");
    fs::write(&file, script).unwrap();
    let out_file = root.join("output");
    fs::write(&out_file, "").unwrap();
    let mut cmd = Command::new(tool("bash").expect("bash must be available"));
    cmd.arg(&file)
        .env("PATH", path_with(&fakes))
        .env("FAKE_GH", &data)
        .env("GITHUB_REPOSITORY", "owner/repo")
        .env("GITHUB_SHA", step_sha())
        .env("TAG", STEP_TAG)
        .env("ASSET", STEP_ASSET)
        .env("GITHUB_OUTPUT", &out_file)
        .env("GITHUB_STEP_SUMMARY", root.join("summary"))
        .env("RUNNER_TEMP", &tmp);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("bash must run");
    let run = StepRun {
        code: out.status.code(),
        text: String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr),
        output: fs::read_to_string(&out_file).unwrap(),
    };
    let _ = fs::remove_dir_all(&root);
    run
}

fn jq_present() -> bool {
    let present = tool("jq").is_some();
    assert!(
        present || std::env::var_os("CI").is_none(),
        "CI must have jq"
    );
    present
}

#[test]
fn existing_release_check_refuses_each_case_by_exit_code_and_marker() {
    if !jq_present() {
        return;
    }
    let script = step_script("Check for an existing");
    let ref_key = format!("git_ref_tags_{STEP_TAG}");
    let rel_key = format!("releases_tags_{STEP_TAG}");
    let tag_at = |ty: &str, sha: &str| {
        (
            ref_key.as_str(),
            200,
            format!("{{\"object\":{{\"type\":\"{ty}\",\"sha\":\"{sha}\"}}}}"),
        )
    };
    let here = tag_at("commit", &step_sha());
    let rel = |pre: bool, assets: Vec<(String, Option<String>)>| {
        (rel_key.as_str(), 200, release_json(pre, &assets))
    };
    let mut missing = complete_assets();
    missing.pop();
    let mut null_digest = complete_assets();
    null_digest[1].1 = None;
    let mut duplicate = complete_assets();
    duplicate.push(duplicate[0].clone());
    // (case, fixtures, exit code, marker or exists= line)
    let cases: Vec<(&str, Vec<(&str, u16, String)>, i32, &str)> = vec![
        ("absent", vec![], 0, "exists=false"),
        (
            "complete",
            vec![here.clone(), rel(true, complete_assets())],
            0,
            "exists=true",
        ),
        (
            "ref-502",
            vec![(ref_key.as_str(), 502, "{}".to_owned())],
            15,
            "[refuse:ref-lookup-failed]",
        ),
        (
            "other-commit",
            vec![
                tag_at("commit", &"9".repeat(40)),
                rel(true, complete_assets()),
            ],
            11,
            "[refuse:tag-elsewhere]",
        ),
        (
            "annotated",
            vec![tag_at("tag", &step_sha()), rel(true, complete_assets())],
            11,
            "[refuse:tag-elsewhere]",
        ),
        (
            "no-release",
            vec![here.clone()],
            12,
            "[refuse:tag-without-release]",
        ),
        (
            "not-prerelease",
            vec![here.clone(), rel(false, complete_assets())],
            13,
            "[refuse:not-prerelease]",
        ),
        (
            "asset-missing",
            vec![here.clone(), rel(true, missing)],
            14,
            "[refuse:asset-incomplete]",
        ),
        (
            "null-digest",
            vec![here.clone(), rel(true, null_digest)],
            14,
            "[refuse:asset-incomplete]",
        ),
        (
            "duplicate",
            vec![here.clone(), rel(true, duplicate)],
            14,
            "[refuse:asset-incomplete]",
        ),
    ];
    for (case, fixtures, want, marker) in cases {
        let run = run_step(&format!("existing-{case}"), &script, &fixtures, &[]);
        assert_eq!(run.code, Some(want), "{case}:\n{}", run.text);
        if want == 0 {
            assert_eq!(run.output, format!("{marker}\n"), "{case}:\n{}", run.text);
            assert!(!run.text.contains("[refuse:"), "{case}:\n{}", run.text);
        } else {
            assert!(
                run.text.contains(&format!("::error::{marker} ")),
                "{case}:\n{}",
                run.text
            );
            assert_eq!(run.output, "", "{case}: a refusal must not set exists");
        }
        if case == "asset-missing" {
            assert!(
                run.text
                    .contains(&format!("gh release delete {STEP_TAG} --cleanup-tag")),
                "{case}: the remedy must delete the tag too:\n{}",
                run.text
            );
        }
    }
}

#[test]
fn attestation_requirement_refuses_each_case_by_exit_code_and_marker() {
    if !jq_present() {
        return;
    }
    let script = step_script("Require a build provenance attestation");
    let rel_key = format!("releases_tags_{STEP_TAG}");
    let att_key = format!("attestations_{}", digest("a"));
    let rel = (
        rel_key.as_str(),
        200,
        release_json(true, &complete_assets()),
    );
    let mut no_digest = complete_assets();
    no_digest[0].1 = None;
    let att = |status: u16, body: &str| (att_key.as_str(), status, body.to_owned());
    // (case, EXISTS, ATTESTATION_ID, fixtures, exit code, marker)
    let cases: Vec<(&str, &str, &str, Vec<(&str, u16, String)>, i32, &str)> = vec![
        (
            "new-attested",
            "false",
            "52558529",
            vec![],
            0,
            "attestation 52558529",
        ),
        (
            "new-no-id",
            "false",
            "",
            vec![],
            21,
            "[refuse:no-attestation-id]",
        ),
        (
            "old-attested",
            "true",
            "",
            vec![rel.clone(), att(200, "{\"attestations\":[{}]}")],
            0,
            "1 build provenance attestation(s)",
        ),
        (
            "old-none-404",
            "true",
            "",
            vec![rel.clone(), att(404, "{}")],
            24,
            "[refuse:unattested-release]",
        ),
        (
            "old-none-empty",
            "true",
            "",
            vec![rel.clone(), att(200, "{\"attestations\":[]}")],
            24,
            "[refuse:unattested-release]",
        ),
        (
            "old-lookup-502",
            "true",
            "",
            vec![rel.clone(), att(502, "{}")],
            23,
            "[refuse:attestation-lookup-failed]",
        ),
        (
            "old-no-digest",
            "true",
            "",
            vec![(rel_key.as_str(), 200, release_json(true, &no_digest))],
            22,
            "[refuse:no-asset-digest]",
        ),
        ("no-check", "", "", vec![], 25, "[refuse:no-existing-check]"),
    ];
    for (case, exists, id, fixtures, want, marker) in cases {
        let envs = [
            ("EXISTS", exists),
            ("ATTESTATION_ID", id),
            ("ATTESTATION_URL", "https://example.invalid/attestations/1"),
        ];
        let run = run_step(&format!("attest-{case}"), &script, &fixtures, &envs);
        assert_eq!(run.code, Some(want), "{case}:\n{}", run.text);
        assert!(
            run.text.contains(marker),
            "{case}: expected {marker:?}:\n{}",
            run.text
        );
        if want != 0 {
            assert!(
                run.text.contains(&format!("::error::{marker} ")),
                "{case}:\n{}",
                run.text
            );
        }
        if case.starts_with("old-none") {
            assert!(
                run.text
                    .contains(&format!("gh release delete {STEP_TAG} --cleanup-tag")),
                "{case}: the remedy must delete the tag too:\n{}",
                run.text
            );
        }
    }
}

/// FTBB N4: every step that writes a release, a tag or an attestation runs
/// only when no complete release exists at this commit.
#[test]
fn every_publishing_write_is_gated_on_no_existing_release() {
    let wf = release();
    let publish = job(&wf, "publish");
    let writes = [
        "uses: actions/attest-build-provenance@",
        "gh release create",
        "gh release delete",
        "gh api -X DELETE",
        "gh release upload",
        "gh release edit",
    ];
    let mut gated = 0;
    for step in publish.split("      - name: ").skip(1) {
        let writes_here = step
            .lines()
            .any(|l| writes.iter().any(|w| l.trim_start().starts_with(w)));
        if !writes_here {
            continue;
        }
        let cond = step
            .lines()
            .find(|l| l.starts_with("        if: "))
            .unwrap_or_else(|| panic!("a writing step must have an if:\n{step}"));
        assert!(
            cond.contains("steps.existing.outputs.exists == 'false'"),
            "a writing step must be gated on exists == 'false':\n{step}"
        );
        gated += 1;
    }
    assert_eq!(gated, 3, "attest, publish and the opt-in latest move");
}
