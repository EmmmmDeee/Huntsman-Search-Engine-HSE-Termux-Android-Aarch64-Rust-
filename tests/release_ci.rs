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
        "In-progress replacement with rebuilt lookup paths.",
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
fn release_publish_requires_shared_quality_gate() {
    let wf = release();
    let quality_msrv = job(&wf, "quality-msrv");
    let quality = job(&wf, "quality");
    let build = job(&wf, "build");
    let publish = job(&wf, "publish");

    assert!(
        quality_msrv.contains("toolchain: \"1.87\"")
            && quality_msrv.contains("bash scripts/repair-gate.sh msrv"),
        "release must independently validate the repository MSRV before build/publish"
    );

    for required in [
        "bash scripts/repair-gate.sh full",
        "docker build --pull -f Dockerfile -t huntsman-recon:railway .",
        "bash scripts/railway-live-acceptance.sh",
        "persist-credentials: false",
    ] {
        assert!(
            quality.contains(required),
            "release quality job must contain {required:?}"
        );
    }
    assert!(
        build.contains("needs: [resolve, quality-msrv, quality]"),
        "release build must not run before stable and MSRV quality acceptance pass"
    );
    assert!(
        publish.contains("needs: [resolve, quality-msrv, quality, build]"),
        "release publish must depend on stable/MSRV quality and the verified build"
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
    let bash = tool("bash").expect("bash must be available");
    let mut cmd = Command::new(bash);
    cmd.arg(script).arg(dir);
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
        "releases/tags/",
        "git/ref/tags/",
        "build=false",
        "publish=false\n            echo \"Release",
    ] {
        assert!(
            !resolve.contains(forbidden),
            "resolve must not skip an existing release: found {forbidden:?}"
        );
    }
    assert!(
        resolve.contains("commits/${GITHUB_SHA}/pulls")
            && resolve.contains("GH_TOKEN: ${{ github.token }}"),
        "resolve may use the API only to prove merged-PR origin"
    );
    assert!(
        !build.contains("    if:"),
        "build must run whenever the path-scoped release workflow is triggered so publish can verify or refuse an existing release"
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
fn scanner_detects_each_rule_on_supported_artifact_kinds_without_printing_values() {
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
            // A generic Bearer prefix is deliberately text-only. Optimized
            // binaries may coalesce adjacent static strings into one printable
            // run, so applying this generic rule to `strings` output creates
            // false positives. Provider-specific signatures remain binary-scanned.
            if rule == "bearer-token" && ext == "bin" {
                continue;
            }
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
fn scanner_ignores_linker_coalesced_generic_bearer_run_in_binary() {
    if !scanner_tools_present() {
        return;
    }
    let dir = scratch("binary-bearer-literal");
    clean_fixture(&dir);
    fs::write(
        dir.join("linked.bin"),
        [
            b"\x00\x01Bearer ".as_slice(),
            b"compiled_runtime_label_for_authorization_header".as_slice(),
            b"\x00\xff".as_slice(),
        ]
        .concat(),
    )
    .unwrap();
    let (code, text) = scan(&dir);
    assert_eq!(
        code,
        Some(0),
        "generic binary bearer text must not fail:\n{text}"
    );
    assert!(text.contains("key scan: 0 finding(s)"), "{text}");
    assert!(!text.contains("rule=bearer-token"), "{text}");
    let _ = fs::remove_dir_all(&dir);
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
    fs::write(prefix.join("bin/huntsman-recon"), b"old build\n").unwrap();
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

const GOOD_RECON_FIXTURE: &[u8] = br#"#!/bin/sh
case "$1" in
  check) mkdir -p var; printf 'fixture-ledger\n' > var/ledger.json ;;
  verify) [ "$2" = var/ledger.json ] && [ -f "$2" ] ;;
  *) exit 64 ;;
esac
"#;

fn installer_tools_present() -> bool {
    let tools = [
        "sha256sum",
        "install",
        "mktemp",
        "mv",
        "cut",
        "cmp",
        "cp",
        "timeout",
    ];
    let present = tools.iter().all(|tool_name| tool(tool_name).is_some());
    assert!(
        present || std::env::var_os("CI").is_none(),
        "CI must have installer coreutils"
    );
    present
}

fn installer_sha_line(tag: &str, bytes: &[u8]) -> String {
    let asset = "huntsman-recon-aarch64-linux-android";
    let probe = scratch(tag);
    fs::write(probe.join("b"), bytes).unwrap();
    let line = format!("{}  {asset}\n", sha256_hex(&probe.join("b")));
    let _ = fs::remove_dir_all(&probe);
    line
}

fn assert_live_binary_only(root: &Path) {
    assert_eq!(
        bin_entries(root),
        ["huntsman-recon"],
        "installer must leave no staging entries"
    );
}

#[test]
fn installer_replaces_the_binary_atomically_and_only_after_verification() {
    if !installer_tools_present() {
        return;
    }
    let good = installer_sha_line("install-probe", GOOD_RECON_FIXTURE);
    let (code, text, root) = run_installer("ok", GOOD_RECON_FIXTURE, &good);
    assert_eq!(code, Some(0), "{text}");
    let dest = root.join("prefix/bin/huntsman-recon");
    assert_eq!(fs::read(&dest).unwrap(), GOOD_RECON_FIXTURE);
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    assert_live_binary_only(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn installer_checksum_failure_preserves_existing_binary() {
    if !installer_tools_present() {
        return;
    }
    let asset = "huntsman-recon-aarch64-linux-android";
    let bad = format!("{}  {asset}\n", "0".repeat(64));
    let (code, text, root) = run_installer("bad", GOOD_RECON_FIXTURE, &bad);
    assert_ne!(code, Some(0), "a sha256 mismatch must fail:\n{text}");
    assert_eq!(
        fs::read(root.join("prefix/bin/huntsman-recon")).unwrap(),
        b"old build\n"
    );
    assert_live_binary_only(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn installer_runtime_acceptance_failure_preserves_existing_binary() {
    if !installer_tools_present() {
        return;
    }
    let bad_runtime = br#"#!/bin/sh
case "$1" in
  check) exit 9 ;;
  *) exit 64 ;;
esac
"#;
    let sha = installer_sha_line("install-runtime-fail-probe", bad_runtime);
    let (code, text, root) = run_installer("runtime-fail", bad_runtime, &sha);
    assert_ne!(
        code,
        Some(0),
        "runtime rejection must abort install:\n{text}"
    );
    assert!(
        text.contains("offline runtime acceptance failed"),
        "installer must identify the failed acceptance stage:\n{text}"
    );
    assert_eq!(
        fs::read(root.join("prefix/bin/huntsman-recon")).unwrap(),
        b"old build\n"
    );
    assert_live_binary_only(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn installer_source_contract_uses_private_stage_runtime_gate_and_atomic_activation() {
    let src = fs::read_to_string(INSTALL).unwrap();
    for required in [
        "stage_dir=\"\"",
        "mktemp -d \"$PREFIX/bin/.${DEST_NAME}.install.XXXXXX\"",
        "install -m 0755 \"$tmp/$ASSET\" \"$stage\"",
        "timeout 30 \"$stage\" check",
        "timeout 30 \"$stage\" verify var/ledger.json",
        "cmp -s \"$stage\" \"$dest\"",
        "mv -f \"$stage\" \"$dest\"",
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
