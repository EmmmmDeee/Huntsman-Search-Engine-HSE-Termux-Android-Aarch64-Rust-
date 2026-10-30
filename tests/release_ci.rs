//! Contract for the live release workflow. GitHub only runs workflows under the
//! root `.github/workflows/`; the copy under `legacy/` is inert. Deleting the
//! root file (f0a1c64) silently stopped every main-channel pre-release.

use std::fmt::Write as _;
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
fn root_installer_changes_trigger_release_dry_run_on_pull_requests() {
    let wf = release();
    let paths = wf
        .split_once("  pull_request:\n    paths:\n")
        .expect("release must have pull_request path filters")
        .1
        .split_once("\npermissions:")
        .expect("pull_request paths must precede permissions")
        .0;
    for required in [
        "      - \"install.sh\"",
        "      - \"tests/root_installer.rs\"",
    ] {
        assert!(
            paths.lines().any(|line| line == required),
            "release PR dry-run must include {required:?}"
        );
    }
}

#[test]
fn android_repo_mapper_changes_trigger_release_dry_run_on_pull_requests() {
    let wf = release();
    let paths = wf
        .split_once("  pull_request:\n    paths:\n")
        .expect("release must have pull_request path filters")
        .1
        .split_once("\npermissions:")
        .expect("pull_request paths must precede permissions")
        .0;
    assert!(
        paths
            .lines()
            .any(|line| line == "      - \"tools/agent_repo_map.rs\""),
        "Android mapper Rust changes must trigger release PR dry-run"
    );
}

#[test]
fn lifecycle_publication_changes_trigger_release_dry_run_on_pull_requests() {
    let wf = release();
    let paths = wf
        .split_once("  pull_request:\n    paths:\n")
        .expect("release must have pull_request path filters")
        .1
        .split_once("\npermissions:")
        .expect("pull_request paths must precede permissions")
        .0;
    for required in [
        "      - \"scripts/lifecycle.sh\"",
        "      - \"tests/lifecycle_sync.rs\"",
    ] {
        assert!(
            paths.lines().any(|line| line == required),
            "lifecycle publication changes must trigger release PR dry-run: {required:?}"
        );
    }
}

#[test]
fn main_pushes_build_and_current_head_publishes_main_channel_pre_releases_only() {
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
        "--draft --latest=false",
        "gh release edit \"$TAG\" --draft=false --prerelease --latest=false",
        "main advanced to",
        "Actions artifact",
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
            "        if: vars.PROMOTE_RECON_TO_LATEST == 'true' && (steps.existing.outputs.exists == 'true' || steps.publish.outputs.published == 'true')\n"
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
        2,
        "only centralized candidate cleanup and the gated latest step may delete a release"
    );
    assert!(step.contains("gh release delete latest"));
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
        "    permissions:\n      contents: write     # create the tags and pre-releases\n      actions: read       # inspect exact-commit main CI before publishing\n      id-token: write     # Sigstore-backed provenance\n      attestations: write # record the attestation\n"
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
fn release_build_embeds_and_verifies_exact_commit_provenance() {
    let wf = release();
    let build = job(&wf, "build");
    assert!(
        wf.contains("HUNTSMAN_BUILD_SHA: ${{ github.sha }}"),
        "release workflow must bind build provenance to github.sha"
    );
    assert!(
        build.contains("grep -Fq \"$GITHUB_SHA\""),
        "final Android binary must be checked for the exact embedded commit"
    );
    assert!(build.contains("embedded_build_sha: ${GITHUB_SHA}"));
    assert!(
        wf.contains("--build-arg HUNTSMAN_BUILD_SHA=\"$GITHUB_SHA\""),
        "Container release-gate image must receive the same commit provenance"
    );
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

/// Every push to main starts a build. A push that touched only installer, docs or test files used
/// to start none, so the head had no build of its own: on 2026-10-21 main sat at 0a6784b with no
/// prebuilt and the installer fell back to an older one. The push trigger therefore has no path
/// filter; pull requests keep theirs, so a PR dry run still runs only for release-path changes.
#[test]
fn every_main_push_starts_a_build_so_the_head_has_its_own() {
    let wf = release();
    let push = wf
        .split_once("\non:\n")
        .and_then(|(_, on)| on.split_once("\n  push:\n"))
        .map(
            |(_, rest)| match rest.split_once("\n  workflow_dispatch:") {
                Some((push, _)) => push,
                None => rest,
            },
        )
        .expect("the workflow has a push trigger");
    assert!(
        push.contains("branches:\n      - main"),
        "the push trigger must name main"
    );
    assert!(
        !push.contains("paths:"),
        "a push to main must start a build whatever it changed: a push with no path filter match left its head without a prebuilt"
    );
}

#[test]
fn termux_acceptance_changes_trigger_release_dry_run_on_pull_requests() {
    let wf = release();
    let paths = wf
        .split_once("  pull_request:\n")
        .and_then(|(_, rest)| rest.split_once("\npermissions:"))
        .map(|(paths, _)| paths)
        .expect("the release workflow must have a pull-request path filter");
    for path in [
        r#"- "scripts/termux-runtime-acceptance.sh""#,
        r#"- "tests/termux_runtime_acceptance.rs""#,
    ] {
        assert!(
            paths.contains(path),
            "release PR acceptance must be triggered by {path}"
        );
    }
}

#[test]
fn superseded_main_builds_are_verified_without_historical_release_failures() {
    let wf = release();
    let publish = job(&wf, "publish");
    assert!(
        !publish.contains("concurrency:") && !wf.contains("queue: max"),
        "publish must not queue old main commits until they become historical"
    );
    // Every main push keeps its own build run, so superseded commits still get
    // verification and an Actions artifact.
    assert!(wf.contains(
        "  group: release-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}\n"
    ));
    for required in [
        "id: existing",
        "verifying it, not replacing it",
        "not ${GITHUB_SHA}; refusing",
        "is missing or has no digest",
        "id: head",
        "git/ref/heads/main",
        "steps.head.outputs.publish == 'true'",
        "gh api -X POST \"$api/git/refs\"",
        "-f ref=\"refs/tags/${TAG}\"",
        "-f sha=\"$GITHUB_SHA\"",
        "--verify-tag --draft --latest=false",
        "read -r type actual",
        "[ \"$actual\" != \"$GITHUB_SHA\" ]",
        "current=\"$(gh api \"$api/git/ref/heads/main\" --jq .object.sha)\"",
        "gh release delete \"$TAG\" --yes --cleanup-tag",
        "gh release edit \"$TAG\" --draft=false --prerelease --latest=false",
        "published=false",
        "published=true",
        "Actions artifact",
    ] {
        assert!(
            publish.contains(required),
            "publish job must contain {required:?}"
        );
    }
    let per_commit = publish
        .split("      - name: ")
        .find(|s| s.starts_with("Publish pre-release "))
        .expect("per-commit publish step must exist");
    assert!(
        !per_commit.contains("--target \"$GITHUB_SHA\""),
        "per-commit publication must not ask GITHUB_TOKEN to mint a historical target"
    );
}

#[test]
fn orphan_main_drafts_without_backing_tags_are_reconciled_fail_closed() {
    let wf = release();
    let publish = job(&wf, "publish");
    let reconcile = publish
        .split("      - name: ")
        .find(|s| s.starts_with("Reconcile orphan main-channel draft releases"))
        .expect("publish must reconcile orphan main-channel drafts");

    for required in [
        "set -euo pipefail",
        "gh api --paginate \"$api/releases?per_page=100\"",
        "select(.draft == true)",
        "^main-[0-9a-f]{7}$",
        "git/ref/tags/${stale_tag}",
        "gh api -X DELETE \"$api/releases/${id}\"",
        "> \"$drafts\"",
        "done < \"$drafts\"",
    ] {
        assert!(
            reconcile.contains(required),
            "orphan reconciliation must contain {required:?}"
        );
    }
    assert!(
        !reconcile.contains("|| true"),
        "draft enumeration/deletion must fail closed rather than hide API failures"
    );
    let reconcile_pos = publish
        .find("      - name: Reconcile orphan main-channel draft releases")
        .unwrap();
    let existing_pos = publish.find("      - name: Check for an existing").unwrap();
    assert!(
        reconcile_pos < existing_pos,
        "stale invalid drafts must be reconciled before current-tag existence checks"
    );
}

#[test]
fn per_commit_publish_anchors_the_tag_before_creating_the_draft() {
    let wf = release();
    let publish = job(&wf, "publish");
    let step = publish
        .split("      - name: ")
        .find(|s| s.starts_with("Publish pre-release "))
        .expect("per-commit publish step must exist");

    let pre_tag_head = step
        .find("git/ref/heads/main")
        .expect("publish must re-check live main immediately before tag creation");
    let create_ref = step
        .find("gh api -X POST \"$api/git/refs\"")
        .expect("publish must create the immutable tag explicitly");
    let create_release = step
        .find("gh release create \"$TAG\"")
        .expect("publish must create the release");
    assert!(
        pre_tag_head < create_ref,
        "live main must be rechecked immediately before any release tag is created"
    );
    assert!(
        create_ref < create_release,
        "the immutable tag must exist before draft release creation"
    );
    assert!(
        step.contains("--verify-tag --draft --latest=false"),
        "draft creation must require the pre-created tag"
    );
    assert!(
        step.contains("ref=\"$(gh api \"$api/git/ref/tags/${TAG}\"")
            && step.contains("grep -qF '(HTTP 404)'"),
        "read_tag must read the tag itself, and retry only a 404"
    );
    let reads: Vec<usize> = step
        .match_indices("          read_tag\n")
        .map(|(at, _)| at)
        .collect();
    assert!(
        reads.len() == 2
            && create_ref < reads[0]
            && reads[0] < create_release
            && create_release < reads[1],
        "the tag must be verified before and after draft creation"
    );
    let pre_check = step
        .find("if superseded; then")
        .expect("publish must ask whether a newer build supersedes it before creating the tag");
    let post_check = step
        .find("|| superseded; then")
        .expect("publish must ask again after creating the draft");
    assert!(
        pre_check < create_ref && create_release < post_check,
        "live main must be checked both immediately before tag creation and again before publication"
    );
    assert!(
        step.contains("trap cleanup_on_exit EXIT")
            && step.contains("cleanup_candidate()")
            && step.contains("candidate_tag=true")
            && step.contains("candidate_release=true"),
        "an error after tag creation must trigger transactional candidate cleanup"
    );
    assert!(
        step.contains("gh api -X DELETE \"$api/git/refs/tags/${TAG}\""),
        "candidate cleanup must remove an orphan tag when no draft exists"
    );
    assert!(
        step.contains("gh release delete \"$TAG\" --yes --cleanup-tag"),
        "candidate cleanup and publication-race cleanup must remove both draft and tag"
    );
    assert!(
        step.matches("candidate_release=false").count() >= 2
            && step.matches("candidate_tag=false").count() >= 2,
        "successful publication and intentional race cleanup must disarm the failure trap"
    );
    assert!(
        !step.contains("--target \"$GITHUB_SHA\""),
        "release creation must never ask GitHub to synthesize a historical target"
    );
}

#[test]
fn post_publish_check_requires_a_matching_non_empty_digest() {
    let wf = release();
    let step = wf
        .split("      - name: ")
        .find(|s| s.starts_with("Verify published pre-releases"))
        .expect("verify step must exist");
    assert!(
        step.contains("if: steps.existing.outputs.exists == 'true' || steps.publish.outputs.published == 'true'"),
        "superseded CI-only builds must skip release verification"
    );
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
            && quality_msrv.contains("cargo run --locked -p xtask -- gate msrv"),
        "release must independently validate the repository MSRV before build/publish"
    );

    for required in [
        "cargo run --locked -p xtask -- gate full",
        "bash scripts/container-build-retry.sh --pull --build-arg HUNTSMAN_BUILD_SHA=\"$GITHUB_SHA\" -f Dockerfile -t huntsman-recon:container .",
        "bash scripts/container-live-acceptance.sh",
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
        publish.contains("needs: [resolve, quality-msrv, quality, build, web-ui]"),
        "release publish must depend on stable/MSRV quality, the verified build and the web UI check"
    );
}

#[test]
fn publish_waits_for_the_web_ui_browser_check_on_the_same_commit() {
    // The web UI is half of the target, so a build whose page fails the phone-browser check must
    // not reach the pre-release channel. Publish waits for a web-ui job in this workflow. That job
    // runs the same check CI runs, against the same commit, so the page it passes is the page this
    // build ships.
    let wf = release();
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("the CI workflow must exist");
    let web_ui = job(&wf, "web-ui");
    let publish = job(&wf, "publish");
    let drive = "node tools/web-ui-check/check.cjs target/debug/huntsman-recon";

    assert!(
        publish.contains("needs: [resolve, quality-msrv, quality, build, web-ui]"),
        "release publish must wait for the web UI browser check"
    );
    assert!(
        web_ui.contains("cargo build --locked --bin huntsman-recon")
            && web_ui.contains("npm install --no-package-lock --ignore-scripts")
            && web_ui.contains(drive),
        "release web-ui job must build the server and drive the page as CI does"
    );
    assert!(
        ci.contains(drive),
        "CI must drive the same page check the release web-ui job runs"
    );
    assert!(
        web_ui.contains("persist-credentials: false"),
        "the browser job must check out without a write credential"
    );
}

#[test]
fn publishing_requires_release_build_and_zero_finding_key_scan() {
    let wf = release();
    for required in [
        "HSE_RELEASE: \"1\"",
        "bash .github/scripts/scan-for-keys.sh dist",
        "grep -qx \"result: PASS (0 findings)\" key-scan-report.txt",
        "dist/key-scan-report.txt",
        "has no digest for asset",
    ] {
        assert!(wf.contains(required), "{RELEASE} must contain {required:?}");
    }
    let install = fs::read_to_string(INSTALL).expect("Termux installer must exist");
    for required in [
        "CHANNEL=\"${HUNTSMAN_CHANNEL:-recon}\"",
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
    with_known_hex(&mut cmd);
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

/// The value `name` is pinned to in the workflow-level `env` of release.yml.
fn workflow_env(name: &str) -> String {
    let wf = release();
    let prefix = format!("\n  {name}: \"");
    let from = wf
        .find(&prefix)
        .unwrap_or_else(|| panic!("{RELEASE} env must pin {name}"))
        + prefix.len();
    let to = from + wf[from..].find('"').expect("quoted value");
    wf[from..to].to_owned()
}

/// Synthetic stand-ins for the per-commit known values (in CI: github.sha and
/// sha256 of Cargo.lock). Never real, never all digits.
fn test_build_sha() -> String {
    fake("", "5e6f7a8b", 5)
}
fn test_cargo_lock_sha256() -> String {
    fake("", "9c8d7e6f", 8)
}

/// The known hex values the scanner strips, as release.yml hands them over:
/// the two pinned constants straight from the workflow env.
fn known_hex() -> [(&'static str, String); 4] {
    [
        ("HUNTSMAN_BUILD_SHA", test_build_sha()),
        (
            "HUNTSMAN_RUSTC_COMMIT",
            workflow_env("HUNTSMAN_RUSTC_COMMIT"),
        ),
        (
            "HUNTSMAN_DIRECTIVE_SHA256",
            workflow_env("HUNTSMAN_DIRECTIVE_SHA256"),
        ),
        ("HUNTSMAN_CARGO_LOCK_SHA256", test_cargo_lock_sha256()),
    ]
}

/// Sets every known hex value on `cmd`, overriding anything inherited (CI sets
/// `HUNTSMAN_BUILD_SHA`). A caller's own env, applied afterwards, still wins.
fn with_known_hex(cmd: &mut Command) -> &mut Command {
    for (k, v) in known_hex() {
        cmd.env(k, v);
    }
    cmd
}

/// std's 00..ff hex byte table and 00..99 decimal digit-pair table.
fn std_tables() -> (String, String) {
    let (mut hex_table, mut digit_table) = (String::new(), String::new());
    for b in 0..=255u8 {
        write!(hex_table, "{b:02x}").unwrap();
    }
    for n in 0..100 {
        write!(digit_table, "{n:02}").unwrap();
    }
    (hex_table, digit_table)
}

/// Two files shaped like the release `dist/`: `bin` carries every benign hex
/// run seen in the real main-f3b5b75 / main-f199841 binaries, glued the way
/// `strings` joins adjacent literals; `p.json` names the build SHA, the
/// Cargo.lock digest and the sha256 of `bin`, like the provenance and report.
/// It scans clean only because the scanner deletes those exact values.
fn clean_fixture(dir: &Path) {
    let [(_, build), (_, rustc), (_, directive), (_, lock)] = known_hex();
    let (hex_table, digit_table) = std_tables();
    let mut rustc_paths = Vec::new();
    for file in ["core/src/fmt/mod.rs", "std/src/io/mod.rs"] {
        rustc_paths.extend_from_slice(format!("/rustc/{rustc}/library/{file}\x00").as_bytes());
    }
    fs::write(
        dir.join("bin"),
        [
            b"\x00\x7fELF usage: huntsman-recon [check]\x00".as_slice(),
            // 31 hex is one short of the key shape.
            fake("", "c", 31).as_bytes(),
            b"\x00".as_slice(),
            hex_table.as_bytes(),
            b"\x00".as_slice(),
            // All digits: std's other decimal formatting tables.
            fake("", "0", 64).as_bytes(),
            b"\x00".as_slice(),
            &rustc_paths,
            // As in the real binaries: the build SHA before the version
            // "0.2.0", the directive digest before "embedded", std's digit
            // table before "assertion".
            format!("{build}0.2.0").as_bytes(),
            b"\x00".as_slice(),
            format!("{directive}embedded canonical").as_bytes(),
            b"\x00".as_slice(),
            format!("{digit_table}assertion failed").as_bytes(),
            b"\x00".as_slice(),
        ]
        .concat(),
    )
    .unwrap();
    let bin_sha = sha256_hex(&dir.join("bin"));
    fs::write(
        dir.join("p.json"),
        format!(
            "{{\"commit\":\"{build}\",\"cargo_lock_sha256\":\"{lock}\",\"artifact_sha256\":\"{bin_sha}\",\"upper\":\"{}\"}}\n",
            "AB".repeat(16)
        ),
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
        "strings",
        "python3",
        "grep",
        "find",
        "sort",
        "cat",
        "mktemp",
        "rm",
        "realpath",
        "sha256sum",
    ];
    let fixture = scratch("tools-fixture");
    clean_fixture(&fixture);
    let ghp = fake_ghp();
    fs::write(
        fixture.join("gh.bin"),
        [b"\x00 t=".as_slice(), ghp.as_bytes(), b" \x00\xfe"].concat(),
    )
    .unwrap();
    for missing in [
        None,
        Some("strings"),
        Some("python3"),
        Some("realpath"),
        Some("sha256sum"),
    ] {
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
    for required in [
        "for attempt in 1 2 3 4 5 6 7 8 9 10",
        "[ \"$attempt\" -eq 10 ] || sleep 3",
        "could not verify merged pull request association",
        "after bounded retry",
    ] {
        assert!(
            resolve.contains(required),
            "merged-PR origin gate must tolerate bounded GitHub indexing lag: missing {required:?}"
        );
    }
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
fn attestation_is_a_required_step_before_publishing() {
    let wf = release();
    assert!(!wf.contains("Re-run to retry"));
    assert!(!wf.contains("A re-run will not add it"));
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
    run_installer_with(name, binary, sha_line, false, false, false)
}

/// As `run_installer`; also exercise a managed service and its disabled state.
fn run_installer_with(
    name: &str,
    binary: &[u8],
    sha_line: &str,
    dest_is_dir: bool,
    managed: bool,
    service_down: bool,
) -> (Option<i32>, String, PathBuf) {
    let root = scratch(&format!("install-{name}"));
    let assets = root.join("assets");
    let fakes = root.join("fakes");
    let prefix = root.join("prefix");
    for d in [
        &assets,
        &fakes,
        &prefix.join("bin"),
        &root.join("tmp"),
        &root.join("home"),
    ] {
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
    if managed {
        let state = root.join("home/.huntsman");
        let service = prefix.join("var/service/huntsman-serve");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&service).unwrap();
        fs::write(
            state.join("installed-revision"),
            "revision=ffffffffffffffffffffffffffffffffffffffff\n",
        )
        .unwrap();
        fs::write(service.join("run"), "#!/bin/sh\n").unwrap();
        if service_down {
            fs::write(service.join("down"), "").unwrap();
        }
        write_exec(
            &prefix.join("bin/huntsman"),
            "#!/usr/bin/env bash\ncase \"$1\" in\n restart) echo restart >> \"$MOCK_LOG\" ;;\n fix) \"$HUNTSMAN_RECON\" fix ;;\n doctor) \"$HUNTSMAN_RECON\" doctor \"$2\" ;;\n *) exit 64 ;;\nesac\n",
        );
    }
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
        .env("HOME", root.join("home"))
        .env("MOCK_LOG", root.join("controller.log"))
        .env("FAKE_ASSETS", &assets)
        .env("HUNTSMAN_CHANNEL", "recon")
        .env("HUNTSMAN_RELEASE_TAG", "main-0a1b2c3")
        .env(
            "HUNTSMAN_TEST_BUILD_SHA",
            "0a1b2c3000000000000000000000000000000000",
        )
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
  build-sha) printf '%s\n' "${HUNTSMAN_TEST_BUILD_SHA:?}" ;;
  check) mkdir -p var; printf 'fixture-ledger\n' > var/ledger.json ;;
  verify) [ "$2" = var/ledger.json ] && [ -f "$2" ] ;;
  fix) printf 'revision=%s\n' "${HUNTSMAN_TEST_BUILD_SHA:?}" > "$HOME/.huntsman/installed-revision" ;;
  doctor) [ "$2" = --probe ] ;;
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
fn standalone_release_upgrade_reconciles_managed_install_and_restores_supervised_service() {
    if !installer_tools_present() {
        return;
    }
    let sha = installer_sha_line("managed", GOOD_RECON_FIXTURE);
    let (code, output, root) =
        run_installer_with("managed", GOOD_RECON_FIXTURE, &sha, false, true, false);
    assert_eq!(code, Some(0), "{output}");
    assert_eq!(
        fs::read_to_string(root.join("home/.huntsman/installed-revision")).unwrap(),
        "revision=0a1b2c3000000000000000000000000000000000\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("controller.log")).unwrap(),
        "restart\n",
        "active managed service must restart exactly once"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn standalone_release_upgrade_preserves_intentionally_stopped_service() {
    if !installer_tools_present() {
        return;
    }
    let sha = installer_sha_line("managed-down", GOOD_RECON_FIXTURE);
    let (code, output, root) =
        run_installer_with("managed-down", GOOD_RECON_FIXTURE, &sha, false, true, true);
    assert_eq!(code, Some(0), "{output}");
    assert!(
        !root.join("controller.log").exists(),
        "a deliberately stopped service must not be started"
    );
    assert_eq!(
        fs::read_to_string(root.join("home/.huntsman/installed-revision")).unwrap(),
        "revision=0a1b2c3000000000000000000000000000000000\n"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn standalone_release_upgrade_reports_postinstall_failure_instead_of_claiming_success() {
    if !installer_tools_present() {
        return;
    }
    let fixture = String::from_utf8(GOOD_RECON_FIXTURE.to_vec())
        .unwrap()
        .replace(
            "fix) printf 'revision=%s\\n' \"${HUNTSMAN_TEST_BUILD_SHA:?}\" > \"$HOME/.huntsman/installed-revision\" ;;",
            "fix) exit 9 ;;",
        );
    assert!(fixture.contains("fix) exit 9 ;;"));
    let sha = installer_sha_line("managed-fail", fixture.as_bytes());
    let (code, output, root) =
        run_installer_with("managed-fail", fixture.as_bytes(), &sha, false, true, false);
    assert_ne!(code, Some(0), "{output}");
    assert!(output.contains("metadata repair failed"), "{output}");
    assert_eq!(
        fs::read_to_string(root.join("home/.huntsman/installed-revision")).unwrap(),
        "revision=ffffffffffffffffffffffffffffffffffffffff\n",
        "failed reconciliation must not silently falsify provenance"
    );
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
fn installer_rejects_an_older_binary_even_with_a_matching_download_checksum() {
    if !installer_tools_present() {
        return;
    }
    // This fixture still implements check + verify, and the checksum matches.
    // Its embedded provenance is deliberately from a different revision.
    let wrong = String::from_utf8(GOOD_RECON_FIXTURE.to_vec())
        .expect("ASCII fixture")
        .replace(
            "${HUNTSMAN_TEST_BUILD_SHA:?}",
            "ffffffffffffffffffffffffffffffffffffffff",
        );
    let binary = wrong.as_bytes();
    let sha = installer_sha_line("wrong-embedded-revision", binary);
    let (code, text, root) = run_installer("wrong-revision", binary, &sha);
    assert_ne!(code, Some(0), "mismatched revision was accepted: {text}");
    assert!(
        text.contains("staged binary revision does not match release main-0a1b2c3"),
        "{text}"
    );
    assert_eq!(
        fs::read(root.join("prefix/bin/huntsman-recon")).unwrap(),
        b"old build\n",
        "a mismatch must never replace the installed executable"
    );
    assert_live_binary_only(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn installer_rejects_missing_or_invalid_embedded_revision() {
    if !installer_tools_present() {
        return;
    }
    let invalid = String::from_utf8(GOOD_RECON_FIXTURE.to_vec())
        .expect("ASCII fixture")
        .replace("${HUNTSMAN_TEST_BUILD_SHA:?}", "not-a-commit");
    let sha = installer_sha_line("invalid-embedded-revision", invalid.as_bytes());
    let (code, text, root) = run_installer("invalid-revision", invalid.as_bytes(), &sha);
    assert_ne!(code, Some(0), "invalid revision was accepted: {text}");
    assert!(
        text.contains("staged binary has invalid build-sha"),
        "{text}"
    );
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
  build-sha) printf '%s\n' "${HUNTSMAN_TEST_BUILD_SHA:?}" ;;
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
        "timeout 30 \"$stage\" build-sha",
        "timeout 30 \"$stage\" check",
        "timeout 30 \"$stage\" verify var/ledger.json",
        "cmp -s \"$stage\" \"$dest\"",
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

#[test]
fn installer_rejects_an_unknown_channel_before_any_download_and_names_the_real_default() {
    let Some(bash) = tool("bash") else {
        return;
    };
    let out = Command::new(bash)
        .arg(INSTALL)
        .env("HUNTSMAN_CHANNEL", "recn")
        .env_remove("PREFIX")
        .output()
        .expect("bash must run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        out.stdout.is_empty(),
        "nothing may be downloaded or installed"
    );
    assert_eq!(
        err.trim_end(),
        "install-termux: HUNTSMAN_CHANNEL must be 'recon' (default) or 'hse', got 'recn'"
    );
}

/// A fake `curl` that knows commit refs and per-tag release assets, and logs every URL it is asked
/// for. `$FAKE_ASSETS/refs/main~N` holds the commit id the API returns for `main~N`;
/// `$FAKE_ASSETS/releases/TAG/ASSET` is a published asset. Anything else is a 404 (exit 22).
const TAGGED_FAKE_CURL: &str = r#"#!/usr/bin/env bash
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o | -H | --proto) [ "$1" = -o ] && out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >> "$FAKE_LOG"
case "$url" in
  https://api.github.com/repos/*/commits/main~*) file="$FAKE_ASSETS/refs/${url##*/commits/}" ;;
  https://github.com/*/releases/download/*) file="$FAKE_ASSETS/releases/${url#*/releases/download/}" ;;
  *) exit 22 ;;
esac
[ -f "$file" ] || exit 22
if [ -n "$out" ]; then cp "$file" "$out"; else cat "$file"; fi
"#;

/// Runs `script` as the Termux installer for the recon channel without `HUNTSMAN_RELEASE_TAG`.
/// `refs[n]` is the commit id of `main~n`; `released` are the commit ids with a published recon
/// build. Returns (exit code, output, URLs asked for, scratch root).
fn run_tag_resolving_installer(
    name: &str,
    script: &Path,
    refs: &[String],
    released: &[&str],
    expected_sha: &str,
) -> (Option<i32>, String, String, PathBuf) {
    let root = scratch(&format!("resolve-{name}"));
    let (assets, fakes, prefix) = (root.join("assets"), root.join("fakes"), root.join("prefix"));
    for d in [
        &assets.join("refs"),
        &fakes,
        &prefix.join("bin"),
        &root.join("tmp"),
    ] {
        fs::create_dir_all(d).unwrap();
    }
    for (depth, sha) in refs.iter().enumerate() {
        fs::write(assets.join(format!("refs/main~{depth}")), sha).unwrap();
    }
    let asset = "huntsman-recon-aarch64-linux-android";
    for sha in released {
        let tag = format!("main-{}", &sha[..7]);
        let dir = assets.join("releases").join(&tag);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(asset), GOOD_RECON_FIXTURE).unwrap();
        fs::write(
            dir.join(format!("{asset}.sha256")),
            installer_sha_line(&tag, GOOD_RECON_FIXTURE),
        )
        .unwrap();
    }
    fs::write(prefix.join("bin/huntsman-recon"), b"old build\n").unwrap();
    write_exec(&fakes.join("curl"), TAGGED_FAKE_CURL);
    write_exec(&fakes.join("uname"), "#!/usr/bin/env bash\necho aarch64\n");
    let log = root.join("urls.log");
    fs::write(&log, "").unwrap();
    let path = format!(
        "{}:{}",
        fakes.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new(tool("bash").expect("bash must be available"))
        .arg(script)
        .env("PATH", path)
        .env("PREFIX", &prefix)
        .env("TMPDIR", root.join("tmp"))
        .env("FAKE_ASSETS", &assets)
        .env("FAKE_LOG", &log)
        .env("HUNTSMAN_CHANNEL", "recon")
        .env("HUNTSMAN_TEST_BUILD_SHA", expected_sha)
        .env_remove("HUNTSMAN_RELEASE_TAG")
        .output()
        .expect("bash must run");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (
        out.status.code(),
        text,
        fs::read_to_string(&log).unwrap(),
        root,
    )
}

fn commit_id(digit: char) -> String {
    std::iter::repeat_n(digit, 40).collect()
}

#[test]
fn the_repository_installer_installs_the_newest_published_recon_build() {
    if !installer_tools_present() {
        return;
    }
    // main~0 has no build yet (a docs-only change, or one still building); main~1 has one.
    let refs = [commit_id('a'), commit_id('b'), commit_id('c')];
    let (code, text, urls, root) = run_tag_resolving_installer(
        "newest",
        Path::new(INSTALL),
        &refs,
        &[&refs[1], &refs[2]],
        &refs[1],
    );
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        fs::read(root.join("prefix/bin/huntsman-recon")).unwrap(),
        GOOD_RECON_FIXTURE
    );
    assert!(
        text.contains("Installed") && text.contains("(main-bbbbbbb)"),
        "{text}"
    );
    let asked: Vec<&str> = urls.lines().collect();
    assert!(
        asked[0].ends_with("/commits/main~0")
            && asked[1].ends_with("/main-aaaaaaa/huntsman-recon-aarch64-linux-android.sha256")
            && asked[2].ends_with("/commits/main~1")
            && asked[3].ends_with("/main-bbbbbbb/huntsman-recon-aarch64-linux-android.sha256"),
        "walks back from the head of main and stops at the first published build: {asked:?}"
    );
    assert!(
        !urls.contains("main-ccccccc") && !urls.contains("main~2"),
        "{asked:?}"
    );
    assert_live_binary_only(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_repository_installer_stops_when_no_recent_commit_has_a_build() {
    if !installer_tools_present() {
        return;
    }
    let refs: Vec<String> = (0..40)
        .map(|n| format!("{n:040x}").replace('0', "d"))
        .collect();
    let (code, text, urls, root) =
        run_tag_resolving_installer("none", Path::new(INSTALL), &refs, &[], &refs[0]);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains(
            "no published recon build among the last 30 commits of main; set HUNTSMAN_RELEASE_TAG=main-<sha7>"
        ),
        "{text}"
    );
    assert_eq!(urls.matches("/commits/main~").count(), 30, "{urls}");
    assert_eq!(
        fs::read(root.join("prefix/bin/huntsman-recon")).unwrap(),
        b"old build\n",
        "the live binary is untouched"
    );
    assert_live_binary_only(&root);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_release_stamped_installer_never_asks_the_api_for_a_tag() {
    if !installer_tools_present() {
        return;
    }
    // Stamp a copy the way the release job does.
    let stamped_dir = scratch("stamped-installer");
    let stamped = stamped_dir.join("install-termux.sh");
    let source = fs::read_to_string(INSTALL).unwrap();
    fs::write(&stamped, source.replace("@RECON_TAG@", "main-eeeeeee")).unwrap();
    let refs = [commit_id('a'), commit_id('e')];
    let (code, text, urls, root) =
        run_tag_resolving_installer("stamped", &stamped, &refs, &[&refs[0], &refs[1]], &refs[1]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("(main-eeeeeee)"), "{text}");
    assert!(!urls.contains("api.github.com"), "{urls}");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&stamped_dir);
}

#[test]
fn install_doc_fetches_the_repository_installer_from_its_real_path() {
    let script = fs::read_to_string(INSTALL).unwrap();
    let repo = script
        .lines()
        .find_map(|line| line.strip_prefix("REPO=\""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("the installer names its repository");
    let url = format!("https://raw.githubusercontent.com/{repo}/main/{INSTALL}");
    let doc = fs::read_to_string("docs/INSTALL.md").unwrap();
    let section = doc
        .split("## Prebuilt Termux release")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("docs/INSTALL.md keeps its prebuilt section");
    assert!(
        section.contains(&format!(
            "curl -fsSL {url} -o \"$TMPDIR/install-termux.sh\""
        )),
        "the no-compiler install must fetch {url}"
    );
    assert!(section.contains("bash \"$TMPDIR/install-termux.sh\""));
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

/// Security's hex-run rule (#876 re-review): after the exact known values are
/// deleted, any run holding 32 lowercase hex in a row is a finding unless it
/// is all digits or part of the 00..ff table. No length is exempt (no 40/64
/// exception, no end-trim fringe), so a key glued to n more hex chars is
/// caught for every n, as is a key glued to a known value or to "password".
/// One file per way of gluing `hex` to other hex; each must be a finding.
fn glued_key_cases(hex: &str) -> Vec<(String, Vec<u8>)> {
    let [(_, build), (_, rustc), (_, directive), (_, lock)] = known_hex();
    let (hex_table, digit_table) = std_tables();
    let tail = format!("{}{}", random_hex32(), random_hex32());
    let mut cases: Vec<(String, Vec<u8>)> = vec![
        (
            "password.bin".into(),
            [
                b"\x00\x01password".as_slice(),
                hex.as_bytes(),
                b"ZZZ\x00\x02",
            ]
            .concat(),
        ),
        (
            "password.txt".into(),
            format!("password{hex}\n").into_bytes(),
        ),
        (
            "hex-after.bin".into(),
            [b"\x00\x01".as_slice(), hex.as_bytes(), b"cafe\x00"].concat(),
        ),
        (
            "run128.txt".into(),
            format!("v={}\n", hex.repeat(4)).into_bytes(),
        ),
    ];
    // key + n hex: 0..=13 spans the old 40-hex fringe (8..=12) and one past
    // it; 30..=37 spans the old 64-hex fringe (32..=36). 8 and 32 make runs
    // of exactly 40 and 64, the lengths the old rule exempted.
    for n in (0..=13).chain(30..=37) {
        cases.push((
            format!("key-plus-{n}.bin"),
            [
                b"\x00\x01".as_slice(),
                hex.as_bytes(),
                &tail.as_bytes()[..n],
                b"\x00",
            ]
            .concat(),
        ));
        cases.push((
            format!("plus-{n}-key.txt"),
            format!("v={}{hex}\n", &tail[..n]).into_bytes(),
        ));
    }
    // A key glued to each exact known value, on either side, is still a key:
    // deleting the known value leaves it standing.
    for (name, known) in [
        ("build-sha", &build),
        ("rustc", &rustc),
        ("directive", &directive),
        ("cargo-lock", &lock),
        ("hex-table", &hex_table),
        ("digit-table", &digit_table),
    ] {
        cases.push((
            format!("{name}-then-key.bin"),
            [
                b"\x00\x01".as_slice(),
                known.as_bytes(),
                hex.as_bytes(),
                b"\x00",
            ]
            .concat(),
        ));
        cases.push((
            format!("key-then-{name}.txt"),
            format!("v={hex}{known}\n").into_bytes(),
        ));
    }
    // An unknown commit SHA or digest is not stripped at all.
    cases.push((
        "other-sha-then-key.bin".into(),
        [
            b"\x00\x01".as_slice(),
            &tail.as_bytes()[..40],
            hex.as_bytes(),
            b"\x00",
        ]
        .concat(),
    ));
    cases
}

#[test]
fn hex_run_rule_catches_a_key_packed_against_other_hex() {
    if !scanner_tools_present() {
        return;
    }
    let hex = random_hex32();
    let cases = glued_key_cases(&hex);
    let dir = scratch("hexrun");
    clean_fixture(&dir);
    for (file, bytes) in &cases {
        fs::write(dir.join(file), bytes).unwrap();
    }
    let (code, text) = scan(&dir);
    assert_eq!(code, Some(1), "every glued key must fail the scan:\n{text}");
    let real = fs::canonicalize(&dir).unwrap();
    for (file, _) in &cases {
        assert!(
            text.contains(&format!(
                "FINDING file={}/{file} resolved={}/{file} rule=hibp-key-hex (value withheld)",
                dir.display(),
                real.display()
            )),
            "{file} must be a finding:\n{text}"
        );
    }
    assert!(
        text.contains(&format!("key scan: {} finding(s)", cases.len())),
        "exactly one finding per planted file, none from the clean fixture:\n{text}"
    );
    assert_redacted(&text, &hex, "glued keys");
    let _ = fs::remove_dir_all(&dir);
}

/// Runs that adjacent read-only data makes in a linked binary, each with at most four different
/// digits in any 32-character window. "style" laid out before a zero-filled 64-hex constant is
/// what failed the aarch64 release build of #907; the other two are `x86_64` release layouts.
fn uniform_runs() -> Vec<(&'static str, Vec<u8>)> {
    let zeros = "0".repeat(64);
    vec![
        (
            "tag-then-zero-hash.bin",
            [b"\x00\x01style".as_slice(), zeros.as_bytes(), b"\x00"].concat(),
        ),
        (
            "digit-then-zeros-then-ca.bin",
            [b"\x00\x014".as_slice(), zeros.as_bytes(), b"ca\x00"].concat(),
        ),
        (
            "splat-vectors.bin",
            [
                b"\x00\x01".as_slice(),
                "d".repeat(16).as_bytes(),
                "6".repeat(16).as_bytes(),
                b"\x00",
            ]
            .concat(),
        ),
        (
            "zero-hash-text.txt",
            format!("prev={zeros}e\n").into_bytes(),
        ),
        (
            "four-digits.txt",
            format!("v={}\n", "0a1b".repeat(8)).into_bytes(),
        ),
    ]
}

/// A key is 32 random hex digits: it uses 14 different ones on average and four or fewer with
/// probability 9.9e-17 (exactly sum_{j<=4} C(16,j) S(32,j) j! / 16^32). A run whose every
/// 32-digit window uses four or fewer is layout, not a key.
#[test]
fn hex_run_rule_ignores_a_run_too_uniform_to_be_a_key() {
    if !scanner_tools_present() {
        return;
    }
    let dir = scratch("uniform-runs");
    clean_fixture(&dir);
    for (file, bytes) in uniform_runs() {
        fs::write(dir.join(file), bytes).unwrap();
    }
    let (code, text) = scan(&dir);
    assert_eq!(code, Some(0), "uniform runs are layout, not keys:\n{text}");
    assert!(text.contains("key scan: 0 finding(s)"), "{text}");
    let _ = fs::remove_dir_all(&dir);
}

/// The boundary: five different digits in one 32-digit window is still key-shaped, and a key
/// glued to a uniform run is still found by its own window.
#[test]
fn hex_run_rule_still_flags_five_different_digits_and_a_key_next_to_zeros() {
    if !scanner_tools_present() {
        return;
    }
    let dir = scratch("uniform-boundary");
    clean_fixture(&dir);
    let five = "0a1b2".repeat(7);
    let key = random_hex32();
    let zeros = "0".repeat(64);
    fs::write(dir.join("five-digits.txt"), format!("v={five}\n")).unwrap();
    fs::write(
        dir.join("key-in-zeros.bin"),
        [
            b"\x00\x01".as_slice(),
            zeros.as_bytes(),
            key.as_bytes(),
            zeros.as_bytes(),
            b"\x00",
        ]
        .concat(),
    )
    .unwrap();
    let (code, text) = scan(&dir);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("key scan: 2 finding(s)"), "{text}");
    for file in ["five-digits.txt", "key-in-zeros.bin"] {
        assert!(
            text.contains(&format!("{file} rule=hibp-key-hex (value withheld)")),
            "{file} must be a finding:\n{text}"
        );
    }
    assert_redacted(&text, &key, "key in zeros");
    let _ = fs::remove_dir_all(&dir);
}

/// The loosening Security blocked must not come back in any form.
#[test]
fn hex_run_rule_has_no_length_exception_or_end_trim() {
    let src = fs::read_to_string(SCAN).unwrap();
    for gone in ["HEX_FRINGE", "benign_hex_core", "40 | 64", "{40}", "{64}"] {
        assert!(!src.contains(gone), "{SCAN} must not contain {gone:?}");
    }
    for want in [
        "for k in \"${KNOWN_HEX[@]}\"; do m=${m//\"$k\"/}; done",
        "KNOWN_HEX+=(\"$hex_table\" \"$digit_table\")",
        "for spec in HUNTSMAN_BUILD_SHA:40 HUNTSMAN_RUSTC_COMMIT:40 HUNTSMAN_DIRECTIVE_SHA256:64 HUNTSMAN_CARGO_LOCK_SHA256:64; do",
    ] {
        assert!(src.contains(want), "{SCAN} must contain {want:?}");
    }
}

/// Every known value is needed: without it the real-binary shapes in the
/// clean fixture (the glued build SHA, rustc paths, directive digest, the
/// provenance's Cargo.lock digest) are findings. Unset means stricter.
#[test]
fn each_known_hex_value_is_needed_and_unset_only_makes_the_scan_stricter() {
    if !scanner_tools_present() {
        return;
    }
    let dir = scratch("known-needed");
    clean_fixture(&dir);
    for (name, _) in known_hex() {
        let bash = tool("bash").expect("bash must be available");
        let mut cmd = Command::new(bash);
        cmd.arg(SCAN).arg(&dir);
        with_known_hex(&mut cmd).env_remove(name);
        let out = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "without {name}:\n{text}");
        assert!(
            text.contains("rule=hibp-key-hex (value withheld)"),
            "without {name}:\n{text}"
        );
        assert!(!text.contains(&format!("stripped: {name}")), "{text}");
    }
    let (code, text) = scan(&dir);
    assert_eq!(code, Some(0), "positive control:\n{text}");
    assert!(
        text.contains("known hex values stripped: HUNTSMAN_BUILD_SHA HUNTSMAN_RUSTC_COMMIT HUNTSMAN_DIRECTIVE_SHA256 HUNTSMAN_CARGO_LOCK_SHA256 + scanned-file sha256 + std tables"),
        "{text}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A known value with the wrong shape (empty, short, uppercase, a bare 32-hex
/// key) would strip arbitrary hex, so both scanner copies refuse it.
#[test]
fn both_scanner_copies_refuse_a_malformed_known_hex_value() {
    if !scanner_tools_present() {
        return;
    }
    let root = scratch("known-malformed");
    let dir = root.join("dist");
    fs::create_dir_all(&dir).unwrap();
    clean_fixture(&dir);
    let inline = root.join("inlined-scan-for-keys.sh");
    fs::write(&inline, inlined_scanner()).unwrap();
    let key = random_hex32();
    let upper = test_build_sha().to_ascii_uppercase();
    for script in [PathBuf::from(SCAN), inline] {
        for (name, len) in [
            ("HUNTSMAN_BUILD_SHA", 40),
            ("HUNTSMAN_RUSTC_COMMIT", 40),
            ("HUNTSMAN_DIRECTIVE_SHA256", 64),
            ("HUNTSMAN_CARGO_LOCK_SHA256", 64),
        ] {
            for bad in ["", "d", key.as_str(), upper.as_str()] {
                let ctx = format!("{} with {name}={} chars", script.display(), bad.len());
                let (code, text) =
                    run_script_with(&script, &dir, &[(name, std::ffi::OsStr::new(bad))]);
                assert_eq!(code, Some(1), "{ctx}:\n{text}");
                assert!(
                    text.contains(&format!(
                        "{name} must be exactly {len} lowercase hex characters (got {} characters); refusing",
                        bad.len()
                    )),
                    "{ctx}:\n{text}"
                );
                assert!(
                    !text.contains("files scanned:"),
                    "{ctx} must not scan:\n{text}"
                );
                assert_redacted(&text, &key, &ctx);
            }
        }
    }
    let _ = fs::remove_dir_all(&root);
}

/// Known values come from the workflow, never from a build-job output: the
/// two constants are pinned in the workflow env (and checked against rustc and
/// the checkout before anything builds), the build SHA is github.sha, and the
/// Cargo.lock digest is hashed from the checkout (build) or from the
/// repository at github.sha (publish, which checks out nothing).
#[test]
fn known_hex_values_come_from_the_workflow_not_from_build_outputs() {
    let wf = release();
    assert_eq!(
        workflow_env("HUNTSMAN_DIRECTIVE_SHA256"),
        huntsman_recon::directive_lock::EXPECTED_SHA256,
        "the workflow pin must track directive_lock::EXPECTED_SHA256"
    );
    let rustc = workflow_env("HUNTSMAN_RUSTC_COMMIT");
    assert!(
        rustc.len() == 40
            && rustc
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert!(wf.contains("\n  HUNTSMAN_BUILD_SHA: ${{ github.sha }}\n"));
    for line in wf.lines().filter(|l| l.contains("HUNTSMAN_")) {
        assert!(
            !line.contains("needs.") && !line.contains("steps."),
            "a known hex value must not come from a job or step output: {line}"
        );
    }
    let build = job(&wf, "build");
    let pin = build
        .find("name: Prove the key scan's pinned hex values still hold")
        .expect("build must check the pins");
    let cargo = build
        .find("run: cargo build --release --locked --target aarch64-linux-android")
        .unwrap();
    assert!(
        pin < cargo,
        "the pins must be checked before any build code runs"
    );
    for want in [
        "got=\"$(rustc -vV | sed -n 's/^commit-hash: //p')\"",
        "[ \"$got\" = \"$HUNTSMAN_RUSTC_COMMIT\" ]",
        "grep -Fqx \"    \\\"${HUNTSMAN_DIRECTIVE_SHA256}\\\";\" src/directive_lock.rs",
        "HUNTSMAN_CARGO_LOCK_SHA256=\"$(sha256sum Cargo.lock | cut -d' ' -f1)\"",
    ] {
        assert!(build.contains(want), "build must contain {want:?}");
    }
    let publish = job(&wf, "publish");
    for want in [
        "\"repos/${GITHUB_REPOSITORY}/contents/Cargo.lock?ref=${GITHUB_SHA}\" > \"$lock\"",
        "HUNTSMAN_CARGO_LOCK_SHA256=\"$(sha256sum \"$lock\" | cut -d' ' -f1)\"",
        "[ \"$HUNTSMAN_BUILD_SHA\" = \"$GITHUB_SHA\" ]",
    ] {
        assert!(publish.contains(want), "publish must contain {want:?}");
    }
    assert!(
        !publish.contains("actions/checkout"),
        "publish must check out nothing"
    );
    let src = fs::read_to_string(SCAN).unwrap();
    assert!(src.contains("d=$(sha256sum -- \"${src_of[\"$f\"]}\")"));
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

/// Runs `script ARG` under `timeout -k 2 10` (which signals the whole
/// process group, so a runaway `find` dies too). Exit 124/137 means it hung.
fn run_script_with_timeout(script: &Path, arg: &Path) -> (Option<i32>, String) {
    let timeout = tool("timeout").expect("coreutils timeout must be installed");
    let bash = tool("bash").expect("bash must be available");
    let mut cmd = Command::new(timeout);
    cmd.args(["-k", "2", "10"]).arg(bash).arg(script).arg(arg);
    let out = with_known_hex(&mut cmd).output().expect("timeout must run");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code(), text)
}

/// (case, set-up given (scratch root, root/dist, planted bytes) returning
/// the scan argument, exit code, expected text, findings when exit is 1).
type SymlinkCase = (
    &'static str,
    fn(&Path, &Path, &[u8]) -> PathBuf,
    i32,
    &'static str,
);

fn link(target: impl AsRef<Path>, at: impl AsRef<Path>) {
    std::os::unix::fs::symlink(target, at).unwrap();
}

#[allow(clippy::too_many_lines)]
fn symlink_cases() -> Vec<SymlinkCase> {
    vec![
        // Followed inside the roots, and each real file scanned once.
        (
            "dir-inside",
            |_, d, x| {
                fs::create_dir_all(d.join("sub")).unwrap();
                fs::write(d.join("sub/z-secret.bin"), x).unwrap();
                link("sub", d.join("linkdir"));
                d.to_owned()
            },
            1,
            "dist/sub/z-secret.bin resolved=",
        ),
        (
            "file-inside",
            |_, d, x| {
                fs::write(d.join("z-secret.bin"), x).unwrap();
                link("z-secret.bin", d.join("link.bin"));
                d.to_owned()
            },
            1,
            "dist/z-secret.bin resolved=",
        ),
        (
            "two-links-one-dir",
            |_, d, x| {
                fs::create_dir_all(d.join("sub")).unwrap();
                fs::write(d.join("sub/z-secret.bin"), x).unwrap();
                link("sub", d.join("link-a"));
                link("sub", d.join("link-b"));
                d.to_owned()
            },
            1,
            "scanning each once",
        ),
        (
            "two-links-no-direct-path",
            |r, d, x| {
                // Scanned through a symlinked parent: no listed path is the
                // real one, so only the resolved-path dedupe keeps it to one.
                fs::create_dir_all(d.join("sub")).unwrap();
                fs::write(d.join("sub/z-secret.bin"), x).unwrap();
                link("sub", d.join("link-a"));
                link("sub", d.join("link-b"));
                link(r, r.join("alias"));
                r.join("alias/dist")
            },
            1,
            "scanning each once (3 of 5)",
        ),
        (
            "trailing-newline-names",
            |_, d, x| {
                fs::write(d.join("sec\n"), x).unwrap();
                link("sec\n", d.join("lnk\n"));
                d.to_owned()
            },
            1,
            "scanning each once (3 of 4)",
        ),
        (
            "symlink-argument",
            |r, d, x| {
                fs::write(d.join("z-secret.bin"), x).unwrap();
                link(d, r.join("arg-link"));
                r.join("arg-link")
            },
            1,
            "dist/z-secret.bin resolved=",
        ),
        // Refused: outside the roots, broken, looping.
        (
            "proc-self-environ",
            |_, d, _| {
                link("/proc/self/environ", d.join("env"));
                d.to_owned()
            },
            2,
            "env::symlink resolves outside the scanned roots",
        ),
        (
            "file-outside",
            |r, d, x| {
                fs::write(r.join("outside.bin"), x).unwrap();
                link(r.join("outside.bin"), d.join("out.bin"));
                d.to_owned()
            },
            2,
            "out.bin::symlink resolves outside the scanned roots",
        ),
        (
            "dir-outside",
            |r, d, x| {
                fs::create_dir_all(r.join("elsewhere")).unwrap();
                fs::write(r.join("elsewhere/z.bin"), x).unwrap();
                link(r.join("elsewhere"), d.join("out-dir"));
                d.to_owned()
            },
            2,
            "out-dir::symlink resolves outside the scanned roots",
        ),
        (
            "dot-dot-escape",
            |r, d, x| {
                fs::write(r.join("outside.bin"), x).unwrap();
                fs::create_dir_all(d.join("sub")).unwrap();
                link("../../outside.bin", d.join("sub/esc"));
                d.to_owned()
            },
            2,
            "sub/esc::symlink resolves outside the scanned roots",
        ),
        (
            "sibling-prefix-dir",
            |r, d, x| {
                fs::create_dir_all(r.join("dist-evil")).unwrap();
                fs::write(r.join("dist-evil/z.bin"), x).unwrap();
                link("../dist-evil", d.join("evil"));
                d.to_owned()
            },
            2,
            "evil::symlink resolves outside the scanned roots",
        ),
        (
            "sibling-prefix-file",
            |r, d, x| {
                fs::create_dir_all(r.join("dist-evil")).unwrap();
                fs::write(r.join("dist-evil/z.bin"), x).unwrap();
                link("../dist-evil/z.bin", d.join("evil.bin"));
                d.to_owned()
            },
            2,
            "evil.bin::symlink resolves outside the scanned roots",
        ),
        (
            "broken",
            |_, d, _| {
                link("does-not-exist", d.join("broken"));
                d.to_owned()
            },
            2,
            "broken::broken or looping symlink",
        ),
        (
            "loop",
            |_, d, _| {
                link("loop-b", d.join("loop-a"));
                link("loop-a", d.join("loop-b"));
                d.to_owned()
            },
            2,
            "::broken or looping symlink",
        ),
        (
            "ancestor-loop",
            |_, d, _| {
                link(".", d.join("self"));
                d.to_owned()
            },
            2,
            "find failed on:",
        ),
        (
            "fifo",
            |_, d, _| {
                let ok = Command::new("mkfifo").arg(d.join("pipe")).status().unwrap();
                assert!(ok.success());
                d.to_owned()
            },
            2,
            "pipe::not a regular file, directory or symlink",
        ),
        (
            "broken-symlink-argument",
            |r, _, _| {
                link(r.join("nowhere"), r.join("arg-link"));
                r.join("arg-link")
            },
            2,
            "cannot resolve scan path",
        ),
        // Last, so a mutant that follows links fails an earlier case first and
        // never walks the real filesystem from /.
        (
            "link-to-filesystem-root",
            |_, d, _| {
                link("/", d.join("slash"));
                d.to_owned()
            },
            2,
            "slash::symlink resolves outside the scanned roots",
        ),
    ]
}

/// FTBB N7 / REFACTOR R2, one rule for both repos: a symlink that resolves
/// inside the scanned roots is followed (each real file scanned once); a
/// broken, looping or outside one exits 2 and is named. Temp dirs only, and
/// every run is killed after 10 s, so a link to / cannot walk the real
/// filesystem or hang the suite.
#[test]
fn scanner_follows_symlinks_inside_the_roots_and_refuses_the_rest() {
    if !scanner_tools_present() {
        return;
    }
    let ghp = fake_ghp();
    let planted = [b"\x00 t=".as_slice(), ghp.as_bytes(), b" \x00"].concat();
    for (case, set_up, want, message) in symlink_cases() {
        let root = scratch(&format!("symlink-{case}"));
        let dir = root.join("dist");
        fs::create_dir_all(&dir).unwrap();
        clean_fixture(&dir);
        let arg = set_up(&root, &dir, &planted);
        let inline = root.join("inlined-scan-for-keys.sh");
        fs::write(&inline, inlined_scanner()).unwrap();
        for script in [PathBuf::from(SCAN), inline] {
            let ctx = format!("{} with symlink case {case}", script.display());
            let start = std::time::Instant::now();
            let (code, text) = run_script_with_timeout(&script, &arg);
            assert!(
                !matches!(code, Some(124 | 137)) && start.elapsed().as_secs() < 10,
                "{ctx} hung:\n{text}"
            );
            assert_eq!(code, Some(want), "{ctx}:\n{text}");
            assert!(
                text.contains(message),
                "{ctx}: expected {message:?}:\n{text}"
            );
            if case == "link-to-filesystem-root" {
                assert!(
                    !text.contains("slash/"),
                    "{ctx} must name no path under the link:\n{text}"
                );
            }
            if want == 1 {
                let real = format!(
                    "resolved={}/dist/",
                    fs::canonicalize(&root).unwrap().display()
                );
                assert!(
                    text.contains(&real),
                    "{ctx}: must print the resolved path:\n{text}"
                );
            }
            if want == 2 {
                assert!(
                    !text.contains("files scanned:"),
                    "{ctx} must not scan:\n{text}"
                );
            } else {
                assert!(
                    text.contains("key scan: 1 finding(s)"),
                    "{ctx}: one token, one finding:\n{text}"
                );
            }
            assert_redacted(&text, &ghp, &ctx);
        }
        let _ = fs::remove_dir_all(&root);
    }
}

/// A scan path starting with `-` is a path, never a `find` option. A root
/// named `-L`, `-H` or `-P` would otherwise switch find's link mode and walk
/// "." instead. The current directory holds sentinels that only a walk of
/// "." would reach: another planted key and a dangling link. Temp dirs only,
/// under `timeout`.
#[test]
fn scanner_treats_a_dash_leading_root_as_a_path() {
    if !scanner_tools_present() {
        return;
    }
    let ghp = fake_ghp();
    let planted = [b"\x00 t=".as_slice(), ghp.as_bytes(), b" \x00"].concat();
    let timeout = tool("timeout").expect("coreutils timeout must be installed");
    let bash = tool("bash").expect("bash must be available");
    for name in ["-dist", "-L", "-P", "-H"] {
        let cwd = scratch(&format!("dash-root{name}"));
        fs::create_dir_all(cwd.join(name)).unwrap();
        clean_fixture(&cwd.join(name));
        fs::write(cwd.join(name).join("z-secret.bin"), &planted).unwrap();
        fs::create_dir_all(cwd.join("sibling")).unwrap();
        fs::write(cwd.join("sibling/outside-secret.bin"), &planted).unwrap();
        link("does-not-exist", cwd.join("dangling-outside-the-root"));
        let inline = cwd.join("inlined-scan-for-keys.sh");
        fs::write(&inline, inlined_scanner()).unwrap();
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCAN);
        for script in [file, inline] {
            let ctx = format!("{} on root {name}", script.display());
            let mut cmd = Command::new(&timeout);
            cmd.args(["-k", "2", "10"])
                .arg(&bash)
                .arg(&script)
                .arg(name)
                .current_dir(&cwd);
            let out = with_known_hex(&mut cmd).output().expect("timeout must run");
            let text = String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr);
            assert!(
                !matches!(out.status.code(), Some(124 | 137)),
                "{ctx} hung:\n{text}"
            );
            assert_eq!(out.status.code(), Some(1), "{ctx} must scan it:\n{text}");
            let want = format!(
                "FINDING file=./{name}/z-secret.bin resolved={}/{name}/z-secret.bin rule=github-token (value withheld)",
                fs::canonicalize(&cwd).unwrap().display()
            );
            assert!(text.contains(&want), "{ctx}: expected {want:?}:\n{text}");
            assert!(text.contains("key scan: 1 finding(s)"), "{ctx}:\n{text}");
            for outside in ["sibling", "outside-secret", "dangling-outside-the-root"] {
                assert!(
                    !text.contains(outside),
                    "{ctx} walked outside the root:\n{text}"
                );
            }
            assert_redacted(&text, &ghp, &ctx);
        }
        let _ = fs::remove_dir_all(&cwd);
    }
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
        .contains("wide=$(strings -a -e l -n 8 -- \"$src\") || { echo \"::error::strings -e l failed on $f\"; exit 1; }"));
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
    // The installer runs the staged recon binary offline (`check`, then
    // `verify`) before moving it; this stand-in passes both.
    let new_build =
        b"#!/bin/sh\nif [ \"$1\" = build-sha ]; then printf '%s\\n' \"${HUNTSMAN_TEST_BUILD_SHA:?}\"; fi\nexit 0\n";
    let probe = scratch("install-dir-probe");
    fs::write(probe.join("b"), new_build).unwrap();
    let good = format!("{}  {asset}\n", sha256_hex(&probe.join("b")));
    let _ = fs::remove_dir_all(&probe);
    let (code, text, root) = run_installer_with("dest-dir", new_build, &good, true, false, false);
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
# Fake `gh api [-X METHOD] PATH [--jq EXPR] [-f K=V]...` and `gh release ...`.
# Every call is appended to $FAKE_GH/calls. A GET answers from
# $FAKE_GH/<key>.json, where key is PATH without repos/<repo>/ and with / as _;
# <key>.status overrides the HTTP status, a missing fixture is a 404, and
# <key>.lag holding N answers the first N GETs with a 404, as GitHub does for a
# moment after a ref is created. Any other method, and `gh release`, succeeds
# unless <METHOD>_<key>.status or release_<SUBCOMMAND>.status says otherwise.
fail() { printf '%s' '{"message":"Fake"}'; echo "gh: Fake (HTTP $1)" >&2; exit 1; }
if [ "${1:-}" = release ]; then
  echo "$*" >> "$FAKE_GH/calls"
  status=0
  if [ -f "$FAKE_GH/release_${2:-}.status" ]; then status="$(cat "$FAKE_GH/release_${2:-}.status")"; fi
  [ "$status" = 0 ] || fail "$status"
  exit 0
fi
[ "${1:-}" = api ] || { echo "fake gh: unexpected: $*" >&2; exit 99; }
shift
method=GET path="" jq=""
while [ $# -gt 0 ]; do
  case "$1" in
    --jq) jq="$2"; shift 2 ;;
    -X) method="$2"; shift 2 ;;
    -f|-F) shift 2 ;;
    -*) echo "fake gh: unexpected flag $1" >&2; exit 99 ;;
    *) path="$1"; shift ;;
  esac
done
key="${path#repos/"$GITHUB_REPOSITORY"/}"
key="${key//\//_}"
echo "$method $path" >> "$FAKE_GH/calls"
if [ "$method" != GET ]; then
  status=200
  if [ -f "$FAKE_GH/${method}_$key.status" ]; then status="$(cat "$FAKE_GH/${method}_$key.status")"; fi
  [ "$status" = 200 ] || fail "$status"
  printf '%s\n' '{}'
  exit 0
fi
if [ -f "$FAKE_GH/$key.lag" ]; then
  lag="$(cat "$FAKE_GH/$key.lag")"
  if [ "$lag" -gt 0 ]; then echo "$((lag - 1))" > "$FAKE_GH/$key.lag"; fail 404; fi
fi
status=404
body='{"message":"Not Found"}'
if [ -f "$FAKE_GH/$key.json" ]; then status=200; body="$(cat "$FAKE_GH/$key.json")"; fi
if [ -f "$FAKE_GH/$key.status" ]; then status="$(cat "$FAKE_GH/$key.status")"; fi
if [ "$status" != 200 ]; then printf '%s' "$body"; echo "gh: Fake (HTTP $status)" >&2; exit 1; fi
if [ -n "$jq" ]; then jq -r "$jq" <<<"$body"; else printf '%s\n' "$body"; fi
"#;

/// A `sleep` that only records how long it was asked to wait, so a bounded retry runs at once.
const FAKE_SLEEP: &str = "#!/usr/bin/env bash\necho \"sleep $*\" >> \"$FAKE_GH/calls\"\n";

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
    /// The fake `gh` and `sleep` calls, one per line, in order.
    calls: String,
}

/// A fake `gh api` answer: (fixture key, HTTP status, body).
type Answer = (String, u16, String);

/// Runs `script` with the fake `gh`.
fn run_step(name: &str, script: &str, fixtures: &[Answer], envs: &[(&str, &str)]) -> StepRun {
    run_step_with(name, script, fixtures, &[], envs)
}

/// Runs `script` with the fake `gh` and `sleep`, in a scratch working directory. Each `files`
/// entry is written into the fake's data directory as is, such as a `<key>.lag`.
fn run_step_with(
    name: &str,
    script: &str,
    fixtures: &[Answer],
    files: &[(&str, &str)],
    envs: &[(&str, &str)],
) -> StepRun {
    let root = scratch(&format!("step-{name}"));
    let (fakes, data, tmp) = (root.join("fakes"), root.join("gh"), root.join("tmp"));
    for d in [&fakes, &data, &tmp] {
        fs::create_dir_all(d).unwrap();
    }
    write_exec(&fakes.join("gh"), FAKE_GH);
    write_exec(&fakes.join("sleep"), FAKE_SLEEP);
    for (key, status, body) in fixtures {
        fs::write(data.join(format!("{key}.json")), body).unwrap();
        if *status != 200 {
            fs::write(data.join(format!("{key}.status")), status.to_string()).unwrap();
        }
    }
    for (file, body) in files {
        fs::write(data.join(file), body).unwrap();
    }
    let file = root.join("step.sh");
    fs::write(&file, script).unwrap();
    let out_file = root.join("output");
    fs::write(&out_file, "").unwrap();
    let mut cmd = Command::new(tool("bash").expect("bash must be available"));
    cmd.arg(&file)
        .current_dir(&root)
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
        calls: fs::read_to_string(data.join("calls")).unwrap_or_default(),
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

/// (case, fake answers, exit code, marker or `exists=` line).
type ExistingCase = (&'static str, Vec<Answer>, i32, &'static str);

fn existing_cases() -> Vec<ExistingCase> {
    let tag_at = |ty: &str, sha: &str| -> Answer {
        (
            format!("git_ref_tags_{STEP_TAG}"),
            200,
            format!("{{\"object\":{{\"type\":\"{ty}\",\"sha\":\"{sha}\"}}}}"),
        )
    };
    let here = || tag_at("commit", &step_sha());
    let rel = |pre: bool, assets: &[(String, Option<String>)]| -> Answer {
        (
            format!("releases_tags_{STEP_TAG}"),
            200,
            release_json(pre, assets),
        )
    };
    let full = complete_assets();
    let mut missing = full.clone();
    missing.pop();
    let mut null_digest = full.clone();
    null_digest[1].1 = None;
    let mut duplicate = full.clone();
    duplicate.push(duplicate[0].clone());
    let ref_502: Answer = (format!("git_ref_tags_{STEP_TAG}"), 502, "{}".to_owned());
    vec![
        ("absent", vec![], 0, "exists=false"),
        ("complete", vec![here(), rel(true, &full)], 0, "exists=true"),
        ("ref-502", vec![ref_502], 15, "[refuse:ref-lookup-failed]"),
        (
            "other-commit",
            vec![tag_at("commit", &"9".repeat(40)), rel(true, &full)],
            11,
            "[refuse:tag-elsewhere]",
        ),
        (
            "annotated",
            vec![tag_at("tag", &step_sha()), rel(true, &full)],
            11,
            "[refuse:tag-elsewhere]",
        ),
        (
            "no-release",
            vec![here()],
            12,
            "[refuse:tag-without-release]",
        ),
        (
            "not-prerelease",
            vec![here(), rel(false, &full)],
            13,
            "[refuse:not-prerelease]",
        ),
        (
            "asset-missing",
            vec![here(), rel(true, &missing)],
            14,
            "[refuse:asset-incomplete]",
        ),
        (
            "null-digest",
            vec![here(), rel(true, &null_digest)],
            14,
            "[refuse:asset-incomplete]",
        ),
        (
            "duplicate",
            vec![here(), rel(true, &duplicate)],
            14,
            "[refuse:asset-incomplete]",
        ),
    ]
}

#[test]
fn existing_release_check_refuses_each_case_by_exit_code_and_marker() {
    if !jq_present() {
        return;
    }
    let script = step_script("Check for an existing");
    for (case, fixtures, want, marker) in existing_cases() {
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

/// (case, `EXISTS`, `ATTESTATION_ID`, fake answers, exit code, marker).
type AttestCase = (
    &'static str,
    &'static str,
    &'static str,
    Vec<Answer>,
    i32,
    &'static str,
);

fn attest_cases() -> Vec<AttestCase> {
    let rel = |assets: &[(String, Option<String>)]| -> Answer {
        (
            format!("releases_tags_{STEP_TAG}"),
            200,
            release_json(true, assets),
        )
    };
    let att = |status: u16, body: &str| -> Answer {
        (
            format!("attestations_{}", digest("a")),
            status,
            body.to_owned(),
        )
    };
    let full = complete_assets();
    let mut no_digest = full.clone();
    no_digest[0].1 = None;
    let one = "{\"attestations\":[{}]}";
    let none = "{\"attestations\":[]}";
    vec![
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
            vec![rel(&full), att(200, one)],
            0,
            "1 build provenance attestation(s)",
        ),
        (
            "old-none-404",
            "true",
            "",
            vec![rel(&full), att(404, "{}")],
            24,
            "[refuse:unattested-release]",
        ),
        (
            "old-none-empty",
            "true",
            "",
            vec![rel(&full), att(200, none)],
            24,
            "[refuse:unattested-release]",
        ),
        (
            "old-lookup-502",
            "true",
            "",
            vec![rel(&full), att(502, "{}")],
            23,
            "[refuse:attestation-lookup-failed]",
        ),
        (
            "old-no-digest",
            "true",
            "",
            vec![rel(&no_digest)],
            22,
            "[refuse:no-asset-digest]",
        ),
        ("no-check", "", "", vec![], 25, "[refuse:no-existing-check]"),
    ]
}

#[test]
fn attestation_requirement_refuses_each_case_by_exit_code_and_marker() {
    if !jq_present() {
        return;
    }
    let script = step_script("Require a build provenance attestation");
    for (case, exists, id, fixtures, want, marker) in attest_cases() {
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

/// The publish step run with main still at this commit. The new tag answers its first `lag`
/// reads with a 404, then with `tag_status`.
fn publish_run(case: &str, lag: &str, tag_status: u16) -> StepRun {
    let main = (
        "git_ref_heads_main".to_owned(),
        200,
        format!("{{\"object\":{{\"sha\":\"{}\"}}}}", step_sha()),
    );
    let tag = (
        format!("git_ref_tags_{STEP_TAG}"),
        tag_status,
        format!(
            "{{\"object\":{{\"type\":\"commit\",\"sha\":\"{}\"}}}}",
            step_sha()
        ),
    );
    let lag_file = format!("git_ref_tags_{STEP_TAG}.lag");
    run_step_with(
        &format!("publish-{case}"),
        &step_script("Publish pre-release "),
        &[main, tag],
        &[(lag_file.as_str(), lag)],
        &[
            ("GITHUB_SERVER_URL", "https://github.com"),
            ("GITHUB_RUN_ID", "1"),
        ],
    )
}

fn count_calls(run: &StepRun, call: &str) -> usize {
    run.calls.lines().filter(|line| *line == call).count()
}

/// GitHub can answer 404 for a tag for a moment after creating it. That failed the publish of
/// main-d325921 and left the commit with no pre-release. The step waits it out, bounded, and
/// publishes.
#[test]
fn publish_waits_for_a_new_tag_to_become_readable() {
    if !jq_present() {
        return;
    }
    let run = publish_run("lagging-tag", "2", 200);
    assert_eq!(run.code, Some(0), "{}\n{}", run.text, run.calls);
    assert_eq!(run.output, "published=true\n", "{}", run.text);
    let calls: Vec<&str> = run.calls.lines().collect();
    let create = calls
        .iter()
        .position(|call| call.starts_with("release create "))
        .unwrap_or_else(|| panic!("the draft must be created:\n{}", run.calls));
    let tag_read = format!("GET repos/owner/repo/git/ref/tags/{STEP_TAG}");
    assert_eq!(
        calls[..create]
            .iter()
            .filter(|call| **call == tag_read)
            .count(),
        3,
        "two lagging reads and the one that answers, before the draft:\n{}",
        run.calls
    );
    assert_eq!(count_calls(&run, "sleep 3"), 2, "{}", run.calls);
    assert!(
        calls.iter().any(|call| call.starts_with("release edit ")),
        "{}",
        run.calls
    );
    assert!(!run.calls.contains("DELETE"), "{}", run.calls);
}

/// A tag that never becomes readable is retried a bounded number of times, then the step fails
/// and removes the tag it created, so no orphan tag outlives the run.
#[test]
fn publish_gives_up_on_a_tag_that_never_reads_and_removes_it() {
    if !jq_present() {
        return;
    }
    let run = publish_run("unreadable-tag", "99", 200);
    assert_eq!(run.code, Some(1), "{}\n{}", run.text, run.calls);
    assert!(
        run.text.contains(&format!(
            "::error::tag {STEP_TAG} was still not readable after bounded retry"
        )),
        "{}",
        run.text
    );
    let tag_read = format!("GET repos/owner/repo/git/ref/tags/{STEP_TAG}");
    assert_eq!(count_calls(&run, &tag_read), 10, "{}", run.calls);
    assert_eq!(count_calls(&run, "sleep 3"), 9, "{}", run.calls);
    assert!(!run.calls.contains("release create"), "{}", run.calls);
    assert_eq!(
        run.calls.lines().last(),
        Some(format!("DELETE repos/owner/repo/git/refs/tags/{STEP_TAG}").as_str()),
        "{}",
        run.calls
    );
    assert_eq!(run.output, "", "a failed publish must not report published");
}

/// Only a 404 is the lag of a new ref. Any other error reading the tag fails at once, and the
/// tag is removed.
#[test]
fn publish_fails_at_once_on_any_other_tag_read_error() {
    if !jq_present() {
        return;
    }
    let run = publish_run("tag-502", "0", 502);
    assert_eq!(run.code, Some(1), "{}\n{}", run.text, run.calls);
    let tag_read = format!("GET repos/owner/repo/git/ref/tags/{STEP_TAG}");
    assert_eq!(count_calls(&run, &tag_read), 1, "{}", run.calls);
    assert_eq!(count_calls(&run, "sleep 3"), 0, "{}", run.calls);
    assert!(!run.calls.contains("release create"), "{}", run.calls);
    assert!(
        run.calls
            .contains(&format!("DELETE repos/owner/repo/git/refs/tags/{STEP_TAG}")),
        "{}",
        run.calls
    );
}

/// A 40-character object name of a commit other than the build's.
fn other_sha(c: char) -> String {
    c.to_string().repeat(40)
}

/// Fake answer: main's head is `sha`.
fn main_head(sha: &str) -> Answer {
    (
        "git_ref_heads_main".to_owned(),
        200,
        format!("{{\"object\":{{\"sha\":\"{sha}\"}}}}"),
    )
}

/// Fake answer: comparing the build's commit with `head` gives `status` and `commits`.
fn compare_to(head: &str, status: &str, commits: &[&str]) -> Answer {
    let commits: Vec<String> = commits
        .iter()
        .map(|c| format!("{{\"sha\":\"{c}\"}}"))
        .collect();
    (
        format!("compare_{}...{head}", step_sha()),
        200,
        format!(
            "{{\"status\":\"{status}\",\"commits\":[{}]}}",
            commits.join(",")
        ),
    )
}

/// The fixture key of the release builds of main pushes, as the workflow asks for them.
const RUNS_KEY: &str = "actions_workflows_release.yml_runs?branch=main&event=push&per_page=100";

/// A release build of a main push: its head sha, status and conclusion (empty while it runs).
type Build<'a> = (&'a str, &'a str, &'a str);

/// Fake answer: the release builds of main pushes.
fn release_runs(runs: &[Build<'_>]) -> Answer {
    let runs: Vec<String> = runs
        .iter()
        .map(|(sha, status, conclusion)| {
            let conclusion = if conclusion.is_empty() {
                "null".to_owned()
            } else {
                format!("\"{conclusion}\"")
            };
            format!(
                "{{\"head_sha\":\"{sha}\",\"status\":\"{status}\",\"conclusion\":{conclusion}}}"
            )
        })
        .collect();
    (
        RUNS_KEY.to_owned(),
        200,
        format!("{{\"workflow_runs\":[{}]}}", runs.join(",")),
    )
}

/// Runs the head check with the fake `gh`.
fn head_run(case: &str, fixtures: &[Answer]) -> StepRun {
    run_step(
        &format!("head-{case}"),
        &step_script("Check whether a newer main build supersedes this commit"),
        fixtures,
        &[],
    )
}

/// Runs the publish step with main moved on to `newer`, which the build's commit precedes,
/// and `runs` as the release builds of main pushes.
fn publish_run_moved(case: &str, newer: &str, runs: &[Build<'_>]) -> StepRun {
    let tag = (
        format!("git_ref_tags_{STEP_TAG}"),
        200,
        format!(
            "{{\"object\":{{\"type\":\"commit\",\"sha\":\"{}\"}}}}",
            step_sha()
        ),
    );
    run_step_with(
        &format!("publish-{case}"),
        &step_script("Publish pre-release "),
        &[
            main_head(newer),
            tag,
            compare_to(newer, "ahead", &[newer]),
            release_runs(runs),
        ],
        &[],
        &[
            ("GITHUB_SERVER_URL", "https://github.com"),
            ("GITHUB_RUN_ID", "1"),
        ],
    )
}

/// The decision whether a newer main build supersedes this one is one function, inlined in
/// the head check and in the publish step (which checks out nothing), byte for byte.
#[test]
fn the_superseding_build_check_is_inlined_identically_in_the_head_and_publish_steps() {
    let head = step_script("Check whether a newer main build supersedes this commit");
    let publish = step_script("Publish pre-release ");
    let block = |script: &str| -> String {
        let from = script
            .find("newer_build() {")
            .expect("newer_build must be defined");
        let end = script[from..]
            .find("superseded() {")
            .expect("superseded must follow newer_build")
            + from;
        let end = script[end..].find("\n}\n").expect("superseded must end") + end + 3;
        script[from..end].to_owned()
    };
    assert_eq!(
        block(&head),
        block(&publish),
        "the head check and the publish step must carry the same decision"
    );
    for required in [
        "current=\"$(gh api \"$api/git/ref/heads/main\" --jq .object.sha)\" || return 2",
        "[ \"$current\" != \"$GITHUB_SHA\" ] || return 1",
        "compare/${GITHUB_SHA}...${current}",
        "--jq '.status, .commits[].sha'",
        "actions/workflows/release.yml/runs?branch=main&event=push&per_page=100",
        ".status == \"queued\" or .status == \"in_progress\" or .status == \"waiting\" or .status == \"pending\" or .status == \"requested\" or (.status == \"completed\" and .conclusion == \"success\")",
        "[ \"${cmp%%$'\\n'*}\" = \"ahead\" ] || { NEWER=\"$current\"; return 0; }",
        "grep -qxF \"$sha\" <<<\"$live\"",
        "refusing to decide publication\"; exit 1",
    ] {
        assert!(
            block(&head).contains(required),
            "the decision must keep {required:?}:\n{}",
            block(&head)
        );
    }
}

/// A build at main's head publishes and asks GitHub nothing more.
#[test]
fn a_build_at_mains_head_publishes_and_asks_nothing_more() {
    if !jq_present() {
        return;
    }
    let run = head_run("still-head", &[main_head(&step_sha())]);
    assert_eq!(run.code, Some(0), "{}", run.text);
    assert_eq!(run.output, "publish=true\n", "{}", run.text);
    assert_eq!(
        run.calls.trim(),
        "GET repos/owner/repo/git/ref/heads/main",
        "a build at main's head asks nothing more"
    );
}

/// A build whose commit main has moved past still publishes unless a newer commit has a
/// release build of its own that is queued, running or succeeded. Before this, any movement of
/// main skipped publication, so a push that touched no release path (which starts no build) or
/// a newer build that failed left the prebuilt behind main until the next release push.
#[test]
fn a_moved_main_skips_publication_only_for_a_newer_commit_with_a_live_or_successful_build() {
    if !jq_present() {
        return;
    }
    let (newer, elsewhere) = (other_sha('1'), other_sha('3'));
    let cases: Vec<(&str, Vec<Build<'_>>, bool)> = vec![
        ("newer-running", vec![(&newer, "in_progress", "")], false),
        ("newer-queued", vec![(&newer, "queued", "")], false),
        (
            "newer-succeeded",
            vec![(&newer, "completed", "success")],
            false,
        ),
        ("newer-without-build", vec![], true),
        ("newer-failed", vec![(&newer, "completed", "failure")], true),
        (
            "newer-cancelled",
            vec![(&newer, "completed", "cancelled")],
            true,
        ),
        (
            "build-of-another-commit",
            vec![(&elsewhere, "in_progress", "")],
            true,
        ),
    ];
    for (case, runs, publishes) in cases {
        let run = head_run(
            case,
            &[
                main_head(&newer),
                compare_to(&newer, "ahead", &[&newer]),
                release_runs(&runs),
            ],
        );
        assert_eq!(run.code, Some(0), "{case}: {}", run.text);
        let expected = if publishes {
            "publish=true\n"
        } else {
            "publish=false\n"
        };
        assert_eq!(run.output, expected, "{case}: {}", run.text);
        assert_eq!(
            run.text.contains(&format!("main advanced to {newer}")),
            !publishes,
            "{case} names the superseding commit exactly when it skips: {}",
            run.text
        );
        assert_eq!(
            count_calls(&run, "GET repos/owner/repo/git/ref/heads/main"),
            1,
            "{case}"
        );
        assert!(
            run.calls.contains("GET repos/owner/repo/actions/workflows/release.yml/runs?branch=main&event=push&per_page=100"),
            "{case}: {}",
            run.calls
        );
    }
}

/// A commit between the build's and main's head with a successful build supersedes it even
/// though main's head has none (a docs-only push after a release push), and a main that no
/// longer descends from the build's commit never publishes it.
#[test]
fn an_intermediate_successful_build_supersedes_and_a_diverged_main_never_publishes() {
    if !jq_present() {
        return;
    }
    let (newer, mid) = (other_sha('1'), other_sha('2'));
    let run = head_run(
        "intermediate-succeeded",
        &[
            main_head(&newer),
            compare_to(&newer, "ahead", &[&mid, &newer]),
            release_runs(&[(&mid, "completed", "success")]),
        ],
    );
    assert_eq!(run.output, "publish=false\n", "{}", run.text);
    assert!(
        run.text.contains(&format!("main advanced to {mid}")),
        "{}",
        run.text
    );

    let run = head_run(
        "diverged",
        &[
            main_head(&newer),
            compare_to(&newer, "diverged", &[]),
            release_runs(&[]),
        ],
    );
    assert_eq!(run.output, "publish=false\n", "{}", run.text);
    assert!(
        run.text.contains(&format!("main advanced to {newer}")),
        "{}",
        run.text
    );
}

/// GitHub being unreadable fails the head check rather than deciding either way.
#[test]
fn the_head_check_fails_rather_than_guess_when_github_cannot_be_read() {
    if !jq_present() {
        return;
    }
    let newer = other_sha('1');
    let unreadable: Vec<(&str, Vec<Answer>)> = vec![
        (
            "head",
            vec![("git_ref_heads_main".to_owned(), 502, "{}".to_owned())],
        ),
        (
            "compare",
            vec![
                main_head(&newer),
                (
                    format!("compare_{}...{newer}", step_sha()),
                    502,
                    "{}".to_owned(),
                ),
            ],
        ),
        (
            "runs",
            vec![
                main_head(&newer),
                compare_to(&newer, "ahead", &[&newer]),
                (RUNS_KEY.to_owned(), 502, "{}".to_owned()),
            ],
        ),
    ];
    for (case, fixtures) in unreadable {
        let run = head_run(&format!("unreadable-{case}"), &fixtures);
        assert_eq!(run.code, Some(1), "{case}: {}", run.text);
        assert_eq!(run.output, "", "{case} must decide nothing: {}", run.text);
        assert!(
            run.text.contains("refusing to decide publication"),
            "{case}: {}",
            run.text
        );
    }
}

/// The publish step applies the same rule immediately before creating the tag: main having
/// moved on to a commit with no build of its own still publishes, and a newer live build
/// stops the step before any persistent write.
#[test]
fn publish_applies_the_same_rule_before_creating_the_tag() {
    if !jq_present() {
        return;
    }
    let newer = other_sha('1');
    let run = publish_run_moved("moved-without-build", &newer, &[]);
    assert_eq!(run.code, Some(0), "{}\n{}", run.text, run.calls);
    assert_eq!(run.output, "published=true\n", "{}", run.text);
    assert_eq!(
        count_calls(&run, "POST repos/owner/repo/git/refs"),
        1,
        "{}",
        run.calls
    );
    assert!(run.calls.contains("release edit "), "{}", run.calls);
    assert!(!run.calls.contains("DELETE"), "{}", run.calls);

    let run = publish_run_moved("moved-with-build", &newer, &[(&newer, "in_progress", "")]);
    assert_eq!(run.code, Some(0), "{}\n{}", run.text, run.calls);
    assert_eq!(run.output, "published=false\n", "{}", run.text);
    assert!(
        run.text.contains(&format!("main advanced to {newer}")),
        "{}",
        run.text
    );
    assert!(
        !run.calls.contains("POST "),
        "no persistent write: {}",
        run.calls
    );
    assert!(!run.calls.contains("release create"), "{}", run.calls);
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
    let (mut gated, mut reconcile, mut latest) = (0, 0, 0);
    for step in publish.split("      - name: ").skip(1) {
        let writes_here = step
            .lines()
            .any(|l| writes.iter().any(|w| l.trim_start().starts_with(w)));
        if !writes_here {
            continue;
        }
        // Main's orphan-draft reconciliation (#853) deletes only a draft
        // main-<sha7> release whose tag is absent. It never touches a release
        // that has a tag, so it cannot replace or re-attest an existing one.
        if step.starts_with("Reconcile orphan main-channel draft releases") {
            for required in [
                "select(.draft == true)",
                "[[ \"$stale_tag\" =~ ^main-[0-9a-f]{7}$ ]] || continue",
                "if ! gh api \"$api/git/ref/tags/${stale_tag}\" >/dev/null 2>&1; then",
            ] {
                assert!(step.contains(required), "reconcile must keep {required:?}");
            }
            let deletes: Vec<&str> = step
                .lines()
                .map(str::trim_start)
                .filter(|l| writes.iter().any(|w| l.starts_with(w)))
                .collect();
            assert_eq!(
                deletes,
                ["gh api -X DELETE \"$api/releases/${id}\""],
                "reconcile may only delete the orphan draft"
            );
            reconcile += 1;
            continue;
        }
        // The opt-in `latest` move (#869, ad86c60d) also runs on a re-run of an
        // existing release: it promotes the published bytes, and every write in
        // it targets `latest`, never this commit's main-<sha7> release or tag.
        if step.starts_with("Move the rolling `latest` pre-release") {
            assert!(
                step.contains("        if: vars.PROMOTE_RECON_TO_LATEST == 'true' && "),
                "moving latest must stay behind the opt-in:\n{step}"
            );
            for l in step.lines().map(str::trim_start) {
                if writes.iter().any(|w| l.starts_with(w)) {
                    assert!(
                        l.starts_with("gh release delete latest ")
                            || l == "gh api -X DELETE \"$api/git/refs/tags/latest\""
                            || l == "gh release create latest \\",
                        "the latest step may only write `latest`: {l:?}"
                    );
                }
            }
            latest += 1;
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
    assert_eq!(gated, 2, "attest and publish");
    assert_eq!(reconcile, 1, "the orphan-draft reconciliation step");
    assert_eq!(latest, 1, "the opt-in latest move");
}

/// The promotion of `latest` is checked offline, against a stub `gh` that serves a fixture
/// release. A re-run whose rebuilt provenance differs from the published one must still
/// promote the published bytes, and a tampered download must be refused.
#[test]
fn promoting_latest_takes_the_published_bytes_offline() {
    let out = Command::new("bash")
        .arg("scripts/release-promote-self-check.sh")
        .output()
        .expect("bash must run the promotion self-check");
    assert!(
        out.status.success(),
        "promotion self-check failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn release_reads_of_the_latest_tag_fail_on_anything_but_a_missing_tag() {
    // A read that fails for any reason other than a 404 must stop the release. A masked read
    // reads as "no latest tag", which skips the never-move-backwards check and the verification.
    let wf = fs::read_to_string(".github/workflows/release.yml").expect("release workflow");
    for masked in [
        "commits/refs/tags/latest\" --jq .sha 2>/dev/null || true",
        "commits/refs/tags/latest\" --jq .sha 2>/dev/null || echo absent",
        "releases/latest\" --jq .tag_name 2>/dev/null || true",
        "git/ref/tags/latest\" >/dev/null 2>&1; then",
    ] {
        assert!(
            !wf.contains(masked),
            "release.yml masks a failed read: {masked}"
        );
    }
    assert!(
        wf.contains("echo \"reason=${status}\" >> \"$GITHUB_OUTPUT\""),
        "the latest step must say why it did not move latest, for the verify step"
    );
}

/// The identity probe in release.yml greps the aarch64 binary for the hand-written usage line to
/// prove it is huntsman-recon, not the legacy hse. Its pattern is hand-maintained, so a change to
/// the `USAGE` constant can silently stop it matching (as appending `correlate`/`run-history`
/// after `verify LEDGER` did, failing #908's aarch64 build). This ties the two together.
fn identity_probe_pattern() -> String {
    let wf = release();
    let marker = "-m1 'usage: huntsman-recon";
    let open = wf
        .find(marker)
        .expect("release.yml must grep the binary for the usage line");
    let rest = &wf[open + "-m1 '".len()..];
    rest[..rest.find('\'').expect("the grep pattern is single-quoted")].to_owned()
}

fn live_usage_line() -> String {
    let src = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/mod.rs"))
        .expect("src/cli/mod.rs");
    let marker = "const USAGE: &str = \"";
    let start = src.find(marker).expect("USAGE constant") + marker.len();
    let rest = &src[start..];
    rest[..rest.find("\";").expect("USAGE string end")].to_owned()
}

/// Whether a basic-regexp `pattern` using only `.*` and `\[`/`\]` escapes matches somewhere in
/// `text`, by the same existence rule `grep` applies: each literal segment between `.*` occurs in
/// order. The usage line is one `strings` line, so `.` never has a newline to not match.
fn bre_dotstar_matches(pattern: &str, text: &str) -> bool {
    let mut pos = 0;
    for raw in pattern.split(".*") {
        let lit = raw.replace("\\[", "[").replace("\\]", "]");
        if lit.is_empty() {
            continue;
        }
        match text[pos..].find(&lit) {
            Some(offset) => pos += offset + lit.len(),
            None => return false,
        }
    }
    true
}

#[test]
fn the_identity_probe_matches_the_usage_line_it_proves() {
    let pattern = identity_probe_pattern();
    let usage = live_usage_line();
    assert!(
        bre_dotstar_matches(&pattern, &usage),
        "release.yml identity probe no longer matches the usage line it proves:\n  pattern: {pattern}\n  usage:   {usage}"
    );
    // The pre-#908 pattern required `verify LEDGER` to be the last command; the regression that
    // failed #908's build is that it no longer is. If this ever matches again, the fix regressed.
    assert!(
        !bre_dotstar_matches("usage: huntsman-recon \\[check.*verify LEDGER\\]", &usage),
        "the usage line ends at `verify LEDGER]` again; the probe's `.*` tail is now untested"
    );
    // Dropping a command the probe anchors on must fail it: it is an identity check, not a smoke test.
    let without_verify = usage.replacen("verify LEDGER", "VERIFY_REMOVED", 1);
    assert!(
        !bre_dotstar_matches(&pattern, &without_verify),
        "the probe still matches after `verify LEDGER` is gone, so it proves nothing"
    );
}

/// Release publication must not race the independent exact-main CI workflow:
/// QEMU aarch64 library tests are part of CI, not the release's quality jobs.
#[test]
fn release_publication_waits_for_successful_exact_main_ci() {
    let wf = release();
    let publish = job(&wf, "publish");
    let gate = publish
        .find("      - name: Require successful exact-main CI before publishing")
        .expect("publish must wait for exact-main CI");
    let download = publish
        .find("      - name: Download staged release files")
        .expect("publish must download release assets");
    assert!(
        gate < download,
        "CI gate must precede all publication steps"
    );
    for required in [
        "      actions: read",
        "actions/workflows/ci.yml/runs",
        "-f head_sha=\"$GITHUB_SHA\"",
        "-f event=push",
        ".head_sha == $sha",
        ".event == \"push\"",
        "completed:success",
        "completed:*",
        "timeout-minutes: 65",
    ] {
        assert!(
            publish.contains(required),
            "release publication is missing exact-CI gate contract: {required:?}"
        );
    }
}
