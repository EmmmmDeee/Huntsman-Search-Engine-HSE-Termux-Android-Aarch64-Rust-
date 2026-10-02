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
        step.contains("        if: vars.PROMOTE_RECON_TO_LATEST == 'true'\n"),
        "moving `latest` must be gated on PROMOTE_RECON_TO_LATEST == 'true'"
    );
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
        build.contains("contents: read"),
        "build job must be read-only"
    );
    assert!(build.contains("persist-credentials: false"));
    for forbidden in ["write", "GH_TOKEN", "secrets."] {
        assert!(
            !build.contains(forbidden),
            "build job must not contain {forbidden:?}"
        );
    }
    assert!(publish.contains("contents: write"));
    assert!(publish.contains("persist-credentials: false"));
    assert!(publish.contains("needs.resolve.outputs.publish == 'true'"));
    assert!(
        publish.contains("bash .github/scripts/scan-for-keys.sh dist"),
        "publish must re-scan the downloaded bytes"
    );
    assert!(
        !publish.contains("cargo "),
        "publish job must not run cargo"
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

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("release-ci-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn scan(dir: &Path) -> (bool, String) {
    let out = Command::new("bash")
        .arg(SCAN)
        .arg(dir)
        .output()
        .expect("bash must be available");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

/// Synthetic values only: assembled at runtime so no key-shaped literal sits
/// in the source tree.
fn fake(prefix: &str, unit: &str, n: usize) -> String {
    format!("{prefix}{}", unit.repeat(n))
}

#[test]
fn scanner_passes_clean_files_and_fails_on_synthetic_keys_without_printing_them() {
    if Command::new("strings").arg("--version").output().is_err() {
        // The release workflow requires `strings`; the scanner itself fails
        // closed without it. Skip only the behavioural check on such hosts.
        return;
    }
    let clean = scratch("clean");
    fs::write(
        clean.join("p.json"),
        format!(
            "{{\"commit\":\"{}\",\"sha256\":\"{}\"}}\n",
            "a1".repeat(20),
            "b2".repeat(32)
        ),
    )
    .unwrap();
    fs::write(
        clean.join("bin"),
        b"\x00\x7fELF usage: huntsman-recon [check]\x00",
    )
    .unwrap();
    let (ok, text) = scan(&clean);
    assert!(ok, "clean fixtures must pass:\n{text}");
    assert!(text.contains("key scan: 0 finding(s)"), "{text}");

    let hibp = fake("", "0a1b2c3d", 4);
    let github = fake("ghp_", "Ab3", 13);
    let cases: [(&str, Vec<u8>, &str); 3] = [
        (
            "hex.bin",
            [b"\x00\x01 k=".as_slice(), hibp.as_bytes(), b" \x00\xff"].concat(),
            "hibp-key-hex",
        ),
        (
            "hex.json",
            format!("{{\"v\":\"{hibp}\"}}\n").into_bytes(),
            "hibp-key-hex",
        ),
        (
            "gh.bin",
            [b"\x00 t=".as_slice(), github.as_bytes(), b" \x00\xfe"].concat(),
            "github-token",
        ),
    ];
    for (file, bytes, rule) in cases {
        let dir = scratch(file);
        fs::write(dir.join(file), &bytes).unwrap();
        let (ok, text) = scan(&dir);
        assert!(!ok, "{file} must fail the scan:\n{text}");
        assert!(text.contains(&format!("rule={rule}")), "{file}: {text}");
        assert!(
            !text.contains(&hibp) && !text.contains(&github),
            "{file}: scanner output must not contain the value"
        );
    }
}
