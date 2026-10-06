//! Binary acceptance. `check` runs in a scratch directory so the repo is not touched.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("huntsman-cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn check_reproduces_committed_artifacts() {
    let dir = scratch("check");
    let out = bin().arg("check").current_dir(&dir).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout,
        "command_hierarchy=accepted\naccepted techniques=0\nbrisbane_sydney_m=732379\n"
    );
    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("var");
    for name in ["ledger.json", "navigator.json", "stix-bundle.json"] {
        assert_eq!(
            fs::read(dir.join("var").join(name)).unwrap(),
            fs::read(committed.join(name)).unwrap(),
            "var/{name} differs from `check` output; re-run `cargo run -- check`"
        );
    }
    let verify = bin()
        .args(["verify", "var/ledger.json"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stdout).contains("admitted=0"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn failures_exit_nonzero() {
    let dir = scratch("fail");
    let missing = dir.join("missing");
    let out = bin()
        .args(["search", "port"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66), "unreadable dir is not hits=0");
    fs::write(dir.join("ledger.json"), b"[{\"prev\":\"x\"}]").unwrap();
    let out = bin()
        .arg("verify")
        .arg(dir.join("ledger.json"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(65));
    for query in ["", "a", "- !"] {
        let out = bin().args(["search", query]).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{query:?} is not hits=0");
        assert!(out.stdout.is_empty(), "{:?}", out.stdout);
    }
    assert_eq!(bin().arg("nope").output().unwrap().status.code(), Some(64));
    assert_eq!(
        bin()
            .args(["geo", "91,0", "0,0"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(65)
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn help_and_version_are_available() {
    let help = bin().arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("Commands:"));
    assert!(help.contains("fetch                 Make a guarded HTTP request"));
    assert!(help.contains("public-only"));

    for (command, usage) in [
        ("geo", "geo LAT,LON LAT,LON"),
        ("search", "search QUERY [DIR]"),
        ("people", "people NAME [--save FILE]"),
        ("fetch", "fetch URL [--body]"),
        ("hibp", "hibp [breach NAME"),
        ("recon", "recon crtsh TARGET"),
    ] {
        let out = bin().args([command, "--help"]).output().unwrap();
        assert!(out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(usage),
            "{command} help should include {usage:?}"
        );
    }

    let positional_help = bin().args(["classify", "200", "--help"]).output().unwrap();
    assert!(positional_help.status.success());
    assert!(
        String::from_utf8_lossy(&positional_help.stdout).contains("outcome=inconclusive"),
        "a positional response body equal to --help must reach classify"
    );

    let version = bin().arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        format!("huntsman-recon {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn people_skips_single_token_without_network() {
    let out = bin().args(["people", "Madonna"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("skipped"),
        "skip path must print a skip line: {stdout:?}"
    );
}

#[test]
fn people_missing_name_is_usage() {
    let out = bin().arg("people").output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
}

#[test]
fn people_skip_does_not_write_save_file() {
    let dir = scratch("people-skip-save");
    let path = dir.join("skipped.json");
    let out = bin()
        .args(["people", "Madonna", "--save"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("skipped"), "{stdout:?}");
    assert!(!stdout.contains("saved="), "{stdout:?}");
    assert!(!path.exists(), "skip must not create {}", path.display());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn people_save_without_path_is_usage() {
    let out = bin().args(["people", "--save"]).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
}

#[test]
fn classify_reports_causal_outcome_and_action() {
    let run = |status: &str, body: &str| {
        let out = bin().args(["classify", status, body]).output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let waf = run("403", "<html>checking your browser cloudflare</html>");
    assert!(waf.ends_with("outcome=bot_waf\naction=backoff\n"), "{waf}");
    let auth = run("403", "key revoked");
    assert!(
        auth.ends_with("outcome=auth_rejected\naction=require_credential\n"),
        "{auth}"
    );
    let ok = run("200", "{}");
    assert!(ok.ends_with("outcome=inconclusive\naction=retry\n"), "{ok}");
}

#[test]
fn multibyte_documents_do_not_crash_search() {
    let dir = scratch("utf8");
    fs::write(dir.join("a.txt"), "[éééééé datadome zürich").unwrap();
    let out = bin().args(["search", "zürich"]).arg(&dir).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn identifier_geohash_and_coarsen_commands() {
    let run = |args: &[&str]| {
        let out = bin().args(args).output().unwrap();
        (out.status.code(), String::from_utf8(out.stdout).unwrap())
    };
    assert_eq!(
        run(&["id", "53 004 085 616"]),
        (Some(0), "abn=53004085616\nacn=004085616\n".into())
    );
    assert_eq!(
        run(&["id", "062-000"]),
        (
            Some(0),
            "bsb=062000\ninstitution=Commonwealth Bank\n".into()
        )
    );
    assert_eq!(run(&["id", "51824753557"]).0, Some(65));
    assert_eq!(run(&["id"]).0, Some(64));
    assert_eq!(
        run(&["geohash", "57.64911,10.40744", "11"]),
        (Some(0), "u4pruydqqvj\n".into())
    );
    assert_eq!(
        run(&["geohash", "57.64911,10.40744"]),
        (Some(0), "u4pruyd\n".into())
    );
    assert_eq!(
        run(&["geohash", "0,0", "0"]).0,
        Some(65),
        "precision 0 is not clamped"
    );
    assert_eq!(run(&["geohash", "0,0", "99"]).0, Some(65));
    assert_eq!(run(&["geohash", "0,0", "x"]).0, Some(65));
    assert_eq!(
        run(&["coarsen", "-27.4698,153.0251"]),
        (Some(0), "-27.5,153.0\n".into())
    );
    assert_eq!(run(&["coarsen", "999,999"]).0, Some(65));
}

#[test]
fn recon_refuses_bad_usage_and_a_missing_key_before_any_request() {
    for args in [
        &["recon"][..],
        &["recon", "nope", "x"],
        &["recon", "crtsh", " "],
        &["recon", "dns", " "],
        &["recon", "stolen-tax", "  "],
        &["recon", "stolen-tax", "a@example.com", "--bogus", "f"],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{args:?}");
    }

    let bad_domain = bin().args(["recon", "dns", "localhost"]).output().unwrap();
    assert_eq!(bad_domain.status.code(), Some(65));
    assert!(
        String::from_utf8_lossy(&bad_domain.stderr).contains("bad domain"),
        "{:?}",
        String::from_utf8_lossy(&bad_domain.stderr)
    );
    assert_eq!(bad_domain.stdout.len(), 0);

    let out = bin()
        .args(["recon", "stolen-tax", "a@example.com"])
        .env_remove("HUNTSMAN_STOLEN_TAX_KEY")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
    assert!(String::from_utf8_lossy(&out.stderr).contains("HUNTSMAN_STOLEN_TAX_KEY"));
    assert_eq!(out.stdout.len(), 0);

    let dir = scratch("recon");
    let keys = dir.join("keys.env");
    fs::write(
        &keys,
        "OTHER_KEY=k3y-8f2a91\nHUNTSMAN_STOLEN_TAX_KEY=changeme\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();
    }
    for file in [keys.clone(), dir.join("absent.env")] {
        let out = bin()
            .args(["recon", "stolen-tax", "a@example.com", "--keys"])
            .arg(&file)
            .env_remove("HUNTSMAN_STOLEN_TAX_KEY")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(66), "{}", file.display());
    }
    let _ = fs::remove_dir_all(&dir);
}
