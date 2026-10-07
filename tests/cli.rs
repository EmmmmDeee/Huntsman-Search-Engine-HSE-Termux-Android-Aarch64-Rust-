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
        "command_hierarchy=accepted\nselftest_admitted_techniques=0\nbrisbane_sydney_m=732379\n"
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
fn directive_check_is_useful_outside_a_source_checkout() {
    let dir = scratch("directive-embedded");
    let out = bin()
        .args(["directive", "check"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("directive=check"));
    assert!(stdout.contains("scope=embedded"));
    assert!(stdout.contains("mirrors=0"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn directive_check_verifies_an_explicit_repository_root() {
    let dir = scratch("directive-repository");
    let root = env!("CARGO_MANIFEST_DIR");
    let out = bin()
        .args(["directive", "check", root])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("scope=repository"));
    assert!(stdout.contains("mirrors=6"));
    assert!(stdout.contains(&format!("root={root}")));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn directive_sync_outside_a_checkout_is_actionable() {
    let dir = scratch("directive-sync-no-root");
    let out = bin()
        .args(["directive", "sync"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires a source checkout"));
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
        ("diagnostics", "diagnostics [--json]"),
        ("build-sha", "build-sha"),
        ("geo", "geo LAT,LON LAT,LON"),
        ("search", "search QUERY [DIR]"),
        ("domain-lifecycle", "domain-lifecycle analyze INPUT.json"),
        ("people", "people NAME [--save FILE]"),
        ("phone", "phone NUMBER [--save FILE]"),
        ("scan", "scan SELECTOR [-k people|email|username|phone]"),
        ("investigate", "investigate TEXT..."),
        ("modules", "modules [--json]"),
        ("attack", "attack status|coverage|gaps [--json]"),
        ("query", "query QUERY..."),
        ("sf", "sf [-M|-T|-V]"),
        ("serve", "serve [--bind ADDR]"),
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
fn diagnostics_and_build_sha_are_offline_structured_and_non_secret() {
    let dir = scratch("diagnostics");
    let diagnostics = bin()
        .args(["diagnostics", "--json"])
        .env("HOME", &dir)
        .env("PREFIX", "/usr")
        .env_remove("TERMUX_VERSION")
        .output()
        .unwrap();
    assert!(
        diagnostics.status.success(),
        "{}",
        String::from_utf8_lossy(&diagnostics.stderr)
    );
    let stdout = String::from_utf8(diagnostics.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        value["build_sha"]
            .as_str()
            .is_some_and(|sha| !sha.is_empty())
    );
    assert!(value["reachable_modules"].as_u64().unwrap() > 0);
    assert!(
        value["network_modules"].as_u64().unwrap() <= value["reachable_modules"].as_u64().unwrap()
    );
    assert!(
        value["attack_mapped_modules"].as_u64().unwrap()
            <= value["network_modules"].as_u64().unwrap()
    );
    assert!(value["providers_total"].as_u64().unwrap() > 0);
    assert!(
        value["providers_configured"].as_u64().unwrap()
            <= value["providers_total"].as_u64().unwrap()
    );
    assert_eq!(value["credential_resolution"], "ok");
    assert_eq!(value["credential_warning"], false);
    assert_eq!(value["selfcheck_command"], "huntsman-recon check");
    assert!(!stdout.contains("fingerprint"));
    assert!(!stdout.contains("HUNTSMAN_"));

    let sha = bin().arg("build-sha").output().unwrap();
    assert!(sha.status.success());
    let expected = match option_env!("HUNTSMAN_BUILD_SHA") {
        Some(value) => value,
        None => "unknown",
    };
    assert_eq!(
        String::from_utf8(sha.stdout).unwrap(),
        format!("{expected}\n")
    );

    let bad = bin().args(["diagnostics", "--live"]).output().unwrap();
    assert_eq!(bad.status.code(), Some(64));
    let _ = fs::remove_dir_all(&dir);
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
fn scan_routes_single_token_to_people_without_network() {
    let out = bin().args(["scan", "Madonna"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("scan_route=people"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("skipped"));
}

#[test]
fn scan_kind_override_routes_phone_offline() {
    let out = bin()
        .args(["scan", "-k", "phone", "0412 345 678"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("scan_route=phone"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("+61412345678"));
}

#[test]
fn scan_auto_routes_recognised_phone_syntax() {
    let out = bin().args(["scan", "+44 20 7183 8750"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("scan_route=phone"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("country:GB"));
}

#[test]
fn scan_input_file_runs_every_unique_offline_seed() {
    let dir = scratch("scan-input-file");
    let path = dir.join("seeds.txt");
    fs::write(
        &path,
        "# phones\n0412 345 678\n\n+44 20 7183 8750\n0412 345 678\n",
    )
    .unwrap();

    let out = bin()
        .arg("scan")
        .arg("--input-file")
        .arg(&path)
        .args(["-k", "phone"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("+61412345678"), "{stdout:?}");
    assert!(stdout.contains("+442071838750"), "{stdout:?}");
    assert!(stderr.contains("batch: scanning 2 seed(s)"), "{stderr:?}");
    assert!(
        stderr.contains("batch complete: 2 succeeded, 0 failed, 2 total"),
        "{stderr:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn scan_input_file_attempts_remaining_seeds_after_failure() {
    let dir = scratch("scan-input-file-failure");
    let path = dir.join("seeds.txt");
    fs::write(&path, "not-a-phone\n0412 345 678\n").unwrap();

    let out = bin()
        .arg("scan")
        .arg("--input-file")
        .arg(&path)
        .args(["-k", "phone"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(65));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("+61412345678"),
        "later valid seed was not attempted: {stdout:?}"
    );
    assert!(
        stderr.contains("batch complete: 1 succeeded, 1 failed, 2 total"),
        "{stderr:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn scan_input_file_refuses_ambiguous_save_or_selector_mix() {
    let dir = scratch("scan-input-file-usage");
    let path = dir.join("seeds.txt");
    fs::write(&path, "0412 345 678\n").unwrap();

    let save = bin()
        .arg("scan")
        .arg("--input-file")
        .arg(&path)
        .args(["--save", "out.json"])
        .output()
        .unwrap();
    assert_eq!(save.status.code(), Some(64));

    let selector = bin()
        .arg("scan")
        .arg("0412 345 678")
        .arg("--input-file")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(selector.status.code(), Some(64));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn modules_lists_only_reachable_catalog_entries() {
    let text = bin().arg("modules").output().unwrap();
    assert_eq!(text.status.code(), Some(0));
    let stdout = String::from_utf8(text.stdout).unwrap();
    for name in [
        "phone_intl",
        "github_user",
        "gravatar",
        "classify_module",
        "sf_compat",
        "web_server",
        "crtsh",
    ] {
        assert!(stdout.contains(name), "missing reachable module {name}");
    }
    assert!(
        !stdout.contains("netlas"),
        "registered-but-unwired services must not appear as reachable modules"
    );

    let json = bin().args(["modules", "--json"]).output().unwrap();
    assert_eq!(json.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        value["count"].as_u64(),
        value["modules"].as_array().map(|items| items.len() as u64)
    );

    let web_query = value["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["name"] == "web_query")
        .expect("web_query reachable module");
    assert_eq!(web_query["category"], "search");

    let bad = bin().args(["modules", "--all"]).output().unwrap();
    assert_eq!(bad.status.code(), Some(64));
}

#[test]
fn attack_restores_legacy_static_coverage_surface() {
    let status = bin().args(["attack", "status", "--json"]).output().unwrap();
    assert_eq!(status.status.code(), Some(0));
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status_json["tactic_id"], "TA0043");
    assert_eq!(status_json["coverage_basis"], "leaf_techniques");
    assert!(status_json["leaf_techniques_total"].as_u64().unwrap() > 0);
    assert!(status_json["leaf_techniques_covered"].as_u64().unwrap() > 0);

    let coverage = bin()
        .args(["attack", "coverage", "--json"])
        .output()
        .unwrap();
    assert_eq!(coverage.status.code(), Some(0));
    let coverage_json: serde_json::Value = serde_json::from_slice(&coverage.stdout).unwrap();
    let covered = coverage_json["covered"].as_array().unwrap();
    covered
        .first()
        .expect("ATT&CK static coverage must contain at least one covered leaf");
    assert!(
        covered
            .iter()
            .any(|row| !row["modules"].as_array().unwrap().is_empty()),
        "static coverage must carry evidence from at least one reachable module"
    );

    let gaps = bin().args(["attack", "gaps", "--json"]).output().unwrap();
    assert_eq!(gaps.status.code(), Some(0));
    let gaps_json: serde_json::Value = serde_json::from_slice(&gaps.stdout).unwrap();
    assert!(gaps_json["gaps"].is_array());

    let navigator = bin().args(["attack", "navigator"]).output().unwrap();
    assert_eq!(navigator.status.code(), Some(0));
    let navigator_json: serde_json::Value = serde_json::from_slice(&navigator.stdout).unwrap();
    assert_eq!(navigator_json["domain"], "enterprise-attack");
    navigator_json["techniques"]
        .as_array()
        .unwrap()
        .first()
        .expect("Navigator layer must contain ATT&CK techniques");

    let bad = bin()
        .args(["attack", "navigator", "--json"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("attack status|coverage|gaps"));
}

#[test]
fn sf_metadata_and_offline_phone_path_work() {
    let modules = bin().args(["sf", "-M"]).output().unwrap();
    assert_eq!(modules.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&modules.stdout);
    assert!(stdout.contains("phone_intl"), "{stdout:?}");
    assert!(stdout.contains("github_user"), "{stdout:?}");

    let types = bin().args(["sf", "-T"]).output().unwrap();
    assert_eq!(types.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&types.stdout);
    assert!(stdout.contains("EMAILADDR"), "{stdout:?}");
    assert!(stdout.contains("PHONE_NUMBER"), "{stdout:?}");

    let scan = bin()
        .args(["sf", "-s", "+61412345678", "-u", "passive", "-o", "json"])
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(value[0]["event_type"], "PHONE_NUMBER");
    assert_eq!(value[0]["data"], "+61412345678");
}

#[test]
fn sf_rejects_unrebuilt_target_classes_explicitly() {
    let out = bin()
        .args(["sf", "-s", "example.org", "-u", "all"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not available yet"));
}

#[test]
fn serve_rejects_invalid_or_unconfigured_public_bind_before_listening() {
    let invalid = bin()
        .args(["serve", "--bind", "not-a-socket"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid serve bind"));

    let public = bin()
        .args(["serve", "--bind", "0.0.0.0:8080"])
        .env_remove("HSE_AUTH_TOKEN")
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&public.stderr).contains("HSE_AUTH_TOKEN"));
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
fn investigate_extracts_actionable_entities_without_network() {
    let out = bin()
        .args([
            "investigate",
            "mail",
            "ada@example.com",
            "visit",
            "https://example.com",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("entities=2"), "{stdout:?}");
    assert!(stdout.contains("email\tada@example.com"), "{stdout:?}");
    assert!(stdout.contains("url\thttps://example.com"), "{stdout:?}");
    assert!(stdout.contains("evidence\tclassifier"), "{stdout:?}");
}

#[test]
fn investigate_reads_one_bounded_local_file() {
    let dir = scratch("investigate-file");
    let path = dir.join("input.txt");
    fs::write(
        &path,
        "contact ada@example.com and visit https://example.org",
    )
    .unwrap();
    let out = bin()
        .arg("investigate")
        .arg("--file")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("entities=2"), "{stdout:?}");
    assert!(stdout.contains("email\tada@example.com"), "{stdout:?}");
    assert!(stdout.contains("url\thttps://example.org"), "{stdout:?}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn query_missing_terms_is_usage() {
    let out = bin().arg("query").output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(out.stdout, Vec::<u8>::new());
    assert!(String::from_utf8_lossy(&out.stderr).contains("query QUERY"));
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
