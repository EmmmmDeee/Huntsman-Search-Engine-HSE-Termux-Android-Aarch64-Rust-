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
    assert_eq!(
        out.status.code(),
        Some(65),
        "a malformed ledger is bad data"
    );
    let out = bin()
        .arg("verify")
        .arg(dir.join("absent-ledger.json"))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(66),
        "a missing ledger is unreadable input, not bad data"
    );
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
        (
            "scan",
            "scan SELECTOR [-k people|email|exposure|username|phone|domain|ip|netblock|asn|network|crypto|geocode]",
        ),
        ("investigate", "investigate TEXT..."),
        ("modules", "modules [--json]"),
        ("attack", "attack status|coverage|gaps [--json]"),
        ("query", "query QUERY..."),
        ("sf", "sf [-M|-T|-V]"),
        ("serve", "serve [--bind ADDR] [--history DIR]"),
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
    assert_eq!(value["termux"], "not_detected");
    assert!(value.get("build_sha_known").is_none());
    assert!(value.get("android_target").is_none());
    assert!(value.get("credential_warning").is_none());
    assert_eq!(value["selfcheck_command"], "huntsman-recon check");
    assert!(!stdout.contains("fingerprint"));
    assert!(!stdout.contains("HUNTSMAN_"));

    let sha = bin().arg("build-sha").output().unwrap();
    assert!(sha.status.success());
    let expected = huntsman_recon::diagnostics::embedded_build_sha();
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
fn scan_refuses_an_inferred_single_word_instead_of_skipping_it() {
    let out = bin().args(["scan", "Madonna"]).output().unwrap();
    assert_eq!(out.status.code(), Some(65));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("scan_route=people"), "{err}");
    assert!(err.contains("pass -k people"), "{err}");
    assert!(String::from_utf8_lossy(&out.stdout).is_empty());
}

#[test]
fn scan_does_not_report_a_mistyped_phone_as_a_skipped_name() {
    let out = bin().args(["scan", "0412"]).output().unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("scan_route=people"));
}

#[test]
fn scan_with_an_explicit_people_kind_refuses_a_single_token_instead_of_skipping() {
    // A skip exits 0, which would report a refused lookup as a success. The scan refuses it (65),
    // as main did, and the people command is not reached.
    let out = bin()
        .args(["scan", "-k", "people", "Madonna"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(65));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("scan_route=people"), "{err}");
    assert!(err.contains("needs a name"), "{err}");
    assert!(String::from_utf8_lossy(&out.stdout).is_empty());
}

#[test]
fn scan_refuses_an_option_that_a_leading_space_hides_from_the_check() {
    let out = bin().args(["scan", " --bogus", "Ada"]).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("needs SELECTOR before options"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
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
        "phone_nanp",
        "github_user",
        "gravatar",
        "duolingo",
        "openpgp_keys",
        "classify_module",
        "sf_compat",
        "web_server",
        "crtsh",
        "netlas",
        "otx",
        "urlscan",
        "ipinfo",
        "kickbox",
        "robtex",
        "hackertarget",
        "stopforumspam",
        "isc",
        "maltiverse",
        "phishstats",
        "cleantalk",
        "xposed_or_not",
    ] {
        assert!(stdout.contains(name), "missing reachable module {name}");
    }
    assert!(
        !stdout.contains("onyphe"),
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
}

/// A southern-hemisphere point's leading dash is a value, not an option: `scans run` routes
/// `-33.86,151.21` to the network lookup as it does `33.86,151.21`. Choosing a module that does
/// not take a point stops both offline, after routing.
#[test]
fn scans_run_takes_a_point_with_a_negative_latitude() {
    let home = scratch("scans-negative-point");
    for point in ["-33.86,151.21", "33.86,151.21"] {
        let out = bin()
            .args(["scans", "run", point, "-m", "sfp_hibp"])
            .env("HOME", &home)
            .env_remove("HUNTSMAN_HOME")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{point}: {stderr}");
        assert!(
            stderr.contains("the network lookup asks"),
            "{point}: {stderr}"
        );
    }
    let _ = fs::remove_dir_all(&home);
}

/// `sf -s` saves its scan with the others, as `sf.py` does, so `scans` reads it and `sf -C`
/// correlates it again.
#[test]
fn sf_scan_is_a_saved_scan_that_scans_reads_and_sf_correlates() {
    let home = scratch("sf-saved");
    let run = |args: &[&str]| bin().args(args).env("HOME", &home).output().unwrap();
    let scan = run(&["sf", "-s", "+61412345678", "-u", "passive", "-o", "json"]);
    let stderr = String::from_utf8_lossy(&scan.stderr);
    assert_eq!(scan.status.code(), Some(0), "{stderr}");
    let value: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(value[0]["event_type"], "PHONE_NUMBER");
    assert_eq!(value[0]["data"], "+61412345678");

    let list = run(&["scans", "list", "--json"]);
    assert_eq!(list.status.code(), Some(0));
    let list: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let [saved] = list.as_array().unwrap().as_slice() else {
        panic!("one saved scan: {list}");
    };
    assert_eq!(saved["target"], "+61412345678");
    assert_eq!(saved["target_type"], "PHONE_NUMBER");
    assert_eq!(saved["status"], "FINISHED");
    let id = saved["id"].as_str().unwrap();
    assert!(stderr.contains(id), "{stderr}");
    assert_eq!(
        saved["elements"].as_u64(),
        Some(value.as_array().unwrap().len() as u64)
    );

    let correlate = run(&["sf", "-C", id]);
    assert_eq!(
        correlate.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&correlate.stderr)
    );
    assert!(String::from_utf8_lossy(&correlate.stdout).starts_with("ID\tRISK\tRULE"));
    assert_eq!(run(&["sf", "-C", "no-such-scan"]).status.code(), Some(66));
    let quiet = run(&["sf", "-q", "-s", "+61412345678"]);
    assert_eq!(quiet.status.code(), Some(0));
    assert!(quiet.stderr.is_empty(), "{:?}", quiet.stderr);
    let _ = fs::remove_dir_all(&home);
}

/// `scans compare` sets a later scan against an earlier one: the change per type, then what was
/// added and removed, or the same as a file.
#[test]
fn scans_compare_lists_what_a_later_scan_added_and_removed() {
    let home = scratch("scans-compare");
    let run = |args: &[&str]| bin().args(args).env("HOME", &home).output().unwrap();
    let id = |args: &[&str]| {
        let out = run(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        record["id"].as_str().unwrap().to_owned()
    };
    let earlier = id(&["scans", "run", "+61412345678", "-u", "passive", "--json"]);
    let later = id(&["scans", "run", "+61412345679", "-u", "passive", "--json"]);

    let table = run(&["scans", "compare", &earlier, &later]);
    let stdout = String::from_utf8_lossy(&table.stdout);
    assert_eq!(
        table.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&table.stderr)
    );
    assert!(
        stdout.starts_with(&format!("earlier={earlier} ")),
        "{stdout}"
    );
    assert!(stdout.contains(&format!("\nlater={later} ")), "{stdout}");
    assert!(
        stdout.contains("\nTYPE\tEARLIER\tLATER\tADDED\tREMOVED\tKEPT\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("\nPHONE_NUMBER\t1\t1\t1\t1\t0\n"),
        "{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("+\tPHONE_NUMBER\t") && line.ends_with("\t+61412345679")),
        "{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("-\tPHONE_NUMBER\t") && line.ends_with("\t+61412345678")),
        "{stdout}"
    );

    let json = run(&["scans", "compare", &earlier, &later, "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["unchanged"], false);
    let same = run(&["scans", "compare", &earlier, &earlier, "--json"]);
    let same: serde_json::Value = serde_json::from_slice(&same.stdout).unwrap();
    assert_eq!(same["unchanged"], true);

    let csv = run(&["scans", "compare", &earlier, &later, "-f", "csv"]);
    assert_eq!(csv.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&csv.stdout)
            .starts_with("Change,Scan Name,Updated,Type,Module,Source,F/P,Data\r\n")
    );
    assert_eq!(run(&["scans", "compare", &earlier]).status.code(), Some(64));
    assert_eq!(
        run(&["scans", "compare", &earlier, "0000000000000000"])
            .status
            .code(),
        Some(66)
    );
    let _ = fs::remove_dir_all(&home);
}

/// A local Spiderfoot-format rule, under `home`, that raises a HIGH correlation for any phone
/// number. Returns the directory holding it.
fn write_phone_rule(home: &Path) -> PathBuf {
    let rules = home.join("rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(
        rules.join("phone_present.yaml"),
        "id: phone_present\nversion: 1\nmeta:\n  name: Phone number present\n  description: >\n    A phone number is in the scan.\n  risk: HIGH\ncollections:\n  - collect:\n      - method: exact\n        field: type\n        value: PHONE_NUMBER\naggregation:\n  field: data\nheadline:\n  text: \"Phone number found: {data}\"\n  publish_collections:\n    - 1\n",
    )
    .unwrap();
    rules
}

/// `scans alert` decides whether a later scan of one target warrants attention: a new correlation
/// at or above `--min-risk` raises it and exits 1; a correlation that has gone never does; scans of
/// different targets are refused. The rule here is a local Spiderfoot-format file, so nothing is
/// fetched.
#[test]
fn scans_alert_raises_on_a_new_correlation_and_never_on_one_that_went() {
    let home = scratch("scans-alert");
    let rules = write_phone_rule(&home);
    let run = |args: &[&str]| bin().args(args).env("HOME", &home).output().unwrap();
    let id = |args: &[&str]| {
        let out = run(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        record["id"].as_str().unwrap().to_owned()
    };
    let earlier = id(&["scans", "run", "+61412345678", "-u", "passive", "--json"]);
    let later = id(&["scans", "run", "+61412345678", "-u", "passive", "--json"]);
    let other = id(&["scans", "run", "+61412345679", "-u", "passive", "--json"]);

    let quiet = run(&["scans", "alert", &earlier, &later]);
    assert_eq!(quiet.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&quiet.stdout).starts_with("no alert\t"),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );

    let correlated = run(&[
        "scans",
        "correlate",
        &later,
        "--rules",
        rules.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        correlated.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&correlated.stderr)
    );

    let raised = run(&["scans", "alert", &earlier, &later]);
    assert_eq!(raised.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&raised.stdout);
    assert!(stdout.starts_with("ALERT\t"), "{stdout}");
    assert!(
        stdout.contains("HIGH\tcorrelation\tphone_present\t"),
        "{stdout}"
    );

    let json = run(&["scans", "alert", &earlier, &later, "--json"]);
    assert_eq!(json.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["alert"]["raised"], true);
    assert_eq!(json["alert"]["reasons"][0]["kind"], "correlation");
    assert_eq!(json["alert"]["reasons"][0]["risk"], "HIGH");

    let medium = run(&["scans", "alert", &earlier, &later, "--min-risk", "medium"]);
    assert_eq!(medium.status.code(), Some(1));

    let gone = run(&["scans", "alert", &later, &earlier]);
    assert_eq!(
        gone.status.code(),
        Some(0),
        "a correlation that went away must not raise an alert"
    );

    let refused = run(&["scans", "alert", &earlier, &other]);
    assert_eq!(refused.status.code(), Some(64));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("different targets"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(run(&["scans", "alert", &earlier]).status.code(), Some(64));
    assert_eq!(
        run(&["scans", "alert", &earlier, &later, "--min-risk", "urgent"])
            .status
            .code(),
        Some(64)
    );
    assert_eq!(
        run(&["scans", "alert", &earlier, "0000000000000000"])
            .status
            .code(),
        Some(66)
    );
    let _ = fs::remove_dir_all(&home);
}

/// `scans watch` runs a saved scan's target again, saves the new scan, and alerts on what it finds
/// that the earlier scan did not.
#[test]
fn scans_watch_runs_the_target_again_and_alerts_on_what_is_new() {
    let home = scratch("scans-watch");
    let rules = write_phone_rule(&home);
    let run = |args: &[&str]| bin().args(args).env("HOME", &home).output().unwrap();
    let earlier = {
        let out = run(&["scans", "run", "+61412345678", "-u", "passive", "--json"]);
        assert_eq!(out.status.code(), Some(0));
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        record["id"].as_str().unwrap().to_owned()
    };

    let watched = run(&[
        "scans",
        "watch",
        &earlier,
        "--rules",
        rules.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        watched.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&watched.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&watched.stdout).unwrap();
    assert_eq!(json["earlier"], earlier.as_str());
    assert_ne!(json["later"], earlier.as_str(), "watch saves a new scan");
    assert_eq!(json["alert"]["raised"], true);
    assert_eq!(json["alert"]["reasons"][0]["rule"], "phone_present");

    let listed = run(&["scans", "list", "--json"]);
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(2),
        "the earlier scan and the one watch ran"
    );

    let quiet = run(&["scans", "watch", &earlier]);
    assert_eq!(quiet.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&quiet.stdout).starts_with("no alert\t"),
        "{}",
        String::from_utf8_lossy(&quiet.stdout)
    );

    assert_eq!(run(&["scans", "watch"]).status.code(), Some(64));
    assert_eq!(
        run(&["scans", "watch", "0000000000000000"]).status.code(),
        Some(66)
    );
    let _ = fs::remove_dir_all(&home);
}

/// `scans alerts` lists every decision `alert` and `watch` made, raised or not, oldest first.
#[test]
fn scans_alerts_keeps_a_history_of_every_decision() {
    let home = scratch("scans-alerts");
    let rules = write_phone_rule(&home);
    let run = |args: &[&str]| bin().args(args).env("HOME", &home).output().unwrap();
    let earlier = {
        let out = run(&["scans", "run", "+61412345678", "-u", "passive", "--json"]);
        assert_eq!(out.status.code(), Some(0));
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        record["id"].as_str().unwrap().to_owned()
    };
    assert_eq!(
        run(&["scans", "alert", &earlier, &earlier]).status.code(),
        Some(0)
    );
    let watched = run(&[
        "scans",
        "watch",
        &earlier,
        "--rules",
        rules.to_str().unwrap(),
    ]);
    assert_eq!(watched.status.code(), Some(1));

    let json = run(&["scans", "alerts", "--json"]);
    assert_eq!(json.status.code(), Some(0));
    let entries: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let entries = entries.as_array().unwrap();
    assert_eq!(entries.len(), 2, "one quiet decision and one raised one");
    assert_eq!(entries[0]["raised"], false);
    assert_eq!(entries[0]["earlier"], earlier.as_str());
    assert_eq!(entries[1]["raised"], true);
    assert_eq!(entries[1]["reasons"][0]["rule"], "phone_present");
    assert!(
        entries[0].get("target").is_none(),
        "the history keeps no target"
    );

    let table = run(&["scans", "alerts"]);
    let stdout = String::from_utf8_lossy(&table.stdout);
    assert!(
        stdout.starts_with("AT\tRAISED\tEARLIER\tLATER\tREASONS\n"),
        "{stdout}"
    );
    assert_eq!(stdout.lines().count(), 3, "{stdout}");
    assert_eq!(run(&["scans", "alerts", "extra"]).status.code(), Some(64));
    let _ = fs::remove_dir_all(&home);
}

/// `--notify` posts a phone notification through `termux-notification` when an alert is raised,
/// naming the risk and rule but never the target; without the helper it exits 69; a decision
/// that raises nothing posts nothing. A fake helper on PATH stands in for Termux:API.
#[cfg(unix)]
#[test]
fn scans_notify_posts_a_phone_notification_without_the_target() {
    use std::os::unix::fs::PermissionsExt;
    let home = scratch("scans-notify");
    let rules = write_phone_rule(&home);
    let helpers = home.join("bin");
    let nothing = home.join("empty");
    fs::create_dir_all(&helpers).unwrap();
    fs::create_dir_all(&nothing).unwrap();
    let notified = home.join("notified");
    let helper = helpers.join("termux-notification");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
            notified.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |path: &Path, args: &[&str]| {
        bin()
            .args(args)
            .env("HOME", &home)
            .env("PATH", path)
            .output()
            .unwrap()
    };
    let earlier = {
        let out = run(
            &helpers,
            &["scans", "run", "+61412345678", "-u", "passive", "--json"],
        );
        assert_eq!(out.status.code(), Some(0));
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        record["id"].as_str().unwrap().to_owned()
    };
    let rules = rules.to_str().unwrap();

    let raised = run(
        &helpers,
        &["scans", "watch", &earlier, "--rules", rules, "--notify"],
    );
    assert_eq!(
        raised.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&raised.stderr)
    );
    let posted = fs::read_to_string(&notified).unwrap();
    assert!(posted.contains("Huntsman alert"), "{posted}");
    assert!(posted.contains("HIGH phone_present"), "{posted}");
    assert!(!posted.contains("+61412345678"), "{posted}");

    let missing = run(
        &nothing,
        &["scans", "watch", &earlier, "--rules", rules, "--notify"],
    );
    assert_eq!(missing.status.code(), Some(69));
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("termux-notification"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );

    fs::remove_file(&notified).unwrap();
    let quiet = run(
        &helpers,
        &["scans", "alert", &earlier, &earlier, "--notify"],
    );
    assert_eq!(quiet.status.code(), Some(0));
    assert!(
        !notified.exists(),
        "a decision that raises nothing posts nothing"
    );
    let _ = fs::remove_dir_all(&home);
}

/// `scans prune --keep N` lists the ended scans beyond the newest N of each target and deletes
/// them only with `--apply`, keeping the newest; it refuses to run without a `--keep` of at least 1.
/// `scans cycle` is one continuous cycle a scheduler can run: off until targets are configured,
/// it then runs the due target's scan to its end, and the next run finds nothing due; a keys-file
/// setting is read as serve reads it, and a wrong one is refused naming it.
#[test]
fn scans_cycle_runs_what_is_due_once_and_then_nothing() {
    let home = scratch("scans-cycle");
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let mut command = bin();
        command.args(args).env("HOME", &home);
        for name in [
            "HUNTSMAN_HOME",
            "HUNTSMAN_ENV_FILE",
            "HUNTSMAN_CONTINUOUS_TARGETS",
            "HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES",
            "HUNTSMAN_CONTINUOUS_NOTIFY",
            "HUNTSMAN_CONTINUOUS_KEEP",
        ] {
            command.env_remove(name);
        }
        command.envs(env.iter().copied()).output().unwrap()
    };
    let off = run(&["scans", "cycle"], &[]);
    assert_eq!(off.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&off.stderr).contains("HUNTSMAN_CONTINUOUS_TARGETS"));
    assert_eq!(run(&["scans", "cycle", "x"], &[]).status.code(), Some(64));

    let keys = home.join(".huntsman.env");
    fs::write(&keys, "HUNTSMAN_CONTINUOUS_TARGETS=+61412345678\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let first = run(&["scans", "cycle", "--json"], &[]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let tally: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(tally["collected"], 1, "{tally}");
    assert_eq!(tally["failed"], 0, "{tally}");
    let listed = run(&["scans", "list", "--json"], &[]);
    let rows: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["status"], "FINISHED", "run to its end before exit");

    let again = run(&["scans", "cycle"], &[]);
    assert_eq!(again.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&again.stdout).starts_with("cycle: 0 scans collected, 0 failed"),
        "{}",
        String::from_utf8_lossy(&again.stdout)
    );

    let wrong = run(&["scans", "cycle"], &[("HUNTSMAN_CONTINUOUS_KEEP", "none")]);
    assert_eq!(wrong.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("HUNTSMAN_CONTINUOUS_KEEP"));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn scans_prune_lists_then_deletes_only_what_is_beyond_the_newest() {
    let home = scratch("scans-prune");
    let run = |args: &[&str]| bin().args(args).env("HOME", &home).output().unwrap();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let out = run(&["scans", "run", "+61412345678", "-u", "passive", "--json"]);
        assert_eq!(out.status.code(), Some(0));
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        ids.push(record["id"].as_str().unwrap().to_owned());
    }
    let listed = |run: &dyn Fn(&[&str]) -> std::process::Output| -> Vec<String> {
        let out = run(&["scans", "list", "--json"]);
        let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect()
    };

    let dry = run(&["scans", "prune", "--keep", "1"]);
    assert_eq!(dry.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&dry.stdout);
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("would delete\t"))
            .count(),
        2,
        "{stdout}"
    );
    assert!(stdout.contains("pass --apply"), "{stdout}");
    assert_eq!(listed(&run).len(), 3, "a dry run deletes nothing");

    let json = run(&["scans", "prune", "--keep", "1", "--json"]);
    let plan: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let planned: Vec<&str> = plan["scans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        planned,
        vec![ids[0].as_str(), ids[1].as_str()],
        "oldest first"
    );

    let applied = run(&["scans", "prune", "--keep", "1", "--apply"]);
    assert_eq!(
        applied.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_eq!(
        listed(&run),
        vec![ids[2].clone()],
        "only the newest is left"
    );
    let again = run(&["scans", "prune", "--keep", "1", "--apply"]);
    assert!(String::from_utf8_lossy(&again.stdout).starts_with("0 of 1 saved scans deleted"));

    assert_eq!(run(&["scans", "prune"]).status.code(), Some(64));
    assert_eq!(
        run(&["scans", "prune", "--keep", "0"]).status.code(),
        Some(64)
    );
    assert_eq!(
        run(&["scans", "prune", "--keep", "x"]).status.code(),
        Some(64)
    );
    assert_eq!(
        run(&["scans", "prune", "extra", "--keep", "1"])
            .status
            .code(),
        Some(64)
    );
    let _ = fs::remove_dir_all(&home);
}

/// `scans search` finds elements in every saved scan, or only the ones named, each with its scan.
#[test]
fn scans_search_finds_values_in_every_scan_or_the_ones_named() {
    let home = scratch("scans-search");
    let run = |args: &[&str]| bin().args(args).env("HOME", &home).output().unwrap();
    let id = |args: &[&str]| {
        let out = run(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        record["id"].as_str().unwrap().to_owned()
    };
    let first = id(&["scans", "run", "+61412345678", "-u", "passive", "--json"]);
    let second = id(&["scans", "run", "+61412345679", "-u", "passive", "--json"]);
    let lines = |args: &[&str]| -> Vec<String> {
        let out = run(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect()
    };
    let phone = |line: &String, scan: &str, number: &str| {
        line.starts_with(&format!("{scan}\t"))
            && line.contains("\tPHONE_NUMBER\t")
            && line.ends_with(&format!("\t{number}"))
    };
    // Text anywhere: both numbers, each under its own scan.
    let both = lines(&["scans", "search", "61412345", "-t", "PHONE_NUMBER"]);
    assert_eq!(
        both[0],
        "SCAN\tID\tUPDATED\tTYPE\tMODULE\tSOURCE\tF/P\tDATA"
    );
    assert!(
        both.iter().any(|line| phone(line, &first, "+61412345678")),
        "{both:?}"
    );
    assert!(
        both.iter().any(|line| phone(line, &second, "+61412345679")),
        "{both:?}"
    );
    // A wildcard is the whole value; a regex is anywhere; named scans only.
    let one = lines(&["scans", "search", "*79", "-t", "PHONE_NUMBER"]);
    assert_eq!(one.len(), 2, "{one:?}");
    assert!(phone(&one[1], &second, "+61412345679"), "{one:?}");
    let named = lines(&["scans", "search", "/5678$/", &first, "-t", "PHONE_NUMBER"]);
    assert_eq!(named.len(), 2, "{named:?}");
    assert!(phone(&named[1], &first, "+61412345678"), "{named:?}");
    assert_eq!(
        lines(&["scans", "search", "61412345", &second, "-t", "PHONE_NUMBER"]).len(),
        2
    );
    let json = run(&[
        "scans",
        "search",
        "61412345",
        "-t",
        "PHONE_NUMBER",
        "--json",
    ]);
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(
        json.as_array()
            .unwrap()
            .iter()
            .all(|row| row["scan_name"].is_string() && row["scan_target"].is_string())
    );
    assert_eq!(run(&["scans", "search"]).status.code(), Some(64));
    assert_eq!(run(&["scans", "search", "/(a/"]).status.code(), Some(64));
    // Groups nested past the limit are a bad pattern too, not a stack overflow.
    let hostile = run(&["scans", "search", &format!("/{}/", "(".repeat(100_000))]);
    assert_eq!(
        hostile.status.code(),
        Some(64),
        "{}",
        String::from_utf8_lossy(&hostile.stderr)
    );
    assert!(String::from_utf8_lossy(&hostile.stderr).contains("nested too deeply"));
    assert_eq!(
        run(&["scans", "search", "x", "0000000000000000"])
            .status
            .code(),
        Some(66)
    );
    let _ = fs::remove_dir_all(&home);
}

/// `sf.py`'s output flags shape the rows, `-d` prints the scan's log, `-l` is `serve --bind`,
/// and the combinations `sf.py` refuses are refused before any request.
#[test]
fn sf_takes_sf_py_output_flags_debug_and_listen() {
    let home = scratch("sf-flags");
    let run = |args: &[&str]| bin().args(args).env("HOME", &home).output().unwrap();
    let csv = run(&[
        "sf",
        "-q",
        "-s",
        "+61412345678",
        "-o",
        "csv",
        "-D",
        ";",
        "-H",
        "-r",
    ]);
    assert_eq!(
        csv.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&csv.stderr)
    );
    let csv = String::from_utf8_lossy(&csv.stdout);
    let first = csv.lines().next().unwrap();
    assert!(!first.starts_with("Source"), "{csv}");
    assert_eq!(first.matches(';').count(), 3, "{csv}");
    // A CSV cell a spreadsheet would read as a formula keeps its leading quote guard.
    assert!(first.ends_with(";'+61412345678"), "{csv}");

    let debug = run(&["sf", "-s", "+61412345678", "-d", "-F", "PHONE_NUMBER"]);
    let stderr = String::from_utf8_lossy(&debug.stderr);
    assert_eq!(debug.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("[INFO] huntsman: scan created"), "{stderr}");
    assert_eq!(String::from_utf8_lossy(&debug.stdout).lines().count(), 2);

    // -m picks the modules the saved scan asks, and a target none of them looks up is bad data.
    let chosen = run(&[
        "sf",
        "-s",
        "+61412345678",
        "-m",
        "sfp_numverify",
        "-F",
        "PHONE_NUMBER",
    ]);
    let stderr = String::from_utf8_lossy(&chosen.stderr);
    assert_eq!(chosen.status.code(), Some(0), "{stderr}");
    assert_eq!(String::from_utf8_lossy(&chosen.stdout).lines().count(), 2);
    let unasked = run(&["sf", "-s", "+61412345678", "-m", "sfp_gravatar"]);
    let stderr = String::from_utf8_lossy(&unasked.stderr);
    assert_eq!(unasked.status.code(), Some(65), "{stderr}");
    assert!(
        stderr.contains("none of the chosen modules (sfp_gravatar) looks up the target"),
        "{stderr}"
    );

    let listen = run(&["sf", "-l", "not-a-socket"]);
    assert_eq!(listen.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&listen.stderr).contains("invalid serve bind"));
    for refused in [
        &["sf", "-s", "example.org", "-f"][..],
        &["sf", "-s", "example.org", "-D", ";"],
        &["sf", "-s", "example.org", "-m", "sfp_not_a_module"],
    ] {
        let out = run(refused);
        assert_eq!(out.status.code(), Some(64), "{refused:?}");
        assert!(out.stdout.is_empty(), "{refused:?}");
    }
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn sf_refuses_a_target_no_lookup_can_take() {
    let home = scratch("sf-refuses");
    for (target, why) in [
        ("192.0.2.0/24", "not valid for a netblock scan"),
        ("192.0.2.1", "not valid for a ip scan"),
        ("Jane 123", "two alphabetic tokens"),
    ] {
        let out = bin()
            .args(["sf", "-s", target])
            .env("HOME", &home)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(65), "{target}: {stderr}");
        assert!(stderr.contains(why), "{target}: {stderr}");
        assert!(out.stdout.is_empty(), "{target}");
    }
    let _ = fs::remove_dir_all(&home);
}

/// `sf -s` exits as the plain lookup it runs would for the same outcome. A trust store without a
/// certificate fails every request before a socket opens, so every source is unusable: `people`,
/// `domain` and `ip` refuse, and `sf -s` of the same target must exit with the same status and
/// message. It exited 65, the status of bad data, from a status table of its own that also sent an
/// egress refusal to 69 instead of 77; it now runs the plain lookups' own `collect` and keeps the
/// refusal it gave.
#[test]
fn sf_scan_exits_as_the_plain_lookup_does() {
    let dir = scratch("sf-status");
    let bundle = dir.join("no-certificates.pem");
    fs::write(&bundle, "not a certificate\n").unwrap();
    let run = |args: &[&str]| {
        bin()
            .args(args)
            .env("HOME", &dir)
            .env("HUNTSMAN_CA_BUNDLE", &bundle)
            .output()
            .unwrap()
    };
    for (plain, target) in [
        ("people", "Jane Citizen"),
        ("domain", "example.org"),
        ("ip", "1.1.1.1"),
    ] {
        let lookup = run(&[plain, target]);
        assert!(
            matches!(lookup.status.code(), Some(69 | 77)),
            "{plain}: {:?} {}",
            lookup.status.code(),
            String::from_utf8_lossy(&lookup.stderr)
        );
        let sf = run(&["sf", "-s", target]);
        let stderr = String::from_utf8_lossy(&sf.stderr);
        assert_eq!(
            sf.status.code(),
            lookup.status.code(),
            "sf {target}: {stderr}"
        );
        assert!(sf.stdout.is_empty(), "{:?}", sf.stdout);
        assert_eq!(stderr, String::from_utf8_lossy(&lookup.stderr), "{target}");
    }
    let people = run(&["sf", "-s", "Jane Citizen"]);
    assert_eq!(people.status.code(), Some(69));
    assert!(String::from_utf8_lossy(&people.stderr).contains("HUNTSMAN_CA_BUNDLE"));
    let _ = fs::remove_dir_all(&dir);
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
    // A missing required credential exits 66, as ARCHITECTURE.md documents.
    assert_eq!(public.status.code(), Some(66));
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
fn investigate_reports_digit_groups_as_whole_identifiers_and_addresses() {
    let out = bin()
        .arg("investigate")
        .arg("call +61 412 345 678 about ABN 51 824 753 556 at 12 Queen Street Brisbane")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("entities=3"), "{stdout:?}");
    assert!(stdout.contains("phone\t+61412345678"), "{stdout:?}");
    assert!(stdout.contains("abn_acn\t51824753556"), "{stdout:?}");
    assert!(stdout.contains("address\t12 Queen Street"), "{stdout:?}");
}

#[test]
fn investigate_reads_addresses_in_angle_brackets_and_bare_ipv6() {
    let out = bin()
        .arg("investigate")
        .arg("From: Ada Lovelace <ada@example.com> via 2606:4700:4700::1111, order 123456")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("entities=2"), "{stdout:?}");
    assert!(stdout.contains("email\tada@example.com"), "{stdout:?}");
    assert!(
        stdout.contains("ip_address\t2606:4700:4700::1111"),
        "{stdout:?}"
    );
    assert!(!stdout.contains("abn_acn"), "{stdout:?}");
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
    // Only a sent credential can be rejected, and `classify` is given no request: a 403 that is no
    // challenge page is the provider refusing it.
    let refused = run("403", "forbidden");
    assert!(
        refused.ends_with("outcome=upstream4xx\naction=investigate\n"),
        "{refused}"
    );
    let auth = run("401", "key revoked");
    assert!(
        auth.ends_with("outcome=auth_required\naction=require_credential\n"),
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

/// `geo` prints whole metres on the sphere of `geohash::EARTH_RADIUS_KM`, the figure `check`
/// reports as `brisbane_sydney_m`, in either order of the two coordinates.
#[test]
fn geo_prints_the_great_circle_distance_in_whole_metres() {
    for pair in [
        ["-27.4698,153.0251", "-33.8688,151.2093"],
        ["-33.8688,151.2093", "-27.4698,153.0251"],
    ] {
        let out = bin().arg("geo").args(pair).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{pair:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "732379\n",
            "{pair:?}"
        );
        assert!(out.stderr.is_empty(), "{pair:?}: {:?}", out.stderr);
    }
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
    // A hash on its own decodes to the cell it names, which holds the encoded point.
    assert_eq!(
        run(&["geohash", "u4pruydqqvj"]),
        (
            Some(0),
            "center=57.64911063,10.40743969\nlat_min=57.64910996\nlat_max=57.64911130\n\
             lon_min=10.40743902\nlon_max=10.40744036\n"
                .into()
        )
    );
    assert_eq!(run(&["geohash", "U4PRUYD"]).0, Some(0), "case is folded");
    assert_eq!(
        run(&["geohash", "u4pa"]).0,
        Some(65),
        "a is not in the alphabet"
    );
    assert_eq!(
        run(&["geohash", "u4pruydqqvjxy"]).0,
        Some(65),
        "13 characters"
    );
    assert_eq!(
        run(&["coarsen", "-27.4698,153.0251"]),
        (Some(0), "-27.5,153.0\n".into())
    );
    assert_eq!(run(&["coarsen", "999,999"]).0, Some(65));
}

#[test]
fn stolen_tax_uses_a_key_in_the_default_file() {
    // Every lookup reads the keys `credential-status` reports, so a key placed only in the
    // default file is used, not refused as missing (66). A CA bundle that cannot be parsed fails
    // the TLS handshake, so the key is never sent and the run ends as unavailable (69).
    let home = scratch("stolen-default-file");
    let default_file = home.join(".huntsman.env");
    fs::write(
        &default_file,
        "HUNTSMAN_STOLEN_TAX_KEY=fixture-not-a-key-0001\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&default_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let bundle = home.join("not-a-ca.pem");
    fs::write(&bundle, "not a certificate\n").unwrap();
    let out = bin()
        .args(["recon", "stolen-tax", "a@example.com"])
        .env_remove("HUNTSMAN_STOLEN_TAX_KEY")
        .env("HOME", &home)
        .env("HUNTSMAN_CA_BUNDLE", &bundle)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(69), "{stderr}");
    assert!(!stderr.contains("no API key"), "{stderr}");
    assert!(!stderr.contains("fixture-not-a-key"), "{stderr}");
    assert_eq!(out.stdout.len(), 0);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn recon_refuses_bad_usage_and_a_missing_key_before_any_request() {
    // An empty home keeps a developer's real key out of the run, so the missing-key refusal
    // happens here and no paid request can be made.
    let home = scratch("recon-home");
    for args in [
        &["recon"][..],
        &["recon", "nope", "x"],
        &["recon", "crtsh", " "],
        &["recon", "dns", " "],
        &["recon", "stolen-tax", "  "],
        &["recon", "stolen-tax", "a@example.com", "--bogus", "f"],
    ] {
        let out = bin().args(args).env("HOME", &home).output().unwrap();
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
        .env("HOME", &home)
        .output()
        .unwrap();
    // The README documents a missing key as exit 66, before any request.
    assert_eq!(out.status.code(), Some(66));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no API key for this keyed lookup"), "{err}");
    assert!(
        err.contains("HUNTSMAN_STOLEN_TAX_KEY"),
        "refusal must name the key to set: {err}"
    );
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
    // A readable file without the slot is a missing key, and so is an absent file: both
    // are exit 66, before any request.
    for (file, code) in [(keys.clone(), 66), (dir.join("absent.env"), 66)] {
        let out = bin()
            .args(["recon", "stolen-tax", "a@example.com", "--keys"])
            .arg(&file)
            .env_remove("HUNTSMAN_STOLEN_TAX_KEY")
            .env("HOME", &home)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code), "{}", file.display());
    }
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&home);
}

/// The bytes a terminal acts on, other than the line feed and tab the reports use as separators.
fn terminal_controls(text: &str) -> Vec<char> {
    text.chars()
        .filter(|c| (c.is_control() && !matches!(c, '\n' | '\t')) || *c == '\u{2028}')
        .collect()
}

#[cfg(unix)]
#[test]
fn search_prints_a_hostile_file_name_as_text_on_one_row() {
    // A directory taken from somewhere else: its file names are the sender's choice.
    let dir = scratch("search-names");
    let docs = dir.join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("esc\u{1b}[2Jname.txt"), "the needle is here\n").unwrap();
    fs::write(docs.join("x\n9\tforged.txt"), "another needle\n").unwrap();
    let out = bin()
        .args(["search", "needle", "docs"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(terminal_controls(&stdout), Vec::<char>::new(), "{stdout:?}");
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(rows.len(), 2, "one row per file: {stdout:?}");
    for row in rows {
        assert_eq!(
            row.matches('\t').count(),
            2,
            "score, id and source: {row:?}"
        );
    }
    assert!(stdout.contains("esc\\u{1b}[2Jname.txt"), "{stdout:?}");
    assert!(stdout.contains("x\\n9\\tforged.txt"), "{stdout:?}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_error_that_echoes_input_cannot_drive_the_terminal() {
    // serde names an unknown field in its message, and the field is whatever the file held.
    let dir = scratch("error-echo");
    fs::write(dir.join("in.json"), "{\"\\u001b]0;x\\u0007\\u009b2J\": 1}").unwrap();
    let out = bin()
        .args(["domain-lifecycle", "analyze", "in.json", "--as-of", "1"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("unknown field"), "{stderr:?}");
    assert_eq!(terminal_controls(&stderr), Vec::<char>::new(), "{stderr:?}");
    assert!(stderr.contains("\\u{1b}]0;x\\u{7}\\u{9b}2J"), "{stderr:?}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn run_history_show_prints_the_text_of_a_hostile_history_file_as_text() {
    // The file is read as written, and anyone may have written it.
    let dir = scratch("run-history-hostile");
    fs::write(
        dir.join("runs.jsonl"),
        "{\"commit\":\"abc\\u001b]0;x\\u0007\\nforged\",\"suite\":\"unit\\u009b2J\\u2028\",\"passed\":1,\"failed\":0,\"recorded_at_unix\":5}\n",
    )
    .unwrap();
    let out = bin()
        .args(["run-history", "show", "--file", "runs.jsonl"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(terminal_controls(&stdout), Vec::<char>::new(), "{stdout:?}");
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
    assert!(
        stdout.contains("commit=abc\\u{1b}]0;x\\u{7}\\nforged suite=unit\\u{9b}2J\\u{2028} "),
        "{stdout:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// `correlate --history` is the shipped entry point for the cross-scan pivot: a saved scan is
/// bridged to every earlier saved scan that saw the same identifier, end to end through the
/// binary and real artifact files, offline.
#[test]
fn correlate_history_pivots_a_saved_scan_across_earlier_saved_scans() {
    use huntsman_recon::entity::{Entity, EntityKind};
    use huntsman_recon::scan_artifact::{self, ScanArtifact};
    let dir = scratch("correlate-history");
    let history = dir.join("history");
    fs::create_dir_all(&history).unwrap();
    let saved = |scan_id: &str, email: &str| {
        let entity = Entity::new(EntityKind::Email, email, 0.9, scan_id);
        ScanArtifact::new(scan_id, vec![entity], Vec::new())
    };
    let current = dir.join("now.json");
    scan_artifact::write(&current, &saved("scan-now", "ada@example.com")).unwrap();
    scan_artifact::write(
        &history.join("old.json"),
        &saved("scan-old", "ada@example.com"),
    )
    .unwrap();
    scan_artifact::write(
        &history.join("other.json"),
        &saved("scan-other", "bob@example.com"),
    )
    .unwrap();

    let out = bin()
        .args([
            "correlate",
            current.to_str().unwrap(),
            "--history",
            history.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("scan_id=scan-now entities=1 relations=0\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("history_scans=2 cross_scan=historical\n"),
        "{stdout}"
    );
    let bridges: Vec<_> = stdout
        .lines()
        .filter(|l| l.starts_with("bridge "))
        .collect();
    assert_eq!(bridges.len(), 1, "{stdout}");
    assert!(
        bridges[0].starts_with("bridge tier=Direct kind=email uid="),
        "{stdout}"
    );
    assert!(bridges[0].ends_with(" scans=scan-old"), "{stdout}");
    assert!(
        !stdout.contains("ada@example.com"),
        "the pivot must not echo identifiers: {stdout}"
    );

    // Without --history the output is unchanged from before the pivot existed.
    let plain = bin()
        .args(["correlate", current.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(plain.status.success());
    assert!(
        !String::from_utf8(plain.stdout)
            .unwrap()
            .contains("cross_scan=")
    );

    // A broken history fails before any report is printed: 65 for bad data, 66 for no dir.
    fs::write(history.join("broken.json"), b"{ nope").unwrap();
    let bad = bin()
        .args([
            "correlate",
            current.to_str().unwrap(),
            "--history",
            history.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(65));
    assert_eq!(String::from_utf8_lossy(&bad.stdout), "");
    assert!(String::from_utf8_lossy(&bad.stderr).contains("broken.json"));
    let missing = dir.join("absent");
    let absent = bin()
        .args([
            "correlate",
            current.to_str().unwrap(),
            "--history",
            missing.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(absent.status.code(), Some(66));
    let usage = bin()
        .args(["correlate", current.to_str().unwrap(), "--histroy", "x"])
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(64));
}

#[test]
fn universal_research_preview_is_subject_neutral_and_offline() {
    for (args, expected) in [
        (
            &["research", "--plan", "unclassified", "historical", "term"][..],
            "route=adaptive_web_search\tkeyless=true\n",
        ),
        (
            &["research", "--plan", "example.org"][..],
            "route=scan\tkind=domain\n",
        ),
        (
            &["research", "--plan", "@MixedCase"][..],
            "route=scan\tkind=username\n",
        ),
        (
            &["research", "--plan", "-27.4705,153.0260"][..],
            "route=scan\tkind=geocode\n",
        ),
    ] {
        let out = bin().args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8(out.stdout).unwrap(), expected, "{args:?}");
    }
    for args in [
        &["research", "--plan"][..],
        &["research", "--plan", ""][..],
        &["research", "--plan", "127.0.0.1"][..],
        &["research", "--plan", "192.168.1.0/24"][..],
        &["research", "--plan", "1.1.1.1/33"][..],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}
