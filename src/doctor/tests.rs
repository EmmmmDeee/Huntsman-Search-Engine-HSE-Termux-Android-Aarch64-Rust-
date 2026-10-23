//! Each failure mode `doctor` knows, made on disk in a scratch home, with the check it trips and
//! the repair that clears it.

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

use super::*;
use crate::serve_probe::{ServeProbe, ServeState};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_SHA: &str = "89abcdef0123456789abcdef0123456789abcdef";

struct FakeHost {
    free: u64,
    rustc: Option<&'static str>,
    accept: Result<(), String>,
    path_sha: Option<&'static str>,
    acceptance_runs: Cell<usize>,
}

impl Default for FakeHost {
    fn default() -> Self {
        Self {
            free: 8 * 1024 * 1024 * 1024,
            rustc: Some("rustc 1.90.0"),
            accept: Ok(()),
            path_sha: Some(SHA),
            acceptance_runs: Cell::new(0),
        }
    }
}

impl Host for FakeHost {
    fn free_bytes(&self, _path: &Path) -> Option<u64> {
        Some(self.free)
    }
    fn rustc_version(&self) -> Option<String> {
        self.rustc.map(str::to_owned)
    }
    fn build_sha_of(&self, _exe: &Path) -> Option<String> {
        self.path_sha.map(str::to_owned)
    }
    fn acceptance(&self) -> Result<(), String> {
        self.acceptance_runs.set(self.acceptance_runs.get() + 1);
        self.accept.clone()
    }
    fn now_unix(&self) -> u64 {
        1_760_000_000
    }
}

/// A scratch home holding a healthy install: state dir, record, keys file, binary on PATH.
struct Scratch {
    home: PathBuf,
    bin: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let home = std::env::temp_dir().join(format!(
            "huntsman-doctor-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&home);
        let bin = home.join("usr/bin");
        fs::create_dir_all(&bin).expect("bin");
        let exe = bin.join("huntsman-recon");
        fs::write(&exe, "#!/bin/sh\n").expect("exe");
        set_mode(&exe, 0o755).expect("mode");
        let state = home.join(STATE_DIR);
        fs::create_dir_all(&state).expect("state");
        set_mode(&state, 0o700).expect("mode");
        let record = state.join(PROVENANCE_FILE);
        fs::write(
            &record,
            format!(
                "revision={SHA}\nrepository={REPOSITORY}\nrustc=rustc 1.90.0\ncargo_target_dir={}\n",
                home.join(BUILD_CACHE).display()
            ),
        )
        .expect("record");
        set_mode(&record, 0o600).expect("mode");
        let keys = home.join(DEFAULT_KEYS_FILE);
        fs::write(&keys, "# keys\n").expect("keys");
        set_mode(&keys, 0o600).expect("mode");
        fs::create_dir_all(home.join("tmp")).expect("tmp");
        Self { home, bin }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    fn examine(&self, host: &FakeHost) -> Report {
        self.with_ctx(SHA, |ctx| examine(ctx, host))
    }

    fn with_ctx<T>(&self, sha: &str, run: impl FnOnce(&Context<'_>) -> T) -> T {
        let keys = Keys::default();
        let serve = not_running();
        let ctx = Context {
            home: Some(self.home.clone()),
            state_dir_override: None,
            env_file_override: None,
            termux: TermuxState::NotDetected,
            prefix: None,
            path_dirs: vec![self.bin.clone()],
            tmpdir: Some(self.path("tmp")),
            current_exe: Some(self.bin.join("huntsman-recon")),
            cwd: Some(self.path("work")),
            build_sha: sha,
            version: "9.9.9",
            keys: KeyState::Resolved(&keys),
            probes: None,
            serve: &serve,
        };
        run(&ctx)
    }

    fn fix(&self, host: &FakeHost) -> (Vec<Repaired>, Report) {
        self.with_ctx(SHA, |ctx| {
            let report = examine(ctx, host);
            let repairs = repair(ctx, &report, host);
            (repairs, examine(ctx, host))
        })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn not_running() -> ServeProbe {
    ServeProbe {
        addr: "127.0.0.1:8080".into(),
        state: ServeState::NotRunning,
        version: None,
        problems: Vec::new(),
        elapsed_ms: 1,
    }
}

fn status_of(report: &Report, id: &str) -> Status {
    report
        .get(id)
        .unwrap_or_else(|| panic!("no {id} check"))
        .status
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("meta").permissions().mode() & 0o777
}

#[test]
fn a_healthy_install_has_no_failure_and_no_repair() {
    let scratch = Scratch::new("healthy");
    let report = scratch.examine(&FakeHost::default());
    for check in &report.checks {
        assert_ne!(check.status, Status::Fail, "{check:?}");
        assert!(check.repair.is_none(), "{check:?}");
    }
    // No keys is a warning, not a failure: keyless sources still run.
    assert_eq!(status_of(&report, "keys"), Status::Warn);
    assert_eq!(report.status(), Status::Warn);
    let text = render(&report);
    assert!(
        text.ends_with("doctor=warn ok=11 warn=1 fail=0\n"),
        "{text}"
    );
}

#[test]
fn a_missing_binary_fails_and_names_the_installer() {
    let scratch = Scratch::new("nobin");
    fs::remove_file(scratch.bin.join("huntsman-recon")).expect("rm");
    let report = scratch.examine(&FakeHost::default());
    let check = report.get("binary").expect("binary");
    assert_eq!(check.status, Status::Fail);
    assert_eq!(check.fix.as_deref(), Some(REINSTALL));
    assert!(!check.auto_fix);
}

#[test]
fn another_build_on_path_is_a_warning_naming_both_builds() {
    let scratch = Scratch::new("otherbin");
    let host = FakeHost {
        path_sha: Some(OTHER_SHA),
        ..FakeHost::default()
    };
    let report = scratch.with_ctx(SHA, |ctx| {
        let ctx = Context {
            current_exe: Some(PathBuf::from("/elsewhere/huntsman-recon")),
            ..clone_ctx(ctx)
        };
        examine(&ctx, &host)
    });
    let check = report.get("binary").expect("binary");
    assert_eq!(check.status, Status::Warn, "{check:?}");
    assert!(
        check.message.contains("89abcde") && check.message.contains("0123456"),
        "{check:?}"
    );
}

fn clone_ctx<'a>(ctx: &Context<'a>) -> Context<'a> {
    Context {
        home: ctx.home.clone(),
        state_dir_override: ctx.state_dir_override.clone(),
        env_file_override: ctx.env_file_override.clone(),
        termux: ctx.termux,
        prefix: ctx.prefix.clone(),
        path_dirs: ctx.path_dirs.clone(),
        tmpdir: ctx.tmpdir.clone(),
        current_exe: ctx.current_exe.clone(),
        cwd: ctx.cwd.clone(),
        build_sha: ctx.build_sha,
        version: ctx.version,
        keys: match &ctx.keys {
            KeyState::Resolved(keys) => KeyState::Resolved(keys),
            KeyState::Error(error) => KeyState::Error(error.clone()),
        },
        probes: ctx.probes,
        serve: ctx.serve,
    }
}

#[test]
fn a_sha_mismatch_is_stale_provenance_and_fix_rerecords_after_acceptance() {
    let scratch = Scratch::new("stale");
    let record = scratch.path(".huntsman/installed-revision");
    let old = format!(
        "revision={OTHER_SHA}\nrepository=https://example.invalid/r.git\nrustc=rustc 1.80.0\ncargo_target_dir=/data/cache\n"
    );
    fs::write(&record, &old).expect("write");
    let host = FakeHost::default();
    let report = scratch.examine(&host);
    let check = report.get("provenance").expect("provenance");
    assert_eq!(check.status, Status::Fail);
    assert!(check.message.contains("stale"), "{check:?}");
    assert_eq!(check.fix.as_deref(), Some(FIX));

    let (repairs, after) = scratch.fix(&host);
    assert!(repairs.iter().all(|r| r.ok), "{repairs:?}");
    assert_eq!(status_of(&after, "provenance"), Status::Ok);
    let written = fs::read_to_string(&record).expect("record");
    assert!(
        written.starts_with(&format!("revision={SHA}\n")),
        "{written}"
    );
    assert!(
        written.contains("repository=https://example.invalid/r.git\n"),
        "{written}"
    );
    assert!(written.contains("rustc=rustc 1.90.0\n"), "{written}");
    assert!(
        written.contains("cargo_target_dir=/data/cache\n"),
        "{written}"
    );
    assert!(written.ends_with("recorded_by=doctor\n"), "{written}");
    assert_eq!(mode(&record), 0o600);
    let backup = scratch.path(".huntsman/installed-revision.bak-1760000000");
    assert_eq!(fs::read_to_string(&backup).expect("backup"), old);
    assert_eq!(mode(&backup), 0o600);
}

#[test]
fn a_record_is_never_rewritten_when_acceptance_fails() {
    let scratch = Scratch::new("noaccept");
    let record = scratch.path(".huntsman/installed-revision");
    fs::write(&record, format!("revision={OTHER_SHA}\n")).expect("write");
    let host = FakeHost {
        accept: Err("`huntsman-recon check` exited 9".into()),
        ..FakeHost::default()
    };
    let (repairs, after) = scratch.fix(&host);
    let attempt = repairs
        .iter()
        .find(|r| r.check == "provenance")
        .expect("tried");
    assert!(!attempt.ok);
    assert!(
        attempt
            .error
            .as_deref()
            .unwrap_or("")
            .contains("acceptance failed")
    );
    assert_eq!(
        fs::read_to_string(&record).expect("kept"),
        format!("revision={OTHER_SHA}\n")
    );
    assert_eq!(status_of(&after, "provenance"), Status::Fail);
    assert_eq!(status_of(&after, "selfcheck"), Status::Fail);
}

#[test]
fn a_binary_without_a_commit_cannot_confirm_or_rewrite_the_record() {
    let scratch = Scratch::new("unknownsha");
    let host = FakeHost::default();
    let report = scratch.with_ctx("unknown", |ctx| examine(ctx, &host));
    assert_eq!(status_of(&report, "build_sha"), Status::Warn);
    let check = report.get("provenance").expect("provenance");
    assert_eq!(check.status, Status::Warn);
    assert!(check.repair.is_none());
    assert_eq!(check.fix.as_deref(), Some(REINSTALL));
}

#[test]
fn a_missing_record_is_written_by_fix() {
    let scratch = Scratch::new("norecord");
    fs::remove_file(scratch.path(".huntsman/installed-revision")).expect("rm");
    let host = FakeHost::default();
    assert_eq!(
        status_of(&scratch.examine(&host), "provenance"),
        Status::Warn
    );
    let (_, after) = scratch.fix(&host);
    assert_eq!(status_of(&after, "provenance"), Status::Ok);
    let written = fs::read_to_string(scratch.path(".huntsman/installed-revision")).expect("record");
    assert!(
        written.contains(&format!("repository={REPOSITORY}\n")),
        "{written}"
    );
}

#[test]
fn a_garbled_record_fails_and_fix_rewrites_it() {
    let scratch = Scratch::new("garbled");
    fs::write(
        scratch.path(".huntsman/installed-revision"),
        "\u{0}\u{1}junk",
    )
    .expect("write");
    let host = FakeHost::default();
    let check = scratch
        .examine(&host)
        .get("provenance")
        .cloned()
        .expect("check");
    assert_eq!(check.status, Status::Fail);
    assert!(check.message.contains("no valid revision"), "{check:?}");
    let (_, after) = scratch.fix(&host);
    assert_eq!(status_of(&after, "provenance"), Status::Ok);
}

#[test]
fn a_missing_state_dir_and_keys_file_are_created_private() {
    let scratch = Scratch::new("nostate");
    fs::remove_dir_all(scratch.path(".huntsman")).expect("rm");
    fs::remove_file(scratch.path(".huntsman.env")).expect("rm");
    let host = FakeHost::default();
    let before = scratch.examine(&host);
    assert_eq!(status_of(&before, "state_dir"), Status::Warn);
    assert_eq!(status_of(&before, "env_file"), Status::Warn);
    let (repairs, after) = scratch.fix(&host);
    assert!(repairs.iter().all(|r| r.ok), "{repairs:?}");
    // The directory is made before the record that lives in it.
    assert_eq!(repairs[0].check, "state_dir", "{repairs:?}");
    assert_eq!(mode(&scratch.path(".huntsman")), 0o700);
    assert_eq!(mode(&scratch.path(".huntsman.env")), 0o600);
    assert_eq!(fs::read(scratch.path(".huntsman.env")).expect("env"), b"");
    for id in ["state_dir", "env_file", "provenance"] {
        assert_eq!(status_of(&after, id), Status::Ok, "{id}");
    }
}

#[test]
fn an_open_state_dir_is_tightened() {
    let scratch = Scratch::new("openstate");
    set_mode(&scratch.path(".huntsman"), 0o755).expect("mode");
    let host = FakeHost::default();
    assert_eq!(
        status_of(&scratch.examine(&host), "state_dir"),
        Status::Warn
    );
    let (_, after) = scratch.fix(&host);
    assert_eq!(status_of(&after, "state_dir"), Status::Ok);
    assert_eq!(mode(&scratch.path(".huntsman")), 0o700);
}

#[test]
fn a_state_path_that_is_a_file_is_never_moved_by_fix() {
    let scratch = Scratch::new("statefile");
    fs::remove_dir_all(scratch.path(".huntsman")).expect("rm");
    fs::write(scratch.path(".huntsman"), "mine").expect("file");
    let check = scratch
        .examine(&FakeHost::default())
        .get("state_dir")
        .cloned()
        .expect("check");
    assert_eq!(check.status, Status::Fail);
    assert!(check.repair.is_none());
    assert!(
        check
            .fix
            .as_deref()
            .unwrap_or("")
            .starts_with("mv ~/.huntsman ~/.huntsman.bak")
    );
}

#[test]
fn a_keys_file_others_can_read_fails_and_fix_makes_it_private_without_touching_it() {
    let scratch = Scratch::new("loosekeys");
    let keys = scratch.path(".huntsman.env");
    let content = "HUNTSMAN_SHODAN_KEY=doctor-test-secret-value-1\n";
    fs::write(&keys, content).expect("write");
    set_mode(&keys, 0o644).expect("mode");
    let host = FakeHost::default();
    let report = scratch.examine(&host);
    let check = report.get("env_file").expect("check");
    assert_eq!(check.status, Status::Fail);
    assert!(check.message.contains("mode 644"), "{check:?}");
    let json = serde_json::to_string(&report).expect("json");
    assert!(!json.contains("doctor-test-secret-value-1"));
    let (_, after) = scratch.fix(&host);
    assert_eq!(status_of(&after, "env_file"), Status::Ok);
    assert_eq!(mode(&keys), 0o600);
    assert_eq!(fs::read_to_string(&keys).expect("keys"), content);
}

#[test]
fn a_malformed_keys_file_names_the_line_but_never_a_value() {
    let scratch = Scratch::new("badkeys");
    fs::write(
        scratch.path(".huntsman.env"),
        "HUNTSMAN_SHODAN_KEY=doctor-test-secret-value-2\nthis line has no equals doctor-test-secret-value-3\n",
    )
    .expect("write");
    let report = scratch.examine(&FakeHost::default());
    let check = report.get("env_file").expect("check");
    assert_eq!(check.status, Status::Fail);
    assert!(check.message.contains("keys line 2"), "{check:?}");
    assert!(check.repair.is_none());
    let text = render(&report);
    assert!(!text.contains("doctor-test-secret-value"), "{text}");
}

#[test]
fn a_keys_file_slot_that_matches_no_provider_warns_and_names_it_but_never_the_value() {
    let scratch = Scratch::new("unknownslot");
    fs::write(
        scratch.path(".huntsman.env"),
        "HUNTSMAN_SHODAN_KEY=doctor-test-secret-value-known\nHUNTSMAN_SHODAN=doctor-test-secret-value-misnamed\n",
    )
    .expect("write");
    let report = scratch.examine(&FakeHost::default());
    let check = report.get("env_file").expect("check");
    assert_eq!(check.status, Status::Warn, "{check:?}");
    assert!(check.message.contains("read by no provider"), "{check:?}");
    assert!(check.message.contains("HUNTSMAN_SHODAN"), "{check:?}");
    assert_eq!(
        check.repair, None,
        "a misnamed slot is the operator's to rename, not an automatic repair"
    );
    let text = serde_json::to_string(&report).expect("json");
    assert!(!text.contains("doctor-test-secret-value"), "{text}");
}

#[test]
fn obsolete_install_dir_setting_has_a_precise_manual_fix() {
    let scratch = Scratch::new("legacyinstallslot");
    fs::write(
        scratch.path(".huntsman.env"),
        format!(
            "{}=/private/install/path-not-to-print\n",
            crate::environment::LEGACY_INSTALL_DIR_ENV
        ),
    )
    .expect("write");
    let report = scratch.examine(&FakeHost::default());
    let check = report.get("env_file").expect("check");
    assert_eq!(check.status, Status::Warn, "{check:?}");
    assert_eq!(
        check.fix.as_deref(),
        Some("huntsman-recon keys remove HUNTSMAN_INSTALL_DIR")
    );
    assert!(!check.auto_fix, "removing a slot is operator-controlled");
    assert!(check.repair.is_none());
    let text = render(&report);
    assert!(!text.contains("/private/install/path-not-to-print"), "{text}");
}

#[test]
fn a_symlinked_keys_file_fails() {
    let scratch = Scratch::new("linkkeys");
    let keys = scratch.path(".huntsman.env");
    fs::rename(&keys, scratch.path("real.env")).expect("mv");
    std::os::unix::fs::symlink(scratch.path("real.env"), &keys).expect("link");
    let check = scratch
        .examine(&FakeHost::default())
        .get("env_file")
        .cloned()
        .expect("check");
    assert_eq!(check.status, Status::Fail);
    assert!(check.message.contains("symlink"), "{check:?}");
    assert!(check.repair.is_none());
}

#[test]
fn an_installer_env_file_elsewhere_is_reported() {
    let scratch = Scratch::new("envoverride");
    let report = scratch.with_ctx(SHA, |ctx| {
        let ctx = Context {
            env_file_override: Some(PathBuf::from("/sdcard/hse.env")),
            ..clone_ctx(ctx)
        };
        examine(&ctx, &FakeHost::default())
    });
    let check = report.get("env_file").expect("check");
    assert_eq!(check.status, Status::Warn);
    assert!(check.message.contains("HUNTSMAN_ENV_FILE"), "{check:?}");
}

#[test]
fn configured_keys_are_named_by_provider_never_by_value() {
    let scratch = Scratch::new("keys");
    let keys = Keys::parse("HUNTSMAN_SHODAN_KEY=doctor-test-secret-value-4\n").expect("keys");
    let report = scratch.with_ctx(SHA, |ctx| {
        let ctx = Context {
            keys: KeyState::Resolved(&keys),
            ..clone_ctx(ctx)
        };
        examine(&ctx, &FakeHost::default())
    });
    let check = report.get("keys").expect("keys");
    assert_eq!(check.status, Status::Ok, "{check:?}");
    assert!(check.message.starts_with("1 of "), "{check:?}");
    assert!(!render(&report).contains("doctor-test-secret-value-4"));
}

#[test]
fn a_rejected_key_fails_the_keys_check() {
    let scratch = Scratch::new("rejected");
    let keys = Keys::parse("HUNTSMAN_SHODAN_KEY=doctor-test-secret-value-5\n").expect("keys");
    let mut probes: Vec<ProviderProbeStatus> = provider_credentials::status(&keys)
        .into_iter()
        .map(|provider| ProviderProbeStatus {
            probe: if provider.configured {
                ProbeState::Rejected
            } else {
                ProbeState::NotConfigured
            },
            provider,
            evidence: Vec::new(),
        })
        .collect();
    let report = scratch.with_ctx(SHA, |ctx| {
        let ctx = Context {
            keys: KeyState::Resolved(&keys),
            probes: Some(&probes),
            ..clone_ctx(ctx)
        };
        examine(&ctx, &FakeHost::default())
    });
    let check = report.get("keys").expect("keys");
    assert_eq!(check.status, Status::Fail, "{check:?}");
    assert!(check.message.contains("rejected"), "{check:?}");
    probes.clear();
}

#[test]
fn a_broken_ledger_fails_and_is_never_touched() {
    let scratch = Scratch::new("ledger");
    let saved = scratch.path(".huntsman/scans/run.ledger.json");
    fs::create_dir_all(saved.parent().expect("parent")).expect("dir");
    fs::write(&saved, "[{\"prev\": \"x\", \"hash\": ").expect("write");
    // A chain-shaped file under another name is found too.
    let named_otherwise = scratch.path(".huntsman/scans/alice.json");
    fs::write(
        &named_otherwise,
        "[{\"prev\":\"0\",\"hash\":\"1\",\"claim\":{}}]",
    )
    .expect("write");
    // Other JSON is not a ledger.
    fs::write(scratch.path(".huntsman/settings.json"), "{\"a\":1}").expect("write");
    let host = FakeHost::default();
    let report = scratch.examine(&host);
    let check = report.get("ledgers").expect("ledgers");
    assert_eq!(check.status, Status::Fail);
    assert!(check.message.starts_with("2 broken ledgers"), "{check:?}");
    assert!(check.repair.is_none());
    let _ = scratch.fix(&host);
    assert!(saved.exists() && named_otherwise.exists());
}

#[test]
fn a_good_ledger_in_the_working_directory_verifies() {
    let scratch = Scratch::new("goodledger");
    let var = scratch.path("work/var");
    fs::create_dir_all(&var).expect("var");
    let entry = crate::ledger::seal(&crate::ledger::Claim {
        claim: "doctor test".into(),
        source: "tests".into(),
        component: "src/doctor.rs".into(),
        technique_id: None,
        status: crate::stage::Status::Unverified,
        evidence_level: crate::stage::EvidenceLevel::Assertion,
        does_not_show: "anything".into(),
    });
    crate::ledger::save_chain(&var.join("ledger.json"), &[entry]).expect("save");
    let check = scratch
        .examine(&FakeHost::default())
        .get("ledgers")
        .cloned()
        .expect("check");
    assert_eq!(check.status, Status::Ok);
    assert_eq!(check.message, "1 ledgers verified");
}

#[test]
fn failing_acceptance_fails_selfcheck() {
    let scratch = Scratch::new("selfcheck");
    let host = FakeHost {
        accept: Err("`huntsman-recon check` exited 9".into()),
        ..FakeHost::default()
    };
    let check = scratch
        .examine(&host)
        .get("selfcheck")
        .cloned()
        .expect("check");
    assert_eq!(check.status, Status::Fail);
    assert!(check.message.contains("exited 9"), "{check:?}");
}

fn serve_report(scratch: &Scratch, probe: &ServeProbe) -> Check {
    scratch.with_ctx(SHA, |ctx| {
        let ctx = Context {
            serve: probe,
            ..clone_ctx(ctx)
        };
        examine(&ctx, &FakeHost::default())
            .get("serve")
            .cloned()
            .expect("serve")
    })
}

#[test]
fn each_serve_state_maps_to_its_check() {
    let scratch = Scratch::new("serve");
    let probe = |state, version: Option<&str>| ServeProbe {
        addr: "127.0.0.1:8080".into(),
        state,
        version: version.map(str::to_owned),
        problems: vec!["/ does not call /api/analyze".into()],
        elapsed_ms: 3,
    };
    let healthy = serve_report(&scratch, &probe(ServeState::Healthy, Some("9.9.9")));
    assert_eq!(healthy.status, Status::Ok);
    let old = serve_report(&scratch, &probe(ServeState::Healthy, Some("9.9.8")));
    assert_eq!(old.status, Status::Warn);
    assert!(old.message.contains("9.9.8"), "{old:?}");
    let off = serve_report(&scratch, &probe(ServeState::NotRunning, None));
    assert_eq!(off.status, Status::Ok);
    // Port in use by another program.
    let foreign = serve_report(&scratch, &probe(ServeState::Foreign, None));
    assert_eq!(foreign.status, Status::Fail);
    assert_eq!(
        foreign.fix.as_deref(),
        Some("huntsman-recon serve --bind 127.0.0.1:8081")
    );
    let locked = serve_report(&scratch, &probe(ServeState::Unauthorized, Some("9.9.9")));
    assert_eq!(locked.status, Status::Warn);
    let broken = serve_report(&scratch, &probe(ServeState::Degraded, Some("9.9.9")));
    assert_eq!(broken.status, Status::Fail);
    assert!(broken.message.contains("/api/analyze"), "{broken:?}");
}

fn tag_cache(dir: &Path) {
    fs::create_dir_all(dir.join("release")).expect("cache");
    fs::write(
        dir.join("CACHEDIR.TAG"),
        format!("{CACHEDIR_SIGNATURE}\n# cargo\n"),
    )
    .expect("tag");
    fs::write(dir.join("release/blob"), vec![0_u8; 4096]).expect("blob");
}

#[test]
fn low_disk_fails_and_fix_clears_only_a_tagged_build_cache() {
    let scratch = Scratch::new("lowdisk");
    let cache = scratch.path(BUILD_CACHE);
    tag_cache(&cache);
    let host = FakeHost {
        free: 100 * 1024 * 1024,
        ..FakeHost::default()
    };
    let check = scratch.examine(&host).get("disk").cloned().expect("disk");
    assert_eq!(check.status, Status::Fail);
    assert!(check.auto_fix, "{check:?}");
    let (repairs, _) = scratch.fix(&host);
    assert!(
        repairs.iter().any(|r| r.check == "disk" && r.ok),
        "{repairs:?}"
    );
    assert!(!cache.exists());
}

#[test]
fn low_disk_never_removes_an_untagged_directory() {
    let scratch = Scratch::new("untagged");
    let cache = scratch.path(BUILD_CACHE);
    fs::create_dir_all(&cache).expect("cache");
    fs::write(cache.join("important"), "keep").expect("file");
    let host = FakeHost {
        free: 100 * 1024 * 1024,
        ..FakeHost::default()
    };
    let check = scratch.examine(&host).get("disk").cloned().expect("disk");
    assert_eq!(check.status, Status::Fail);
    assert!(!check.auto_fix);
    let _ = scratch.fix(&host);
    assert!(cache.join("important").exists());
    assert_eq!(
        clear_build_cache(&cache).unwrap_err(),
        "no Cargo CACHEDIR.TAG there, so it is kept"
    );
}

#[test]
fn tight_disk_warns() {
    let scratch = Scratch::new("tightdisk");
    let host = FakeHost {
        free: 600 * 1024 * 1024,
        ..FakeHost::default()
    };
    assert_eq!(status_of(&scratch.examine(&host), "disk"), Status::Warn);
}

#[test]
fn a_build_cache_from_another_rustc_is_stale_and_fix_clears_it() {
    let scratch = Scratch::new("stalecache");
    let cache = scratch.path(BUILD_CACHE);
    tag_cache(&cache);
    let host = FakeHost {
        rustc: Some("rustc 1.91.0"),
        ..FakeHost::default()
    };
    let check = scratch
        .examine(&host)
        .get("build_cache")
        .cloned()
        .expect("cache");
    assert_eq!(check.status, Status::Warn);
    assert!(
        check.message.contains("1.90.0") && check.message.contains("1.91.0"),
        "{check:?}"
    );
    let (_, after) = scratch.fix(&host);
    assert!(!cache.exists());
    assert_eq!(status_of(&after, "build_cache"), Status::Ok);
}

#[test]
fn a_current_build_cache_is_kept() {
    let scratch = Scratch::new("currentcache");
    let cache = scratch.path(BUILD_CACHE);
    tag_cache(&cache);
    let host = FakeHost::default();
    let check = scratch
        .examine(&host)
        .get("build_cache")
        .cloned()
        .expect("cache");
    assert_eq!(check.status, Status::Ok);
    assert!(check.message.contains("reused"), "{check:?}");
    let _ = scratch.fix(&host);
    assert!(cache.exists());
}

#[test]
fn termux_paths_are_checked_under_termux() {
    let scratch = Scratch::new("termux");
    let termux = |prefix: Option<&str>, path: Vec<PathBuf>, tmp: Option<PathBuf>| {
        scratch.with_ctx(SHA, |ctx| {
            let ctx = Context {
                termux: TermuxState::Detected,
                prefix: prefix.map(PathBuf::from),
                path_dirs: path,
                tmpdir: tmp,
                ..clone_ctx(ctx)
            };
            examine(&ctx, &FakeHost::default())
                .get("termux")
                .cloned()
                .expect("termux")
        })
    };
    let prefix = "/data/data/com.termux/files/usr";
    let bin = PathBuf::from(prefix).join("bin");
    let tmp = scratch.path("tmp");
    assert_eq!(
        termux(Some(prefix), vec![bin.clone()], Some(tmp.clone())).status,
        Status::Ok
    );
    assert_eq!(
        termux(Some("/usr"), vec![bin.clone()], Some(tmp.clone())).status,
        Status::Fail
    );
    assert_eq!(
        termux(None, vec![bin.clone()], Some(tmp.clone())).status,
        Status::Fail
    );
    assert_eq!(termux(Some(prefix), vec![], Some(tmp)).status, Status::Warn);
    assert_eq!(
        termux(Some(prefix), vec![bin.clone()], None).status,
        Status::Warn
    );
    assert_eq!(
        termux(Some(prefix), vec![bin], Some(scratch.path("missing"))).status,
        Status::Warn
    );
}

#[test]
fn without_home_the_home_checks_fail_with_one_fix() {
    let scratch = Scratch::new("nohome");
    let report = scratch.with_ctx(SHA, |ctx| {
        let ctx = Context {
            home: None,
            ..clone_ctx(ctx)
        };
        examine(&ctx, &FakeHost::default())
    });
    for id in ["provenance", "state_dir", "env_file"] {
        assert_eq!(status_of(&report, id), Status::Fail, "{id}");
    }
}

#[test]
fn repairs_run_once_even_when_two_checks_ask() {
    let scratch = Scratch::new("once");
    let cache = scratch.path(BUILD_CACHE);
    tag_cache(&cache);
    // Low disk and a stale cache both ask to clear the same cache.
    let host = FakeHost {
        free: 100 * 1024 * 1024,
        rustc: Some("rustc 1.91.0"),
        ..FakeHost::default()
    };
    let (repairs, _) = scratch.fix(&host);
    let clears = repairs
        .iter()
        .filter(|r| r.action.starts_with("removed the build cache"))
        .count();
    assert_eq!(clears, 1, "{repairs:?}");
    assert!(repairs.iter().all(|r| r.ok), "{repairs:?}");
}

#[test]
fn every_failure_or_warning_names_a_fix() {
    let scratch = Scratch::new("fixes");
    fs::remove_dir_all(scratch.path(".huntsman")).expect("rm");
    set_mode(&scratch.path(".huntsman.env"), 0o640).expect("mode");
    fs::remove_file(scratch.bin.join("huntsman-recon")).expect("rm");
    let host = FakeHost {
        free: 1,
        accept: Err("x".into()),
        ..FakeHost::default()
    };
    let report = scratch.examine(&host);
    for check in &report.checks {
        if check.status != Status::Ok {
            assert!(
                check.fix.as_deref().is_some_and(|fix| !fix.is_empty()),
                "{check:?}"
            );
        }
        assert_eq!(check.auto_fix, check.repair.is_some(), "{check:?}");
    }
    assert!(report.count(Status::Fail) >= 4, "{}", render(&report));
}

#[test]
fn the_text_report_prints_a_repeated_fix_once() {
    let scratch = Scratch::new("render");
    fs::remove_file(scratch.bin.join("huntsman-recon")).expect("rm");
    let report = scratch.with_ctx("unknown", |ctx| examine(ctx, &FakeHost::default()));
    let text = render(&report);
    assert_eq!(text.matches(REINSTALL).count(), 1, "{text}");
    assert!(text.contains("fix: the same command as above"), "{text}");
}

/// A FIFO with no writer must be rejected promptly. The deadline detects a blocking open
/// without hanging the test runner when testing a regressed implementation.
#[cfg(unix)]
#[test]
fn a_cache_tag_fifo_without_writer_is_rejected_promptly() {
    use std::sync::mpsc;
    use std::time::Duration;

    let scratch = Scratch::new("tag-fifo-no-writer");
    let cache = scratch.home.join("cache");
    fs::create_dir_all(&cache).expect("cache");
    let tag = cache.join("CACHEDIR.TAG");
    let made = std::process::Command::new("mkfifo")
        .arg(&tag)
        .status()
        .expect("mkfifo");
    assert!(made.success(), "mkfifo {}", tag.display());

    let (answer, answered) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let _ = answer.send(tagged_cache(&cache));
    });
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(2)),
        Ok(false),
        "tagged_cache must not block opening a FIFO without a writer"
    );
    reader.join().expect("reader");
}

#[cfg(unix)]
#[test]
fn a_cache_tag_symlink_is_rejected_even_if_target_has_signature() {
    let scratch = Scratch::new("tag-symlink");
    let cache = scratch.home.join("cache");
    fs::create_dir_all(&cache).expect("cache");
    let target = scratch.home.join("other-tag");
    fs::write(&target, CACHEDIR_SIGNATURE).expect("target");
    std::os::unix::fs::symlink(&target, cache.join("CACHEDIR.TAG")).expect("symlink");
    assert!(!tagged_cache(&cache));
}

#[test]
fn a_regular_cache_tag_with_signature_is_accepted() {
    let scratch = Scratch::new("tag-regular");
    let cache = scratch.home.join("cache");
    fs::create_dir_all(&cache).expect("cache");
    fs::write(cache.join("CACHEDIR.TAG"), CACHEDIR_SIGNATURE).expect("tag");
    assert!(tagged_cache(&cache));
}
