use super::*;
use std::fs;

/// Build a fake Termux home: the cache artefacts `install.sh` creates, plus a
/// `~/.huntsman` holding the operator's data.
fn fake_home() -> tempfile::TempDir {
    let td = tempfile::tempdir().expect("tempdir");
    let home = td.path();
    let cache = home.join(".cache");
    fs::create_dir_all(cache.join("hse-dl")).expect("mk hse-dl");
    fs::write(cache.join("hse-dl/hse-aarch64"), vec![0u8; 4096]).expect("asset");
    fs::write(cache.join("hse-prebuilt"), vec![0u8; 2048]).expect("prebuilt");
    fs::write(cache.join("hse-autoupdate"), "1700000000").expect("stamp");
    fs::create_dir_all(cache.join("hse-build/release/.fingerprint")).expect("mk build");
    fs::write(cache.join("hse-build/release/.fingerprint/lib-log"), vec![0u8; 8192])
        .expect("artefact");
    fs::write(cache.join("hse-install.log"), vec![0u8; 512]).expect("install log");
    fs::write(cache.join("hse-bg.log"), vec![0u8; 256]).expect("bg log");

    // The operator's data — must never appear in the reclaim set.
    let hs = home.join(".huntsman");
    fs::create_dir_all(hs.join("dossiers")).expect("mk dossiers");
    fs::write(hs.join("huntsman.db"), vec![0u8; 65536]).expect("db");
    fs::write(hs.join("key_pool.json"), "{}").expect("keys");
    fs::write(hs.join("key_vault.db"), vec![0u8; 1024]).expect("vault");
    fs::write(hs.join("dossiers/scan-1.md"), "report").expect("dossier");
    td
}

/// The single most important property of this whole command: it must never
/// propose deleting anything under `~/.huntsman`. That directory is the scan
/// database, the key pool, the key vault and the dossiers — the operator's
/// collected intelligence and secrets. A repair that reclaims those has
/// destroyed exactly what it exists to protect.
#[test]
fn reclaim_never_targets_operator_data() {
    let td = fake_home();
    let home = td.path();
    // Check BOTH modes: `--deep` widens the allowlist, which is where an
    // over-broad entry would most plausibly be introduced.
    for deep in [false, true] {
        for t in reclaimable_targets(home, Some(home.join("src")), deep) {
            let p = t.path.to_string_lossy().to_string();
            assert!(
                !p.contains(".huntsman"),
                "reclaim target {p} is inside the operator's data directory (deep={deep})"
            );
        }
    }
}

/// The shallow (default) set must be cheap to regenerate: no build caches, no
/// logs. An operator running plain `hse repair` should not silently lose a
/// 15-20 minute rebuild or the post-mortem record of a failed install.
#[test]
fn shallow_reclaim_excludes_expensive_and_diagnostic_artefacts() {
    let td = fake_home();
    let home = td.path();
    let shallow: Vec<String> = reclaimable_targets(home, None, false)
        .iter()
        .map(|t| t.path.to_string_lossy().to_string())
        .collect();

    for excluded in ["hse-build", "hse-install.log", "hse-bg.log"] {
        assert!(
            !shallow.iter().any(|p| p.contains(excluded)),
            "{excluded} must require --deep, found in the default set: {shallow:?}"
        );
    }
    // …and it must still do something useful by default.
    assert!(
        shallow.iter().any(|p| p.contains("hse-dl")),
        "the default set must still reclaim re-downloadable assets"
    );
}

/// `--deep` picks up the big one. The pasted-from-device symptom that motivated
/// this command was a multi-gigabyte `target/release/.fingerprint/**` tree.
#[test]
fn deep_reclaim_includes_both_build_cache_locations() {
    let td = fake_home();
    let home = td.path();
    let src = home.join("src-checkout");
    let deep: Vec<String> = reclaimable_targets(home, Some(src.clone()), true)
        .iter()
        .map(|t| t.path.to_string_lossy().to_string())
        .collect();

    assert!(
        deep.iter().any(|p| p.ends_with("hse-build")),
        "the CARGO_TARGET_DIR cache must be reclaimable under --deep: {deep:?}"
    );
    assert!(
        deep.iter()
            .any(|p| p == &src.join("target").to_string_lossy().to_string()),
        "an in-tree target/ under the source checkout must be reclaimable too: {deep:?}"
    );
}

/// Never propose deleting the tree the running binary lives in.
///
/// Found by RUNNING the command, not by reasoning about it: a `--dry-run --deep`
/// on a development checkout offered to free 21.9 GiB from `<checkout>/target`,
/// which is exactly where the executing `hse` had been built. Reclaiming it
/// would have deleted the binary mid-run. On a normal Termux install the live
/// binary sits at `$PREFIX/bin/hse`, well outside any build cache, so the guard
/// is inert there and decisive in the one place it matters.
#[test]
fn never_reclaims_the_tree_holding_the_running_binary() {
    // The test binary lives under this crate's own target directory, so using
    // its grandparent as the "install dir" reproduces the exact hazard.
    let exe = std::env::current_exe().expect("current_exe");
    let target_dir = exe
        .ancestors()
        .find(|p| p.file_name().is_some_and(|n| n == "target"))
        .expect("test binary must live under a target/ directory");
    let checkout = target_dir.parent().expect("target has a parent");

    let targets = reclaimable_targets(checkout, Some(checkout.to_path_buf()), true);
    for t in &targets {
        assert!(
            !exe.starts_with(&t.path),
            "reclaim target {} contains the running binary {}",
            t.path.display(),
            exe.display()
        );
    }
    // Specifically: the in-tree target/ entry must have been filtered out.
    assert!(
        !targets.iter().any(|t| t.path == target_dir),
        "the running binary's own target/ must not be offered for reclaim"
    );
}

/// Sizes must be measured recursively, or the report understates a build tree
/// by orders of magnitude and the operator cannot judge whether to run --deep.
#[test]
fn size_is_measured_recursively() {
    let td = fake_home();
    let home = td.path();
    let build = reclaimable_targets(home, None, true)
        .into_iter()
        .find(|t| t.path.ends_with("hse-build"))
        .expect("build cache target");
    assert!(
        build.size_bytes() >= 8192,
        "nested artefact bytes must be counted, got {}",
        build.size_bytes()
    );
}

/// Removing a tree actually removes it, and the operator's data survives a full
/// deep reclaim untouched — the end-to-end form of the safety property.
#[test]
fn deep_reclaim_removes_caches_and_leaves_data_intact() {
    let td = fake_home();
    let home = td.path();

    for t in reclaimable_targets(home, None, true) {
        if t.exists() {
            t.remove().expect("remove");
        }
    }

    assert!(!home.join(".cache/hse-dl").exists());
    assert!(!home.join(".cache/hse-build").exists());
    assert!(!home.join(".cache/hse-prebuilt").exists());

    // Every operator artefact still present and unmodified in size.
    let hs = home.join(".huntsman");
    assert_eq!(fs::metadata(hs.join("huntsman.db")).unwrap().len(), 65536);
    assert!(hs.join("key_pool.json").is_file());
    assert!(hs.join("key_vault.db").is_file());
    assert!(hs.join("dossiers/scan-1.md").is_file());
}

/// A live background server must keep its log: deleting it out from under a
/// running process loses the record the operator is most likely to need.
#[test]
fn a_live_server_retains_its_log() {
    let td = fake_home();
    let home = td.path();
    // Our own PID is definitionally live.
    fs::write(
        home.join(".cache/hse-bg.pid"),
        std::process::id().to_string(),
    )
    .expect("pid file");

    let bg_log = reclaimable_targets(home, None, true)
        .into_iter()
        .find(|t| t.path.ends_with("hse-bg.log"))
        .expect("bg log target");

    match bg_log.remove().expect("guarded remove must not error") {
        Reclaimed::Retained(why) => assert!(
            why.contains("hse-bg stop"),
            "the retention reason must tell the operator how to proceed, got: {why}"
        ),
        Reclaimed::Removed => panic!("a live server's log must be retained"),
    }
    assert!(home.join(".cache/hse-bg.log").is_file());
}

/// A stale PID file must not block the reclaim forever. PID 2^31-1 is not a
/// live process on any Linux this runs on.
#[test]
fn a_stale_pid_file_does_not_block_reclaim() {
    let td = fake_home();
    let home = td.path();
    fs::write(home.join(".cache/hse-bg.pid"), "2147483647").expect("pid file");

    let bg_log = reclaimable_targets(home, None, true)
        .into_iter()
        .find(|t| t.path.ends_with("hse-bg.log"))
        .expect("bg log target");

    assert_eq!(bg_log.remove().expect("remove"), Reclaimed::Removed);
    assert!(!home.join(".cache/hse-bg.log").exists());
}

/// A missing target is a no-op, not an error — a fresh install has none of
/// these, and `hse repair` must be safe to run at any time.
#[test]
fn absent_targets_are_not_errors() {
    let td = tempfile::tempdir().expect("tempdir");
    for t in reclaimable_targets(td.path(), None, true) {
        assert!(!t.exists());
        assert_eq!(t.remove().expect("absent remove is Ok"), Reclaimed::Removed);
    }
}

/// The run verdict is the worst stage status, so a single failure cannot be
/// masked by later successes.
#[test]
fn verdict_is_the_worst_stage_status() {
    let mk = |status| StageReport {
        id: "t",
        title: "t",
        status,
        detail: vec![],
        remediation: None,
        bytes_freed: 0,
    };
    let rep = RepairReport {
        stages: vec![
            mk(StageStatus::Ok),
            mk(StageStatus::Repaired),
            mk(StageStatus::Failed),
            mk(StageStatus::Ok),
        ],
        bytes_freed: 0,
        dry_run: false,
    };
    assert_eq!(rep.verdict(), StageStatus::Failed);
    assert!(rep.had_failure());
    assert!(into_result(&rep).is_err());

    // A warn is reportable but not a failure — offline, or no keys configured,
    // must still exit 0 so `hse repair` is usable in a scripted boot sequence.
    let warned = RepairReport {
        stages: vec![mk(StageStatus::Ok), mk(StageStatus::Warn)],
        bytes_freed: 0,
        dry_run: false,
    };
    assert_eq!(warned.verdict(), StageStatus::Warn);
    assert!(!warned.had_failure());
    assert!(into_result(&warned).is_ok());
}

/// An empty run is `Ok`, not a panic on `max()` over nothing.
#[test]
fn an_empty_report_is_ok() {
    let rep = RepairReport {
        stages: vec![],
        bytes_freed: 0,
        dry_run: false,
    };
    assert_eq!(rep.verdict(), StageStatus::Ok);
    assert!(into_result(&rep).is_ok());
}

#[test]
fn human_bytes_covers_the_range_an_operator_sees() {
    assert_eq!(human_bytes(0), "0 B");
    assert_eq!(human_bytes(512), "512 B");
    assert_eq!(human_bytes(2048), "2 KiB");
    assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
}

/// Status labels are the scriptable contract of `--json`; pin them.
#[test]
fn status_labels_are_stable() {
    assert_eq!(StageStatus::Ok.as_str(), "ok");
    assert_eq!(StageStatus::Skipped.as_str(), "skipped");
    assert_eq!(StageStatus::Repaired.as_str(), "repaired");
    assert_eq!(StageStatus::Warn.as_str(), "warn");
    assert_eq!(StageStatus::Failed.as_str(), "failed");
}
