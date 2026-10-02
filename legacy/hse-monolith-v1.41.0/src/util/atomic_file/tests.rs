use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_then_read_round_trips_and_sets_mode_0600() {
        let dir = tempdir().expect("should succeed");
        let path = dir.path().join("store.json");
        write(&path, b"{\"a\":true}").expect("should succeed");
        assert_eq!(std::fs::read(&path).expect("should succeed"), b"{\"a\":true}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("should succeed").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "destination must be private");
        }
        // No temp straggler from a successful write.
        let strays = std::fs::read_dir(dir.path())
            .expect("should succeed")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(strays, 0, "successful write must leave no temp");
    }

    #[test]
    fn concurrent_writes_never_corrupt_or_strand() {
        // Eight writers hammering the same path must always leave valid content
        // and no temp straggler — the property a shared fixed temp would break.
        let dir = tempdir().expect("should succeed");
        let path = dir.path().join("store.json");
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for j in 0..25u32 {
                        let body = format!("{{\"w{i}\":{}}}", j % 2 == 0);
                        let _ = write(&path, body.as_bytes());
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("should succeed");
        }
        let s = std::fs::read_to_string(&path).expect("should succeed");
        serde_json::from_str::<serde_json::Value>(&s)
            .expect("destination must always be a complete, valid file");
        let strays = std::fs::read_dir(dir.path())
            .expect("should succeed")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(strays, 0, "no temp stragglers after concurrent writes");
    }

    #[test]
    #[cfg(unix)]
    fn create_dir_private_is_0700() {
        // §7 S3: the ~/.huntsman tree must be owner-only.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("should succeed");
        // Recursive private dir → every created component is 0700.
        let nested = dir.path().join("a/b/c");
        create_dir_private(&nested).expect("should succeed");
        let dmode = std::fs::metadata(&nested).expect("should succeed").permissions().mode();
        assert_eq!(dmode & 0o777, 0o700, "private dir must be owner-only");
    }

    #[test]
    #[cfg(unix)]
    fn create_dir_private_retightens_a_preexisting_loose_dir() {
        // Regression guard: an UPGRADED install may already have ~/.huntsman at
        // 0755 (older builds used a plain create_dir_all). `DirBuilder::mode()`
        // only affects dirs it creates, so create_dir_private must re-tighten a
        // pre-existing loose dir — otherwise the world-readable key vault / pool
        // beneath it would stay traversable by another local UID.
        //
        // Unix-only: PermissionsExt::mode() doesn't exist on other platforms, and
        // the 0700 guarantee this test pins is itself POSIX-permissions-only —
        // matching the sibling `create_dir_private_is_0700` test's gating.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().expect("should succeed");
        let loose = tmp.path().join("huntsman");
        std::fs::create_dir(&loose).expect("should succeed");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).expect("should succeed");
        assert_eq!(
            std::fs::metadata(&loose).expect("should succeed").permissions().mode() & 0o777,
            0o755,
            "precondition: dir starts world-listable"
        );
        create_dir_private(&loose).expect("should succeed");
        assert_eq!(
            std::fs::metadata(&loose).expect("should succeed").permissions().mode() & 0o777,
            0o700,
            "a pre-existing loose dir must be re-tightened to owner-only"
        );
    }

/// The privacy classification tests the property that matters — no group or
/// other access — not equality with `0o700`.
///
/// This is what decides whether `create_dir_private` stays quiet or warns that
/// secrets are exposed, so both kinds of wrongness cost something real: a false
/// negative leaves `key_vault.db` readable by other local UIDs with nobody told,
/// and a false positive cries wolf on a directory that is perfectly private and
/// trains operators to ignore the warning.
///
/// Driven by values rather than by contriving a filesystem this process cannot
/// chmod, which is not reproducible in a unit test — the same reason the
/// per-host circuit breaker takes `now` as a parameter.
#[cfg(unix)]
#[test]
fn private_mode_classification_looks_at_group_and_other_only() {
    // Private: nothing for group or other, whatever the owner holds.
    for mode in [0o700, 0o600, 0o500, 0o400, 0o000, 0o300] {
        assert!(
            is_private_mode(mode),
            "{mode:o} grants no group/other access and must count as private"
        );
    }

    // Exposed: any single group or other bit is enough.
    for mode in [0o755, 0o750, 0o705, 0o701, 0o710, 0o770, 0o777, 0o644, 0o007] {
        assert!(
            !is_private_mode(mode),
            "{mode:o} is reachable by another local UID and must NOT count as private"
        );
    }

    // Real modes from `metadata()` carry the file-type bits above 0o7777
    // (S_IFDIR = 0o040000). Those must not be mistaken for permission bits, or
    // every directory would be classified from the wrong field.
    assert!(
        is_private_mode(0o040700),
        "the S_IFDIR type bits must not affect the classification"
    );
    assert!(
        !is_private_mode(0o040755),
        "a 0755 directory is exposed regardless of its type bits"
    );
}
