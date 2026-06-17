use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_then_read_round_trips_and_sets_mode_0600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.json");
        write(&path, b"{\"a\":true}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":true}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "destination must be private");
        }
        // No temp straggler from a successful write.
        let strays = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(strays, 0, "successful write must leave no temp");
    }

    #[test]
    fn concurrent_writes_never_corrupt_or_strand() {
        // Eight writers hammering the same path must always leave valid content
        // and no temp straggler — the property a shared fixed temp would break.
        let dir = tempdir().unwrap();
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
            h.join().unwrap();
        }
        let s = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str::<serde_json::Value>(&s)
            .expect("destination must always be a complete, valid file");
        let strays = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(strays, 0, "no temp stragglers after concurrent writes");
    }

    #[test]
    #[cfg(unix)]
    fn create_dir_private_is_0700_and_set_private_is_0600() {
        // §7 S3: the ~/.huntsman tree must be owner-only, and a file SQLite
        // created for us (the DB) must be restrictable after the fact.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        // Recursive private dir → every created component is 0700.
        let nested = dir.path().join("a/b/c");
        create_dir_private(&nested).unwrap();
        let dmode = std::fs::metadata(&nested).unwrap().permissions().mode();
        assert_eq!(dmode & 0o777, 0o700, "private dir must be owner-only");
        // set_private tightens an existing 0644 file to 0600.
        let f = dir.path().join("db.sqlite");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        set_private(&f).unwrap();
        let fmode = std::fs::metadata(&f).unwrap().permissions().mode();
        assert_eq!(fmode & 0o777, 0o600, "existing file must be restricted to owner-only");
    }
