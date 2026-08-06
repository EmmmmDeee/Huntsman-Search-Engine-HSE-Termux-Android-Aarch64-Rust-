use super::*;

    fn template_for_test() -> &'static str {
        "# top comment\n\
         HUNTSMAN_OATHNET_KEY=\"insert_oathnet_pro_key_here\"\n\
         HUNTSMAN_SHODAN_KEY=\"insert_shodan_key_here\"\n\
         HUNTSMAN_HIBP_KEY=\"insert_haveibeenpwned_key_here\"\n"
    }

    #[test]
    fn merge_preserves_real_values() {
        let existing = "HUNTSMAN_OATHNET_KEY=\"real-rotated-key-abc\"\n";
        let merged = merge_template(existing, template_for_test());
        assert!(merged.contains("HUNTSMAN_OATHNET_KEY=\"real-rotated-key-abc\""));
        // Other placeholders stay.
        assert!(merged.contains("HUNTSMAN_SHODAN_KEY=\"insert_shodan_key_here\""));
    }

    #[test]
    fn merge_preserves_a_real_value_written_with_an_export_prefix() {
        // `docs/SEEKNOW_SETUP.md` tells operators to add a key by appending
        //     echo 'export HUNTSMAN_SEEKNOW_KEY="…"' >> ~/.huntsman.env
        // and `dotenvy` (util::keys::io) accepts that form, so the key WORKS —
        // right up until the next `curl … | bash`. `parse_kv` took everything
        // before `=` as the key name, so the name was `export HUNTSMAN_…`,
        // which failed the `HUNTSMAN_` check and returned None. `merge_template`
        // therefore never saw the value and wrote the TEMPLATE PLACEHOLDER over
        // the operator's real key. Silent, and on the documented happy path.
        let existing = "export HUNTSMAN_OATHNET_KEY=\"real-rotated-key-abc\"\n";
        let merged = merge_template(existing, template_for_test());
        assert!(
            merged.contains("real-rotated-key-abc"),
            "an `export`-prefixed key was dropped by the merge; merged:\n{merged}"
        );
        assert!(
            !merged.contains("insert_oathnet_pro_key_here"),
            "the placeholder overwrote a real operator key; merged:\n{merged}"
        );
    }

    #[test]
    fn parse_kv_accepts_the_documented_export_form() {
        // Same defect at the unit level, and the reason `export` must be
        // stripped rather than merely tolerated: the KEY NAME has to come out
        // clean so it matches the template line it is meant to replace.
        assert_eq!(
            parse_kv("export HUNTSMAN_X=\"abc\""),
            Some(("HUNTSMAN_X".to_string(), "abc".to_string()))
        );
        // Unquoted and extra-whitespace variants of the same shell idiom.
        assert_eq!(
            parse_kv("export   HUNTSMAN_X=plain"),
            Some(("HUNTSMAN_X".to_string(), "plain".to_string()))
        );
        // `export` must only be honoured as a STANDALONE leading keyword. This
        // input is chosen so it can only pass while that holds: strip `export`
        // without requiring the separating whitespace and the name becomes
        // `HUNTSMAN_X`, which parses as a real key and fails this assertion.
        //
        // (`exported=1` would NOT test anything: its key is `exported` when the
        // rule is right and `ed` when it is wrong, and neither starts with
        // `HUNTSMAN_`, so it returns None either way — a guard that cannot
        // catch the regression it exists to prevent.)
        assert_eq!(parse_kv("exportHUNTSMAN_X=1"), None);
    }

    #[test]
    fn merge_keeps_placeholders_for_unset_keys() {
        let merged = merge_template("", template_for_test());
        assert!(merged.contains("HUNTSMAN_OATHNET_KEY=\"insert_oathnet_pro_key_here\""));
        assert!(merged.contains("HUNTSMAN_SHODAN_KEY=\"insert_shodan_key_here\""));
        assert!(merged.contains("HUNTSMAN_HIBP_KEY=\"insert_haveibeenpwned_key_here\""));
    }

    #[test]
    fn merge_preserves_top_comment() {
        let merged = merge_template("", template_for_test());
        assert!(merged.starts_with("# top comment"));
    }

    #[test]
    fn read_existing_env_treats_missing_file_as_empty() {
        let dir = tempfile::tempdir().expect("should succeed");
        let path = dir.path().join("does-not-exist.env");
        assert_eq!(read_existing_env(&path).expect("should succeed"), "");
    }

    #[test]
    fn read_existing_env_surfaces_non_notfound_errors_instead_of_silently_emptying() {
        // A directory path passed to `read_to_string` fails with an error kind
        // OTHER than NotFound. The old `unwrap_or_default()` collapsed this
        // (and any other read failure — permission denied, a non-UTF-8 byte
        // from disk corruption) into "", which would make the subsequent merge
        // believe every currently-configured HUNTSMAN_* key was absent and
        // overwrite them all with template placeholders. The error must
        // surface instead.
        let dir = tempfile::tempdir().expect("should succeed");
        let err = read_existing_env(dir.path()).expect_err("should be an error");
        assert!(
            err.to_string().contains("read "),
            "expected a read error, got: {err}"
        );
    }

    #[test]
    fn merge_appends_user_custom_keys() {
        let existing = "HUNTSMAN_CUSTOM_INTEGRATION_KEY=\"my-secret\"\n";
        let merged = merge_template(existing, template_for_test());
        assert!(merged.contains("# --- USER-CUSTOM KEYS"));
        assert!(merged.contains("HUNTSMAN_CUSTOM_INTEGRATION_KEY=\"my-secret\""));
    }

    #[test]
    fn merge_ignores_blank_and_comment_lines_in_existing() {
        let existing = "\n# a comment\nHUNTSMAN_SHODAN_KEY=\"actual-key\"\n";
        let merged = merge_template(existing, template_for_test());
        assert!(merged.contains("HUNTSMAN_SHODAN_KEY=\"actual-key\""));
    }

    #[test]
    fn parse_kv_handles_quoted_and_unquoted() {
        assert_eq!(
            parse_kv("HUNTSMAN_X=\"abc\""),
            Some(("HUNTSMAN_X".into(), "abc".into()))
        );
        assert_eq!(
            parse_kv("HUNTSMAN_X=plain"),
            Some(("HUNTSMAN_X".into(), "plain".into()))
        );
        assert_eq!(parse_kv("# comment"), None);
        assert_eq!(parse_kv(""), None);
        assert_eq!(parse_kv("OTHER_VAR=ignored"), None);
    }

    #[test]
    fn placeholder_detection() {
        assert!(is_placeholder("insert_oathnet_pro_key_here"));
        assert!(is_placeholder("insert_x_here"));
        assert!(!is_placeholder("real-value-xyz"));
        assert!(!is_placeholder(""));
        assert!(!is_placeholder("insert_x"));
        assert!(!is_placeholder("x_here"));
    }

    #[test]
    fn merge_against_full_template_is_idempotent() {
        // Apply the merge twice with the same input — the second pass
        // must produce identical output (deterministic + stable).
        let existing = "HUNTSMAN_OATHNET_KEY=\"real-a\"\nHUNTSMAN_SHODAN_KEY=\"real-b\"\n";
        let once = merge_template(existing, ENV_TEMPLATE);
        let twice = merge_template(&once, ENV_TEMPLATE);
        assert_eq!(
            once, twice,
            "merge_template must be idempotent against the canonical template"
        );
    }

    // ── autonomous key discovery ────────────────────────────────────────────

    #[test]
    fn discover_finds_env_keys_absent_or_placeholder_in_file() {
        let existing = "HUNTSMAN_SHODAN_KEY=\"realshodan\"\n\
                        HUNTSMAN_HIBP_KEY=\"insert_haveibeenpwned_key_here\"\n";
        let env = vec![
            // already a real value in the file → not re-discovered
            ("HUNTSMAN_SHODAN_KEY".to_string(), "realshodan".to_string()),
            // file only has a placeholder → discovered
            ("HUNTSMAN_HIBP_KEY".to_string(), "abc123".to_string()),
            // absent from the file → discovered
            ("HUNTSMAN_VIRUSTOTAL_KEY".to_string(), "vt456".to_string()),
            // not a HUNTSMAN_ var → ignored
            ("PATH".to_string(), "/usr/bin".to_string()),
            // empty / placeholder / unquotable values → skipped
            ("HUNTSMAN_EMPTY".to_string(), "   ".to_string()),
            ("HUNTSMAN_PH".to_string(), "insert_x_here".to_string()),
            ("HUNTSMAN_BAD".to_string(), "has\"quote".to_string()),
        ];
        let found = discover_env_keys(existing, env);
        let names: Vec<&str> = found.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["HUNTSMAN_HIBP_KEY", "HUNTSMAN_VIRUSTOTAL_KEY"]);
        assert_eq!(
            found
                .iter()
                .find(|(k, _)| k.as_str() == "HUNTSMAN_HIBP_KEY")
                .map(|(_, v)| v.as_str()),
            Some("abc123")
        );
    }

    #[test]
    fn discover_dedups_and_sorts_by_key() {
        let env = vec![
            ("HUNTSMAN_B".to_string(), "b1".to_string()),
            ("HUNTSMAN_A".to_string(), "a1".to_string()),
            ("HUNTSMAN_A".to_string(), "a2".to_string()), // duplicate key → first wins
        ];
        assert_eq!(
            discover_env_keys("", env),
            vec![
                ("HUNTSMAN_A".to_string(), "a1".to_string()),
                ("HUNTSMAN_B".to_string(), "b1".to_string()),
            ]
        );
    }

    #[test]
    fn discover_empty_when_env_adds_nothing() {
        let existing = "HUNTSMAN_SHODAN_KEY=\"real\"\n";
        let env = vec![("HUNTSMAN_SHODAN_KEY".to_string(), "real".to_string())];
        assert!(discover_env_keys(existing, env).is_empty());
    }

    #[test]
    fn inject_then_merge_activates_discovered_key() {
        let discovered = vec![("HUNTSMAN_SHODAN_KEY".to_string(), "disc-value".to_string())];
        let injected = inject_discovered("", &discovered);
        assert!(injected.contains("HUNTSMAN_SHODAN_KEY=\"disc-value\""));
        // Through the template merge the discovered value replaces the placeholder.
        let merged = merge_template(&injected, template_for_test());
        assert!(merged.contains("HUNTSMAN_SHODAN_KEY=\"disc-value\""));
        assert!(!merged.contains("insert_shodan_key_here"));
    }

    #[test]
    fn inject_is_a_no_op_without_discoveries() {
        assert_eq!(
            inject_discovered("HUNTSMAN_X=\"y\"\n", &[]),
            "HUNTSMAN_X=\"y\"\n"
        );
    }
