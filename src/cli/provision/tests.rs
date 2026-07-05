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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.env");
        assert_eq!(read_existing_env(&path).unwrap(), "");
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
        let dir = tempfile::tempdir().unwrap();
        let err = read_existing_env(dir.path()).unwrap_err();
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
