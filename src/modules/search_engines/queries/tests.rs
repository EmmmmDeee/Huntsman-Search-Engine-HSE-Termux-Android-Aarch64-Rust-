use super::*;

    #[test]
    fn separator_swaps_are_generated_and_deduped() {
        let v = generate_username_variants("jerome.despal");
        assert!(v.contains(&"jeromedespal".to_string())); // separators removed
        assert!(v.contains(&"jerome_despal".to_string())); // → underscore
        assert!(v.contains(&"jerome-despal".to_string())); // → dash
        // The original form is never emitted as its own variant.
        assert!(!v.contains(&"jerome.despal".to_string()));
    }

    #[test]
    fn trailing_digit_and_truncation_variants() {
        let v = generate_username_variants("jdespal");
        assert!(v.contains(&"jdespal1".to_string()));
        assert!(v.contains(&"jdespal2".to_string()));
        assert!(v.contains(&"jdespa".to_string())); // last char dropped
    }

    #[test]
    fn digit_terminated_handles_skip_digit_variants() {
        // Already ends in a digit → no `…1`/`…2` appended.
        let v = generate_username_variants("agent007");
        assert!(!v.iter().any(|s| s.ends_with("0071") || s.ends_with("0072")));
    }

    #[test]
    fn multibyte_handle_truncates_by_char_without_panicking() {
        // Regression: a handle ending in a multi-byte codepoint must not panic
        // on the truncation slice, and must drop a whole char.
        let v = generate_username_variants("andré");
        assert!(v.contains(&"andr".to_string())); // 'é' dropped whole
        assert!(v.iter().all(|s| s != "andré"));

        // Pure non-ASCII handle (every char multi-byte) — also must not panic.
        let _ = generate_username_variants("Ωμέγα");
    }

    #[test]
    fn short_handle_yields_no_variants() {
        // No separators, < 4 chars → nothing (too short to pivot on).
        assert!(generate_username_variants("ab").is_empty());
    }

    #[test]
    fn interleave_runs_regional_dorks_early() {
        let base = vec!["base0".to_string(), "base1".into(), "base2".into()];
        let regional = vec!["au0".to_string(), "au1".into()];
        let q = interleave_regional(base, regional);
        // Strongest base query first, then AU dorks, then the rest.
        assert_eq!(q, ["base0", "au0", "au1", "base1", "base2"]);
        // AU dorks land before the tail base queries (won't be starved).
        let au_pos = q.iter().position(|x| x == "au0").unwrap();
        let tail_pos = q.iter().position(|x| x == "base1").unwrap();
        assert!(au_pos < tail_pos);
        // Degenerate inputs.
        assert_eq!(interleave_regional(vec![], vec!["a".into()]), ["a"]);
        assert_eq!(interleave_regional(vec!["b".into()], vec![]), ["b"]);
    }

    #[test]
    fn detect_region_flags_australian_seeds() {
        use crate::core::scan::Target;
        assert_eq!(
            detect_region(&Target::new(TargetKind::Domain, "example.com.au")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Email, "person@deakin.edu.au")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "+61 412 345 678")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(
                TargetKind::Address,
                "10 Queen St, Brisbane QLD"
            )),
            Some(Region::Au)
        );
        // Non-AU seeds → no region.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Domain, "example.com")),
            None
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Username, "jdoe")),
            None
        );
    }

    #[test]
    fn detect_region_phone_distinguishes_au_cc_from_us_area_code() {
        use crate::core::scan::Target;
        // Bare AU country code at full international length → AU.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "61 412 345 678")),
            Some(Region::Au)
        );
        // US `610` area code (10 digits) must NOT be read as AU country code.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "610-555-1234")),
            None
        );
        // `+61` stays unambiguous regardless of spacing.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "+61 2 9000 0000")),
            Some(Region::Au)
        );
    }
