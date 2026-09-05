use super::*;
    use crate::core::scan::TargetKind;

    // ── parse_target_kind ───────────────────────────────────────────────────

    #[test]
    fn parse_email() {
        assert_eq!(parse_target_kind("email").expect("should succeed"), TargetKind::Email);
        assert_eq!(parse_target_kind("EMAIL").expect("should succeed"), TargetKind::Email);
        assert_eq!(parse_target_kind(" Email ").expect("should succeed"), TargetKind::Email);
    }

    #[test]
    fn parse_username() {
        assert_eq!(parse_target_kind("username").expect("should succeed"), TargetKind::Username);
    }

    #[test]
    fn parse_phone() {
        assert_eq!(parse_target_kind("phone").expect("should succeed"), TargetKind::Phone);
    }

    #[test]
    fn parse_name_aliases() {
        assert_eq!(parse_target_kind("name").expect("should succeed"), TargetKind::FullName);
        assert_eq!(parse_target_kind("fullname").expect("should succeed"), TargetKind::FullName);
    }

    #[test]
    fn parse_ip_aliases() {
        assert_eq!(parse_target_kind("ip").expect("should succeed"), TargetKind::IpAddress);
        assert_eq!(
            parse_target_kind("ipaddress").expect("should succeed"),
            TargetKind::IpAddress
        );
    }

    #[test]
    fn parse_domain() {
        assert_eq!(parse_target_kind("domain").expect("should succeed"), TargetKind::Domain);
    }

    #[test]
    fn parse_asn() {
        assert_eq!(parse_target_kind("asn").expect("should succeed"), TargetKind::Asn);
    }

    #[test]
    fn parse_coords_aliases() {
        assert_eq!(
            parse_target_kind("coords").expect("should succeed"),
            TargetKind::Coordinates
        );
        assert_eq!(
            parse_target_kind("coordinates").expect("should succeed"),
            TargetKind::Coordinates
        );
    }

    #[test]
    fn parse_address() {
        assert_eq!(parse_target_kind("address").expect("should succeed"), TargetKind::Address);
    }

    #[test]
    fn parse_unknown_kind_is_err() {
        assert!(parse_target_kind("foobar").is_err());
        assert!(parse_target_kind("").is_err());
    }

    #[test]
    fn every_seed_kind_canonical_form_round_trips() {
        // Total invariant: the canonical string the system emits for EVERY seed
        // kind (`canonical_str` — also serde/API/entity `kind`) must parse back to
        // that exact kind via the CLI parser. Regression: `full_name`/`ip_address`
        // did not (only `fullname`/`ipaddress` were accepted), so a copied
        // canonical kind failed on the CLI. Driven over the complete kind list so
        // a newly-added kind that forgets the alias fails here.
        for &kind in crate::core::dependency::ALL_TARGET_KINDS {
            let canon = kind.canonical_str();
            assert_eq!(
                parse_target_kind(canon).ok(),
                Some(kind),
                "canonical form {canon:?} must round-trip through parse_target_kind"
            );
        }
    }

    // ── split_csv ───────────────────────────────────────────────────────────

    #[test]
    fn split_csv_none_stays_none() {
        assert!(split_csv(None).is_none());
    }

    #[test]
    fn split_csv_single_entry() {
        let r = split_csv(Some("dns_resolver".into())).expect("should succeed");
        assert_eq!(r, vec!["dns_resolver"]);
    }

    #[test]
    fn split_csv_multiple_entries() {
        let r = split_csv(Some("a, b ,c".into())).expect("should succeed");
        assert_eq!(r, vec!["a", "b", "c"]);
    }

    #[test]
    fn split_csv_empty_string() {
        let r = split_csv(Some(String::new())).expect("should succeed");
        assert_eq!(r, vec![""]);
    }

    // ── cost_label ──────────────────────────────────────────────────────────

    #[test]
    fn cost_labels() {
        assert_eq!(
            crate::app::export::cost_label(crate::core::ModuleCost::Free),
            "free"
        );
        assert_eq!(
            crate::app::export::cost_label(crate::core::ModuleCost::KeyGated),
            "key-gated"
        );
        assert_eq!(
            crate::app::export::cost_label(crate::core::ModuleCost::Paid),
            "paid"
        );
    }

    // ── truncate ────────────────────────────────────────────────────────────

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        let r = truncate("hello world", 5);
        assert!(r.contains('…'));
        assert_eq!(r.chars().count(), 5);
    }

    #[test]
    fn truncate_unicode() {
        let r = truncate("café latte", 5);
        assert_eq!(r.chars().count(), 5);
        assert!(r.ends_with('…'));
    }

    // ── resolve_seed ────────────────────────────────────────────────────────

    #[test]
    fn resolve_seed_prefers_explicit_cli_value() {
        let got = resolve_seed(Some("alice".to_string()), Some("default".to_string())).expect("should succeed");
        assert_eq!(got, "alice");
    }

    #[test]
    fn resolve_seed_falls_back_to_default_when_value_absent() {
        let got = resolve_seed(None, Some("default".to_string())).expect("should succeed");
        assert_eq!(got, "default");
    }

    #[test]
    fn resolve_seed_blank_cli_value_falls_back_to_default() {
        // `-v "  "` is treated as absent, not as a blank target.
        let got = resolve_seed(Some("   ".to_string()), Some("default".to_string())).expect("should succeed");
        assert_eq!(got, "default");
    }

    #[test]
    fn resolve_seed_trims_explicit_value() {
        let got = resolve_seed(Some("  bob  ".to_string()), None).expect("should succeed");
        assert_eq!(got, "bob");
    }

    #[test]
    fn resolve_seed_errors_when_nothing_set() {
        let err = resolve_seed(None, None).expect_err("should be an error").to_string();
        assert!(err.contains("--value"), "{err}");
        assert!(err.contains("HUNTSMAN_DEFAULT_SEED"), "{err}");
    }

    // ── resolve_scan_id ─────────────────────────────────────────────────────

    #[test]
    fn resolve_scan_id_recovers_incomplete_scans() {
        use crate::core::scan::{Scan, ScanStatus, Target};
        use crate::storage::Store;

        let store = Store::open(":memory:").expect("should succeed");
        let target = Target { kind: TargetKind::Email, value: "test@example.com".to_string() };
        let mut scan = Scan::new("abc123", target);
        scan.status = ScanStatus::Running;
        store.upsert_scan(&scan).expect("should succeed");

        // An interrupted (non-complete) scan's checkpointed data must be
        // RECOVERABLE — resolve returns Ok so export/audit can read its partial
        // entities, never discarding collected findings (warning goes to stderr).
        assert_eq!(
            crate::app::runtime::resolve_scan_id(&store, "abc123").expect("should succeed"),
            "abc123"
        );
        // A genuinely-absent scan still errors loudly.
        assert!(crate::app::runtime::resolve_scan_id(&store, "no-such-scan").is_err());
    }

    #[test]
    fn config_set_rejects_an_unknown_toggle_key_instead_of_persisting_it() {
        // `hse config module.shodann off` used to print "○ off" and persist a
        // key nothing reads — a silent no-op the operator took as "disabled".
        // The same validator the web toggle endpoint uses now rejects it, and
        // the command exits non-zero without touching settings.json.
        let err = crate::cli::config::cmd_config(
            Some("module.no_such_module_xyz".to_string()),
            Some("off".to_string()),
        )
        .expect_err("an unknown toggle key must be an error");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown toggle key") && msg.contains("module.no_such_module_xyz"),
            "{msg}"
        );
        // An unset key resolves to the caller's default; had `off` been
        // persisted, this would read back `false`.
        assert!(
            crate::util::settings::get_bool("module.no_such_module_xyz", true),
            "nothing may have been persisted for the rejected key"
        );
    }

    // ── bsi profile aliasing (shared with `hse assurance --profile`) ─────────

    #[test]
    fn bsi_profile_railway_aliases_cloud() {
        use crate::core::assurance::Profile;
        // The directive names `hse bsi profile railway`; a Railway/container
        // deployment is exactly the cloud-hosted profile under which C5 applies.
        assert_eq!(super::assurance::parse_profile("railway").unwrap(), Profile::Cloud);
        assert_eq!(super::assurance::parse_profile("RAILWAY").unwrap(), Profile::Cloud);
        // Canonical names still resolve; a bare word matches its profile.
        assert_eq!(super::assurance::parse_profile("cloud").unwrap(), Profile::Cloud);
        assert_eq!(super::assurance::parse_profile("android").unwrap(), Profile::Android);
        assert_eq!(
            super::assurance::parse_profile("hse-bsi-web").unwrap(),
            Profile::Web
        );
        // An unknown profile is a clean error, never a silent default.
        assert!(super::assurance::parse_profile("nope").is_err());
    }
