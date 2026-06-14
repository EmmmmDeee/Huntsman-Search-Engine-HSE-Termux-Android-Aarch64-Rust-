use super::*;

    #[test]
    fn accepts_identity_and_org_kinds() {
        let m = ExaSearch;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::FullName,
            TargetKind::Domain,
            TargetKind::Organisation,
            TargetKind::Phone,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
        // Not for IPs, coords, ASNs.
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn cost_is_keygated() {
        assert!(matches!(ExaSearch.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn email_regex_matches_standard_addresses() {
        assert!(EMAIL_RE.is_match("contact alice@example.com please"));
        assert!(EMAIL_RE.is_match("bob.smith+tag@sub.example.co.uk"));
    }

    #[test]
    fn phone_regex_matches_intl_format() {
        assert!(PHONE_RE.is_match("+44 20 7946 0958"));
        assert!(PHONE_RE.is_match("+1-555-123-4567"));
    }
