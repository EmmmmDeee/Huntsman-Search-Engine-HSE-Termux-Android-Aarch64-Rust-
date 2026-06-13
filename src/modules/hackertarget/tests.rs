use super::*;

    #[test]
    fn accepts_domain_and_ip() {
        let m = HackerTarget;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            HackerTarget.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn description_non_empty() {
        assert!(!HackerTarget.description().is_empty());
    }
