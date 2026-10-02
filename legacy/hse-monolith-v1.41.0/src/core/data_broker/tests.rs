use super::*;

    #[test]
    fn lookup_matches_label_aligned_host_and_subdomains() {
        assert_eq!(
            broker_for_host("spokeo.com").map(|b| b.name),
            Some("Spokeo")
        );
        assert_eq!(
            broker_for_host("www.spokeo.com").map(|b| b.name),
            Some("Spokeo")
        );
        assert_eq!(
            broker_for_host("WWW.Spokeo.COM.").map(|b| b.name),
            Some("Spokeo")
        );
        // A subdomain of a broker still resolves to the broker.
        assert_eq!(
            broker_for_host("teaser.spokeo.com").map(|b| b.name),
            Some("Spokeo")
        );
        // Substring-but-not-label-aligned must NOT match.
        assert_eq!(broker_for_host("notspokeo.com"), None);
        assert_eq!(broker_for_host("spokeo.com.evil.test"), None);
        // A non-broker host.
        assert_eq!(broker_for_host("github.com"), None);
    }

    #[test]
    fn registry_is_well_formed() {
        for b in BROKERS {
            assert!(!b.domain.is_empty() && b.domain.contains('.'));
            assert_eq!(b.domain, b.domain.to_ascii_lowercase());
            assert!(!b.domain.starts_with("www."));
            assert!(!b.name.is_empty());
        }
        // Alphabetical by domain (stable review/output order).
        let mut sorted = BROKERS.to_vec();
        sorted.sort_by_key(|b| b.domain);
        assert_eq!(
            BROKERS.iter().map(|b| b.domain).collect::<Vec<_>>(),
            sorted.iter().map(|b| b.domain).collect::<Vec<_>>(),
            "BROKERS must stay sorted by domain"
        );
    }

    /// Drift-guard: every broker this registry knows must also be recognised as
    /// a mega/aggregator domain by the engine's expansion gate, so the two views
    /// of "this is a people-search site" can't diverge — the engine dampens
    /// exactly the sites this module flags as locating the subject's data.
    #[test]
    fn every_broker_is_a_known_mega_domain() {
        for b in BROKERS {
            assert!(
                crate::core::scan::is_noncentral_domain(b.domain),
                "broker {} is not in the engine's mega/infra domain list — add it \
                 to MEGA_DOMAINS so expansion still treats it as aggregator noise",
                b.domain
            );
        }
    }
