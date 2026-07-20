use super::*;

    #[test]
    fn catalogue_is_well_formed_and_sorted() {
        for t in RECONNAISSANCE {
            assert!(
                t.id.starts_with('T') && t.id.len() >= 5,
                "bad technique id {:?}",
                t.id
            );
            // IDs are `Tdddd` or `Tdddd.ddd`.
            let core = t.id.trim_start_matches('T');
            let (base, sub) = core
                .split_once('.')
                .map_or((core, None), |(b, s)| (b, Some(s)));
            assert!(base.len() == 4 && base.bytes().all(|b| b.is_ascii_digit()));
            if let Some(sub) = sub {
                assert!(
                    sub.bytes().all(|b| b.is_ascii_digit()),
                    "bad sub {:?}",
                    t.id
                );
            }
            assert!(!t.name.is_empty());
        }
        let mut sorted = RECONNAISSANCE.to_vec();
        sorted.sort_by_key(|t| t.id);
        assert_eq!(
            RECONNAISSANCE.iter().map(|t| t.id).collect::<Vec<_>>(),
            sorted.iter().map(|t| t.id).collect::<Vec<_>>(),
            "RECONNAISSANCE must stay sorted by id"
        );
        // No duplicate IDs.
        let mut ids: Vec<&str> = RECONNAISSANCE.iter().map(|t| t.id).collect();
        ids.dedup();
        assert_eq!(ids.len(), RECONNAISSANCE.len(), "duplicate technique id");
    }

    #[test]
    fn catalogue_is_the_complete_reconnaissance_tactic() {
        // The full MITRE ATT&CK Reconnaissance tactic (TA0043): all ten
        // techniques and every sub-technique. Pins that the catalogue holds the
        // WHOLE tactic (so a coverage/gap report is honest) and that nothing
        // drifted in or out.
        #[rustfmt::skip]
        const FULL_TA0043: &[&str] = &[
            "T1589", "T1589.001", "T1589.002", "T1589.003",
            "T1590", "T1590.001", "T1590.002", "T1590.003", "T1590.004", "T1590.005", "T1590.006",
            "T1591", "T1591.001", "T1591.002", "T1591.003", "T1591.004",
            "T1592", "T1592.001", "T1592.002", "T1592.003", "T1592.004",
            "T1593", "T1593.001", "T1593.002", "T1593.003",
            "T1594",
            "T1595", "T1595.001", "T1595.002", "T1595.003",
            "T1596", "T1596.001", "T1596.002", "T1596.003", "T1596.004", "T1596.005",
            "T1597", "T1597.001", "T1597.002",
            "T1598", "T1598.001", "T1598.002", "T1598.003", "T1598.004",
        ];
        let have: std::collections::BTreeSet<&str> =
            RECONNAISSANCE.iter().map(|t| t.id).collect();
        for id in FULL_TA0043 {
            assert!(have.contains(id), "complete TA0043 is missing {id}");
        }
        assert_eq!(
            RECONNAISSANCE.len(),
            FULL_TA0043.len(),
            "catalogue must be EXACTLY the complete tactic — no extra/dropped ids"
        );
        assert_eq!(TACTIC_ID, "TA0043");
        assert_eq!(TACTIC_NAME, "Reconnaissance");
    }

    #[test]
    fn uncovered_reports_real_gaps() {
        // Everything covered → no gaps; nothing covered → the whole tactic.
        assert!(uncovered(|_| true).is_empty());
        assert_eq!(uncovered(|_| false).len(), RECONNAISSANCE.len());
        // A realistic partial set: HSE performs no phishing, so T1598 is a gap.
        let covered: std::collections::BTreeSet<&str> =
            ["T1589.002", "T1596.002"].into_iter().collect();
        let gaps = uncovered(|id| covered.contains(id));
        assert!(
            gaps.iter().any(|t| t.id == "T1598"),
            "Phishing for Information must surface as an honest gap"
        );
        assert!(
            !gaps.iter().any(|t| t.id == "T1589.002"),
            "a covered technique must not be reported as a gap"
        );
    }

    #[test]
    fn technique_lookup_round_trips() {
        assert_eq!(technique("T1596.002").map(|t| t.name), Some("WHOIS"));
        assert_eq!(
            technique("T1593.002").map(|t| t.name),
            Some("Search Engines")
        );
        assert_eq!(technique("T9999"), None);
    }

    #[test]
    fn active_scanning_family_is_catalogued() {
        // The Active Scanning (T1595) family HSE actually performs: portscan maps
        // to the parent + Scanning IP Blocks, and subdomain_takeover — an active
        // dangling-CNAME vulnerability probe — maps to Vulnerability Scanning.
        // Vulnerability Scanning was previously missing from the catalogue, so a
        // module that performs it could only be mis-labelled with a passive
        // technique; this pins that the precise technique now exists to map to.
        assert_eq!(technique("T1595").map(|t| t.name), Some("Active Scanning"));
        assert_eq!(
            technique("T1595.001").map(|t| t.name),
            Some("Scanning IP Blocks")
        );
        assert_eq!(
            technique("T1595.002").map(|t| t.name),
            Some("Vulnerability Scanning")
        );
        // Wordlist Scanning — dictionary subdomain brute-force (dns_intel).
        assert_eq!(
            technique("T1595.003").map(|t| t.name),
            Some("Wordlist Scanning")
        );
    }

    #[test]
    fn every_category_maps_only_to_catalogued_ids() {
        // Drift guard at the source: every ID the category map yields must be a
        // real catalogue entry, for every category (so a typo'd or removed
        // technique is caught without needing the module registry).
        let cats = [
            ModuleCategory::DnsRecon,
            ModuleCategory::Breach,
            ModuleCategory::Infrastructure,
            ModuleCategory::Search,
            ModuleCategory::Social,
            ModuleCategory::Email,
            ModuleCategory::Phone,
            ModuleCategory::Corporate,
            ModuleCategory::Threat,
            ModuleCategory::Sensor,
            ModuleCategory::People,
            ModuleCategory::Web,
            ModuleCategory::Geo,
            ModuleCategory::Other,
        ];
        for cat in cats {
            for id in techniques_for_category(cat) {
                assert!(
                    technique(id).is_some(),
                    "category {cat:?} maps to unknown technique {id}"
                );
            }
        }
    }
