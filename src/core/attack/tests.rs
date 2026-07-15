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
