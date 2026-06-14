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
    fn coverage_dedupes_sorts_and_drops_unknown() {
        let cov = coverage(["T1596.002", "T1589.002", "T1596.002", "T9999"]);
        let ids: Vec<&str> = cov.iter().map(|t| t.id).collect();
        assert_eq!(ids, vec!["T1589.002", "T1596.002"]);
        assert!(coverage(std::iter::empty::<&str>()).is_empty());
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
