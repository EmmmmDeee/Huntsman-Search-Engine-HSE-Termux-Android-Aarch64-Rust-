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

    #[test]
    fn parent_and_subtechnique_relations() {
        assert_eq!(parent_id("T1596.002"), Some("T1596"));
        assert_eq!(parent_id("T1596"), None);
        assert!(is_subtechnique("T1590.005"));
        assert!(!is_subtechnique("T1590"));

        // subtechniques() returns the catalogued children, ID-sorted.
        let subs: Vec<&str> = subtechniques("T1596").iter().map(|t| t.id).collect();
        assert_eq!(
            subs,
            vec!["T1596.001", "T1596.002", "T1596.003", "T1596.004", "T1596.005"]
        );
        let mut sorted = subs.clone();
        sorted.sort_unstable();
        assert_eq!(subs, sorted, "subtechniques must be ID-sorted");
        assert!(subtechniques("T9999").is_empty(), "unknown parent → empty");

        // Catalogue integrity: every sub-technique's parent is itself catalogued,
        // so rollup can never orphan a hit.
        for t in RECONNAISSANCE {
            if let Some(parent) = parent_id(t.id) {
                assert!(
                    technique(parent).is_some(),
                    "sub-technique {} has an uncatalogued parent {parent}",
                    t.id
                );
            }
        }
    }

    fn tagged(id: &str, conf: f64) -> crate::core::entity::Entity {
        let mut e = crate::core::entity::Entity::new(
            crate::core::entity::EntityKind::Email,
            format!("{}@example.com", id.replace('.', "")),
            conf,
            "s",
        );
        e.tag(format!("attack:{id}"));
        e
    }

    #[test]
    fn coverage_reports_exercised_gaps_and_rolls_subtechniques_up() {
        // Two findings via one sub-technique (T1589.002) at differing strength, and
        // one via a different technique (T1596.002). Nothing else is exercised.
        let entities = vec![
            tagged("T1589.002", 0.60),
            tagged("T1589.002", 0.90),
            tagged("T1596.002", 0.50),
        ];
        let rep = coverage(&entities);

        assert_eq!(rep.tactic_id, "TA0043");
        assert_eq!(rep.total_count, RECONNAISSANCE.len());

        let cov = |id: &str| rep.techniques.iter().find(|t| t.id == id).unwrap();

        // Direct sub-technique hit: 2 findings, strongest c_eff 0.90.
        let sub = cov("T1589.002");
        assert!(sub.exercised && sub.is_subtechnique);
        assert_eq!(sub.finding_count, 2);
        assert!((sub.max_c_eff - 0.90).abs() < 1e-9);

        // Rolled UP into the parent T1589 (exercised via its sub-technique).
        let parent = cov("T1589");
        assert!(parent.exercised && !parent.is_subtechnique);
        assert_eq!(parent.finding_count, 2);
        assert!((parent.max_c_eff - 0.90).abs() < 1e-9);

        // The other technique + its parent.
        assert!(cov("T1596.002").exercised);
        assert!(cov("T1596").exercised, "parent rolled up");

        // A technique nothing touched is a gap.
        assert!(!cov("T1597").exercised);
        assert!(rep.gaps().iter().any(|t| t.id == "T1597"));
        assert!(rep.exercised().iter().all(|t| t.exercised));
        assert_eq!(rep.exercised_count, rep.exercised().len());
        // exercised: T1589, T1589.002, T1596, T1596.002 → 4.
        assert_eq!(rep.exercised_count, 4);
    }

    #[test]
    fn coverage_ignores_uncatalogued_tags_and_is_order_independent() {
        let mut a = tagged("T1590.005", 0.7);
        a.tag("attack:T9999.999"); // stale / typo'd → must be ignored
        a.tag("not-an-attack-tag");
        let b = tagged("T1593.001", 0.4);

        let fwd = coverage(&[a.clone(), b.clone()]);
        let rev = coverage(&[b, a]);
        // Deterministic: serialised report is byte-identical across input orders.
        assert_eq!(
            serde_json::to_string(&fwd).unwrap(),
            serde_json::to_string(&rev).unwrap()
        );
        // The bogus tag invented no technique.
        assert!(fwd.techniques.iter().all(|t| t.id != "T9999.999"));
        assert!(fwd.techniques.iter().find(|t| t.id == "T1590.005").unwrap().exercised);
    }
