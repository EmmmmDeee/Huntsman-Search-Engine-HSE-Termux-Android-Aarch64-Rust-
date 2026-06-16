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

#[test]
fn navigator_layer_is_valid_and_marks_exercised_techniques() {
    let cov = coverage(["T1589.002", "T1596.002", "T1589.002"]); // dup collapses
    let json = navigator_layer("HSE scan abc", "test layer", &cov);

    let v: serde_json::Value = serde_json::from_str(&json).expect("layer is valid JSON");
    // Navigator layer envelope.
    assert_eq!(v["domain"], "enterprise-attack");
    assert_eq!(v["versions"]["layer"], "4.5");
    assert_eq!(v["name"], "HSE scan abc");

    let techs = v["techniques"].as_array().expect("techniques array");
    assert_eq!(techs.len(), 2, "deduped to two techniques");
    // Every entry is a reconnaissance technique scored as exercised.
    for t in techs {
        assert_eq!(t["tactic"], "reconnaissance");
        assert_eq!(t["score"], 1);
        assert_eq!(t["enabled"], true);
    }
    let ids: Vec<&str> = techs
        .iter()
        .filter_map(|t| t["techniqueID"].as_str())
        .collect();
    assert!(ids.contains(&"T1589.002"));
    assert!(ids.contains(&"T1596.002"));
}

#[test]
fn navigator_layer_empty_coverage_is_still_valid() {
    let json = navigator_layer("empty", "no techniques", &[]);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(v["techniques"].as_array().map(Vec::len), Some(0));
    assert_eq!(v["domain"], "enterprise-attack");
}

#[test]
fn assessment_partitions_the_catalogue() {
    let covered = coverage(["T1589.002", "T1596.002"]);
    let a = Assessment::from_covered(covered);
    // covered + gaps == the whole catalogue, with no overlap.
    assert_eq!(a.covered.len() + a.gaps.len(), RECONNAISSANCE.len());
    let cov_ids: std::collections::HashSet<&str> = a.covered.iter().map(|t| t.id).collect();
    assert!(a.gaps.iter().all(|t| !cov_ids.contains(t.id)), "no technique in both sets");
    assert!(cov_ids.contains("T1589.002"));
    // A covered technique must not also appear as a gap.
    assert!(!a.gaps.iter().any(|t| t.id == "T1596.002"));
}

#[test]
fn assessment_coverage_pct_bounds() {
    let none = Assessment::from_covered(vec![]);
    assert_eq!(none.covered.len(), 0);
    assert!((none.coverage_pct() - 0.0).abs() < f64::EPSILON);

    let all = Assessment::from_covered(RECONNAISSANCE.iter().collect());
    assert!(all.gaps.is_empty());
    assert!((all.coverage_pct() - 100.0).abs() < f64::EPSILON);

    let some = Assessment::from_covered(coverage(["T1589"]));
    let pct = some.coverage_pct();
    assert!(pct > 0.0 && pct < 100.0, "partial coverage in (0,100): {pct}");
}
