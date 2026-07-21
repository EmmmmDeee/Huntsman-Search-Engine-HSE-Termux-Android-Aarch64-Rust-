use super::*;

    fn parse_id(id: &str) -> (u32, i64) {
        // `Tdddd` or `Tdddd.ddd` → (base, sub) with sub = -1 for a parent.
        let core = id.trim_start_matches('T');
        match core.split_once('.') {
            Some((b, s)) => (b.parse().unwrap(), s.parse().unwrap()),
            None => (core.parse().unwrap(), -1),
        }
    }

    #[test]
    fn catalogue_is_well_formed_sorted_and_unique() {
        for t in ENTERPRISE {
            assert!(
                t.id.starts_with('T') && t.id.len() >= 5,
                "bad technique id {:?}",
                t.id
            );
            let core = t.id.trim_start_matches('T');
            let (base, sub) = core
                .split_once('.')
                .map_or((core, None), |(b, s)| (b, Some(s)));
            assert!(base.len() == 4 && base.bytes().all(|b| b.is_ascii_digit()));
            assert_eq!(
                sub.is_some(),
                t.is_subtechnique,
                "is_subtechnique must match the dotted id form for {}",
                t.id
            );
            if let Some(sub) = sub {
                assert!(sub.bytes().all(|b| b.is_ascii_digit()), "bad sub {:?}", t.id);
            }
            assert!(!t.name.is_empty(), "empty name for {}", t.id);
            assert!(
                !t.tactics.is_empty(),
                "technique {} belongs to no tactic",
                t.id
            );
            // Every tactic a technique claims must be a real catalogued tactic.
            for sn in t.tactics {
                assert!(
                    TACTICS.iter().any(|ta| &ta.shortname == sn),
                    "technique {} references unknown tactic shortname {sn}",
                    t.id
                );
            }
        }
        // Sorted by (base, sub) and duplicate-free.
        let ids: Vec<&str> = ENTERPRISE.iter().map(|t| t.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_by_key(|id| parse_id(id));
        assert_eq!(ids, sorted, "ENTERPRISE must stay sorted by id");
        let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "duplicate technique id");

        // Every sub-technique's parent base technique is present.
        let bases: std::collections::BTreeSet<u32> = ENTERPRISE
            .iter()
            .filter(|t| !t.is_subtechnique)
            .map(|t| parse_id(t.id).0)
            .collect();
        for t in ENTERPRISE.iter().filter(|t| t.is_subtechnique) {
            assert!(
                bases.contains(&parse_id(t.id).0),
                "sub-technique {} has no parent technique in the catalogue",
                t.id
            );
        }
    }

    #[test]
    fn tactics_are_the_complete_enterprise_matrix() {
        // All 14 current MITRE ATT&CK Enterprise tactics, sorted and unique.
        #[rustfmt::skip]
        const FULL: &[(&str, &str)] = &[
            ("TA0001", "Initial Access"),
            ("TA0002", "Execution"),
            ("TA0003", "Persistence"),
            ("TA0004", "Privilege Escalation"),
            ("TA0005", "Defense Evasion"),
            ("TA0006", "Credential Access"),
            ("TA0007", "Discovery"),
            ("TA0008", "Lateral Movement"),
            ("TA0009", "Collection"),
            ("TA0010", "Exfiltration"),
            ("TA0011", "Command and Control"),
            ("TA0040", "Impact"),
            ("TA0042", "Resource Development"),
            ("TA0043", "Reconnaissance"),
        ];
        let have: std::collections::BTreeMap<&str, &str> =
            TACTICS.iter().map(|t| (t.id, t.name)).collect();
        assert_eq!(TACTICS.len(), FULL.len(), "tactic count drifted");
        for (id, name) in FULL {
            assert_eq!(have.get(id), Some(name), "tactic {id} missing/renamed");
        }
        let ids: Vec<&str> = TACTICS.iter().map(|t| t.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "TACTICS must stay sorted by id");
        // Every tactic is reachable by both id and shortname.
        for t in TACTICS {
            assert_eq!(tactic(t.id).map(|x| x.id), Some(t.id));
            assert_eq!(tactic(t.shortname).map(|x| x.id), Some(t.id));
        }
    }

    #[test]
    fn catalogue_is_substantial_and_multi_tactic() {
        // A sanity floor: the real v17.1 Enterprise matrix is ~680 techniques
        // across all tactics. This guards against a truncated regeneration that
        // silently drops the framework back to a single tactic.
        assert!(
            ENTERPRISE.len() > 600,
            "catalogue collapsed to {} techniques — regeneration truncated?",
            ENTERPRISE.len()
        );
        // Techniques exist for every tactic (the whole matrix, not just recon).
        for ta in TACTICS {
            assert!(
                !techniques_for_tactic(ta.shortname).is_empty(),
                "tactic {} ({}) has no techniques",
                ta.id,
                ta.shortname
            );
        }
        // A known post-compromise technique resolves — proof the vocabulary spans
        // beyond Reconnaissance. T1486 (Data Encrypted for Impact) is Impact-only.
        let t1486 = technique("T1486").expect("T1486 must be catalogued");
        assert!(t1486.tactics.contains(&"impact"));
        assert!(!t1486.tactics.contains(&"reconnaissance"));
    }

    #[test]
    fn reconnaissance_slice_is_exactly_the_complete_tactic() {
        // HSE's claimed tactic. Pins that the derived Reconnaissance view is
        // EXACTLY the full TA0043 tactic — so the coverage/gap report is honest
        // and nothing drifted in or out of the slice HSE reports on.
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
            reconnaissance().iter().map(|t| t.id).collect();
        for id in FULL_TA0043 {
            assert!(have.contains(id), "complete TA0043 is missing {id}");
        }
        assert_eq!(
            reconnaissance().len(),
            FULL_TA0043.len(),
            "Reconnaissance slice must be EXACTLY the complete tactic"
        );
        assert_eq!(TACTIC_ID, "TA0043");
        assert_eq!(TACTIC_NAME, "Reconnaissance");
        assert_eq!(tactic(TACTIC_ID).map(|t| t.name), Some(TACTIC_NAME));
    }

    #[test]
    fn uncovered_reports_real_reconnaissance_gaps() {
        let recon_len = reconnaissance().len();
        assert!(uncovered(|_| true).is_empty());
        assert_eq!(uncovered(|_| false).len(), recon_len);
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
        // Coverage/gap reporting is Reconnaissance-only: a post-compromise
        // technique is NEVER surfaced as an HSE gap (HSE never claims that tactic).
        assert!(
            gaps.iter().all(|t| t.tactics.contains(&"reconnaissance")),
            "uncovered must report Reconnaissance techniques only"
        );
    }

    #[test]
    fn technique_lookup_round_trips_across_the_framework() {
        assert_eq!(technique("T1596.002").map(|t| t.name), Some("WHOIS"));
        assert_eq!(technique("T1593.002").map(|t| t.name), Some("Search Engines"));
        // Beyond Reconnaissance — the full framework resolves.
        assert_eq!(
            technique("T1566").map(|t| t.name),
            Some("Phishing"),
            "Initial Access technique must resolve"
        );
        assert_eq!(technique("T9999"), None);
    }

    #[test]
    fn active_scanning_family_is_catalogued() {
        assert_eq!(technique("T1595").map(|t| t.name), Some("Active Scanning"));
        assert_eq!(
            technique("T1595.001").map(|t| t.name),
            Some("Scanning IP Blocks")
        );
        assert_eq!(
            technique("T1595.002").map(|t| t.name),
            Some("Vulnerability Scanning")
        );
        assert_eq!(
            technique("T1595.003").map(|t| t.name),
            Some("Wordlist Scanning")
        );
    }

    #[test]
    fn every_category_maps_only_to_catalogued_ids() {
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
                let t = technique(id)
                    .unwrap_or_else(|| panic!("category {cat:?} maps to unknown technique {id}"));
                // The category defaults are the tactic HSE claims: Reconnaissance.
                assert!(
                    t.tactics.contains(&"reconnaissance"),
                    "category {cat:?} default {id} is not a Reconnaissance technique"
                );
            }
        }
    }
