use super::*;

    fn parse_id(id: &str) -> (u32, i64) {
        // `Tdddd` or `Tdddd.ddd` → (base, sub) with sub = -1 for a parent.
        let core = id.trim_start_matches('T');
        match core.split_once('.') {
            Some((b, s)) => (b.parse().expect("should succeed"), s.parse().expect("should succeed")),
            None => (core.parse().expect("should succeed"), -1),
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

    #[test]
    fn coverage_rolls_up_exercised_techniques_with_counts_and_honest_gaps() {
        let mut exercised = std::collections::BTreeMap::new();
        exercised.insert("T1596.002".to_string(), 5); // WHOIS ×5
        exercised.insert("T1589.002".to_string(), 2); // Email Addresses ×2
        exercised.insert("T9999".to_string(), 99); // unknown → ignored
        let cov = coverage(&exercised);

        assert_eq!(cov.tactic_id, "TA0043");
        // Only the two real techniques are covered, carried in catalogue order
        // (T1589.002 before T1596.002), with their counts.
        assert_eq!(cov.covered.len(), 2);
        assert_eq!(cov.covered[0].technique.id, "T1589.002");
        assert_eq!(cov.covered[0].entity_count, 2);
        assert_eq!(cov.covered[1].technique.id, "T1596.002");
        assert_eq!(cov.covered[1].entity_count, 5);
        // Covered + uncovered exactly partitions the whole catalogue.
        assert_eq!(cov.covered.len() + cov.uncovered.len(), reconnaissance().len());
        assert!(cov.uncovered.iter().any(|t| t.id == "T1598"));
        assert!(!cov.uncovered.iter().any(|t| t.id == "T1596.002"));
        // Fraction matches the covered count.
        assert!(
            (cov.coverage_fraction - 2.0 / reconnaissance().len() as f64).abs() < 1e-9,
            "fraction = {}",
            cov.coverage_fraction
        );
    }

    #[test]
    fn empty_coverage_is_all_gaps() {
        let cov = coverage(&std::collections::BTreeMap::new());
        assert!(cov.covered.is_empty());
        assert_eq!(cov.uncovered.len(), reconnaissance().len());
        assert!((cov.coverage_fraction - 0.0).abs() < 1e-9);
    }

    #[test]
    fn navigator_layer_is_a_valid_honest_layer() {
        let mut exercised = std::collections::BTreeMap::new();
        exercised.insert("T1596.002".to_string(), 5);
        let layer = navigator_layer(&coverage(&exercised), "scan-abc");

        assert_eq!(layer["domain"], "enterprise-attack");
        assert_eq!(layer["versions"]["layer"], "4.5");
        // Exactly one technique per catalogued id (covered + gaps = whole tactic).
        let techs = layer["techniques"].as_array().expect("should succeed");
        assert_eq!(techs.len(), reconnaissance().len());
        // The exercised technique is enabled and scored by its entity count.
        let whois = techs
            .iter()
            .find(|t| t["techniqueID"] == "T1596.002")
            .expect("should succeed");
        assert_eq!(whois["score"], 5);
        assert_eq!(whois["enabled"], true);
        assert_eq!(whois["tactic"], "reconnaissance");
        // A gap is present, disabled, score 0 — the honest picture.
        let phishing = techs.iter().find(|t| t["techniqueID"] == "T1598").expect("should succeed");
        assert_eq!(phishing["score"], 0);
        assert_eq!(phishing["enabled"], false);
        assert_eq!(layer["gradient"]["maxValue"], 5);
    }

    #[test]
    fn every_entity_kind_maps_only_to_catalogued_techniques() {
        // Entity-type mapping drift guard: every technique ID returned by
        // techniques_for_entity_kind must exist in the catalogue for every
        // EntityKind variant. Catches typos and removed techniques at the source.
        use crate::core::entity::EntityKind;
        let kinds = [
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Username,
            EntityKind::Credential,
            EntityKind::ApiKey,
            EntityKind::Password,
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Asn,
            EntityKind::Cidr,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::MacAddress,
            EntityKind::DeviceId,
            EntityKind::Ssid,
            EntityKind::TrackingId,
            EntityKind::CryptoAddress,
            EntityKind::Other("test".to_string()),
        ];
        for kind in kinds {
            for id in techniques_for_entity_kind(&kind) {
                assert!(
                    technique(id).is_some(),
                    "{kind:?} maps to unknown technique {id}"
                );
            }
        }
    }

    #[test]
    fn every_relation_kind_maps_only_to_catalogued_reconnaissance_ids() {
        // Relation-mapping drift guard, the third of the trio beside the
        // category and entity-kind guards. The `match` below has NO `_` arm, so
        // a new RelationKind fails to compile until it is triaged here — the
        // graph layer can't silently stop contributing to coverage.
        use crate::core::relation::RelationKind;
        const EVERY: &[RelationKind] = &[
            RelationKind::SubdomainOf,
            RelationKind::BelongsToDomain,
            RelationKind::HostedOn,
            RelationKind::ResolvesTo,
            RelationKind::RegisteredBy,
            RelationKind::CoLocatedWith,
            RelationKind::DerivedFrom,
            RelationKind::IdentifiedBy,
            RelationKind::AliasOf,
            RelationKind::LocatedAt,
            RelationKind::AssociatedWith,
            RelationKind::SameAs,
            RelationKind::SameOperator,
            RelationKind::SameIdentity,
            RelationKind::SharesSecretWith,
            RelationKind::EmployedBy,
            RelationKind::OfficerOf,
            RelationKind::MemberOf,
            RelationKind::ControlledBy,
            RelationKind::OperatedBy,
        ];
        for &k in EVERY {
            match k {
                RelationKind::SubdomainOf
                | RelationKind::BelongsToDomain
                | RelationKind::HostedOn
                | RelationKind::ResolvesTo
                | RelationKind::RegisteredBy
                | RelationKind::CoLocatedWith
                | RelationKind::DerivedFrom
                | RelationKind::IdentifiedBy
                | RelationKind::AliasOf
                | RelationKind::LocatedAt
                | RelationKind::AssociatedWith
                | RelationKind::SameAs
                | RelationKind::SameOperator
                | RelationKind::SameIdentity
                | RelationKind::SharesSecretWith
                | RelationKind::EmployedBy
                | RelationKind::OfficerOf
                | RelationKind::MemberOf
                | RelationKind::ControlledBy
                | RelationKind::OperatedBy => {}
            }
            for id in techniques_for_relation_kind(k) {
                let t = technique(id)
                    .unwrap_or_else(|| panic!("{k:?} maps to unknown technique {id}"));
                assert!(
                    t.tactics.contains(&"reconnaissance"),
                    "{k:?} maps to {id}, which is not a Reconnaissance technique"
                );
            }
        }
        assert_eq!(EVERY.len(), 20, "one entry per RelationKind variant");
    }

    #[test]
    fn relation_mapping_names_the_affiliation_techniques_exactly() {
        // The mappings that carry the most weight: an edge derived from a
        // companies register is Identify Roles, and a corporate hierarchy is
        // Business Relationships. Pinned so a later edit can't quietly blur them.
        use crate::core::relation::RelationKind;
        assert_eq!(
            techniques_for_relation_kind(RelationKind::OfficerOf),
            &["T1591.004"],
            "a filed officeholder IS Identify Roles"
        );
        assert_eq!(
            techniques_for_relation_kind(RelationKind::ControlledBy),
            &["T1591.002"],
            "the corporate hierarchy IS Business Relationships"
        );
        assert_eq!(technique("T1591.004").map(|t| t.name), Some("Identify Roles"));
        assert_eq!(
            technique("T1591.002").map(|t| t.name),
            Some("Business Relationships")
        );
        // Provenance and normalisation are NOT collection against the target.
        assert!(techniques_for_relation_kind(RelationKind::DerivedFrom).is_empty());
        assert!(techniques_for_relation_kind(RelationKind::SameAs).is_empty());
    }

    #[test]
    fn folding_relations_adds_edge_counts_to_the_entity_tally() {
        use crate::core::relation::{Relation, RelationKind};
        let mut exercised = std::collections::BTreeMap::new();
        exercised.insert("T1591.004".to_string(), 2); // 2 entities already tagged
        let rels = vec![
            Relation::new("a", "b", RelationKind::OfficerOf, 0.9, "s"),
            Relation::new("c", "d", RelationKind::OfficerOf, 0.9, "s"),
            Relation::new("e", "f", RelationKind::ControlledBy, 0.9, "s"),
            // Provenance contributes nothing.
            Relation::new("g", "h", RelationKind::DerivedFrom, 0.9, "s"),
        ];
        fold_relation_techniques(&mut exercised, &rels);
        assert_eq!(
            exercised.get("T1591.004"),
            Some(&4),
            "edge counts add to the entity tally rather than replacing it"
        );
        assert_eq!(exercised.get("T1591.002"), Some(&1));
        assert_eq!(exercised.len(), 2, "DerivedFrom introduced no technique");

        // And the rollup now reports the graph layer's collection as covered.
        let cov = coverage(&exercised);
        assert!(
            cov.covered.iter().any(|c| c.technique.id == "T1591.002"),
            "Business Relationships is covered once a corporate edge exists"
        );
    }

    #[test]
    fn entity_type_mapping_resolves_common_types_correctly() {
        use crate::core::entity::EntityKind;
        // Email addresses → T1589.002
        assert!(techniques_for_entity_kind(&EntityKind::Email).contains(&"T1589.002"));
        // Usernames → T1593.001 (Social Media) + T1589.003 (Employee Names)
        let username_techniques = techniques_for_entity_kind(&EntityKind::Username);
        assert!(username_techniques.contains(&"T1593.001"));
        assert!(username_techniques.contains(&"T1589.003"));
        // IP Addresses → T1590.005
        assert!(techniques_for_entity_kind(&EntityKind::IpAddress).contains(&"T1590.005"));
        // Domains → T1590.001 + T1596.002 + T1593.002 + T1594
        let domain_techniques = techniques_for_entity_kind(&EntityKind::Domain);
        assert!(domain_techniques.contains(&"T1590.001"));
        assert!(domain_techniques.contains(&"T1596.002"));
        assert!(domain_techniques.contains(&"T1593.002"));
        assert!(domain_techniques.contains(&"T1594"));
        // Credentials → T1589.001
        assert!(techniques_for_entity_kind(&EntityKind::Credential).contains(&"T1589.001"));
        // Addresses → T1591.001
        assert!(techniques_for_entity_kind(&EntityKind::Address).contains(&"T1591.001"));
        // Org Info → T1591
        assert!(techniques_for_entity_kind(&EntityKind::Organisation).contains(&"T1591"));
    }

    #[test]
    fn coverage_by_entity_type_aggregates_and_sorts_correctly() {
        // Technique T1589.002 (Email Addresses) carried by 5 Email entities and
        // 2 Username entities; T1593.001 (Social Media) by 3 Username entities.
        let entity_techniques = vec![
            ("Email".to_string(), "T1589.002".to_string()),
            ("Email".to_string(), "T1589.002".to_string()),
            ("Email".to_string(), "T1589.002".to_string()),
            ("Email".to_string(), "T1589.002".to_string()),
            ("Email".to_string(), "T1589.002".to_string()),
            ("Username".to_string(), "T1589.002".to_string()),
            ("Username".to_string(), "T1589.002".to_string()),
            ("Username".to_string(), "T1593.001".to_string()),
            ("Username".to_string(), "T1593.001".to_string()),
            ("Username".to_string(), "T1593.001".to_string()),
        ];
        let by_type = coverage_by_entity_type(&entity_techniques);
        // Only two techniques exercised
        assert_eq!(by_type.len(), 2);
        // First is T1589.002 (catalogue order), second is T1593.001
        assert_eq!(by_type[0].technique.id, "T1589.002");
        assert_eq!(by_type[1].technique.id, "T1593.001");
        // T1589.002 breakdown: 5 Email, 2 Username
        assert_eq!(
            by_type[0].by_entity_type.get("Email"),
            Some(&5),
            "T1589.002 Email count"
        );
        assert_eq!(
            by_type[0].by_entity_type.get("Username"),
            Some(&2),
            "T1589.002 Username count"
        );
        // T1593.001 breakdown: 3 Username
        assert_eq!(
            by_type[1].by_entity_type.get("Username"),
            Some(&3),
            "T1593.001 Username count"
        );
        // Entity type keys are sorted within each technique
        let t1589_types: Vec<&String> = by_type[0].by_entity_type.keys().collect();
        assert!(
            t1589_types
                .windows(2)
                .all(|w| w[0] <= w[1]),
            "entity types must be sorted"
        );
    }

    #[test]
    fn techniques_from_entities_extracts_and_dedupes_attack_tags() {
        use crate::core::entity::{Entity, EntityKind};
        // Create test entities with attack technique tags
        let mut e1 = Entity::new(EntityKind::Email, "test1@example.com", 0.8, "s");
        e1.tag("attack:T1589.002".to_string());
        e1.tag("attack:T1593.002".to_string());

        let mut e2 = Entity::new(EntityKind::Username, "testuser", 0.7, "s");
        e2.tag("attack:T1589.002".to_string()); // Duplicate technique
        e2.tag("attack:T1593.001".to_string());

        let entities = vec![&e1, &e2];
        let techniques = techniques_from_entities(&entities);

        // Should extract 3 unique technique IDs (T1589.002, T1593.001, T1593.002)
        // in sorted order
        assert_eq!(techniques.len(), 3);
        assert_eq!(techniques[0], "T1589.002");
        assert_eq!(techniques[1], "T1593.001");
        assert_eq!(techniques[2], "T1593.002");
    }

    #[test]
    fn techniques_from_entities_ignores_non_attack_tags() {
        use crate::core::entity::{Entity, EntityKind};
        let mut e = Entity::new(EntityKind::Email, "test@example.com", 0.8, "s");
        e.tag("attack:T1589.002".to_string());
        e.tag("sector:tech".to_string()); // Non-attack tag
        e.tag("attack:T1593.002".to_string());

        let entities = vec![&e];
        let techniques = techniques_from_entities(&entities);

        // Should only extract attack techniques, ignore sector tag
        assert_eq!(techniques.len(), 2);
        assert!(techniques.contains(&"T1589.002".to_string()));
        assert!(techniques.contains(&"T1593.002".to_string()));
    }
