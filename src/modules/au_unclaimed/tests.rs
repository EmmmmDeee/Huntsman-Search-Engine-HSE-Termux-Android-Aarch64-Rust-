use super::*;

#[test]
fn accepts_fullname_and_org() {
    let m = AuUnclaimed;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Ha"))); // too short
}

#[test]
fn module_metadata() {
    let m = AuUnclaimed;
    assert_eq!(m.name(), "au_unclaimed");
    assert!(m.attack_techniques().contains(&"T1591.001"));
    assert_eq!(m.cost(), ModuleCost::Free);
}

#[test]
fn module_covers_queensland() {
    // The QLD register is folded in here now (no separate qld_unclaimed module).
    let m = AuUnclaimed;
    assert!(m.description().contains("QLD"));
    // Person + Organisation pivots come from the QLD owner-parsing pass.
    assert!(m.produces().contains(&EntityKind::Person));
    assert!(m.produces().contains(&EntityKind::Organisation));
}

// ── Queensland pass (folded in from the former `qld_unclaimed` module) ──────
//
// These pin that QLD's distinctive, richer capability survives the merge: joint
// owner parsing into Persons, company-owner Organisation pivots, the
// surname-vs-exact family classification, postcode→QLD geo addresses, and
// suburb-level locality enumeration. The evidence source stays `qld_unclaimed`
// so the downstream correlator/relation rules keyed on it keep working.
mod qld {
    use super::super::qld_helpers::{
        SRC, owner_person_names, records_to_entities, suburbs_to_entities,
    };
    use crate::core::entity::{Entity, EntityKind};
    use crate::util::ckan::Response as CkanResp;
    use crate::util::postcode_au::Locality;

    fn sample() -> CkanResp {
        let raw = r#"{
            "result": {
                "total": 3,
                "records": [
                    {"_id":1938437,"ClientId_ActNo":"210580670460","Owner":"HAYLEY AVERY & CURT AVERY","Amount":"545.74","SenderName":"INSURANCE AUSTRALIA GROUP LIMITED","DateRec":"2024-03-14","PCode":"4557","rank":0.0706241},
                    {"_id":913780,"ClientId_ActNo":"207768336631","Owner":"CURT AVERY","Amount":"0.92","SenderName":"REMUNERATION SERVICES","DateRec":"2015-03-31","PCode":"4555","rank":0.057308756},
                    {"_id":1082370,"ClientId_ActNo":"208285682789","Owner":"ERIK AVERY","Amount":"115.45","SenderName":"UNCM DEPT OF TPT AND MAIN ROADS - MAIN ROAD","DateRec":"2016-10-17","PCode":"4552","rank":0.057308756}
                ]
            }
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn owner_person_names_splits_joint_and_excludes_companies() {
        // Joint individuals split on `&`/`and`, each title-cased; companies and
        // the unknown-owner sentinel are excluded (the Organisation pass owns
        // companies).
        assert_eq!(
            owner_person_names("HAYLEY DIEGMANN & CURT DIEGMANN"),
            vec!["Hayley Diegmann".to_string(), "Curt Diegmann".to_string()]
        );
        assert!(owner_person_names("ACME WIDGETS PTY LTD").is_empty());
        assert!(owner_person_names("(unknown owner)").is_empty());
    }

    #[test]
    fn owner_person_names_does_not_fabricate_a_person_from_half_a_business_name() {
        // Shape confirmed against a real QLD Public Trustee register row
        // (live-queried 2026-07-09, resource
        // 872065ae-ddfd-4b5f-ad15-e1935dadd883, q=Lawnton): a towing
        // company, not two people named "Lawnton Towing" and "Recovery"
        // (names here are fictional test data — the register row itself is
        // a company, not a person, so no individual's identity is involved).
        // The " AND "->"&" joint-owner splitter (designed for genuine joint
        // bank holdings) used to tear this into "LAWNTON TOWING" (which
        // happens to be 2 name-shaped tokens, so it passed
        // clean_person_name) and "RECOVERY" (1 token, rejected) -- keeping
        // the half that merely LOOKED like a name and fabricating a "family
        // member" who does not exist.
        assert!(
            owner_person_names("LAWNTON TOWING AND RECOVERY").is_empty(),
            "a business name torn apart by the AND-splitter must not surface \
             a fragment as a fabricated person"
        );

        // A genuine 4-person joint holding (fictional names, initials-style
        // given names + a hyphenated surname — matching the shape of a real
        // live-verified register row) must still split cleanly -- the
        // all-or-nothing group check must not become an all-or-nothing
        // OVER-correction that drops real joint owners.
        assert_eq!(
            owner_person_names(
                "A B FOXGLEN AND C D MOCKRIDGE AND E F FOXGLEN-WREN AND G H TESTBOURNE"
            ),
            vec![
                "A B Foxglen".to_string(),
                "C D Mockridge".to_string(),
                "E F Foxglen-wren".to_string(),
                "G H Testbourne".to_string(),
            ]
        );

        // A genuinely ambiguous mix (one bare given name with no surname of
        // its own, matching a real live register row's shape) is
        // conservatively dropped in full rather than guessed at -- this
        // project's bar is "false positives are worse than missing
        // coverage".
        assert!(owner_person_names("MARCUS AND TAYLOR WRENFIELD AND HOLLOWDALE").is_empty());

        // Two genuine individuals still split correctly (unaffected by the
        // group-integrity check, since both sides independently pass).
        assert_eq!(
            owner_person_names("JORDAN WRENFIELD AND TAYLOR WRENFIELD"),
            vec![
                "Jordan Wrenfield".to_string(),
                "Taylor Wrenfield".to_string()
            ]
        );
    }

    #[test]
    fn owner_person_names_strips_a_trailing_state_suffix_the_register_appends() {
        // Shape confirmed against real QLD Public Trustee register rows
        // (live-queried 2026-07-09) -- the register commonly appends the
        // owner's home state directly to their name with no separating
        // punctuation. Left in place this becomes part of the "name"
        // (title-cased to a garbled "... Qld"), corrupting a genuine
        // person's identity. Given names below are fictional test data;
        // "Lawnton" is kept as the surname because it is the real AU
        // suburb name whose collision with a surname is the phenomenon
        // under test, not a real individual's identity.
        assert_eq!(
            owner_person_names("TAYLOR MORGAN LAWNTON QLD"),
            vec!["Taylor Morgan Lawnton".to_string()]
        );
        assert_eq!(
            owner_person_names("RILEY ASHWORTH LAWNTON QLD"),
            vec!["Riley Ashworth Lawnton".to_string()]
        );
        // A genuine 2-token name is untouched when no state suffix is present.
        assert_eq!(
            owner_person_names("AVERY LAWNTON"),
            vec!["Avery Lawnton".to_string()]
        );
    }

    #[test]
    fn classifies_exact_person_vs_surname_only_family() {
        let recs = sample().result.unwrap().records;
        let curt = records_to_entities(&recs, 3, "Curt Avery", true, "s");
        let exact = |e: &Entity| e.tags.iter().any(|t| t.as_str() == "exact-name-match");
        let addrs: Vec<&Entity> = curt
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .collect();
        assert!(exact(addrs[0]), "HAYLEY & CURT row is an exact Curt match");
        assert!(exact(addrs[1]), "CURT AVERY row is an exact Curt match");
        assert!(!exact(addrs[2]), "ERIK row is only a surname match");

        // The owner Person pass mints the family as first-class people, judged
        // per-person.
        let person = |v: &str| {
            curt.iter()
                .find(|e| e.kind == EntityKind::Person && e.value == v)
        };
        assert!(person("Curt Avery").is_some_and(exact));
        assert!(person("Erik Avery").is_some_and(|e| !exact(e) && e.confidence < 0.50));
    }

    #[test]
    fn company_owner_emits_organisation_for_abn_pivot() {
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":7,"Owner":"ACME WIDGETS PTY LTD","Amount":"1200.00","SenderName":"ASX","PCode":"4000"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .unwrap()
            .result
            .unwrap()
            .records;
        let ents = records_to_entities(&recs, 1, "ACME Widgets", true, "s");
        let org = ents
            .iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .expect("company owner must emit an Organisation");
        assert_eq!(org.value, "ACME WIDGETS PTY LTD");
        assert!(org.tags.iter().any(|t| t.as_str() == "company-owner"));
    }

    #[test]
    fn sender_name_emits_payer_company_organisation() {
        // The SenderName — the employer/estate/insurer that LODGED the money — must
        // surface as a `sender-company` Organisation (the T1591.002 business
        // relationship), previously parsed into evidence and then dropped.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":8,"Owner":"Jane Citizen","Amount":"500.00","SenderName":"GLOBEX EMPLOYMENT PTY LTD","PCode":"4000"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .unwrap()
            .result
            .unwrap()
            .records;
        let ents = records_to_entities(&recs, 1, "Jane Citizen", true, "s");
        let sender = ents
            .iter()
            .find(|e| {
                e.kind == EntityKind::Organisation
                    && e.tags.iter().any(|t| t.as_str() == "sender-company")
            })
            .expect("SenderName company must emit a sender-company Organisation");
        assert!(
            sender.value.to_uppercase().contains("GLOBEX"),
            "got {}",
            sender.value
        );
        assert!(sender.tags.iter().any(|t| t.as_str() == "country:AU"));
    }

    #[test]
    fn parses_records_into_geo_addresses_tagged_qld_source() {
        let resp = sample();
        let result = resp.result.unwrap();
        let ents = records_to_entities(
            &result.records,
            result.total.unwrap(),
            "Avery",
            true,
            "scan-1",
        );
        let addrs: Vec<&Entity> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .collect();
        assert_eq!(addrs.len(), 3, "one address per record");
        assert_eq!(addrs[0].value, "QLD 4557, Australia");
        for e in &addrs {
            assert!(e.tags.iter().any(|t| t.as_str() == "unclaimed-money"));
            assert!(e.tags.iter().any(|t| t.as_str() == "country:AU"));
        }
        // The evidence source is preserved as `qld_unclaimed` so the downstream
        // correlator/relation rules keyed on it keep firing.
        assert_eq!(addrs[0].evidence[0].source, SRC);
        assert_eq!(SRC, "qld_unclaimed");
    }

    #[test]
    fn suburbs_enumerate_into_geocodable_candidates() {
        let locs = vec![
            Locality {
                suburb: "Maleny".into(),
                lat: -26.729,
                lon: 152.7554,
            },
            Locality {
                suburb: "Conondale".into(),
                lat: -26.7333,
                lon: 152.7167,
            },
        ];
        let ents = suburbs_to_entities(&[("4552".to_string(), locs)], "s");
        let coords: Vec<&Entity> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .collect();
        assert_eq!(coords.len(), 1);
        assert!(
            coords[0]
                .tags
                .iter()
                .any(|t| t.as_str() == "postcode-centroid")
        );
        let addrs: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(
            addrs,
            vec![
                "Maleny, QLD 4552, Australia",
                "Conondale, QLD 4552, Australia",
            ]
        );
        assert!(ents.iter().all(|e| e.confidence < 0.50));
    }
}
