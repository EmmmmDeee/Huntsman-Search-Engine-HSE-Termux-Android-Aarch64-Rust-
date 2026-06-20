use super::*;
use serde_json::json;

fn map_from_value(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn accepts_fullname_and_org() {
    let m = AuUnclaimed;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Ha"))); // too short
}

#[test]
fn surname_extracts_last_token() {
    assert_eq!(surname("Haigen Bamford"), "Bamford");
    assert_eq!(surname("Mary Jane Watson"), "Watson");
    assert_eq!(surname("Solo"), "Solo");
}

#[test]
fn owner_matches_all_tokens_case_insensitive() {
    let rec = map_from_value(json!({"OWNER_NAME": "BAMFORD, HAIGEN J"}));
    assert!(owner_matches(&rec, "OWNER_NAME", "Haigen Bamford"));
    assert!(!owner_matches(&rec, "OWNER_NAME", "Jane Smith"));
}

#[test]
fn record_to_entities_emits_address_and_coords() {
    let reg = &REGISTERS[0]; // NSW
    let record = map_from_value(json!({
        "OWNER_NAME": "BAMFORD HAIGEN",
        "POSTCODE": "2000",
        "SUBURB": "Sydney",
    }));
    let ents = record_to_entities(&record, reg, "Haigen Bamford", "s");
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
    assert!(addr.value.contains("NSW"));
    assert!(addr.has_tag("au-state:NSW") && addr.has_tag("country:AU"));
}

#[test]
fn record_to_entities_missing_postcode_returns_empty() {
    let reg = &REGISTERS[0];
    let record = map_from_value(json!({"OWNER_NAME": "BAMFORD HAIGEN"}));
    let ents = record_to_entities(&record, reg, "Haigen Bamford", "s");
    assert!(ents.is_empty(), "no postcode → no entities");
}

#[test]
fn postcode_centroid_covers_six_states_else_none() {
    for (state, lat, lon) in [
        ("NSW", -33.8688, 151.2093),
        ("VIC", -37.8136, 144.9631),
        ("WA", -31.9505, 115.8605),
        ("SA", -34.9285, 138.6007),
        ("TAS", -42.8821, 147.3272),
        ("ACT", -35.2809, 149.1300),
    ] {
        let (got_lat, got_lon) = postcode_centroid("0000", state).unwrap();
        assert!((got_lat - lat).abs() < 1e-9, "{state} lat");
        assert!((got_lon - lon).abs() < 1e-9, "{state} lon");
    }
    assert!(postcode_centroid("4000", "QLD").is_none());
    assert!(postcode_centroid("0800", "NT").is_none());
    assert!(postcode_centroid("2000", "ZZ").is_none());
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
