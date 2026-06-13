use serde_json::{Map, Value};

use crate::core::{
    entity::{Entity, EntityKind},
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{Response as CkanResp, field_str};
use crate::util::postcode_au::Locality;

use super::QldUnclaimed;
use super::helpers::{
    derive_query, exact_postcodes, merge_records, owner_matches_full_name, records_to_entities,
    suburbs_to_entities,
};
use super::SRC;

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
fn accepts_fullname_and_org_only() {
    let m = QldUnclaimed;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jordan Avery")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "ACME Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

#[test]
fn module_metadata() {
    let m = QldUnclaimed;
    assert_eq!(m.name(), "qld_unclaimed");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
}

#[test]
fn derive_query_broadens_full_name_to_surname() {
    assert_eq!(
        derive_query(&Target::new(TargetKind::FullName, "Jordan Avery")),
        "Avery"
    );
    assert_eq!(
        derive_query(&Target::new(TargetKind::FullName, "  Curt   Avery  ")),
        "Avery"
    );
    assert_eq!(
        derive_query(&Target::new(TargetKind::FullName, "Cher")),
        "Cher"
    );
    assert_eq!(
        derive_query(&Target::new(TargetKind::Organisation, "ACME Pty Ltd")),
        "ACME Pty Ltd"
    );
}

#[test]
fn classifies_exact_person_vs_surname_only_family() {
    let resp = sample();
    let result = resp.result.unwrap();

    let fam = records_to_entities(&result.records, 3, "Jordan Avery", true, "s");
    assert!(
        fam.iter()
            .all(|e| e.tags.iter().any(|t| t.as_str() == "family-candidate")),
        "surname-only relatives must be tagged family-candidate"
    );
    assert!(
        fam.iter()
            .all(|e| !e.tags.iter().any(|t| t.as_str() == "exact-name-match"))
    );

    let resp2 = sample();
    let result2 = resp2.result.unwrap();
    let curt = records_to_entities(&result2.records, 3, "Curt Avery", true, "s");
    let exact = |e: &Entity| e.tags.iter().any(|t| t.as_str() == "exact-name-match");
    assert!(exact(&curt[0]), "HAYLEY & CURT row is an exact Curt match");
    assert!(exact(&curt[1]), "CURT AVERY row is an exact Curt match");
    assert!(!exact(&curt[2]), "ERIK row is only a surname match");
    assert!(curt[1].confidence > curt[2].confidence);
}

#[test]
fn company_owner_emits_organisation_for_abn_pivot() {
    let raw = r#"{"result":{"total":1,"records":[
        {"_id":7,"Owner":"ACME WIDGETS PTY LTD","Amount":"1200.00","SenderName":"ASX","PCode":"4000"}
    ]}}"#;
    let resp: CkanResp = serde_json::from_str(raw).unwrap();
    let recs = resp.result.unwrap().records;
    let ents = records_to_entities(&recs, 1, "ACME Widgets", true, "s");
    assert_eq!(ents.len(), 2);
    assert!(ents.iter().any(|e| e.kind == EntityKind::Address));
    let org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("company owner must emit an Organisation");
    assert_eq!(org.value, "ACME WIDGETS PTY LTD");
    assert!(org.tags.iter().any(|t| t.as_str() == "company-owner"));

    let raw2 = r#"{"result":{"total":1,"records":[
        {"_id":8,"Owner":"JANE CITIZEN","Amount":"5.00","PCode":"4000"}
    ]}}"#;
    let recs2: Vec<Map<String, Value>> = serde_json::from_str::<CkanResp>(raw2)
        .unwrap()
        .result
        .unwrap()
        .records;
    let ents2 = records_to_entities(&recs2, 1, "Jane Citizen", true, "s");
    assert_eq!(ents2.len(), 1, "individual owner → no Organisation");
    assert!(ents2.iter().all(|e| e.kind != EntityKind::Organisation));

    let raw3 = r#"{"result":{"total":1,"records":[
        {"_id":9,"Owner":"DEV PTY LTD & GWAD PTY LTD & GWAD2 PTY LTD","Amount":"508.80","SenderName":"QLD URBAN UTILITIES","PCode":"4051"}
    ]}}"#;
    let recs3: Vec<Map<String, Value>> = serde_json::from_str::<CkanResp>(raw3)
        .unwrap()
        .result
        .unwrap()
        .records;
    let ents3 = records_to_entities(&recs3, 1, "DEV", true, "s");
    let orgs: Vec<&str> = ents3
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(orgs, vec!["DEV PTY LTD", "GWAD PTY LTD", "GWAD2 PTY LTD"]);
    let dev = ents3.iter().find(|e| e.value == "DEV PTY LTD").unwrap();
    assert!(
        dev.evidence[0]
            .attributes
            .iter()
            .any(|(k, _)| k.as_str() == "joint_owner")
    );
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
            suburb: "Booroobin".into(),
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
            "Booroobin, QLD 4552, Australia",
            "Conondale, QLD 4552, Australia",
        ]
    );
    assert!(
        ents.iter()
            .all(|e| e.confidence < 0.50 && e.tags.iter().any(|t| t.as_str() == SRC))
    );
    let maleny = ents.iter().find(|e| e.value.starts_with("Maleny")).unwrap();
    let attr = |k: &str| {
        maleny.evidence[0]
            .attributes
            .iter()
            .find(|(a, _)| a.as_str() == k)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(attr("suburb"), Some("Maleny"));
    assert_eq!(attr("postcode"), Some("4552"));
}

#[test]
fn suburbs_enumerated_only_for_exact_match_postcodes() {
    let recs = sample().result.unwrap().records;
    assert_eq!(exact_postcodes(&recs, "Erik Avery", true), vec!["4552"]);
    assert!(exact_postcodes(&recs, "Jordan Avery", true).is_empty());
    assert_eq!(
        exact_postcodes(&recs, "Avery", false),
        vec!["4557", "4555", "4552"]
    );
}

#[test]
fn postcode_only_address_is_coarse_candidate_not_probable() {
    let recs = sample().result.unwrap().records;
    let erik = records_to_entities(&recs, 3, "Erik Avery", true, "s");
    let addr = erik
        .iter()
        .find(|e| e.kind == EntityKind::Address && e.value.contains("4552"))
        .expect("Erik's exact postcode Address");
    assert!(addr.tags.iter().any(|t| t == "exact-name-match"));
    assert!(addr.tags.iter().any(|t| t == "postcode-only"));
    assert!(addr.tags.iter().any(|t| t == "coarse"));
    assert!(
        addr.confidence < 0.40,
        "coarse postcode must be sub-Probable"
    );
    assert_eq!(
        addr.classify(),
        crate::core::entity::Classification::Candidate
    );
}

#[test]
fn ckan_success_false_is_captured() {
    let err: CkanResp =
        serde_json::from_str(r#"{"success":false,"error":{"message":"Resource not found"}}"#)
            .unwrap();
    assert_eq!(err.success, Some(false));
    assert!(err.result.is_none());
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));
    assert_eq!(ok.result.unwrap().records.len(), 0);
}

#[test]
fn verbatim_search_never_tags_family_candidate() {
    let raw = r#"{"result":{"total":1,"records":[
        {"_id":1,"Owner":"ACME WIDGETS PTY LTD","Amount":"10.00","PCode":"4000"}
    ]}}"#;
    let recs = serde_json::from_str::<CkanResp>(raw)
        .unwrap()
        .result
        .unwrap()
        .records;
    let ents = records_to_entities(&recs, 1, "ACME PTY LTD", false, "s");
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
    assert!(addr.tags.iter().any(|t| t.as_str() == "exact-name-match"));
    assert!(!addr.tags.iter().any(|t| t.as_str() == "family-candidate"));
}

#[test]
fn owner_match_is_whole_word_not_substring() {
    assert!(!owner_matches_full_name("CURT AVERY", "M Avery"));
    assert!(!owner_matches_full_name("JOANNE CITIZEN", "Ann Citizen"));
    assert!(owner_matches_full_name(
        "HAYLEY AVERY & CURT AVERY",
        "Curt Avery"
    ));
    assert!(owner_matches_full_name("MS SILVA KAREEM", "silva kareem"));
    assert!(!owner_matches_full_name("ERIK AVERY", "Curt Avery"));
}

#[test]
fn no_postcode_finding_is_not_tagged_geoint() {
    let raw = r#"{"result":{"total":1,"records":[
        {"_id":1,"Owner":"NO POSTCODE PERSON","Amount":"42.00","SenderName":"X"}
    ]}}"#;
    let recs = serde_json::from_str::<CkanResp>(raw)
        .unwrap()
        .result
        .unwrap()
        .records;
    let ents = records_to_entities(&recs, 1, "No Postcode Person", true, "s");
    assert_eq!(
        ents[0].kind,
        EntityKind::Other("unclaimed_money".to_string())
    );
    assert!(!ents[0].tags.iter().any(|t| t.as_str() == "geoint"));
    let raw2 = r#"{"result":{"total":1,"records":[
        {"_id":2,"Owner":"GEO PERSON","Amount":"1.00","PCode":"4000"}
    ]}}"#;
    let recs2 = serde_json::from_str::<CkanResp>(raw2)
        .unwrap()
        .result
        .unwrap()
        .records;
    let ents2 = records_to_entities(&recs2, 1, "Geo Person", true, "s");
    assert!(ents2[0].tags.iter().any(|t| t.as_str() == "geoint"));
}

#[test]
fn merge_records_puts_exact_first_and_dedups_on_id() {
    let exact: Vec<Map<String, Value>> =
        serde_json::from_str(r#"[{"_id":50,"Owner":"JOHN SMITH","PCode":"4000"}]"#).unwrap();
    let broad: Vec<Map<String, Value>> = serde_json::from_str(
        r#"[{"_id":11,"Owner":"ALICE SMITH"},{"_id":50,"Owner":"JOHN SMITH"},{"_id":12,"Owner":"BOB SMITH"}]"#,
    )
    .unwrap();
    let merged = merge_records(exact, broad);
    assert_eq!(merged.len(), 3, "the duplicate id 50 is collapsed");
    assert_eq!(field_str(&merged[0], "_id").as_deref(), Some("50"));
    let ids: Vec<String> = merged.iter().filter_map(|r| field_str(r, "_id")).collect();
    assert_eq!(ids, vec!["50", "11", "12"]);
}

#[test]
fn common_polysemous_surname_produces_no_false_exact_matches() {
    let raw = r#"{"result":{"total":17,"records":[
        {"_id":1,"Owner":"KAREEM AYALA","Amount":"4.45","SenderName":"GOLDEN CASKET","DateRec":"2024-03-19","PCode":"4740"},
        {"_id":2,"Owner":"MS SILVA KAREEM","Amount":"387.54","SenderName":"QLD URBAN UTILITIES","DateRec":"2024-07-25","PCode":"4305"},
        {"_id":3,"Owner":"HUSSEIN KHALEEL KAREEM","Amount":"267.45","SenderName":"DEPT TPT MAIN ROADS","DateRec":"2021-02-18","PCode":"4118"},
        {"_id":4,"Owner":"MR J KAREEM","Amount":"1.95","SenderName":"ENERGEX","DateRec":"2006-02-16","PCode":"2880"}
    ]}}"#;
    let resp: CkanResp = serde_json::from_str(raw).unwrap();
    let recs = resp.result.unwrap().records;
    let ents = records_to_entities(&recs, 17, "Ali Kareem", true, "s");
    assert_eq!(ents.len(), 4);
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Organisation),
        "individual owners must not manufacture company/ABN entities"
    );
    for e in &ents {
        assert!(
            e.tags.iter().any(|t| t.as_str() == "family-candidate"),
            "common-surname row must be a family candidate, not the seed"
        );
        assert!(!e.tags.iter().any(|t| t.as_str() == "exact-name-match"));
        assert!(e.confidence < 0.50);
    }
    assert!(ents.iter().any(|e| e.value.contains("2880")));

    let silva = records_to_entities(&recs, 17, "Silva Kareem", true, "s");
    assert!(
        silva[1]
            .tags
            .iter()
            .any(|t| t.as_str() == "exact-name-match"),
        "MS SILVA KAREEM must be exact for seed 'Silva Kareem'"
    );
    assert!(
        !silva[0]
            .tags
            .iter()
            .any(|t| t.as_str() == "exact-name-match"),
        "KAREEM AYALA must stay a family candidate for seed 'Silva Kareem'"
    );
}

#[test]
fn parses_records_into_geo_addresses() {
    let resp = sample();
    let result = resp.result.unwrap();
    let ents = records_to_entities(
        &result.records,
        result.total.unwrap(),
        "Avery",
        true,
        "scan-1",
    );
    assert_eq!(ents.len(), 3, "one entity per record");

    for e in &ents {
        assert_eq!(e.kind, EntityKind::Address);
        assert!(e.value.contains("QLD"));
        assert!(e.value.ends_with(", Australia"));
        assert!(e.tags.iter().any(|t| t.as_str() == "unclaimed-money"));
        assert!(e.tags.iter().any(|t| t.as_str() == "country:AU"));
    }
    assert_eq!(ents[0].value, "QLD 4557, Australia");

    let ev0 = &ents[0].evidence[0];
    let attr = |k: &str| {
        ev0.attributes
            .iter()
            .find(|(a, _)| a.as_str() == k)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(attr("owner"), Some("HAYLEY AVERY & CURT AVERY"));
    assert_eq!(attr("amount_aud"), Some("545.74"));
    assert_eq!(attr("sender"), Some("INSURANCE AUSTRALIA GROUP LIMITED"));
    assert_eq!(attr("postcode"), Some("4557"));
    assert_eq!(attr("reference"), Some("210580670460"));
    assert_eq!(attr("total_matches"), Some("3"));
}

#[test]
fn record_without_postcode_becomes_finding_not_dropped() {
    let raw = r#"{"result":{"total":1,"records":[
        {"_id":1,"Owner":"NO POSTCODE PERSON","Amount":"42.00","SenderName":"SOME SENDER"}
    ]}}"#;
    let resp: CkanResp = serde_json::from_str(raw).unwrap();
    let result = resp.result.unwrap();
    let ents = records_to_entities(&result.records, 1, "NO POSTCODE PERSON", true, "scan-1");
    assert_eq!(ents.len(), 1, "no-postcode record must still surface");
    assert_eq!(
        ents[0].kind,
        EntityKind::Other("unclaimed_money".to_string())
    );
    assert!(ents[0].value.contains("NO POSTCODE PERSON"));
    assert!(ents[0].value.contains("42.00"));
}

#[test]
fn numeric_ckan_fields_are_stringified_not_dropped() {
    let raw = r#"{"result":{"total":1,"records":[
        {"_id":2,"Owner":"NUMERIC FIELDS","Amount":99.5,"SenderName":"X","PCode":4000}
    ]}}"#;
    let resp: CkanResp = serde_json::from_str(raw).unwrap();
    let result = resp.result.unwrap();
    let ents = records_to_entities(&result.records, 1, "NUMERIC FIELDS", true, "scan-1");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Address);
    assert_eq!(ents[0].value, "QLD 4000, Australia");
    let ev = &ents[0].evidence[0];
    let amt = ev
        .attributes
        .iter()
        .find(|(a, _)| a.as_str() == "amount_aud")
        .map(|(_, v)| v.as_str());
    assert_eq!(amt, Some("99.5"));
}
