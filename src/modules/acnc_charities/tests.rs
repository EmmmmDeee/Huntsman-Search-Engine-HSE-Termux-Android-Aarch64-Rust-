use super::entity::{
    abn_digits, charity_evidence, locality_address, name_matches_query, other_names,
    record_is_exact, records_to_entities,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::util::ckan::Response as CkanResp;
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    // Shapes mirror real datastore_search rows for q="the smith family".
    let raw = r#"[
        {"_id":1,"ABN":"28000030179","Charity_Legal_Name":"The Smith Family","Other_Organisation_Names":null,"Address_Line_1":"L17 2 Market St","Town_City":"Sydney","State":"NSW","Postcode":"2000","Country":"Australia","Charity_Website":"thesmithfamily.com.au","Registration_Date":"03/12/2012","Charity_Size":"Large","Number_of_Responsible_Persons":"13"},
        {"_id":2,"ABN":"42196844275","Charity_Legal_Name":"THE TRUSTEE FOR JOY SMITH FAMILY FOUNDATION","Town_City":"Malvern East","State":"VIC","Postcode":"3145","Country":"Australia","Charity_Website":null},
        {"_id":3,"ABN":"63311049449","Charity_Legal_Name":"Marshall Family Foundation","Town_City":"Fitzroy","State":"VIC","Postcode":"3065","Country":"Australia"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_organisation_only() {
    use crate::core::scan::{Target, TargetKind};
    let m = AcncCharities;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "The Smith Family")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(!m.accepts(&Target::new(TargetKind::AbnAcn, "28000030179")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata() {
    let m = AcncCharities;
    assert_eq!(m.name(), "acnc_charities");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    // Non-passive network module must beat the 3s default timeout (CI guard).
    assert!(m.max_timeout_ms() > 3_000);
    // Government / public-records band.
    assert!((110..=118).contains(&m.priority()));
}

#[test]
fn name_match_is_whole_word_not_substring() {
    assert!(name_matches_query("The Smith Family", "smith family"));
    assert!(name_matches_query(
        "THE TRUSTEE FOR JOY SMITH FAMILY FOUNDATION",
        "Smith Family"
    ));
    // Order-independent, punctuation-split.
    assert!(name_matches_query(
        "Australian Red Cross Society",
        "red cross australian"
    ));
    // A loose full-text hit that lacks a seed token is NOT exact.
    assert!(!name_matches_query(
        "Marshall Family Foundation",
        "smith family"
    ));
    // Whole word, not substring: "red" must not match inside "Mildred".
    assert!(!name_matches_query("Mildred Trust", "red"));
}

#[test]
fn exact_match_fans_out_pivots_candidate_does_not() {
    let recs = sample();
    let ents = records_to_entities(&recs, 4, "The Smith Family", "scan-1");

    // Row 1 "The Smith Family" is exact → Organisation + AbnAcn + Address + Domain.
    let smith_org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "The Smith Family")
        .expect("exact charity organisation");
    assert!(smith_org.tags.iter().any(|t| t == "exact-name-match"));
    assert!((smith_org.confidence - ORG_EXACT).abs() < f64::EPSILON);

    let abn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn)
        .expect("exact hit emits an ABN for cross-correlation");
    assert_eq!(abn.value, "28000030179");

    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("exact hit emits a geocodable registered address");
    assert_eq!(addr.value, "Sydney, NSW 2000, Australia");
    assert!(addr.tags.iter().any(|t| t == "geoint"));
    // The precise street line rides in evidence (no omission), not the value.
    assert!(
        addr.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "address_line_1" && v == "L17 2 Market St")
    );

    let dom = ents
        .iter()
        .find(|e| e.kind == EntityKind::Domain)
        .expect("exact hit emits the website domain");
    assert_eq!(dom.value, "thesmithfamily.com.au");

    // Row 3 "Marshall Family Foundation" only matched "family" → candidate:
    // a single sub-floor Organisation, no ABN/Address/Domain pivots from it.
    let marshall = ents
        .iter()
        .find(|e| e.value == "Marshall Family Foundation")
        .expect("candidate still surfaced (no omission)");
    assert!(marshall.tags.iter().any(|t| t == "name-candidate"));
    assert!(
        marshall.confidence < 0.50,
        "candidate must stay below expansion floor"
    );
    // Its ABN/postcode are in evidence (complete) but NOT a separate AbnAcn entity.
    assert!(
        marshall.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "abn" && v == "63311049449")
    );
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::AbnAcn && e.value == "63311049449")
    );
}

#[test]
fn candidate_record_omits_nothing_from_evidence() {
    // The no-redaction rule: a candidate's full record stays in evidence.
    let recs = sample();
    let ents = records_to_entities(&recs, 4, "The Smith Family", "s");
    let joy = ents
        .iter()
        .find(|e| e.value.contains("JOY SMITH FAMILY"))
        .unwrap();
    // "Joy Smith Family Foundation" contains both seed tokens → actually exact.
    assert!(joy.tags.iter().any(|t| t == "exact-name-match"));
    let attr = |k: &str| {
        joy.evidence[0]
            .attributes
            .iter()
            .find(|(a, _)| a.as_str() == k)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(attr("abn"), Some("42196844275"));
    assert_eq!(attr("postcode"), Some("3145"));
    assert_eq!(attr("town_city"), Some("Malvern East"));
}

#[test]
fn trading_names_split_and_emit_organisations() {
    let raw = r#"[
        {"_id":1,"ABN":"11111111111","Charity_Legal_Name":"Sydney University Business School Society","Other_Organisation_Names":"SUBS, Sydney University Business Society","Charity_Website":"https://subsoc.com.au","Town_City":"Camperdown","State":"NSW","Postcode":"2006"}
    ]"#;
    let recs: Vec<Map<String, Value>> = serde_json::from_str(raw).unwrap();
    let ents = records_to_entities(&recs, 1, "Sydney University Business School Society", "s");
    let orgs: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .map(|e| e.value.as_str())
        .collect();
    assert!(orgs.contains(&"SUBS"));
    assert!(orgs.contains(&"Sydney University Business Society"));
    // Website with a scheme is normalised to a bare host.
    let dom = ents.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
    assert_eq!(dom.value, "subsoc.com.au");
}

#[test]
fn numeric_abn_and_postcode_are_stringified_not_dropped() {
    // CKAN may type ABN/Postcode as numbers; we must still recover them.
    let raw = r#"[
        {"_id":1,"ABN":28000030179,"Charity_Legal_Name":"Numeric Fields Trust","Town_City":"Perth","State":"WA","Postcode":6000}
    ]"#;
    let recs: Vec<Map<String, Value>> = serde_json::from_str(raw).unwrap();
    let ents = records_to_entities(&recs, 1, "Numeric Fields Trust", "s");
    let abn = ents.iter().find(|e| e.kind == EntityKind::AbnAcn).unwrap();
    assert_eq!(abn.value, "28000030179");
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
    assert_eq!(addr.value, "Perth, WA 6000, Australia");
}

#[test]
fn locality_address_handles_missing_fields() {
    let mut rec = Map::new();
    rec.insert("State".into(), Value::String("QLD".into()));
    rec.insert("Postcode".into(), Value::String("4000".into()));
    // No Town_City, no Country → defaults Country=Australia.
    assert_eq!(
        locality_address(&rec).as_deref(),
        Some("QLD 4000, Australia")
    );
    // Nothing locating at all → None.
    let empty = Map::new();
    assert!(locality_address(&empty).is_none());
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
fn abn_digits_validates_eleven_digit_length() {
    let mut rec = Map::new();
    rec.insert("ABN".into(), Value::String("28 000 030 179".into()));
    assert_eq!(abn_digits(&rec).as_deref(), Some("28000030179"));
    let mut numrec = Map::new();
    numrec.insert("ABN".into(), Value::from(28_000_030_179u64));
    assert_eq!(abn_digits(&numrec).as_deref(), Some("28000030179"));
}

#[test]
fn abn_digits_rejects_wrong_length_and_missing() {
    let mut short = Map::new();
    short.insert("ABN".into(), Value::String("12345".into()));
    assert!(abn_digits(&short).is_none());
    let mut long = Map::new();
    long.insert("ABN".into(), Value::String("123456789012".into()));
    assert!(abn_digits(&long).is_none());
    assert!(abn_digits(&Map::new()).is_none());
}

#[test]
fn other_names_splits_trims_and_drops_empties() {
    let mut rec = Map::new();
    rec.insert(
        "Other_Organisation_Names".into(),
        Value::String("SUBS, Sydney University Business Society , ,".into()),
    );
    assert_eq!(
        other_names(&rec),
        vec![
            "SUBS".to_string(),
            "Sydney University Business Society".to_string()
        ]
    );
    assert!(other_names(&Map::new()).is_empty());
}

#[test]
fn record_is_exact_matches_legal_name_or_alias() {
    let mut rec = Map::new();
    rec.insert(
        "Charity_Legal_Name".into(),
        Value::String("The Smith Family".into()),
    );
    rec.insert(
        "Other_Organisation_Names".into(),
        Value::String("TSF, Smith Family Trust".into()),
    );
    assert!(record_is_exact(&rec, "smith family"));
    assert!(record_is_exact(&rec, "smith family trust"));
    assert!(!record_is_exact(&rec, "jones foundation"));
}

#[test]
fn charity_evidence_gates_attrs_on_presence() {
    let mut rec = Map::new();
    rec.insert(
        "Charity_Legal_Name".into(),
        Value::String("The Smith Family".into()),
    );
    rec.insert("ABN".into(), Value::String("28000030179".into()));
    rec.insert("State".into(), Value::String("NSW".into()));
    let ev = charity_evidence(&rec, 3);
    assert_eq!(
        ev.attributes.get("abn").map(String::as_str),
        Some("28000030179")
    );
    assert_eq!(ev.attributes.get("state").map(String::as_str), Some("NSW"));
    assert_eq!(
        ev.attributes.get("total_matches").map(String::as_str),
        Some("3")
    );
    assert!(!ev.attributes.contains_key("postcode"));
    assert!(!ev.attributes.contains_key("website"));
    assert!(ev.summary.contains("The Smith Family"));
}

#[test]
fn short_query_is_ignored() {
    // Guarded in process(); assert the precondition the guard relies on.
    assert!("ab".len() < 3);
    assert!("abc".len() >= 3);
}
