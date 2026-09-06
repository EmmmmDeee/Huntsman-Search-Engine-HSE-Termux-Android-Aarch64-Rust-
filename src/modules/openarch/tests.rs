use super::{OaDate, OaDoc, OaResp, OpenArch, build_entities, recorded_name_covers_seed};
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

/// Live response captured 2026-09-06 for `name=John Smith&number_show=3`
/// (localised `_relationtype`/`_eventtype` duplicates and `archive_org` kept
/// exactly as served — the parser must tolerate them).
const LIVE: &str = r#"{"query":{"name":"John Smith","only_results_with_scans":false,"start":0,"number_show":3,"sort":1,"language":"en"},"response":{"number_found":9539,"docs":[{"pid":"Person1","identifier":"ad5284dd-ce18-7c69-7b15-13f5611676d7","archive_code":"rtr","archive_org":"Reclaim The Records","archive":"Reclaim The Records","personname":"Aaron John Smith","relationtype":"Deceased","_relationtype":"Overledene","eventtype":"Death","_eventtype":"Overlijden","eventdate":{"day":16,"month":9,"year":2018},"eventplace":["Usa"],"sourcetype":"Dossier","url":"https://www.openarchieven.nl/rtr:ad5284dd-ce18-7c69-7b15-13f5611676d7/en"},{"pid":"Person1","identifier":"6a35a451-5c49-d04e-cce4-8d4848e9ed2b","archive_code":"rtr","archive_org":"Reclaim The Records","archive":"Reclaim The Records","personname":"Ajay John Smith","relationtype":"Deceased","_relationtype":"Overledene","eventtype":"Death","_eventtype":"Overlijden","eventdate":{"day":26,"month":5,"year":1973},"eventplace":["Usa"],"sourcetype":"Dossier","url":"https://www.openarchieven.nl/rtr:6a35a451-5c49-d04e-cce4-8d4848e9ed2b/en"},{"pid":"Person1","identifier":"e356cf57-fb7f-dd01-50bd-677dad61c9ed","archive_code":"ins","archive_org":"L'Institut national de la statistique et des études économiques (INSEE)","archive":"French National Institute of Statistics and Economic Studies (INSEE)","personname":"Alan John Smith","relationtype":"Deceased","_relationtype":"Overledene","eventtype":"Death","_eventtype":"Overlijden","eventdate":{"day":9,"month":11,"year":2008},"eventplace":["Narbonne"],"sourcetype":"Civil registration deaths","url":"https://www.openarchieven.nl/ins:e356cf57-fb7f-dd01-50bd-677dad61c9ed/en"}]}}"#;

#[test]
fn metadata() {
    let m = OpenArch;
    assert_eq!(m.name(), "openarch");
    assert_eq!(m.priority(), 44);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.produces().contains(&EntityKind::Person));
    assert!(m.produces().contains(&EntityKind::Url));
    assert_eq!(m.cache_ttl_secs(), 86_400);
}

#[test]
fn live_shape_deserializes_and_yields_a_person_and_a_source_per_record() {
    let body: OaResp = serde_json::from_str(LIVE).expect("live shape parses");
    let response = body.response.expect("response present");
    assert_eq!(response.number_found, Some(9539));
    assert_eq!(response.docs.len(), 3);

    let res = build_entities("John Smith", 9539, &response.docs, "scan");
    let persons: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .collect();
    assert_eq!(persons.len(), 3);
    assert_eq!(urls.len(), 3);

    let alan = persons
        .iter()
        .find(|p| p.value == "Alan John Smith")
        .expect("INSEE record");
    assert!(alan.has_tag("openarch") && alan.has_tag("genealogy"));
    assert!(alan.has_tag("needs-identity-verification"));
    let attrs = &alan.evidence[0].attributes;
    assert_eq!(attrs.get("event_type").map(String::as_str), Some("Death"));
    assert_eq!(
        attrs.get("event_date").map(String::as_str),
        Some("2008-11-09")
    );
    assert_eq!(
        attrs.get("event_place").map(String::as_str),
        Some("Narbonne")
    );
    assert_eq!(
        attrs.get("role_in_record").map(String::as_str),
        Some("Deceased")
    );
    assert_eq!(attrs.get("archive_code").map(String::as_str), Some("ins"));
    assert_eq!(attrs.get("index_total").map(String::as_str), Some("9539"));
    assert!(
        alan.evidence[0]
            .summary
            .starts_with("Open Archives Civil registration deaths: Death 2008-11-09, Narbonne"),
        "{}",
        alan.evidence[0].summary
    );

    let u = urls
        .iter()
        .find(|u| u.value.contains("ins:e356cf57"))
        .expect("record url");
    assert!(u.has_tag("source-document"));
}

#[test]
fn an_empty_index_yields_nothing_and_a_fuzzy_partial_match_is_demoted() {
    assert!(
        build_entities("John Smith", 0, &[], "scan")
            .entities
            .is_empty()
    );

    let partial = OaDoc {
        personname: Some("Johanna Smit".into()),
        eventtype: Some("Birth".into()),
        eventdate: Some(OaDate {
            day: None,
            month: Some(3),
            year: Some(1901),
        }),
        url: Some("https://www.openarchieven.nl/x:1/en".into()),
        ..OaDoc::default()
    };
    assert!(!recorded_name_covers_seed("Johanna Smit", "John Smith"));
    assert!(recorded_name_covers_seed("Aaron John Smith", "John Smith"));
    let res = build_entities("John Smith", 1, &[partial], "scan");
    let p = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("person");
    assert!(p.confidence < crate::core::confidence::LOW_MEDIUM);
    assert!(p.evidence[0].attributes.contains_key("caution"));
    // Month-only date renders without a day.
    assert_eq!(
        p.evidence[0]
            .attributes
            .get("event_date")
            .map(String::as_str),
        Some("1901-03")
    );
}

#[test]
fn duplicate_record_urls_collapse_to_one_source() {
    let d = OaDoc {
        personname: Some("John Smith".into()),
        url: Some("https://www.openarchieven.nl/x:1/en".into()),
        ..OaDoc::default()
    };
    let res = build_entities("John Smith", 2, &[d.clone(), d], "scan");
    assert_eq!(
        res.entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .count(),
        1
    );
}

#[test]
fn a_missing_number_found_still_yields_the_returned_docs() {
    // number_found is optional; if it is absent the returned docs must not be
    // dropped. index_total falls back to docs.len().
    let doc = OaDoc {
        personname: Some("John Smith".into()),
        url: Some("https://www.openarchieven.nl/x:1/en".into()),
        ..OaDoc::default()
    };
    let res = build_entities("John Smith", 0, &[doc], "scan");
    let p = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("a missing number_found must not suppress the returned docs");
    assert_eq!(
        p.evidence[0]
            .attributes
            .get("index_total")
            .map(String::as_str),
        Some("1")
    );
}
