use super::{EuItem, EuResp, Europeana, build_entities};
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

/// Live response captured 2026-09-06 (Europeana's published demo key, `query="John Smith"&rows=2`),
/// reduced to the keys this module reads; the key-bearing `link` field is
/// deliberately absent, as it must never be read or surfaced.
const LIVE: &str = r#"{"apikey":"REDACTED","success":true,"requestNumber":999,"itemsCount":2,"totalResults":1238,"items":[{"id":"/1100/5577","guid":"https://www.europeana.eu/item/1100/5577?utm_source=api&utm_medium=api&utm_campaign=api2demo","title":["John Smith"],"year":["1716"],"dataProvider":["Chester Beatty"],"provider":["MUSEU"],"country":["Ireland"],"type":"IMAGE","edmIsShownAt":["https://viewer.cbl.ie/viewer/ppnresolver?id=Wep_4178_83"],"dcCreator":["Kneller, Godfrey, after","Smith, John"]},{"id":"/2059215/data_sounds_TDF021272","guid":"https://www.europeana.eu/item/2059215/data_sounds_TDF021272?utm_source=api&utm_medium=api&utm_campaign=api2demo","title":["John Smith of Falloch Fine","John Smith, Fellow Fine"],"year":["1959"],"dataProvider":["Sabhal Mòr Ostaig and Tobar an Dualchais"],"provider":["Europeana Sounds"],"country":["United Kingdom"],"type":"SOUND","edmIsShownAt":["https://www.tobarandualchais.co.uk/track/61437"],"dcCreator":["Hamish  Henderson"]}]}"#;

#[test]
fn metadata() {
    let m = Europeana;
    assert_eq!(m.name(), "europeana");
    assert_eq!(m.priority(), 41);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert_eq!(m.attack_techniques(), &["T1593.002"]);
    assert!(m.produces().contains(&EntityKind::Url));
    assert_eq!(m.cache_ttl_secs(), 86_400);
}

#[test]
fn live_shape_yields_the_headline_and_a_source_per_record() {
    let body: EuResp = serde_json::from_str(LIVE).expect("live shape parses");
    assert!(body.success);
    assert_eq!(body.total_results, Some(1238));
    assert_eq!(body.items.len(), 2);

    let res = build_entities(
        TargetKind::FullName,
        "John Smith",
        1238,
        &body.items,
        "scan",
    );
    let headline = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("person headline");
    assert!(headline.has_tag("europeana") && headline.has_tag("needs-identity-verification"));
    assert_eq!(
        headline.evidence[0]
            .attributes
            .get("matching_records")
            .map(String::as_str),
        Some("1238")
    );
    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .collect();
    assert_eq!(urls.len(), 2);
    let first = urls
        .iter()
        .find(|u| u.value == "https://viewer.cbl.ie/viewer/ppnresolver?id=Wep_4178_83")
        .expect(
            "first record url — the holding institution's page, never the key-bearing api link",
        );
    assert!(first.has_tag("source-document"));
    assert!(!first.value.contains("wskey"));
    let attrs = &first.evidence[0].attributes;
    assert_eq!(attrs.get("country").map(String::as_str), Some("Ireland"));
    assert!(attrs.get("title").is_some());
}

#[test]
fn a_refusal_is_not_a_miss_and_no_match_yields_nothing() {
    let refused: EuResp =
        serde_json::from_str(r#"{"success":false,"error":"Invalid API key"}"#).unwrap();
    assert!(!refused.success);
    assert_eq!(refused.error.as_deref(), Some("Invalid API key"));
    assert!(
        build_entities(TargetKind::FullName, "John Smith", 0, &[], "scan")
            .entities
            .is_empty()
    );
}

#[test]
fn a_record_without_any_page_url_is_skipped_and_guid_is_the_fallback() {
    let no_url = EuItem {
        title: vec!["A record".into()],
        ..EuItem::default()
    };
    let guid_only = EuItem {
        title: vec!["John Smith, farmer".into()],
        guid: Some("https://www.europeana.eu/item/1/abc".into()),
        ..EuItem::default()
    };
    let res = build_entities(
        TargetKind::Organisation,
        "John Smith",
        2,
        &[no_url, guid_only],
        "scan",
    );
    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .collect();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].value, "https://www.europeana.eu/item/1/abc");
    assert!(
        res.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation)
    );
}

#[test]
fn a_missing_total_still_yields_the_returned_records() {
    // totalResults is optional; if the provider omits it the returned items
    // must not be dropped. Count falls back to items.len().
    let item = EuItem {
        title: vec!["John Smith, portrait".into()],
        guid: Some("https://www.europeana.eu/item/1/x".into()),
        ..EuItem::default()
    };
    let res = build_entities(TargetKind::FullName, "John Smith", 0, &[item], "scan");
    let headline = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("a missing total must not suppress the returned records");
    assert_eq!(
        headline.evidence[0]
            .attributes
            .get("matching_records")
            .map(String::as_str),
        Some("1")
    );
    assert!(res.entities.iter().any(|e| e.kind == EntityKind::Url));
}
