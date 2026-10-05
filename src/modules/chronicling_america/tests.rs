use super::{ChroniclingAmerica, LocResp, LocResult, build_entities};
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

/// Live loc.gov response captured 2026-09-06 for `q="John Smith"&c=3&at=results,pagination`,
/// reduced to the keys this module reads (each page's OCR `description` truncated
/// to its first 220 characters; array/scalar shapes exactly as served).
const LIVE: &str = r#"{"pagination":{"current":1,"of":202007,"perpage":3,"results":"1 - 3","to":3,"total":67336},"results":[{"id":"http://www.loc.gov/resource/sn87090149/1844-06-20/ed-1/?sp=1","title":"Image 1 of Port-Gibson herald (Port Gibson, Miss.), June 20, 1844","date":"1844-06-20","url":"https://www.loc.gov/resource/sn87090149/1844-06-20/ed-1/?sp=1&q=%22john+smith%22","description":["PORT GIBSON HERALD Vol 2 1ortGibson Miss June 20 1844 No 42 AI 1 II JACOBS EDITOR and propriktob ZtitLIAIft F EI8ELY PUBLISHER Cc lY Y l33 ip m m Love Oil By Eliza Cook Ortvenot love not ye hapless onä of earth 1 Mrs Nor"],"location":["port gibson","claiborne county","claiborne","united states","mississippi"],"number_lccn":["sn87090149"],"partof":["chronicling america","port-gibson herald (port gibson, miss.) 1842-1848","serial and government publications division"],"type":["segment"]},{"id":"http://www.loc.gov/resource/sn84020048/1845-05-03/ed-1/?sp=1","title":"Image 1 of The Ripley advertiser (Ripley, Miss.), May 3, 1845","date":"1845-05-03","url":"https://www.loc.gov/resource/sn84020048/1845-05-03/ed-1/?sp=1&q=%22john+smith%22","description":["Vol Jl JtiMXY Mississippi MAY 184 5 No 21 Tnn ADVERTISE lllPLEY j v roiM Paoranroa mu Ilsimura TERMSi The Auvkirum will hn I iinlcf ulnrly rvory Pnttirdii at 3 50 In mlvnncn in every IriMiinoo No tubtcriiition will bn re"],"location":["tippah","united states","mississippi","ripley"],"number_lccn":["sn84020048"],"partof":["the ripley advertiser (ripley, miss.) 1843-1897","serial and government publications division","chronicling america"],"type":["segment"]},{"id":"http://www.loc.gov/resource/sn86075096/1957-10-15/ed-1/?sp=26","title":"Image 26 of Montana farmer-stockman (Great Falls, Mont.), October 15, 1957","date":"1957-10-15","url":"https://www.loc.gov/resource/sn86075096/1957-10-15/ed-1/?sp=26&q=%22john+smith%22","description":["A m I I i A Short Story By FREDERICK SKERRY IT WAS HALF PAST five on a Sat urday afternoon in late summer when John Smith came slowly down the steps of the Emergency Hospital His hat was now too small for his bandaged he"],"location":["montana","great falls","united states","cascade"],"number_lccn":["sn86075096"],"partof":["chronicling america","serial and government publications division","montana farmer-stockman (great falls, mont.) 1947-1993"],"type":["segment"]}]}"#;

#[test]
fn metadata() {
    let m = ChroniclingAmerica;
    assert_eq!(m.name(), "chronicling_america");
    assert_eq!(m.priority(), 42);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert_eq!(m.attack_techniques(), &["T1593.002"]);
    assert!(m.produces().contains(&EntityKind::Url));
    assert_eq!(m.cache_ttl_secs(), 86_400);
}

#[test]
fn live_shape_yields_the_headline_and_a_source_per_page() {
    let body: LocResp = serde_json::from_str(LIVE).expect("live shape parses");
    let matching = body
        .pagination
        .as_ref()
        .and_then(|p| p.of)
        .expect("pagination.of");
    assert_eq!(matching, 202007);
    assert_eq!(body.results.len(), 3);

    let res = build_entities(
        TargetKind::FullName,
        "John Smith",
        matching,
        &body.results,
        "scan",
    );
    let headline = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("person headline for a name seed");
    assert_eq!(headline.value, "John Smith");
    assert!(headline.has_tag("chronicling_america") && headline.has_tag("historic"));
    assert!(headline.has_tag("needs-identity-verification"));
    assert_eq!(
        headline.evidence[0]
            .attributes
            .get("matching_pages")
            .map(String::as_str),
        Some("202007")
    );

    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .collect();
    assert_eq!(urls.len(), 3);
    // Match by the un-normalised `lccn` evidence attribute, not the exact URL
    // string: `Entity::new` canonicalises a Url value (it trims the trailing
    // `/` before the query, `.../ed-1/?sp=1` -> `.../ed-1?sp=1`), so an exact
    // literal would be brittle against that normalisation. The stable page path
    // still survives, which is what a pivot needs.
    let first = urls
        .iter()
        .find(|u| u.evidence[0].attributes.get("lccn").map(String::as_str) == Some("sn87090149"))
        .expect("first page url (by lccn)");
    assert!(first.has_tag("source-document"));
    assert!(
        first.value.contains("sn87090149/1844-06-20/ed-1"),
        "the newspaper page path survives URL canonicalisation: {}",
        first.value
    );
    let attrs = &first.evidence[0].attributes;
    assert_eq!(attrs.get("date").map(String::as_str), Some("1844-06-20"));
    assert_eq!(attrs.get("lccn").map(String::as_str), Some("sn87090149"));
    assert!(
        attrs
            .get("place")
            .is_some_and(|p| p.contains("port gibson"))
    );
}

#[test]
fn an_org_seed_gets_an_organisation_headline_and_nothing_is_emitted_for_no_match() {
    let page = LocResult {
        title: Some("Image 2 of The daily gazette, March 3, 1901".into()),
        date: Some("1901-03-03".into()),
        url: Some("https://www.loc.gov/resource/sn1/1901-03-03/ed-1/?sp=2".into()),
        description: vec!["... the ACME Company notice ...".into()],
        ..LocResult::default()
    };
    let res = build_entities(TargetKind::Organisation, "ACME Company", 1, &[page], "scan");
    assert!(
        res.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.value == "ACME Company")
    );
    assert!(!res.entities.iter().any(|e| e.kind == EntityKind::Person));
    assert!(
        build_entities(TargetKind::FullName, "John Smith", 0, &[], "scan")
            .entities
            .is_empty()
    );
}

#[test]
fn a_page_whose_ocr_never_names_the_seed_is_kept_but_demoted_and_flagged() {
    let noisy = LocResult {
        title: Some("Image 1 of The herald, June 20, 1844".into()),
        date: Some("1844-06-20".into()),
        url: Some("https://www.loc.gov/resource/sn2/1844-06-20/ed-1/?sp=1".into()),
        description: vec!["J0HN SM1TH garbled".into()],
        ..LocResult::default()
    };
    let clean = LocResult {
        url: Some("https://www.loc.gov/resource/sn2/1844-06-21/ed-1/?sp=1".into()),
        description: vec!["Mr John Smith of this town".into()],
        ..LocResult::default()
    };
    let res = build_entities(
        TargetKind::FullName,
        "John Smith",
        2,
        &[noisy, clean],
        "scan",
    );
    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .collect();
    assert_eq!(urls.len(), 2);
    let (n, c) = (urls[0], urls[1]);
    assert!(n.confidence < c.confidence);
    assert!(n.evidence[0].attributes.contains_key("caution"));
    assert!(!c.evidence[0].attributes.contains_key("caution"));
}

#[test]
fn a_missing_pagination_total_still_yields_the_returned_pages() {
    // pagination.of is optional; if it is absent the returned pages must not be
    // dropped. Count falls back to results.len().
    let page = LocResult {
        url: Some("https://www.loc.gov/resource/sn1/1900-01-01/ed-1/?sp=1".into()),
        description: vec!["Mr John Smith of this town".into()],
        ..LocResult::default()
    };
    let res = build_entities(TargetKind::FullName, "John Smith", 0, &[page], "scan");
    let headline = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("a missing pagination total must not suppress the returned pages");
    assert_eq!(
        headline.evidence[0]
            .attributes
            .get("matching_pages")
            .map(String::as_str),
        Some("1")
    );
    assert!(res.entities.iter().any(|e| e.kind == EntityKind::Url));
}
