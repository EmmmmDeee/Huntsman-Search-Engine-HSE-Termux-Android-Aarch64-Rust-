use super::*;

const SCAN: &str = "scan-test";
const QUERY: &str = "Jordan Avery";

fn item(doi: Option<&str>, url: Option<&str>) -> CrossrefItem {
    CrossrefItem {
        doi: doi.map(str::to_string),
        url: url.map(str::to_string),
    }
}

fn resp(items: Vec<CrossrefItem>) -> CrossrefResp {
    CrossrefResp {
        message: CrossrefMessage { items },
    }
}

fn values(entities: &[Entity]) -> Vec<String> {
    entities.iter().map(|e| e.value.clone()).collect()
}

#[test]
fn empty_response_is_safe() {
    assert!(build_entities(&CrossrefResp::default(), QUERY, SCAN).is_empty());
}

#[test]
fn prefers_url_falls_back_to_doi_and_skips_neither() {
    let r = resp(vec![
        item(Some("10.1/abc"), Some("https://example.org/paper")),
        item(Some("10.1/xyz"), None),
        item(None, None),
    ]);
    let out = build_entities(&r, QUERY, SCAN);
    // The third item (neither DOI nor URL) contributes nothing.
    assert_eq!(out.len(), 2, "unexpected entities: {:?}", values(&out));
    assert!(values(&out).contains(&"https://example.org/paper".to_string()));
    assert!(values(&out).contains(&"https://doi.org/10.1/xyz".to_string()));
}

#[test]
fn blank_doi_and_url_strings_are_treated_as_absent() {
    // Whitespace-only fields must not survive `.trim()` into a bogus
    // "https://doi.org/" or an empty-string URL entity.
    let r = resp(vec![item(Some("   "), Some("   "))]);
    assert!(build_entities(&r, QUERY, SCAN).is_empty());
}

#[test]
fn dedup_is_case_insensitive_on_the_url() {
    // Two items resolving to the same URL differing only in case must
    // collapse to one entity — unlike the crate's cryptocurrency-address
    // dedup, a URL's case does not change what resource it resolves to.
    let r = resp(vec![
        item(None, Some("https://Example.org/Paper")),
        item(None, Some("https://example.org/paper")),
    ]);
    let out = build_entities(&r, QUERY, SCAN);
    assert_eq!(out.len(), 1, "case-differing duplicate URL must collapse");
}

#[test]
fn the_five_result_cap_is_enforced() {
    let items: Vec<CrossrefItem> = (0..25)
        .map(|i| item(Some(&format!("10.1/{i:04}")), None))
        .collect();
    let out = build_entities(&resp(items), QUERY, SCAN);
    assert_eq!(out.len(), CAP, "must stop at the {CAP}-result cap");
}

#[test]
fn every_entity_carries_the_calibrated_confidence_and_kind() {
    let r = resp(vec![item(None, Some("https://example.org/paper"))]);
    let out = build_entities(&r, QUERY, SCAN);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EntityKind::Url);
    assert!(
        (out[0].confidence - WORK_URL_CONFIDENCE).abs() < 1e-9,
        "a name match must not be scored above the calibrated, \
         non-identity-confirming confidence: got {}",
        out[0].confidence
    );
}

#[test]
fn evidence_records_the_query_and_doi() {
    let r = resp(vec![item(Some("10.1/abc"), Some("https://example.org/x"))]);
    let out = build_entities(&r, QUERY, SCAN);
    let ev = out[0].evidence.first().expect("evidence attached");
    assert_eq!(ev.source, SRC);
    assert_eq!(ev.attributes.get("query").map(String::as_str), Some(QUERY));
    assert_eq!(
        ev.attributes.get("doi").map(String::as_str),
        Some("10.1/abc")
    );
}

#[test]
fn projection_is_deterministic() {
    let r = resp(vec![
        item(Some("10.1/a"), None),
        item(Some("10.1/b"), Some("https://example.org/b")),
    ]);
    let a = build_entities(&r, QUERY, SCAN);
    let b = build_entities(&r, QUERY, SCAN);
    assert_eq!(
        values(&a),
        values(&b),
        "identical input must yield an identical projection"
    );
}

#[test]
fn module_metadata_is_coherent() {
    let m = CrossrefSearch;
    assert_eq!(m.name(), "crossref_search");
    assert!(m.accepts(&Target::new(TargetKind::FullName, QUERY)));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Example University")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(
        m.produces().contains(&EntityKind::Url),
        "produces() must declare what build_entities actually emits"
    );
}
