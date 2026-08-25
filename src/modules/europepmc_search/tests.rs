use super::*;

const SCAN: &str = "scan-test";
const QUERY: &str = "Jane Doe";

fn item(doi: Option<&str>, pmid: Option<&str>) -> ResultItem {
    ResultItem {
        doi: doi.map(str::to_string),
        pmid: pmid.map(str::to_string),
    }
}

fn resp(items: Vec<ResultItem>) -> SearchResp {
    SearchResp {
        result_list: ResultList { result: items },
    }
}

fn urls(entities: &[Entity]) -> Vec<String> {
    entities.iter().map(|e| e.value.clone()).collect()
}

#[test]
fn empty_response_is_safe() {
    let out = build_entities(&SearchResp::default(), QUERY, SCAN);
    assert!(out.is_empty());
}

#[test]
fn doi_is_preferred_over_pmid_when_both_are_present() {
    let r = resp(vec![item(Some("10.1/abc"), Some("123"))]);
    let out = build_entities(&r, QUERY, SCAN);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "https://doi.org/10.1/abc");
    assert_eq!(out[0].kind, EntityKind::Url);
}

#[test]
fn falls_back_to_the_pubmed_page_when_no_doi_is_present() {
    let r = resp(vec![item(None, Some("456"))]);
    let out = build_entities(&r, QUERY, SCAN);
    assert_eq!(out.len(), 1);
    // `Entity::new`'s URL normalisation trims the trailing slash the raw
    // "https://pubmed.ncbi.nlm.nih.gov/456/" construction carries — this
    // pins the persisted (normalised) form, not the pre-normalisation string.
    assert_eq!(out[0].value, "https://pubmed.ncbi.nlm.nih.gov/456");
}

#[test]
fn a_result_with_neither_doi_nor_pmid_is_skipped() {
    // Nothing to link to — the source module's judgement is to drop it
    // rather than emit a URL-less entity.
    let r = resp(vec![item(None, None)]);
    let out = build_entities(&r, QUERY, SCAN);
    assert!(out.is_empty());
}

#[test]
fn blank_doi_and_pmid_strings_are_treated_as_absent() {
    // The API can return an empty string rather than omitting the field;
    // whitespace-only values must not produce a bare "https://doi.org/" or
    // "https://pubmed.ncbi.nlm.nih.gov//" entity.
    let r = resp(vec![item(Some("  "), Some(""))]);
    let out = build_entities(&r, QUERY, SCAN);
    assert!(out.is_empty());
}

#[test]
fn mixed_results_prefer_doi_and_fall_back_per_item_and_dedup() {
    let r = resp(vec![
        item(Some("10.1/abc"), Some("123")),
        item(None, Some("456")),
        item(None, None),
    ]);
    let out = build_entities(&r, QUERY, SCAN);
    assert_eq!(out.len(), 2, "the no-id item must contribute nothing");
    let u = urls(&out);
    assert!(u.contains(&"https://doi.org/10.1/abc".to_string()));
    // Trailing slash trimmed by `Entity::new`'s URL normalisation — see
    // `falls_back_to_the_pubmed_page_when_no_doi_is_present`.
    assert!(u.contains(&"https://pubmed.ncbi.nlm.nih.gov/456".to_string()));
}

#[test]
fn dedup_is_case_insensitive_on_the_resulting_url() {
    // Two rows resolving to the same URL, differing only by case, must
    // collapse to one entity — this mirrors the source module's
    // `to_lowercase()` dedup key exactly (unlike bitcoin's addresses, a DOI
    // resolver URL is not case-sensitive data).
    let r = resp(vec![
        item(Some("10.1/ABC"), None),
        item(Some("10.1/abc"), None),
    ]);
    let out = build_entities(&r, QUERY, SCAN);
    assert_eq!(out.len(), 1, "case-differing duplicate URLs must collapse");
}

#[test]
fn the_cap_is_enforced() {
    let items: Vec<ResultItem> = (0..(CAP + 10))
        .map(|i| item(Some(&format!("10.1/doc{i:04}")), None))
        .collect();
    let r = resp(items);
    let out = build_entities(&r, QUERY, SCAN);
    assert_eq!(out.len(), CAP);
}

#[test]
fn evidence_carries_the_identifier_and_the_query() {
    let r = resp(vec![item(Some("10.1/abc"), None)]);
    let out = build_entities(&r, QUERY, SCAN);
    let ev = out[0].evidence.first().expect("evidence attached");
    assert_eq!(ev.source, SRC);
    assert_eq!(
        ev.attributes.get("doi").map(String::as_str),
        Some("10.1/abc")
    );
    assert_eq!(ev.attributes.get("query").map(String::as_str), Some(QUERY));
}

#[test]
fn emitted_entities_carry_the_expected_confidence_and_tags() {
    let r = resp(vec![item(Some("10.1/abc"), None)]);
    let out = build_entities(&r, QUERY, SCAN);
    assert!((out[0].confidence - RESULT_URL_CONFIDENCE).abs() < 1e-9);
    assert!(out[0].has_tag("europepmc"));
    assert!(out[0].has_tag("literature"));
}

#[test]
fn projection_is_deterministic() {
    let r = resp(vec![item(Some("10.1/abc"), None), item(None, Some("456"))]);
    let a = build_entities(&r, QUERY, SCAN);
    let b = build_entities(&r, QUERY, SCAN);
    assert_eq!(urls(&a), urls(&b));
}

#[test]
fn module_metadata_is_coherent() {
    let m = EuropePmcSearch;
    assert_eq!(m.name(), "europepmc_search");
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Labs")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(
        m.produces().contains(&EntityKind::Url),
        "produces() must declare what build_entities actually emits"
    );
    assert!(!m.description().is_empty());
}
