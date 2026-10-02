use super::*;

const SCAN: &str = "scan-test";

#[test]
fn module_metadata_is_coherent() {
    let m = CommonCrawl;
    assert_eq!(m.name(), "commoncrawl");
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(
        m.produces().contains(&EntityKind::Url),
        "produces() must declare what build_entities actually emits"
    );
}

#[test]
fn cdx_query_url_uses_the_domain_matchtype_wildcard() {
    // Regression: a bare `url=<domain>` defaults the CDX-Server API's
    // `matchType` to `exact` — matching only that literal URL string, not
    // the domain's pages — which would silently defeat this module's
    // entire purpose with no error, just a near-empty result. The `*.`
    // prefix triggers `matchType=domain` (the same proven pattern
    // `wayback`'s own CDX domain-match pass uses) without a separate query
    // parameter.
    let url = cdx_query_url(
        "https://index.commoncrawl.org/CC-MAIN-2026-01-index",
        "example.com",
    );
    assert_eq!(
        url,
        "https://index.commoncrawl.org/CC-MAIN-2026-01-index?url=*.example.com&output=json&limit=100"
    );
    assert!(
        !url.contains("&url=example.com&"),
        "must not query with the CDX-Server API's default exact matchType"
    );
}

#[test]
fn parses_jsonl_and_skips_bad_lines() {
    // Mirrors a real CDX response: a full index record, a stray non-JSON
    // line (the index occasionally emits one), a minimal `{"url":...}`
    // record, and a duplicate of the first record's URL.
    let body = "{\"urlkey\":\"com,example)/\",\"url\":\"https://www.example.com/\",\"status\":\"200\"}\n\
                 not json\n\
                 {\"url\":\"http://example.com/x\"}\n\
                 {\"url\":\"https://www.example.com/\"}";
    let ents = build_entities(body, SCAN);
    assert_eq!(ents.len(), 2, "bad line skipped, duplicate collapsed");
    assert!(ents.iter().all(|e| e.kind == EntityKind::Url));
    assert!(ents.iter().any(|e| e.value == "http://example.com/x"));
}

#[test]
fn dedup_is_case_insensitive_on_the_raw_url() {
    // Common Crawl can repeat the same page across snapshot dates, and the
    // exact same page reported with a differently-cased host is still the
    // same page — unlike bitcoin's base58 addresses, where case IS data, a
    // URL's case carries no such distinguishing meaning at the dedup layer,
    // so the pre-emission dedup key case-folds the whole raw string.
    let body = "{\"url\":\"https://EXAMPLE.com/\"}\n{\"url\":\"https://example.com/\"}";
    let ents = build_entities(body, SCAN);
    assert_eq!(ents.len(), 1, "case-differing duplicate must collapse");
}

#[test]
fn blank_and_missing_url_fields_are_skipped() {
    let body = "{\"url\":\"\"}\n{\"status\":\"200\"}\n{}\n   \n\n";
    let ents = build_entities(body, SCAN);
    assert!(
        ents.is_empty(),
        "an empty/absent url field must contribute nothing: {ents:?}"
    );
}

#[test]
fn the_emission_cap_is_enforced() {
    let mut body = String::new();
    for i in 0..(CAP + 25) {
        body.push_str(&format!("{{\"url\":\"https://example.com/page{i}\"}}\n"));
    }
    let ents = build_entities(&body, SCAN);
    assert_eq!(ents.len(), CAP);
}

#[test]
fn projection_is_deterministic() {
    let body = "{\"url\":\"https://example.com/a\"}\n{\"url\":\"https://example.com/b\"}\n{\"url\":\"https://example.com/c\"}";
    let a = build_entities(body, SCAN);
    let b = build_entities(body, SCAN);
    let va: Vec<_> = a.iter().map(|e| &e.value).collect();
    let vb: Vec<_> = b.iter().map(|e| &e.value).collect();
    assert_eq!(va, vb, "identical input must yield an identical projection");
}

#[test]
fn each_url_carries_evidence_and_confidence() {
    let body = "{\"url\":\"https://example.com/a\"}";
    let ents = build_entities(body, SCAN);
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Url);
    assert!((ents[0].confidence - URL_CONFIDENCE).abs() < 1e-9);
    assert_eq!(
        ents[0].evidence.len(),
        1,
        "each URL carries exactly one evidence record"
    );
    assert_eq!(ents[0].evidence[0].source, SRC);
    assert!(ents[0].has_tag("commoncrawl"));
    assert!(ents[0].has_tag("archive"));
}

#[test]
fn empty_body_yields_no_entities() {
    assert!(build_entities("", SCAN).is_empty());
    assert!(build_entities("\n\n   \n", SCAN).is_empty());
}
