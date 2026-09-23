use super::*;

const SCAN: &str = "scan-test";
const QUERY: &str = "Jane Doe";

/// A work whose byline carries the seed (`QUERY` = "Jane Doe" → `"Doe J"`), so
/// the projection tests below exercise the URL/dedup/cap judgement on works
/// that pass the attribution gate — the gate itself is locked separately.
fn item(doi: Option<&str>, pmid: Option<&str>) -> ResultItem {
    ResultItem {
        doi: doi.map(str::to_string),
        pmid: pmid.map(str::to_string),
        author_string: Some("Roe R, Doe J.".to_string()),
        ..ResultItem::default()
    }
}

fn by(doi: &str, authors: Option<&str>) -> ResultItem {
    ResultItem {
        doi: Some(doi.to_string()),
        author_string: authors.map(str::to_string),
        ..ResultItem::default()
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
    let out = build_entities(&SearchResp::default(), TargetKind::FullName, QUERY, SCAN);
    assert!(out.is_empty());
}

#[test]
fn doi_is_preferred_over_pmid_when_both_are_present() {
    let r = resp(vec![item(Some("10.1/abc"), Some("123"))]);
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "https://doi.org/10.1/abc");
    assert_eq!(out[0].kind, EntityKind::Url);
}

#[test]
fn falls_back_to_the_pubmed_page_when_no_doi_is_present() {
    let r = resp(vec![item(None, Some("456"))]);
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
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
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
    assert!(out.is_empty());
}

#[test]
fn blank_doi_and_pmid_strings_are_treated_as_absent() {
    // The API can return an empty string rather than omitting the field;
    // whitespace-only values must not produce a bare "https://doi.org/" or
    // "https://pubmed.ncbi.nlm.nih.gov//" entity.
    let r = resp(vec![item(Some("  "), Some(""))]);
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
    assert!(out.is_empty());
}

#[test]
fn mixed_results_prefer_doi_and_fall_back_per_item_and_dedup() {
    let r = resp(vec![
        item(Some("10.1/abc"), Some("123")),
        item(None, Some("456")),
        item(None, None),
    ]);
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
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
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
    assert_eq!(out.len(), 1, "case-differing duplicate URLs must collapse");
}

#[test]
fn the_cap_is_enforced() {
    let items: Vec<ResultItem> = (0..(CAP + 10))
        .map(|i| item(Some(&format!("10.1/doc{i:04}")), None))
        .collect();
    let r = resp(items);
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
    assert_eq!(out.len(), CAP);
}

#[test]
fn evidence_carries_the_identifier_and_the_query() {
    let r = resp(vec![item(Some("10.1/abc"), None)]);
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
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
    let out = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
    assert!((out[0].confidence - RESULT_URL_CONFIDENCE).abs() < 1e-9);
    assert!(out[0].has_tag("europepmc"));
    assert!(out[0].has_tag("literature"));
}

#[test]
fn projection_is_deterministic() {
    let r = resp(vec![item(Some("10.1/abc"), None), item(None, Some("456"))]);
    let a = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
    let b = build_entities(&r, TargetKind::FullName, QUERY, SCAN);
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

#[tokio::test]
async fn a_404_from_the_search_endpoint_is_a_failed_lookup_and_hit_count_zero_is_the_miss() {
    // Backlog #21. Europe PMC signals "no hits" as a 200 with `hitCount: 0`
    // and an empty `resultList`; the endpoint is fixed, so a 404 is the
    // endpoint gone, never "no publications by this author". Before this a
    // 404 was `Ok(empty)` — a clean negative about the named person.
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::text(404, "Not Found"),
        Canned::text(500, "Internal Server Error"),
        Canned::json(200, r#"{"hitCount":0,"resultList":{"result":[]}}"#),
    ])
    .await;
    let client = reqwest::Client::new();
    let endpoint = build_url(
        &format!("{base}/europepmc/webservices/rest/search"),
        TargetKind::FullName,
        QUERY,
    )
    .expect("a name builds a query");

    let err = search(&client, &endpoint)
        .await
        .expect_err("404 on a fixed search endpoint is a failed lookup");
    assert!(err.to_string().contains("404"), "{err}");
    let err = search(&client, &endpoint)
        .await
        .expect_err("an outage is a failed lookup");
    assert!(err.to_string().contains("500"), "{err}");
    let miss = search(&client, &endpoint)
        .await
        .expect("hitCount 0 is the genuine miss");
    assert!(build_entities(&miss, TargetKind::FullName, QUERY, SCAN).is_empty());
}

#[test]
fn a_work_with_no_author_matching_the_seed_is_not_the_subjects() {
    // REQ-EUROPEPMC-001 (the crossref #14 defect, unfixed here): live
    // 2026-09-23, the unfielded `query=Ada Lovelace` returned an essay ABOUT
    // her ("Charman-Anderson S."), an editorial with no author, and a GPU
    // paper — all filed as the subject's literature at 0.60.
    let r = resp(vec![
        by("10.1016/j.patter.2020.100118", Some("Charman-Anderson S.")),
        by("10.1038/s43588-023-00541-z", None),
        by("10.1000/gpu", Some("Freitag LL.")),
    ]);
    assert!(
        build_entities(&r, TargetKind::FullName, "Ada Lovelace", SCAN).is_empty(),
        "a work nobody of the seed's name wrote is not the subject's"
    );
}

#[test]
fn an_initials_author_string_matches_the_seed() {
    // Europe PMC writes "Surname Initials": "Thorpe IF" is an Ian Thorpe (the
    // namesake question is a separate one); "Thorpe A" is not.
    let r = resp(vec![
        by("10.1021/acs.jpca.7b01852", Some("Carbonaro NJ, Thorpe IF.")),
        by("10.1038/s43016-024-00961-8", Some("Lynch AJ, Thorpe A.")),
        by("10.1002/ece3.9087", Some("van Dorst RM, Argillier C.")),
    ]);
    let out = build_entities(&r, TargetKind::FullName, "Ian Thorpe", SCAN);
    assert_eq!(urls(&out), vec!["https://doi.org/10.1021/acs.jpca.7b01852"]);
    let ev = &out[0].evidence[0];
    assert_eq!(
        ev.attributes.get("matched_author").map(String::as_str),
        Some("Thorpe IF")
    );
    assert!(ev.summary.contains("Europe PMC work by 'Thorpe IF'"));
}

#[test]
fn a_multi_word_family_name_is_read_whole() {
    let r = resp(vec![by("10.1/x", Some("van Dorst RM, Argillier C."))]);
    assert_eq!(
        build_entities(&r, TargetKind::FullName, "Ruben van Dorst", SCAN).len(),
        1
    );
}

#[test]
fn the_name_query_is_author_fielded() {
    let name = build_url(API_BASE, TargetKind::FullName, "Ian Thorpe").expect("a name query");
    assert!(
        name.contains(&format!("query={}", urlencode("AUTH:\"Ian Thorpe\""))),
        "{name}"
    );
    assert!(!name.contains("resultType"), "{name}");
    let org = build_url(
        API_BASE,
        TargetKind::Organisation,
        "University of Wollongong",
    )
    .expect("an organisation query");
    assert!(org.contains("AFF%3A%22University"), "{org}");
    assert!(org.contains("resultType=core"), "{org}");
    assert!(build_url(API_BASE, TargetKind::Email, "a@b.com").is_none());
    // A quote cannot close the phrase early.
    let q = build_url(API_BASE, TargetKind::FullName, "Ian \"Thorpe\"").expect("a name query");
    assert!(q.contains(&urlencode("AUTH:\"Ian Thorpe\"")), "{q}");
}

#[test]
fn an_organisation_is_attributed_by_its_affiliation_line() {
    let hit = ResultItem {
        doi: Some("10.1111/dar.70208".into()),
        affiliation: Some(
            "School of Psychology, University of Wollongong, Wollongong, Australia.".into(),
        ),
        ..ResultItem::default()
    };
    let other = ResultItem {
        doi: Some("10.1/other".into()),
        affiliation: Some("The Wollongong Hospital, Australia.".into()),
        ..ResultItem::default()
    };
    let out = build_entities(
        &resp(vec![hit, other]),
        TargetKind::Organisation,
        "University of Wollongong",
        SCAN,
    );
    assert_eq!(urls(&out), vec!["https://doi.org/10.1111/dar.70208"]);
    assert!(
        out[0].evidence[0]
            .attributes
            .contains_key("matched_affiliation")
    );
}

#[test]
fn distinct_papers_carry_distinct_records() {
    // Scan 7258fc07: one summary per author ("Europe PMC work by 'Thorpe
    // IF'") made every paper by that author one shared evidence record, and
    // the GEXF drew 72 false co-occurrence edges between distinct DOIs. The
    // summary must name the work.
    let r = resp(vec![
        by("10.1/a", Some("Thorpe IF.")),
        by("10.1/b", Some("Thorpe IF.")),
    ]);
    let out = build_entities(&r, TargetKind::FullName, "Ian Thorpe", SCAN);
    assert_eq!(out.len(), 2);
    assert_ne!(out[0].evidence[0].summary, out[1].evidence[0].summary);
    assert!(out[0].evidence[0].summary.contains("doi 10.1/a"));
    let xml = crate::core::gexf::entities_to_gexf(&out, &[], SCAN);
    assert!(
        !xml.contains("<edge "),
        "distinct papers are not a joint record: {xml}"
    );
}

/// REQ-EUROPEPMC-002: the top-level `affiliation` of a `resultType=core` record
/// is the FIRST author's only (and null on some records), while the `AFF:`
/// query matches any author's. A work whose only affiliated author is a
/// co-author must still be attributed — the shape below is the live one.
#[test]
fn an_organisation_is_attributed_through_any_authors_affiliation() {
    let body = r#"{"resultList":{"result":[
      {"doi":"10.1/null-top","affiliation":null,"authorList":{"author":[
        {"fullName":"Smith J"},
        {"fullName":"Braunack-Mayer A","authorAffiliationDetailsList":{"authorAffiliation":[
          {"affiliation":"Australian Centre for Health Engagement, University of Wollongong, NSW, Australia."}]}}]}},
      {"doi":"10.1111/inm.70283","affiliation":"Imam Abdulrahman University, Dammam, Saudi Arabia.",
       "authorList":{"author":[
        {"fullName":"A B","authorAffiliationDetailsList":{"authorAffiliation":[
          {"affiliation":"Imam Abdulrahman University, Dammam, Saudi Arabia."}]}},
        {"fullName":"C D","authorAffiliationDetailsList":{"authorAffiliation":[
          {"affiliation":"Other Place."},
          {"affiliation":"School of Nursing, University of Wollongong, Australia."}]}}]}},
      {"doi":"10.1/nobody","affiliation":"The Wollongong Hospital, Australia.",
       "authorList":{"author":[{"fullName":"E F","authorAffiliationDetailsList":{"authorAffiliation":[
          {"affiliation":"The Wollongong Hospital, Australia."}]}}]}}
    ]}}"#;
    let r: SearchResp = serde_json::from_str(body).expect("live core shape decodes");
    let out = build_entities(
        &r,
        TargetKind::Organisation,
        "University of Wollongong",
        SCAN,
    );
    assert_eq!(
        urls(&out),
        vec![
            "https://doi.org/10.1/null-top",
            "https://doi.org/10.1111/inm.70283"
        ]
    );
    assert_eq!(
        out[1].evidence[0]
            .attributes
            .get("matched_affiliation")
            .map(String::as_str),
        Some("School of Nursing, University of Wollongong, Australia.")
    );
}
