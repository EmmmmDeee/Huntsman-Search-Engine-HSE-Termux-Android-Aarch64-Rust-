use super::*;

const SCAN: &str = "scan-test";
const QUERY: &str = "Jordan Avery";

fn author(given: &str, family: &str) -> CrossrefAuthor {
    CrossrefAuthor {
        given: Some(given.to_string()),
        family: Some(family.to_string()),
        affiliation: vec![],
    }
}

/// A work BY the query's subject (every projection test is about the URL /
/// DOI handling, so each item is attributable).
fn item(doi: Option<&str>, url: Option<&str>) -> CrossrefItem {
    CrossrefItem {
        doi: doi.map(str::to_string),
        url: url.map(str::to_string),
        title: vec![],
        author: vec![author("Jordan", "Avery")],
    }
}

fn build(r: &CrossrefResp) -> Vec<Entity> {
    build_entities(r, TargetKind::FullName, QUERY, SCAN)
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
    assert!(build(&CrossrefResp::default()).is_empty());
}

#[test]
fn prefers_url_falls_back_to_doi_and_skips_neither() {
    let r = resp(vec![
        item(Some("10.1/abc"), Some("https://example.org/paper")),
        item(Some("10.1/xyz"), None),
        item(None, None),
    ]);
    let out = build(&r);
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
    assert!(build(&r).is_empty());
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
    let out = build(&r);
    assert_eq!(out.len(), 1, "case-differing duplicate URL must collapse");
}

#[test]
fn the_five_result_cap_is_enforced() {
    let items: Vec<CrossrefItem> = (0..25)
        .map(|i| item(Some(&format!("10.1/{i:04}")), None))
        .collect();
    let out = build(&resp(items));
    assert_eq!(out.len(), CAP, "must stop at the {CAP}-result cap");
}

#[test]
fn every_entity_carries_the_calibrated_confidence_and_kind() {
    let r = resp(vec![item(None, Some("https://example.org/paper"))]);
    let out = build(&r);
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
    let out = build(&r);
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
    let a = build(&r);
    let b = build(&r);
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

#[test]
fn a_work_that_merely_mentions_the_name_is_not_the_subjects_work() {
    // Backlog #14, observed live 2026-09-15: the all-fields `query=Ada Lovelace`
    // returned "Introduction to the Ada Lovelace Symposium" (Alexander Wolf)
    // and "Ada Lovelace lives forever" (Betty Toole) — works ABOUT the name.
    // Only a work whose author IS the subject is attributable; a work with no
    // author on record cannot be.
    let about = CrossrefItem {
        doi: Some("10.1145/2867731.2867750".into()),
        url: None,
        title: vec!["Introduction to the Ada Lovelace Symposium".into()],
        author: vec![author("Alexander", "Wolf")],
    };
    let by = CrossrefItem {
        doi: Some("10.1093/owc/9780199554652.003.0008".into()),
        url: None,
        title: vec!["Sketch of the Analytical Engine (1843)".into()],
        author: vec![author("Ada", "Lovelace")],
    };
    let unattributed = CrossrefItem {
        doi: Some("10.1/no-authors".into()),
        url: None,
        title: vec![],
        author: vec![],
    };
    let out = build_entities(
        &resp(vec![about, by, unattributed]),
        TargetKind::FullName,
        "Ada Lovelace",
        SCAN,
    );
    assert_eq!(
        values(&out),
        vec!["https://doi.org/10.1093/owc/9780199554652.003.0008".to_string()]
    );
    let ev = &out[0].evidence[0];
    assert_eq!(ev.summary, "Crossref work by 'Ada Lovelace'");
    assert_eq!(
        ev.attributes.get("matched_author").map(String::as_str),
        Some("Ada Lovelace")
    );
    assert_eq!(
        ev.attributes.get("title").map(String::as_str),
        Some("Sketch of the Analytical Engine (1843)")
    );
}

#[test]
fn an_organisation_is_matched_on_an_authors_affiliation() {
    // Live shape 2026-09-15 (`query.affiliation=University of Wollongong`):
    // affiliations are free text with the city and country appended, and a
    // co-author at "The Wollongong Hospital" is a different institution.
    let hospital = || {
        let mut a = author("A", "Sideris");
        a.affiliation = vec![CrossrefAffiliation {
            name: Some("The Wollongong Hospital , Wollongong , Australia".into()),
        }];
        a
    };
    let mut uni = author("G", "Wallace");
    uni.affiliation = vec![CrossrefAffiliation {
        name: Some("University of Wollongong , Wollongong , Australia".into()),
    }];
    let work = CrossrefItem {
        doi: Some("10.1/uow".into()),
        url: None,
        title: vec![],
        author: vec![hospital(), uni],
    };
    let only_hospital = CrossrefItem {
        doi: Some("10.1/hospital".into()),
        url: None,
        title: vec![],
        author: vec![hospital()],
    };
    let out = build_entities(
        &resp(vec![work, only_hospital]),
        TargetKind::Organisation,
        "University of Wollongong",
        SCAN,
    );
    assert_eq!(values(&out), vec!["https://doi.org/10.1/uow".to_string()]);
    assert_eq!(
        out[0].evidence[0]
            .attributes
            .get("matched_affiliation")
            .map(String::as_str),
        Some("University of Wollongong , Wollongong , Australia")
    );
}

#[test]
fn author_matching_takes_the_family_name_and_a_given_name_or_initial() {
    assert!(author_matches("Jordan Avery", "Jordan", "Avery"));
    assert!(author_matches("Jordan Avery", "J.", "Avery"));
    assert!(author_matches("J Avery", "Jordan", "Avery"));
    assert!(author_matches("Avery", "Jordan", "Avery"));
    assert!(author_matches("Jordan Avery", "", "Avery"));
    assert!(author_matches("Anna van der Berg", "Anna", "van der Berg"));
    // Family-first order (Vietnamese) and diacritic folding.
    assert!(author_matches("Nguyễn Văn An", "Van An", "Nguyen"));
    assert!(!author_matches("Jordan Avery", "Morgan", "Avery"));
    assert!(!author_matches("Jordan Avery", "Jordan", "Averys"));
    assert!(!author_matches("Jordan Avery", "Jordan", ""));
    assert!(!author_matches("", "Jordan", "Avery"));
}

#[test]
fn query_is_scoped_to_the_author_or_affiliation_field() {
    let name = build_query(TargetKind::FullName, "Ada Lovelace").expect("a name is searchable");
    assert!(name.contains("query.author=Ada+Lovelace"), "{name}");
    assert!(!name.contains("?query="), "{name}");
    let org = build_query(TargetKind::Organisation, "University of Wollongong")
        .expect("an organisation is searchable");
    assert!(
        org.contains("query.affiliation=University+of+Wollongong"),
        "{org}"
    );
    assert!(build_query(TargetKind::Domain, "example.com").is_none());
}
