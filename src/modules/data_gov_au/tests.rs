use super::*;

const SCAN: &str = "scan-test";

fn org_value(e: &Entity) -> Option<&str> {
    (e.kind == EntityKind::Organisation).then_some(e.value.as_str())
}

fn url_values(entities: &[Entity]) -> Vec<&str> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .map(|e| e.value.as_str())
        .collect()
}

fn org_count(entities: &[Entity]) -> usize {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .count()
}

#[test]
fn fuzzy_contains_matches_either_direction_case_insensitively() {
    assert!(fuzzy_contains(
        "Australian Taxation Office",
        "australian taxation office"
    ));
    assert!(fuzzy_contains(
        "Australian Taxation Office",
        "Taxation Office"
    ));
    assert!(!fuzzy_contains(
        "Australian Taxation Office",
        "Bureau of Meteorology"
    ));
    assert!(!fuzzy_contains("Anything", ""));
}

#[test]
fn fuzzy_contains_does_not_expand_abbreviations() {
    // Documented limitation: an abbreviation matches neither direction of the
    // substring test, so it deliberately does NOT resolve to the full agency name.
    assert!(!fuzzy_contains("Australian Taxation Office", "ATO"));
}

#[test]
fn projects_matching_org_and_dataset_url_filters_unrelated_orgs() {
    let data: PackageSearchResponse = serde_json::from_str(
        r#"{"success":true,"result":{"count":2,"results":[
            {"name":"taxation-statistics-2009-10","organization":{"title":"Australian Taxation Office"}},
            {"name":"weather-data","organization":{"title":"Bureau of Meteorology"}}
        ]}}"#,
    )
    .unwrap();
    let ents = build_entities(&data, "Australian Taxation Office", SCAN);

    assert!(
        ents.iter()
            .any(|e| org_value(e) == Some("Australian Taxation Office")),
        "the matching organisation must be present: {ents:?}"
    );
    assert!(
        url_values(&ents).contains(&"https://data.gov.au/data/dataset/taxation-statistics-2009-10"),
        "the matching dataset's URL must be present: {ents:?}"
    );
    // The Bureau of Meteorology dataset doesn't match the query — must not appear at all.
    assert!(
        !ents
            .iter()
            .any(|e| e.value.contains("Bureau of Meteorology") || e.value.contains("weather-data")),
        "an unrelated organisation/dataset must be filtered out: {ents:?}"
    );

    // Confidence split: a confirmed organisation match outranks its supporting dataset pivot.
    let org = ents
        .iter()
        .find(|e| org_value(e) == Some("Australian Taxation Office"))
        .expect("org entity present");
    let url = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("url entity present");
    assert_eq!(org.confidence, confidence::HIGH);
    assert_eq!(url.confidence, confidence::MEDIUM_HIGH);
    assert!(
        org.confidence > url.confidence,
        "the organisation match must be more confident than its dataset pivot"
    );
}

#[test]
fn empty_result_yields_nothing() {
    let data: PackageSearchResponse = serde_json::from_str(r#"{"success":true}"#).unwrap();
    assert!(build_entities(&data, "anything", SCAN).is_empty());
}

#[test]
fn a_result_with_zero_datasets_yields_nothing() {
    let data: PackageSearchResponse =
        serde_json::from_str(r#"{"success":true,"result":{"count":0,"results":[]}}"#).unwrap();
    assert!(build_entities(&data, "anything", SCAN).is_empty());
}

#[test]
fn datasets_with_no_organization_are_skipped() {
    // CKAN's `organization` field can be null/absent for some records — must not panic and
    // must not be counted as a match.
    let data: PackageSearchResponse = serde_json::from_str(
        r#"{"success":true,"result":{"count":1,"results":[
            {"name":"orphan-dataset","organization":null}
        ]}}"#,
    )
    .unwrap();
    assert!(build_entities(&data, "orphan-dataset", SCAN).is_empty());
}

#[test]
fn repeated_organisation_and_dataset_rows_are_deduplicated() {
    // Two rows report the exact same organisation and dataset name (a realistic CKAN response
    // shape: the same package can legitimately appear more than once across paginated/duplicate
    // rows). The org must be emitted exactly once, and the identical dataset URL exactly once —
    // but a THIRD row sharing the org but naming a DIFFERENT dataset must still add a second,
    // distinct URL.
    let data: PackageSearchResponse = serde_json::from_str(
        r#"{"success":true,"result":{"count":3,"results":[
            {"name":"taxation-statistics-2009-10","organization":{"title":"Australian Taxation Office"}},
            {"name":"taxation-statistics-2009-10","organization":{"title":"Australian Taxation Office"}},
            {"name":"taxation-statistics-2010-11","organization":{"title":"Australian Taxation Office"}}
        ]}}"#,
    )
    .unwrap();
    let ents = build_entities(&data, "Australian Taxation Office", SCAN);

    assert_eq!(
        org_count(&ents),
        1,
        "the same organisation across several rows must be emitted once: {ents:?}"
    );
    let mut urls = url_values(&ents);
    urls.sort_unstable();
    assert_eq!(
        urls,
        vec![
            "https://data.gov.au/data/dataset/taxation-statistics-2009-10",
            "https://data.gov.au/data/dataset/taxation-statistics-2010-11",
        ],
        "distinct dataset names must both survive, the repeated one only once: {ents:?}"
    );
}

#[test]
fn projection_is_deterministic() {
    let data: PackageSearchResponse = serde_json::from_str(
        r#"{"success":true,"result":{"count":2,"results":[
            {"name":"one","organization":{"title":"Australian Taxation Office"}},
            {"name":"two","organization":{"title":"Australian Taxation Office"}}
        ]}}"#,
    )
    .unwrap();
    let a = build_entities(&data, "Australian Taxation Office", SCAN);
    let b = build_entities(&data, "Australian Taxation Office", SCAN);
    let va: Vec<_> = a.iter().map(|e| (&e.kind, &e.value)).collect();
    let vb: Vec<_> = b.iter().map(|e| (&e.kind, &e.value)).collect();
    assert_eq!(va, vb, "identical input must yield an identical projection");
}

#[test]
fn module_metadata_is_coherent() {
    let m = DataGovAu;
    assert_eq!(m.name(), "data_gov_au");
    assert!(m.accepts(&Target::new(
        TargetKind::Organisation,
        "Australian Taxation Office"
    )));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(
        m.produces().contains(&EntityKind::Organisation),
        "produces() must declare the organisation entity build_entities emits"
    );
    assert!(
        m.produces().contains(&EntityKind::Url),
        "produces() must declare the dataset URL entity build_entities emits"
    );
}

#[tokio::test]
async fn short_query_is_skipped_without_a_request() {
    // Below MIN_QUERY_LEN, process() must return early — before any HTTP call is attempted, so
    // this is safe to run with no network access and no mocked response.
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: SCAN.to_string(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let m = DataGovAu;
    let target = Target::new(TargetKind::Organisation, "AB");
    let result = m.process(&target, &ctx).await.expect("should succeed");
    assert!(result.entities.is_empty());
}
