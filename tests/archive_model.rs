use huntsman_recon::archive::{
    ArchiveCapture, ArchiveInterest, ArchiveSource, classify_archive_path, merge_captures,
    parse_archive_url,
};

fn capture(
    source: ArchiveSource,
    dataset: &str,
    collection: Option<&str>,
    url: &str,
    captured_at: &str,
    status: Option<u16>,
    mime: Option<&str>,
    source_url: Option<&str>,
) -> ArchiveCapture {
    ArchiveCapture {
        source,
        dataset: dataset.to_owned(),
        collection: collection.map(str::to_owned),
        original_url: url.to_owned(),
        key: parse_archive_url(url).expect("valid archive URL"),
        captured_at: captured_at.to_owned(),
        status,
        mime: mime.map(str::to_owned),
        digest: None,
        source_url: source_url.map(str::to_owned),
    }
}

#[test]
fn archive_url_key_ignores_scheme_host_case_trailing_dot_and_default_port() {
    let http = parse_archive_url("HTTP://Example.COM.:80/a?x=1").expect("http");
    let https = parse_archive_url("https://example.com/a?x=1").expect("https");
    let https_default =
        parse_archive_url("https://EXAMPLE.com.:443/a?x=1").expect("https default port");

    assert_eq!(http, https);
    assert_eq!(https, https_default);
    assert_eq!(http.host, "example.com");
    assert_eq!(http.port, None);
    assert_eq!(http.path, "/a");
    assert_eq!(http.query, "x=1");
}

#[test]
fn archive_url_key_preserves_non_default_port_path_and_query() {
    let base = parse_archive_url("https://example.com/a?x=1&y=2").expect("base");
    let port = parse_archive_url("https://example.com:8443/a?x=1&y=2").expect("port");
    let path = parse_archive_url("https://example.com/A?x=1&y=2").expect("path");
    let query = parse_archive_url("https://example.com/a?y=2&x=1").expect("query");

    assert_ne!(base, port);
    assert_ne!(base, path);
    assert_ne!(base, query);
    assert_eq!(port.port, Some(8443));
    assert_eq!(path.path, "/A");
    assert_eq!(query.query, "y=2&x=1");
}

#[test]
fn archive_url_rejects_non_http_invalid_and_hostless_values() {
    for raw in [
        "mailto:admin@example.com",
        "javascript:alert(1)",
        "https:///missing-host",
        "not a url",
    ] {
        assert_eq!(parse_archive_url(raw), None, "{raw}");
    }
}

#[test]
fn merge_keeps_first_last_count_and_per_dataset_aggregates() {
    let url = "https://example.com/admin/login?next=%2F";
    let records = merge_captures(vec![
        capture(
            ArchiveSource::Wayback,
            "internet_archive_wayback",
            None,
            url,
            "20240101000000",
            Some(200),
            Some("text/html"),
            Some("https://web.archive.org/web/20240101000000/https://example.com/admin/login?next=%2F"),
        ),
        capture(
            ArchiveSource::Wayback,
            "internet_archive_wayback",
            None,
            "http://EXAMPLE.com:80/admin/login?next=%2F",
            "20240201000000",
            None,
            None,
            Some("https://web.archive.org/web/20240201000000/http://example.com/admin/login?next=%2F"),
        ),
        capture(
            ArchiveSource::CommonCrawl,
            "common_crawl",
            Some("CC-MAIN-2026-30"),
            url,
            "20240301000000",
            Some(301),
            Some("text/html"),
            None,
        ),
    ]);

    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.first_seen, "20240101000000");
    assert_eq!(record.last_seen, "20240301000000");
    assert_eq!(record.capture_count, 3);
    assert_eq!(record.datasets.len(), 2);

    let cc = record
        .datasets
        .iter()
        .find(|dataset| dataset.dataset == "common_crawl")
        .expect("Common Crawl aggregate");
    assert_eq!(cc.capture_count, 1);
    assert_eq!(cc.collections, vec!["CC-MAIN-2026-30"]);
    assert_eq!(cc.latest_status, Some(301));

    let wayback = record
        .datasets
        .iter()
        .find(|dataset| dataset.dataset == "internet_archive_wayback")
        .expect("Wayback aggregate");
    assert_eq!(wayback.capture_count, 2);
    assert!(wayback.collections.is_empty());
    assert_eq!(wayback.first_seen, "20240101000000");
    assert_eq!(wayback.last_seen, "20240201000000");
    assert_eq!(wayback.latest_status, Some(200));
    assert_eq!(wayback.latest_mime.as_deref(), Some("text/html"));
    assert_eq!(wayback.source_urls.len(), 2);
}

#[test]
fn same_dataset_multiple_captures_remain_one_dataset() {
    let records = merge_captures(vec![
        capture(
            ArchiveSource::CommonCrawl,
            "common_crawl",
            Some("CC-MAIN-2026-26"),
            "https://example.com/a",
            "20240101000000",
            Some(200),
            Some("text/html"),
            None,
        ),
        capture(
            ArchiveSource::CommonCrawl,
            "common_crawl",
            Some("CC-MAIN-2026-30"),
            "https://example.com/a",
            "20240201000000",
            Some(200),
            Some("text/html"),
            None,
        ),
    ]);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].datasets.len(), 1);
    assert_eq!(records[0].datasets[0].dataset, "common_crawl");
    assert_eq!(
        records[0].datasets[0].collections,
        vec!["CC-MAIN-2026-26", "CC-MAIN-2026-30"]
    );
    assert_eq!(records[0].datasets[0].capture_count, 2);
}

#[test]
fn unknown_status_or_mime_is_not_invented() {
    let records = merge_captures(vec![capture(
        ArchiveSource::Wayback,
        "internet_archive_wayback",
        None,
        "https://example.com/unknown",
        "20240101000000",
        None,
        None,
        None,
    )]);

    let dataset = &records[0].datasets[0];
    assert_eq!(dataset.latest_status, None);
    assert_eq!(dataset.latest_mime, None);
}

#[test]
fn interest_classification_marks_patterns_without_asserting_security_facts() {
    assert!(classify_archive_path("/report.pdf", "").contains(&ArchiveInterest::Document));
    assert!(
        classify_archive_path("/backup.sql", "").contains(&ArchiveInterest::ArchiveOrBackup)
    );
    assert!(
        classify_archive_path("/.env", "").contains(&ArchiveInterest::ConfigurationLike)
    );
    assert!(classify_archive_path("/assets/app.js", "").contains(&ArchiveInterest::ScriptLike));
    assert!(
        classify_archive_path("/admin/login", "").contains(&ArchiveInterest::AdminAuthApiLike)
    );
    assert!(
        classify_archive_path("/search", "q=hse").contains(&ArchiveInterest::Parameterized)
    );
}

#[test]
fn interest_classification_has_near_miss_negatives() {
    for path in ["/administratorial/home", "/apiary/index", "/configurator/home"] {
        let interests = classify_archive_path(path, "");
        assert!(!interests.contains(&ArchiveInterest::AdminAuthApiLike), "{path}");
        assert!(!interests.contains(&ArchiveInterest::ConfigurationLike), "{path}");
    }
}
