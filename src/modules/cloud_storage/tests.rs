use super::*;

#[test]
fn extract_base_from_domain() {
    assert_eq!(extract_base_name("www.example.com"), "example");
    assert_eq!(extract_base_name("acme-corp.com.au"), "acme-corp");
    assert_eq!(extract_base_name("EXAMPLE.COM"), "example");
}

#[test]
fn short_name_is_skipped() {
    assert!(extract_base_name("a.b").len() < 3);
}

#[test]
fn generates_rich_valid_deduped_names() {
    let names = generate_bucket_names("acme");
    assert_eq!(names[0], "acme", "bare label comes first");
    assert!(names.contains(&"acme-backup".to_string()));
    assert!(names.contains(&"backup-acme".to_string()));
    assert!(names.contains(&"acme-dumps".to_string()));
    // Deduplicated and every name syntactically valid.
    let set: HashSet<&String> = names.iter().collect();
    assert_eq!(set.len(), names.len(), "no duplicates");
    assert!(names.iter().all(|n| is_valid_bucket(n)));
    assert!(names.len() > 30, "a broad permutation set");
}

#[test]
fn validates_bucket_names() {
    assert!(is_valid_bucket("acme-backup"));
    assert!(!is_valid_bucket("ab")); // too short
    assert!(!is_valid_bucket("-acme")); // leading hyphen
    assert!(!is_valid_bucket("acme-")); // trailing hyphen
    assert!(!is_valid_bucket("Acme")); // uppercase
    assert!(!is_valid_bucket("a.b.c")); // dots break the path/SNI assumption
    assert!(!is_valid_bucket(&"a".repeat(64))); // too long
}

#[test]
fn provider_urls_and_classification() {
    assert_eq!(Provider::ALL.len(), 4);
    assert!(Provider::AwsS3.url("acme").contains("s3.amazonaws.com/acme"));
    assert!(Provider::Gcs.url("acme").contains("storage.googleapis.com/acme"));
    assert!(Provider::AzureBlob.url("acme").contains("acme.blob.core.windows.net"));
    assert!(Provider::DigitalOcean.url("acme").contains("digitaloceanspaces.com"));
    assert_eq!(Provider::AwsS3.existence(200), Existence::Public);
    assert_eq!(Provider::AwsS3.existence(403), Existence::Private);
    assert_eq!(Provider::AwsS3.existence(404), Existence::NotFound);
    assert!(Provider::AwsS3.s3_style_listing());
    assert!(!Provider::AzureBlob.s3_style_listing());
}

#[test]
fn parses_s3_listing_keys_and_sizes() {
    let xml = r#"
        <ListBucketResult>
            <Contents><Key>secret/config.env</Key><Size>1024</Size></Contents>
            <Contents><Key>db/backup.sql</Key><Size>2048</Size></Contents>
            <Contents><Key>logs/app.log</Key><Size>4096</Size></Contents>
        </ListBucketResult>
    "#;
    let l = parse_listing(xml, 25);
    assert_eq!(l.object_count, 3);
    assert_eq!(l.total_size, 1024 + 2048 + 4096);
    assert_eq!(
        l.sample,
        vec!["secret/config.env", "db/backup.sql", "logs/app.log"]
    );
}

#[test]
fn listing_sample_is_capped_but_count_is_total() {
    let mut xml = String::from("<ListBucketResult>");
    for i in 0..100 {
        xml.push_str(&format!("<Contents><Key>k{i}</Key><Size>10</Size></Contents>"));
    }
    xml.push_str("</ListBucketResult>");
    let l = parse_listing(&xml, 25);
    assert_eq!(l.object_count, 100, "count is the full total");
    assert_eq!(l.sample.len(), 25, "sample is capped");
    assert_eq!(l.total_size, 1000);
}

#[test]
fn parse_listing_is_total_on_malformed_xml() {
    assert_eq!(parse_listing("", 25).object_count, 0);
    assert_eq!(parse_listing("<Key>unclosed", 25).object_count, 0); // no </Key>
    assert_eq!(
        parse_listing("<ListBucketResult></ListBucketResult>", 25).object_count,
        0
    );
}

#[test]
fn access_severity_orders_listable_above_read_above_private() {
    let listable = Access::PublicListable {
        object_count: 1,
        total_size: 1,
        sample: vec![],
    };
    assert!(listable.severity() > Access::PublicRead.severity());
    assert!(Access::PublicRead.severity() > Access::Private.severity());
}

#[tokio::test]
async fn module_metadata() {
    let m = CloudStorage;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}
