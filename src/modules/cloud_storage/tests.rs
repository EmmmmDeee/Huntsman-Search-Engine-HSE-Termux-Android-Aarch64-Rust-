use super::*;

#[test]
fn extract_base_from_domain() {
    assert_eq!(extract_base_name("www.example.com"), "example");
    assert_eq!(extract_base_name("acme-corp.com.au"), "acme-corp");
    assert_eq!(extract_base_name("EXAMPLE.COM"), "example");
}

#[test]
fn short_name_skipped() {
    assert!(extract_base_name("a.b").len() < 3);
}

#[test]
fn generate_candidates_covers_all_suffixes_and_providers() {
    let names = generate_bucket_candidates("test");
    let expected = SUFFIXES.len() * 5; // 5 providers
    assert_eq!(names.len(), expected);
}

#[test]
fn generate_candidates_contains_all_providers() {
    let names = generate_bucket_candidates("test");
    assert!(names.iter().any(|(u, _, _)| u.contains("s3.amazonaws")));
    assert!(names.iter().any(|(u, _, _)| u.contains("blob.core.windows")));
    assert!(names.iter().any(|(u, _, _)| u.contains("storage.googleapis")));
    assert!(names.iter().any(|(u, _, _)| u.contains("digitaloceanspaces")));
    assert!(names.iter().any(|(u, _, _)| u.contains("wasabisys")));
}

#[test]
fn generate_candidates_contains_new_suffixes() {
    let names = generate_bucket_candidates("acme");
    let urls: Vec<&str> = names.iter().map(|(u, _, _)| u.as_str()).collect();
    // Verify new suffixes are present (S3 format as reference)
    assert!(urls.iter().any(|u| u.contains("acme-prod.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-staging.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-static.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-media.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-logs.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-images.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-uploads.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-test.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-archive.s3")));
    assert!(urls.iter().any(|u| u.contains("acme-files.s3")));
}

#[test]
fn generate_candidates_do_spaces_url_format() {
    let names = generate_bucket_candidates("myorg");
    let do_entries: Vec<_> = names
        .iter()
        .filter(|(_, p, _)| *p == "DigitalOcean Spaces")
        .collect();
    assert!(!do_entries.is_empty());
    // All DO Spaces URLs use the nyc3 region format
    assert!(do_entries
        .iter()
        .all(|(u, _, _)| u.contains(".nyc3.digitaloceanspaces.com")));
}

#[test]
fn generate_candidates_wasabi_url_format() {
    let names = generate_bucket_candidates("myorg");
    let wasabi: Vec<_> = names
        .iter()
        .filter(|(_, p, _)| *p == "Wasabi")
        .collect();
    assert!(!wasabi.is_empty());
    // Wasabi uses path-style with region
    assert!(wasabi
        .iter()
        .all(|(u, _, _)| u.contains("s3.us-east-1.wasabisys.com/")));
}

#[test]
fn is_exposed_aws_s3() {
    assert!(is_exposed(200, "AWS S3"));
    assert!(is_exposed(403, "AWS S3")); // private bucket exists
    assert!(!is_exposed(404, "AWS S3"));
    assert!(!is_exposed(301, "AWS S3"));
}

#[test]
fn is_exposed_azure_blob() {
    assert!(is_exposed(200, "Azure Blob"));
    assert!(!is_exposed(403, "Azure Blob")); // Azure 403 = no public access
    assert!(!is_exposed(404, "Azure Blob"));
}

#[test]
fn is_exposed_gcs() {
    assert!(is_exposed(200, "GCS"));
    assert!(is_exposed(403, "GCS")); // private bucket exists
    assert!(!is_exposed(404, "GCS"));
}

#[test]
fn is_exposed_digitalocean_spaces() {
    assert!(is_exposed(200, "DigitalOcean Spaces"));
    assert!(is_exposed(403, "DigitalOcean Spaces")); // private bucket exists
    assert!(!is_exposed(404, "DigitalOcean Spaces"));
}

#[test]
fn is_exposed_wasabi() {
    assert!(is_exposed(200, "Wasabi"));
    assert!(is_exposed(403, "Wasabi")); // private bucket exists
    assert!(!is_exposed(404, "Wasabi"));
}

#[tokio::test]
async fn module_metadata() {
    let m = CloudStorage;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert_eq!(m.produces(), &[EntityKind::Url]);
}
