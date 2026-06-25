use super::*;

const SEEK_JSON_LD: &str = r#"
<html>
<head>
<script type="application/ld+json">
{
  "@type": "JobPosting",
  "title": "Senior Software Engineer",
  "hiringOrganization": { "name": "Acme Corp Pty Ltd" },
  "jobLocation": {
    "address": {
      "addressLocality": "Sydney",
      "addressRegion": "NSW",
      "addressCountry": "AU"
    }
  },
  "url": "https://www.seek.com.au/job/12345678",
  "description": "A great role at Acme Corp. Contact hr@acmecorp.com.au"
}
</script>
</head>
<body>
<h1>Senior Software Engineer at Acme Corp</h1>
<p>Sydney, NSW</p>
</body>
</html>
"#;

#[test]
fn extract_json_string_basic() {
    let json = r#"{"name": "Acme Corp", "city": "Sydney"}"#;
    assert_eq!(
        extract_json_string(json, "name"),
        Some("Acme Corp".to_string())
    );
    assert_eq!(
        extract_json_string(json, "city"),
        Some("Sydney".to_string())
    );
    assert_eq!(extract_json_string(json, "missing"), None);
}

#[test]
fn parse_seek_job_posting() {
    let entities = parse_seek_html(SEEK_JSON_LD, "Acme Corp", "test-scan");
    assert!(
        entities.iter().any(|e| e.kind == EntityKind::Organisation),
        "should emit an Organisation entity"
    );
    assert!(
        entities.iter().any(|e| e.kind == EntityKind::Address),
        "should emit an Address entity"
    );
    assert!(
        entities.iter().any(|e| e.kind == EntityKind::Url),
        "should emit a Url entity"
    );

    let org = entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .unwrap();
    assert!(
        org.value.contains("Acme Corp"),
        "organisation name should match: {}",
        org.value
    );
    assert!(org.has_tag("seek-employer"));

    let addr = entities
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .unwrap();
    assert!(
        addr.value.contains("Sydney"),
        "address should contain suburb: {}",
        addr.value
    );
    assert!(
        addr.value.contains("NSW"),
        "address should contain state: {}",
        addr.value
    );
    assert!(addr.has_tag("au-state:NSW"));
}

#[test]
fn parse_seek_email_in_listing() {
    let html = r#"
    <script type="application/ld+json">
    {
      "@type": "JobPosting",
      "title": "Accountant",
      "hiringOrganization": { "name": "Finance Partners" },
      "jobLocation": { "address": { "addressLocality": "Melbourne", "addressRegion": "VIC" } },
      "url": "https://www.seek.com.au/job/99887766",
      "description": "Apply to careers@financepartners.com.au"
    }
    </script>
    "#;
    let entities = parse_seek_html(html, "Finance Partners", "test-scan");
    let email_entities: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .collect();
    assert!(
        !email_entities.is_empty(),
        "should extract contact email from listing text"
    );
    assert!(
        email_entities[0].value.contains("financepartners"),
        "email should be from listing, not Seek: {}",
        email_entities[0].value
    );
}

#[test]
fn seek_own_emails_filtered() {
    let html = r#"
    <script type="application/ld+json">
    { "@type": "JobPosting", "hiringOrganization": { "name": "Big Company" },
      "jobLocation": { "address": { "addressLocality": "Brisbane", "addressRegion": "QLD" } },
      "url": "https://www.seek.com.au/job/1111",
      "description": "Apply via noreply@seek.com.au" }
    </script>
    "#;
    let entities = parse_seek_html(html, "Big Company", "test-scan");
    let emails: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .collect();
    assert!(
        emails.iter().all(|e| !e.value.ends_with("@seek.com.au")),
        "Seek's own domain emails should be filtered out"
    );
}

#[test]
fn no_false_positive_unrelated_content() {
    let html = "<html><body><p>No job listings match your search.</p></body></html>";
    let entities = parse_seek_html(html, "Unknown Company XYZ", "test-scan");
    assert!(
        entities
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .count()
            == 0,
        "no organisations should be emitted for empty result pages"
    );
}
