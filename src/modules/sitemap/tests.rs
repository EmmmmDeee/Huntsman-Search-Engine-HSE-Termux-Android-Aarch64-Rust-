use super::*;

#[test]
fn extracts_locs_from_a_urlset() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc><lastmod>2024-01-01</lastmod></url>
  <url><loc>https://example.com/about</loc></url>
  <url>
    <loc>https://example.com/products?id=1&amp;ref=2</loc>
  </url>
</urlset>"#;
    let locs = extract_locs(xml);
    assert_eq!(locs.len(), 3);
    assert!(locs.contains(&"https://example.com/".to_string()));
    assert!(locs.contains(&"https://example.com/about".to_string()));
    // Ampersand entity is unescaped.
    assert!(locs.contains(&"https://example.com/products?id=1&ref=2".to_string()));
}

#[test]
fn extracts_locs_from_a_sitemap_index() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
</sitemapindex>"#;
    assert!(is_sitemap_index(xml));
    let locs = extract_locs(xml);
    assert_eq!(locs.len(), 2);
    assert!(locs.contains(&"https://example.com/sitemap-posts.xml".to_string()));
}

#[test]
fn urlset_is_not_flagged_as_index() {
    let xml = "<urlset><url><loc>https://example.com/</loc></url></urlset>";
    assert!(!is_sitemap_index(xml));
}

#[test]
fn extract_locs_dedups_and_tolerates_attributes_on_the_tag() {
    let xml = "<loc >https://a.example.com/x</loc><loc>https://a.example.com/x</loc>\
               <loc\n>https://a.example.com/y</loc>";
    let locs = extract_locs(xml);
    assert_eq!(locs.len(), 2, "duplicate loc collapsed");
}

#[test]
fn extract_locs_handles_a_truncated_document_without_hanging() {
    // A body cut mid-tag must terminate, not spin.
    let xml = "<urlset><url><loc>https://example.com/ok</loc></url><url><loc>https://exa";
    let locs = extract_locs(xml);
    assert_eq!(locs, vec!["https://example.com/ok".to_string()]);
}

#[test]
fn parses_robots_sitemap_directives_case_insensitively() {
    let robots = "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml\n\
                  SITEMAP:  https://example.com/news-sitemap.xml\n";
    let sitemaps = parse_robots_sitemaps(robots);
    assert_eq!(sitemaps.len(), 2);
    assert!(sitemaps.contains(&"https://example.com/sitemap.xml".to_string()));
    assert!(sitemaps.contains(&"https://example.com/news-sitemap.xml".to_string()));
}

#[test]
fn robots_without_a_sitemap_directive_yields_nothing() {
    let robots = "User-agent: *\nDisallow: /\n";
    assert!(parse_robots_sitemaps(robots).is_empty());
}

#[test]
fn in_scope_gate_confines_to_the_site() {
    // Same site, its www alias, and subdomains are in scope.
    assert!(in_scope("https://example.com/x", "example.com"));
    assert!(in_scope("https://www.example.com/x", "example.com"));
    assert!(in_scope("https://blog.example.com/post", "example.com"));
    // A different site is out of scope (a sitemap pointing off-site).
    assert!(!in_scope("https://evil.test/x", "example.com"));
    // The classic suffix-confusion attack must be rejected.
    assert!(!in_scope("https://example.com.attacker.test/x", "example.com"));
}

#[test]
fn in_scope_handles_public_suffix_www_apex_equivalence() {
    // The bug this fixes: `gov.uk` is itself a public suffix, so
    // registrable_domain("gov.uk") != registrable_domain("www.gov.uk").
    // The effective-site gate must still treat them as the same site.
    assert!(in_scope("https://www.gov.uk/sitemaps/sitemap_1.xml", "gov.uk"));
    assert!(in_scope("https://gov.uk/foo", "gov.uk"));
    assert!(in_scope(
        "https://assets.publishing.service.gov.uk/x",
        "gov.uk"
    ));
    // ...but a different org that merely ends in the string is still rejected.
    assert!(!in_scope("https://notgov.uk/x", "gov.uk"));
}

#[test]
fn effective_site_strips_leading_www_only() {
    assert_eq!(effective_site("www.gov.uk"), "gov.uk");
    assert_eq!(effective_site("gov.uk"), "gov.uk");
    assert_eq!(effective_site("WWW.Example.COM"), "example.com");
    // Only a LEADING www is stripped, not one embedded in a subdomain.
    assert_eq!(effective_site("wwwtest.example.com"), "wwwtest.example.com");
}

#[test]
fn target_host_strips_url_scheme_and_path() {
    assert_eq!(
        target_host(TargetKind::Url, "https://Example.com/path?q=1"),
        "example.com"
    );
    assert_eq!(
        target_host(TargetKind::Domain, "Example.com."),
        "example.com"
    );
}

#[test]
fn metadata_is_well_formed() {
    let m = Sitemap;
    assert_eq!(m.name(), "sitemap");
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@example.com")));
    assert!(m.produces().contains(&EntityKind::Url));
}
