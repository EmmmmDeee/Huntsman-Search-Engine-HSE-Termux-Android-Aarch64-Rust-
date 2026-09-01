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
fn classify_document_treats_a_root_level_index_as_child_pointers() {
    let xml = r#"<sitemapindex>
  <sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
</sitemapindex>"#;
    match classify_document(xml, 0) {
        DocumentKind::Index(children) => assert_eq!(children.len(), 2),
        DocumentKind::UrlSet(_) => panic!("a sitemapindex must never be classified as a urlset"),
    }
}

#[test]
fn classify_document_drops_a_deeper_index_of_indexes_rather_than_mistyping_it_as_pages() {
    // Regression: an index-of-indexes encountered past the one level of
    // recursion this module follows used to fall through to the "emit as
    // page URLs" branch, minting further sitemap-document URLs as if they
    // were ordinary pages.
    let xml = r#"<sitemapindex>
  <sitemap><loc>https://example.com/sitemap-2020.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-2021.xml</loc></sitemap>
</sitemapindex>"#;
    match classify_document(xml, 1) {
        DocumentKind::Index(children) => assert!(
            children.is_empty(),
            "a level-2 index's children must be dropped, not enqueued or emitted"
        ),
        DocumentKind::UrlSet(_) => {
            panic!("an index document must never be classified as a urlset, regardless of depth")
        }
    }
}

#[test]
fn classify_document_treats_a_urlset_as_page_urls_at_any_depth() {
    let xml = "<urlset><url><loc>https://example.com/a</loc></url></urlset>";
    match classify_document(xml, 1) {
        DocumentKind::UrlSet(urls) => assert_eq!(urls, vec!["https://example.com/a".to_string()]),
        DocumentKind::Index(_) => panic!("a urlset must never be classified as an index"),
    }
}

#[test]
fn mark_truncated_annotates_the_last_entitys_last_evidence_record() {
    let mut e = Entity::new(
        EntityKind::Url,
        "https://example.com/a",
        confidence::VERY_HIGH,
        "scan",
    );
    e.add_evidence(Evidence::new(
        SRC,
        "Listed in https://example.com/sitemap.xml",
    ));
    let mut entities = vec![e];
    mark_truncated(&mut entities, 200);
    let ev = entities[0].evidence.last().expect("should succeed");
    assert_eq!(
        ev.attributes
            .get("sitemap_enumeration_truncated")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ev.attributes.get("sitemap_url_cap").map(String::as_str),
        Some("200")
    );
}

#[test]
fn mark_truncated_is_a_noop_on_an_empty_entity_list() {
    let mut entities: Vec<Entity> = Vec::new();
    mark_truncated(&mut entities, 200);
    assert!(entities.is_empty());
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

#[test]
fn loc_entities_decode_exactly_once() {
    // Regression: `xml_unescape` was a `.replace()` chain that fed each
    // replacement the previous one's output, so `&amp;` decoding to `&` paired
    // with the following text into an entity the next link decoded again. A
    // `<loc>` holding the literal text `&lt;` — which a sitemap publishes as
    // `&amp;lt;` — came out as `<`: a silently wrong URL, not an error.
    let xml = "<urlset><url><loc>https://example.com/?q=&amp;lt;tag&amp;gt;</loc></url></urlset>";
    assert_eq!(
        extract_locs(xml),
        vec!["https://example.com/?q=&lt;tag&gt;".to_string()],
        "each &…; is consumed exactly once; no double-decode"
    );
}

#[test]
fn loc_numeric_character_references_decode() {
    // The old chain handled only the five named entities and left every numeric
    // character reference raw, so the stored URL literally contained "&#38;".
    let xml = "<urlset><url><loc>https://example.com/?a=1&#38;b=2&#x26;c=3</loc></url></urlset>";
    assert_eq!(
        extract_locs(xml),
        vec!["https://example.com/?a=1&b=2&c=3".to_string()],
        "decimal and hex character references resolve"
    );
}
