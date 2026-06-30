use super::{AustLii, build_entities, extract_case_links};
use crate::core::entity::EntityKind;
use crate::core::module::{Module, ModuleCost};
use crate::core::scan::{Target, TargetKind};

#[test]
fn build_entities_emits_all_fetched_docs_not_just_the_first_ten() {
    // The request asks for results=20 and extract_case_links applies no cap, so
    // every fetched court/legislation reference must become a Url (no-omission).
    let links: Vec<(String, String)> = (0..15)
        .map(|i| {
            (
                format!("https://www.austlii.edu.au/au/cases/cth/HCA/2023/{i}.html"),
                format!("Case {i} [2023] HCA {i}"),
            )
        })
        .collect();
    let target = Target::new(TargetKind::Organisation, "Acme Corp");
    let res = build_entities(&links, &target, "scan");
    let urls = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .count();
    assert_eq!(urls, 15, "all 15 fetched documents must emit, not just 10");
    // Organisation summary still emitted for an org target with >=2 refs.
    assert!(
        res.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.has_tag("legal-record"))
    );
}

#[test]
fn module_metadata() {
    assert_eq!(AustLii.name(), "austlii");
    assert_eq!(AustLii.priority(), 55);
    assert_eq!(AustLii.max_timeout_ms(), 10_000);
    assert!(matches!(AustLii.cost(), ModuleCost::Free));
}

#[test]
fn accepts_fullname_and_organisation_only() {
    let m = AustLii;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "jsmith")));
}

#[test]
fn extract_case_links_parses_relative_path() {
    let html = r#"<a href="/au/cases/cth/HCA/2023/1.html">Smith v Jones [2023] HCA 1</a>"#;
    let links = extract_case_links(html);
    assert_eq!(links.len(), 1);
    assert_eq!(
        links[0].0,
        "https://www.austlii.edu.au/au/cases/cth/HCA/2023/1.html"
    );
    assert_eq!(links[0].1, "Smith v Jones [2023] HCA 1");
}

#[test]
fn extract_case_links_parses_absolute_url() {
    let html = r#"<a href="https://www.austlii.edu.au/au/cases/nsw/NSWCA/2022/50.html">Re: Example Corp [2022] NSWCA 50</a>"#;
    let links = extract_case_links(html);
    assert_eq!(links.len(), 1);
    assert!(
        links[0]
            .0
            .starts_with("https://www.austlii.edu.au/au/cases/")
    );
    assert!(links[0].1.contains("Example Corp"));
}

#[test]
fn extract_case_links_handles_legislation_path() {
    let html = r#"<a href="/au/legis/cth/consol_act/ca2001172/">Corporations Act 2001</a>"#;
    let links = extract_case_links(html);
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].1, "Corporations Act 2001");
}

#[test]
fn extract_case_links_ignores_non_legal_paths() {
    let html = r#"
        <a href="/cgi-bin/search.cgi?q=test">Search</a>
        <a href="/au/cases/cth/FCA/2020/1.html">Federal Court Case</a>
        <a href="/feedback">Feedback</a>
    "#;
    let links = extract_case_links(html);
    assert_eq!(links.len(), 1);
    assert!(links[0].1.contains("Federal Court Case"));
}

#[test]
fn extract_case_links_returns_empty_on_no_results() {
    let html = "<p>No results found for your query.</p><a href=\"/\">Home</a>";
    let links = extract_case_links(html);
    assert_eq!(links.len(), 0);
}

#[test]
fn extract_case_links_caps_at_multiple_results() {
    let mut html = String::new();
    for i in 0..15 {
        html.push_str(&format!(
            r#"<a href="/au/cases/cth/HCA/2023/{i}.html">Case {i}</a>"#
        ));
    }
    let links = extract_case_links(&html);
    assert_eq!(links.len(), 15);
}

#[test]
fn attack_techniques_include_corporate_intel() {
    let t = AustLii.attack_techniques();
    assert!(
        t.contains(&"T1591.002"),
        "must include victim corporate intel"
    );
}
