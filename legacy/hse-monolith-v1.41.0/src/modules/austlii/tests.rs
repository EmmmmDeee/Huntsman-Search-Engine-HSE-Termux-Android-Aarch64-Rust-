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
                format!("Acme Corp v Case {i} [2023] HCA {i}"),
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
fn build_entities_demotes_and_flags_a_hit_whose_title_never_names_the_query() {
    // Regression: sinosrch.cgi is a full-text search across AustLII's entire
    // corpus, not a party-name-scoped lookup — a judgment can mention the
    // query deep in its body (a witness, a cited third party) while its
    // TITLE (the only text available here) names entirely different
    // litigants. Every hit used to be trusted equally at HIGH_PLUS.
    let links = vec![
        (
            "https://www.austlii.edu.au/au/cases/cth/HCA/2023/1.html".to_string(),
            "John Smith v Acme Pty Ltd [2023] HCA 1".to_string(),
        ),
        (
            "https://www.austlii.edu.au/au/cases/cth/HCA/2023/2.html".to_string(),
            "Totally Unrelated Pty Ltd v Other Party [2019] FCA 812".to_string(),
        ),
    ];
    let target = Target::new(TargetKind::FullName, "John Smith");
    let res = build_entities(&links, &target, "scan");

    let matching = res
        .entities
        .iter()
        .find(|e| e.value.contains("2023/1.html"))
        .expect("title-matching hit");
    assert!((matching.confidence - crate::core::confidence::HIGH_PLUS).abs() < 1e-9);
    assert!(!matching.has_tag("needs-identity-verification"));

    let unrelated = res
        .entities
        .iter()
        .find(|e| e.value.contains("2023/2.html"))
        .expect("non-matching hit still kept, not dropped");
    assert!(
        unrelated.confidence < matching.confidence,
        "a title with no relation to the query must rank below one that names it"
    );
    assert!(unrelated.has_tag("needs-identity-verification"));
    assert!(
        unrelated.evidence[0].attributes.contains_key("caution"),
        "the unverified hit's evidence must carry the caution"
    );
}

#[test]
fn build_entities_organisation_summary_counts_only_title_relevant_hits() {
    // The `legal-record` Organisation summary must reflect genuine relevance,
    // not raw hit count — two coincidental appearances in unrelated case
    // titles must not be presented as "2 legal document references".
    let links = vec![
        (
            "https://www.austlii.edu.au/au/cases/cth/HCA/2023/1.html".to_string(),
            "Totally Unrelated Pty Ltd v Someone [2019] FCA 1".to_string(),
        ),
        (
            "https://www.austlii.edu.au/au/cases/cth/HCA/2023/2.html".to_string(),
            "Another Unrelated Entity v Someone Else [2020] FCA 2".to_string(),
        ),
    ];
    let target = Target::new(TargetKind::Organisation, "Acme Corp");
    let res = build_entities(&links, &target, "scan");
    assert!(
        !res.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.has_tag("legal-record")),
        "two title-irrelevant hits must not manufacture a legal-record summary"
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

#[test]
fn legal_form_tokens_alone_never_make_a_title_relevant() {
    // `Pty` / `Ltd` are in the title of half the corporate judgments on AustLII.
    // An Organisation query that carries them must not have every "… Pty Ltd v
    // …" title graded as naming the subject — and two such strangers must not
    // manufacture a `legal-record` summary for the subject.
    let links = vec![
        (
            "https://www.austlii.edu.au/au/cases/cth/FCA/2019/1.html".to_string(),
            "Totally Unrelated Pty Ltd v Someone [2019] FCA 1".to_string(),
        ),
        (
            "https://www.austlii.edu.au/au/cases/cth/FCA/2020/2.html".to_string(),
            "Another Stranger Pty Ltd v Someone Else [2020] FCA 2".to_string(),
        ),
        (
            "https://www.austlii.edu.au/au/cases/cth/FCA/2021/3.html".to_string(),
            "Acme Pty Ltd v Commissioner of Taxation [2021] FCA 3".to_string(),
        ),
    ];
    let target = Target::new(TargetKind::Organisation, "Acme Pty Ltd");
    let res = build_entities(&links, &target, "scan");

    for stranger in ["2019/1.html", "2020/2.html"] {
        let e = res
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.contains(stranger))
            .expect("stranger hit is still surfaced");
        assert!(
            (e.confidence - crate::core::confidence::LOW_MEDIUM).abs() < 1e-9,
            "a title that shares only a legal-form word with the query must be the \
             unverified tier, got {} for {stranger}",
            e.confidence
        );
        assert!(e.has_tag("needs-identity-verification"));
    }
    let own = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url && e.value.contains("2021/3.html"))
        .expect("the subject's own case");
    assert!((own.confidence - crate::core::confidence::HIGH_PLUS).abs() < 1e-9);
    assert!(!own.has_tag("needs-identity-verification"));
    // One genuine title match is below the ≥2 bar; the two strangers must not
    // count toward it.
    assert!(
        !res.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.has_tag("legal-record")),
        "two legal-form-only title matches must not manufacture a legal-record summary"
    );
}

#[test]
fn a_surname_only_title_does_not_name_a_person_subject() {
    // Australian case titles cite individuals by surname ("Smith v The Queen",
    // "R v Smith"), so a surname token in a title is what EVERY namesake's case
    // looks like. Only a title carrying the whole name is graded as naming the
    // subject; a surname-only (or given-name-only) title stays flagged.
    let links = vec![
        (
            "https://www.austlii.edu.au/au/cases/cth/HCA/2021/3.html".to_string(),
            "Smith v The Queen [2021] HCA 3".to_string(),
        ),
        (
            "https://www.austlii.edu.au/au/cases/nsw/NSWSC/2020/7.html".to_string(),
            "Re the Estate of John Doe [2020] NSWSC 7".to_string(),
        ),
        (
            "https://www.austlii.edu.au/au/cases/nsw/NSWSC/2022/1.html".to_string(),
            "R v John Smith [2022] NSWSC 1".to_string(),
        ),
    ];
    let target = Target::new(TargetKind::FullName, "John Smith");
    let res = build_entities(&links, &target, "scan");

    for partial in ["2021/3.html", "2020/7.html"] {
        let e = res
            .entities
            .iter()
            .find(|e| e.value.contains(partial))
            .expect("partial-name hit is still surfaced");
        assert!(
            (e.confidence - crate::core::confidence::LOW_MEDIUM).abs() < 1e-9,
            "a title naming only part of the subject's name must be the unverified \
             tier, got {} for {partial}",
            e.confidence
        );
        assert!(e.has_tag("needs-identity-verification"));
        assert!(
            e.evidence[0].attributes.contains_key("caution"),
            "the partial-name hit must carry the caution"
        );
    }
    let full = res
        .entities
        .iter()
        .find(|e| e.value.contains("2022/1.html"))
        .expect("full-name hit");
    assert!((full.confidence - crate::core::confidence::HIGH_PLUS).abs() < 1e-9);
    assert!(!full.has_tag("needs-identity-verification"));
}

#[test]
fn every_austlii_document_is_a_source_document_never_a_pivot() {
    // A judgment page names the judge, counsel, witnesses and the other party;
    // mining it for entities attributes strangers to the subject. Every AustLII
    // hit — title-relevant or not — carries the tag the engine's expansion loop
    // refuses to pivot on, so the URL is evidence to read, not a seed.
    let links = vec![
        (
            "https://www.austlii.edu.au/au/cases/cth/HCA/2023/1.html".to_string(),
            "Acme Corp v Someone [2023] HCA 1".to_string(),
        ),
        (
            "https://www.austlii.edu.au/au/cases/cth/HCA/2023/2.html".to_string(),
            "Unrelated Party v Other [2019] FCA 812".to_string(),
        ),
        (
            "https://www.austlii.edu.au/au/legis/cth/consol_act/ca2001172/".to_string(),
            "Corporations Act 2001".to_string(),
        ),
    ];
    let target = Target::new(TargetKind::Organisation, "Acme Corp");
    let res = build_entities(&links, &target, "scan");
    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .collect();
    assert_eq!(urls.len(), 3);
    for u in urls {
        assert!(
            u.has_tag(crate::core::tags::SOURCE_DOCUMENT),
            "{} must be tagged as a source document",
            u.value
        );
    }
}
