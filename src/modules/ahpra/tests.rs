use super::{
    Ahpra, build_practitioner_entities, fetch_register_page, parse_ahpra_html, register_rows,
};
use crate::core::confidence;
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn build_practitioner_entities_emits_every_parsed_row_not_just_20() {
    // Full-fidelity: a common-surname register search (Smith/Nguyen/Lee) returns
    // many practitioners; every parsed row must become a Person entity (the HTML
    // body is already size-bounded upstream). Fail-before: capped at 20.
    let rows: Vec<(String, String, String)> = (0..25)
        .map(|i| {
            (
                format!("Jane Smith {i:02}"),
                "Medical Practitioner".to_string(),
                format!("MED{i:07}"),
            )
        })
        .collect();
    // Gated on the seed, the realistic FullName path: every row here genuinely
    // shares the seed's tokens, so the relevance gate must keep all 25 — it
    // suppresses strangers, never the subject's own common-surname cohort.
    let out = build_practitioner_entities(&rows, Some("Jane Smith"), "s");
    assert_eq!(
        out.len(),
        25,
        "every parsed practitioner must be emitted, not capped at 20"
    );
    assert!(out.iter().all(|e| e.kind == EntityKind::Person));
    assert!(out.iter().any(|e| e.value == "Jane Smith 24"));
}

#[test]
fn metadata() {
    let m = Ahpra;
    assert_eq!(m.name(), "ahpra");
    assert_eq!(m.priority(), 86);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Smith")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Clinic")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn parse_ahpra_html_extracts_rows() {
    let html = r#"<table><tr><th>Name</th><th>Profession</th><th>Registration</th></tr>
<tr><td>Jane Smith</td><td>Medical Practitioner</td><td>MED0001234</td></tr>
<tr><td>Bob Jones</td><td>Nurse</td><td>NMW0005678</td></tr>
</table>"#;
    let rows = parse_ahpra_html(html);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, "Jane Smith");
    assert_eq!(rows[0].1, "Medical Practitioner");
    assert_eq!(rows[1].0, "Bob Jones");
}

// ── REQ-AHPRA-001: a register row is a name match, not a practitioner ID ────

#[test]
fn a_row_whose_name_is_not_the_seed_is_never_emitted() {
    // AHPRA's search is fuzzy and the FullName leg queries a surname field, so
    // the table can carry practitioners who are not the subject at all. Before
    // this, every parsed row became a Person at HIGH_PLUS — a stranger's real
    // health registration minted as the subject's.
    let rows = vec![
        (
            "Jane Smith".to_string(),
            "Medical Practitioner".to_string(),
            "MED0001234".to_string(),
        ),
        (
            "Robert Nguyen".to_string(),
            "Nurse".to_string(),
            "NMW0009999".to_string(),
        ),
    ];
    let out = build_practitioner_entities(&rows, Some("Jane Smith"), "s");
    assert_eq!(out.len(), 1, "only the seed's own name may be emitted");
    assert_eq!(out[0].value, "Jane Smith");
}

#[test]
fn an_organisation_search_is_not_gated_on_the_seed_name() {
    // An Organisation seed returns that clinic's practitioners; their names are
    // supposed to differ from the clinic's, so the name gate must not run.
    let rows = vec![(
        "Jane Smith".to_string(),
        "Medical Practitioner".to_string(),
        "MED0001234".to_string(),
    )];
    let out = build_practitioner_entities(&rows, None, "s");
    assert_eq!(out.len(), 1, "an org search keeps its practitioners");
}

#[test]
fn a_name_only_row_sits_at_the_au_register_anchor_and_says_it_is_unverified() {
    let rows = vec![(
        "Jane Smith".to_string(),
        "Medical Practitioner".to_string(),
        "MED0001234".to_string(),
    )];
    let out = build_practitioner_entities(&rows, Some("Jane Smith"), "s");
    let p = &out[0];
    assert!(
        (p.confidence - confidence::MEDIUM_PLUS).abs() < 1e-9,
        "a single-source name hit belongs at the AU-register anchor, got {}",
        p.confidence
    );
    assert!(
        p.has_tag("needs-identity-verification"),
        "a name-only register hit must say the identity is unproven"
    );
    assert!(
        p.evidence.iter().any(|ev| ev
            .attributes
            .get("caution")
            .is_some_and(|c| c.contains("Name-only match"))),
        "and carry the caution naming what would settle it"
    );
}

#[test]
fn two_practitioners_sharing_a_name_are_marked_as_a_proven_collision() {
    // The register returning the SAME name twice is positive proof the name does
    // not identify one person. The entity value IS the name, so the engine's
    // merge fuses these two rows into one Person carrying both registration
    // numbers — a composite practitioner who does not exist. It must describe
    // its own ambiguity rather than read as one confident registration.
    let rows = vec![
        (
            "Jane Smith".to_string(),
            "Medical Practitioner".to_string(),
            "MED0001234".to_string(),
        ),
        (
            "Jane Smith".to_string(),
            "Nurse".to_string(),
            "NMW0005678".to_string(),
        ),
    ];
    let out = build_practitioner_entities(&rows, Some("Jane Smith"), "s");
    assert_eq!(out.len(), 2);
    for p in &out {
        assert!(
            p.confidence < confidence::MEDIUM_PLUS,
            "a provably multi-holder name must score BELOW a single hit, got {}",
            p.confidence
        );
        assert!(p.has_tag("ambiguous-name"));
        assert!(
            p.evidence.iter().any(|ev| ev
                .attributes
                .get("caution")
                .is_some_and(|c| c.contains("MORE THAN ONE"))),
            "the evidence must state that the name has multiple holders"
        );
    }
}

#[test]
fn a_proven_collision_sits_below_the_expansion_floor_with_its_ownership_unverified() {
    // REQ-NAMESAKE-001: FAILS on ahpra's partial copy of the rule, which scored
    // the collision at confidence::MEDIUM — the expansion floor itself — and left
    // each practitioner's registration attributable to whoever shares the name.
    let rows = vec![
        (
            "Jane Smith".to_string(),
            "Medical Practitioner".to_string(),
            "MED0001234".to_string(),
        ),
        (
            "Jane Smith".to_string(),
            "Nurse".to_string(),
            "NMW0005678".to_string(),
        ),
    ];
    for p in build_practitioner_entities(&rows, Some("Jane Smith"), "s") {
        assert!(p.confidence < confidence::MEDIUM, "{}", p.confidence);
        assert!(
            p.evidence
                .iter()
                .all(|ev| ev.verification
                    == Some(crate::core::entity::VerificationMethod::Unverified))
        );
    }
    // A singly-held name keeps the single-hit anchor.
    let one = build_practitioner_entities(&rows[..1], Some("Jane Smith"), "s");
    assert!((one[0].confidence - confidence::MEDIUM_PLUS).abs() < f64::EPSILON);
    assert!(!one[0].has_tag("ambiguous-name"));
}

// ── REQ-AHPRA-002: the register's blank search form is not a negative ────────

/// An excerpt of the REAL register page, fetched live 2026-09-23 with this
/// module's default User-Agent for the GET it sends (HTTP 200, 169 KB): the
/// opener, title, form tag, a form field, the empty results shell and
/// Cloudflare's injected JSD script verbatim (its ray id scrubbed); the rest
/// elided. The register ignored the query string — no `<table>` anywhere, the
/// searched name nowhere.
const REAL_REGISTER_FORM_EXCERPT: &str = "<!DOCTYPE html>\n\
    <html class=\"no-js\" lang=\"en\" ng-app=\"app\">\n<head>\n\
    <title>Australian Health Practitioner Regulation Agency - \
    Register of practitioners</title>\n</head><body>\
    <form method=\"post\" action=\"/Registration/Registers-of-Practitioners\
    #search-results-anchor\" id=\"mainform\" class=\"search-practitioner-page-component\">\
    <input type=\"hidden\" name=\"name-reg-detail\" />\
    <div id=\"SearchResultsPage\" class=\"main\" data-health-profession-filters=\"\" \
    data-location-state-filter=\"\" data-location-suburb-filter=\"\" data-sex-filters=\"\" \
    data-language-filters=\"\" data-page-num=\"1\">\
    <a id=\"search-results-anchor\" name=\"search-results-anchor\"></a>\
    <h1 class=\"heading\">Register of practitioners</h1></div></form>\
    <script>(function(){function c(){var b=a.contentDocument||(a.contentWindow&&\
    a.contentWindow.document);if(b){var d=b.createElement('script');d.innerHTML=\
    \"window.__CF$cv$params={r:'0123456789abcdef',t:'MTc5MDEzNTgzMw=='};\
    var a=document.createElement('script');\
    a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';\
    document.getElementsByTagName('head')[0].appendChild(a);\";\
    b.getElementsByTagName('head')[0].appendChild(d)}}if(document.body){\
    var a=document.createElement('iframe');a.height=1;a.width=1;\
    a.style.position='absolute';a.style.top=0;a.style.left=0;a.style.border='none';\
    a.style.visibility='hidden';document.body.appendChild(a);\
    if('loading'!==document.readyState)c();else if(window.addEventListener)\
    document.addEventListener('DOMContentLoaded',c);\
    else{var e=document.onreadystatechange||function(){};\
    document.onreadystatechange=function(b){e(b);\
    'loading'!==document.readyState&&(document.onreadystatechange=e,c())}}}})();\
    </script></body>\n</html>\n";

#[test]
fn the_registers_blank_search_form_is_a_failure_not_zero_practitioners() {
    // FAILS before REQ-AHPRA-002: the form parses to zero rows, and zero rows
    // was `Ok(empty)` — coverage's `CleanNegative`, "the subject is not a
    // registered health practitioner", from a page that never ran the search.
    use crate::core::error::Error;
    assert!(parse_ahpra_html(REAL_REGISTER_FORM_EXCERPT).is_empty());
    let err = register_rows(REAL_REGISTER_FORM_EXCERPT)
        .expect_err("the blank search form answers no query");
    assert!(matches!(err, Error::Module { .. }), "{err}");
    assert!(err.to_string().contains("NOT looked up"), "{err}");

    // A page that does carry rows keeps them, form or no form.
    let with_rows = REAL_REGISTER_FORM_EXCERPT.replace(
        "</div></form>",
        "<table><tr><td>Jane Smith</td><td>Medical Practitioner</td><td>MED0001234</td></tr>\
         </table></div></form>",
    );
    let rows = register_rows(&with_rows).expect("real rows are an answer");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "Jane Smith");
}

/// The whole request path, as `process` runs it, against a loopback serving
/// the two pages the register has really answered: the F5 support-ID wall
/// (still `BotChallenge`) and the real register page. FAILS before
/// REQ-AHPRA-002 on the second, which the bare `/cdn-cgi/challenge-platform`
/// marker typed as a wall — and with only the detector fixed it would have
/// read as zero practitioners instead.
#[tokio::test]
async fn the_real_register_page_is_neither_a_wall_nor_a_clean_negative() {
    use crate::core::error::Error;
    use crate::util::http::test_server::{Canned, serve};
    const F5_WALL: &str = include_str!("../../util/html/testdata/wall_ahpra_200_2026-09-18.html");
    let base = serve(vec![
        Canned::html(200, F5_WALL),
        Canned::html(200, REAL_REGISTER_FORM_EXCERPT),
    ])
    .await;
    let client = reqwest::Client::new();
    let target = Target::new(TargetKind::FullName, "Jane Smith");

    let wall = fetch_register_page(&client, &base, &target)
        .await
        .expect_err("the F5 interstitial is a wall");
    assert!(matches!(wall, Error::BotChallenge(_)), "{wall}");

    let page = fetch_register_page(&client, &base, &target)
        .await
        .expect("the real register page is the document, not a wall")
        .expect("a 200 is a page");
    let err = register_rows(&page).expect_err("and it answers no query");
    assert!(matches!(err, Error::Module { .. }), "{err}");
}
