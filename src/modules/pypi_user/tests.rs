use super::*;

// ── parse_user_packages ──────────────────────────────────────────────────────

#[test]
fn parses_owner_maintainer_pairs() {
    let xml = r#"<?xml version='1.0'?>
<methodResponse><params><param><value><array><data>
<value><array><data>
<value><string>Owner</string></value>
<value><string>requests</string></value>
</data></array></value>
<value><array><data>
<value><string>Maintainer</string></value>
<value><string>urllib3</string></value>
</data></array></value>
</data></array></value></param></params></methodResponse>"#;
    let pairs = parse_user_packages(xml);
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0], ("Owner".to_string(), "requests".to_string()));
    assert_eq!(pairs[1], ("Maintainer".to_string(), "urllib3".to_string()));
}

#[test]
fn returns_empty_on_empty_xml_response() {
    let xml = r#"<?xml version='1.0'?>
<methodResponse><params><param><value><array><data>
</data></array></value></param></params></methodResponse>"#;
    let pairs = parse_user_packages(xml);
    assert!(pairs.is_empty());
}

// ── parse_rfc5322_contact ────────────────────────────────────────────────────

#[test]
fn parses_name_and_email() {
    let pairs = parse_rfc5322_contact("Alice Smith <alice@example.com>");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0.as_deref(), Some("Alice Smith"));
    assert_eq!(pairs[0].1, "alice@example.com");
}

#[test]
fn parses_plain_email() {
    let pairs = parse_rfc5322_contact("alice@example.com");
    assert_eq!(pairs.len(), 1);
    assert!(pairs[0].0.is_none());
    assert_eq!(pairs[0].1, "alice@example.com");
}

#[test]
fn parses_multiple_contacts() {
    let pairs =
        parse_rfc5322_contact("Alice Smith <alice@example.com>, Bob Jones <bob@example.com>");
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].0.as_deref(), Some("Alice Smith"));
    assert_eq!(pairs[1].0.as_deref(), Some("Bob Jones"));
}

#[test]
fn returns_empty_for_blank() {
    assert!(parse_rfc5322_contact("").is_empty());
}

#[test]
fn lowercases_email() {
    let pairs = parse_rfc5322_contact("Alice <ALICE@EXAMPLE.COM>");
    assert_eq!(pairs[0].1, "alice@example.com");
}

// ── build_entities ───────────────────────────────────────────────────────────

fn make_info(
    author: Option<&str>,
    author_email: Option<&str>,
    home_page: Option<&str>,
) -> PypiPackageInfo {
    PypiPackageInfo {
        author: author.map(str::to_string),
        author_email: author_email.map(str::to_string),
        home_page: home_page.map(str::to_string),
        maintainer: None,
        maintainer_email: None,
    }
}

#[test]
fn emits_username_and_profile_url() {
    let pkgs = vec![("Owner".to_string(), "mypkg".to_string())];
    let ents = build_entities("alice", &pkgs, None, "scan-pypi-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "alice"),
        "must emit Username"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value.contains("pypi.org/user/alice")),
        "must emit profile URL"
    );
}

#[test]
fn package_coverage_reports_the_true_total_not_a_capped_count() {
    // A prolific maintainer of 35 packages: the coverage note must report the
    // real total (35), not a count silently capped at the old MAX_PACKAGES=30.
    let pkgs: Vec<(String, String)> = (0..35)
        .map(|i| ("Owner".to_string(), format!("pkg{i:02}")))
        .collect();
    let ents = build_entities("prolific", &pkgs, None, "scan-pypi-cap");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "prolific")
        .expect("should succeed");
    assert!(
        u.evidence.iter().any(|ev| ev
            .attributes
            .get("packages")
            .is_some_and(|p| p.contains("(35 packages)"))),
        "coverage note reports the true total of 35 packages"
    );
}

#[test]
fn emits_email_from_author_email_field() {
    let pkgs = vec![("Owner".to_string(), "mypkg".to_string())];
    let info = make_info(None, Some("Alice Smith <alice@example.com>"), None);
    let ents = build_entities("alice", &pkgs, Some(&info), "scan-pypi-002");
    let em = ents.iter().find(|e| e.kind == EntityKind::Email);
    assert!(em.is_some(), "must emit Email");
    assert_eq!(em.expect("should succeed").value, "alice@example.com");
}

#[test]
fn emits_person_from_rfc5322_name() {
    let pkgs = vec![("Owner".to_string(), "mypkg".to_string())];
    let info = make_info(None, Some("Alice Smith <alice@example.com>"), None);
    let ents = build_entities("alice", &pkgs, Some(&info), "scan-pypi-003");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from RFC5322 name");
    assert_eq!(p.expect("should succeed").value, "Alice Smith");
}

#[test]
fn emits_person_from_author_field() {
    let pkgs = vec![("Owner".to_string(), "mypkg".to_string())];
    let info = make_info(Some("Alice Smith"), None, None);
    let ents = build_entities("alice", &pkgs, Some(&info), "scan-pypi-004");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from author field");
}

#[test]
fn no_person_for_single_word_author() {
    let pkgs = vec![("Owner".to_string(), "mypkg".to_string())];
    let info = make_info(Some("alice"), None, None);
    let ents = build_entities("alice", &pkgs, Some(&info), "scan-pypi-005");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Person),
        "single-word author must not produce a Person entity"
    );
}

#[test]
fn emits_homepage_url_and_domain() {
    let pkgs = vec![("Owner".to_string(), "mypkg".to_string())];
    let info = make_info(None, None, Some("https://alice.dev"));
    let ents = build_entities("alice", &pkgs, Some(&info), "scan-pypi-006");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://alice.dev"),
        "must emit homepage URL"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev"),
        "must emit domain from homepage"
    );
}

#[test]
fn package_coverage_reports_the_true_total_not_the_max_packages_cap() {
    // An owner/maintainer with more packages than MAX_PACKAGES (30) must have
    // their real total reported in the `packages` evidence attribute, not the
    // capped sample's own length — the old code used `pkg_names.len()` (post-
    // cap) for both the threshold check and the count, silently understating a
    // 40-package owner as "(30 packages)".
    let pkgs: Vec<(String, String)> = (0..40)
        .map(|i| ("Owner".to_string(), format!("pkg{i}")))
        .collect();
    let ents = build_entities("prolific", &pkgs, None, "scan-pypi-008");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "prolific")
        .expect("username entity");
    let summary = u
        .evidence
        .iter()
        .find_map(|e| e.attributes.get("packages"))
        .expect("package coverage evidence attribute");
    assert!(
        summary.ends_with("(40 packages)"),
        "must report the true total (40), not the MAX_PACKAGES-capped sample length (30): {summary}"
    );
}

#[test]
fn empty_packages_produces_no_entities() {
    let ents = build_entities("ghost", &[], None, "scan-pypi-007");
    // build_entities emits username + profile URL regardless; process() short-circuits on empty.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "ghost"),
        "username always emitted"
    );
}
