use super::*;

fn make_author(
    pauseid: &str,
    name: Option<&str>,
    email: Vec<&str>,
    website_urls: Vec<&str>,
    location: Option<&str>,
    biography: Option<&str>,
) -> CpanAuthor {
    CpanAuthor {
        pauseid: pauseid.to_string(),
        name: name.map(str::to_string),
        email: email.into_iter().map(str::to_string).collect(),
        website: website_urls
            .into_iter()
            .map(|u| CpanSite {
                url: Some(u.to_string()),
            })
            .collect(),
        location: location.map(str::to_string),
        biography: biography.map(str::to_string),
    }
}

#[test]
fn emits_username_and_uppercase_profile_url() {
    let author = make_author("johndoe", None, vec![], vec![], None, None);
    let ents = build_entities(author, "scan-cpan-001");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    // Username value is normalised lowercase so it dedups with the same handle
    // on GitHub/GitLab/etc (cross-platform correlation), while raw_value keeps
    // the canonical uppercase PAUSE ID as observed from the API.
    assert_eq!(u.value, "johndoe");
    assert_eq!(u.raw_value, "JOHNDOE");
    // MetaCPAN author URLs are canonically uppercase; the Url normaliser
    // lowercases only the host, so the uppercase PAUSE ID survives in the path.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://metacpan.org/author/JOHNDOE")
    );
    assert!(u.has_tag("cpan") && u.has_tag("public-profile"));
    assert!((u.confidence - 0.87).abs() < 0.01);
}

#[test]
fn emits_person_from_multi_word_name() {
    let author = make_author("jdoe", Some("John H. Doe"), vec![], vec![], None, None);
    let ents = build_entities(author, "scan-cpan-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word name");
    assert_eq!(p.unwrap().value, "John H. Doe");
    assert!(p.unwrap().has_tag("cpan"));
}

#[test]
fn single_word_name_does_not_emit_person() {
    let author = make_author("jdoe", Some("JDoe"), vec![], vec![], None, None);
    let ents = build_entities(author, "scan-cpan-003");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_public_emails() {
    let author = make_author(
        "perldev",
        None,
        vec!["perldev@example.com", "perldev@cpan.org"],
        vec![],
        None,
        None,
    );
    let ents = build_entities(author, "scan-cpan-004");
    let emails: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| e.value.as_str())
        .collect();
    assert!(emails.contains(&"perldev@example.com"));
    assert!(emails.contains(&"perldev@cpan.org"));
    assert!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Email)
            .all(|e| e.has_tag("cpan"))
    );
}

#[test]
fn emits_website_url_and_domain() {
    let author = make_author(
        "perldev",
        None,
        vec![],
        vec!["https://perldev.io"],
        None,
        None,
    );
    let ents = build_entities(author, "scan-cpan-005");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://perldev.io")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "perldev.io")
    );
}

#[test]
fn emits_address_from_location() {
    let author = make_author("perldev", None, vec![], vec![], Some("Amsterdam, NL"), None);
    let ents = build_entities(author, "scan-cpan-006");
    let a = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(a.is_some(), "must emit Address from location");
    assert_eq!(a.unwrap().value, "Amsterdam, NL");
    assert!(a.unwrap().has_tag("self-asserted"));
}

#[test]
fn extracts_email_from_biography() {
    let author = make_author(
        "perldev",
        None,
        vec![],
        vec![],
        None,
        Some("Reach me at perl.hacker@example.com"),
    );
    let ents = build_entities(author, "scan-cpan-007");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "perl.hacker@example.com")
    );
}

#[test]
fn empty_pauseid_returns_no_entities() {
    let author = CpanAuthor {
        pauseid: String::new(),
        name: None,
        email: vec![],
        website: vec![],
        location: None,
        biography: None,
    };
    assert!(build_entities(author, "scan-cpan-008").is_empty());
}
