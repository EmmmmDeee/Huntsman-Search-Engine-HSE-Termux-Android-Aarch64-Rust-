use super::*;

fn make_author(
    pauseid: &str,
    name: Option<&str>,
    email: Vec<&str>,
    website_urls: Vec<&str>,
    location: Option<Vec<f64>>,
    biography: Option<&str>,
) -> CpanAuthor {
    CpanAuthor {
        pauseid: pauseid.to_string(),
        name: name.map(str::to_string),
        email: email.into_iter().map(str::to_string).collect(),
        website: website_urls.into_iter().map(str::to_string).collect(),
        location,
        biography: biography.map(str::to_string),
        profile: vec![],
        blog: vec![],
    }
}

fn profile(name: &str, id: &str) -> CpanProfile {
    CpanProfile {
        name: Some(name.to_string()),
        id: Some(id.to_string()),
    }
}

#[test]
fn emits_username_and_uppercase_profile_url() {
    let author = make_author("johndoe", None, vec![], vec![], None, None);
    let ents = build_entities(author, "scan-cpan-001");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("should succeed");
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
    assert_eq!(p.expect("should succeed").value, "John H. Doe");
    assert!(p.expect("should succeed").has_tag("cpan"));
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
fn emits_coordinates_from_lat_lon_location() {
    // MetaCPAN `location` is a [lat, lon] pair (RJBS: Philadelphia), not a place
    // string — emit Coordinates directly.
    let author = make_author(
        "perldev",
        None,
        vec![],
        vec![],
        Some(vec![39.952778, -75.163611]),
        None,
    );
    let ents = build_entities(author, "scan-cpan-006");
    let c = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("must emit Coordinates from [lat, lon] location");
    // Entity::new canonicalises Coordinates to 6 decimal places.
    assert_eq!(c.value, "39.952800,-75.163600");
    assert!(c.has_tag("self-asserted") && c.has_tag("geoint") && c.has_tag("cpan"));
    // No place-name Address is fabricated (we only have coordinates).
    assert!(ents.iter().all(|e| e.kind != EntityKind::Address));
}

#[test]
fn invalid_or_null_island_location_emits_no_coordinates() {
    // Out-of-range and (0,0) fixes are rejected.
    for loc in [vec![0.0, 0.0], vec![999.0, 10.0], vec![10.0]] {
        let a = make_author("x", None, vec![], vec![], Some(loc), None);
        assert!(
            build_entities(a, "s")
                .iter()
                .all(|e| e.kind != EntityKind::Coordinates)
        );
    }
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
        profile: vec![],
        blog: vec![],
    };
    assert!(build_entities(author, "scan-cpan-008").is_empty());
}

#[test]
fn deserializes_scalar_or_array_email() {
    // Regression: MetaCPAN returns `email` as a SCALAR string for most authors
    // (RJBS/LEONT/MSTROUT confirmed live). A plain Vec<String> failed the whole
    // author decode ("invalid type: string, expected a sequence"), silently
    // breaking the module. The polymorphic deserializer must accept both.
    // Verbatim live RJBS shape: scalar email, website as an array of URL STRINGS,
    // location as a [lat, lon] float array — every one of which the old struct
    // (Vec<String> email, Vec<CpanSite> website, Option<String> location) failed.
    let scalar = r#"{"pauseid":"RJBS","email":"cpan@semiotic.systems",
        "website":["http://rjbs.cloud/"],"location":[39.952778,-75.163611],
        "profile":[{"id":"rjbs","name":"github"}],"blog":[{"url":"http://rjbs.cloud/blog"}]}"#;
    let a: CpanAuthor = serde_json::from_str(scalar).expect("should succeed");
    assert_eq!(a.email, vec!["cpan@semiotic.systems".to_string()]);
    assert_eq!(a.website, vec!["http://rjbs.cloud/".to_string()]);
    assert_eq!(a.location, Some(vec![39.952778, -75.163611]));
    assert_eq!(a.profile.len(), 1);
    assert_eq!(a.blog.len(), 1);
    // The whole author now builds entities without error (the end-to-end path).
    assert!(!build_entities(a, "s").is_empty());
    // An array of emails still decodes.
    let arr = r#"{"pauseid":"X","email":["a@b.com","c@d.com"]}"#;
    let a2: CpanAuthor = serde_json::from_str(arr).expect("should succeed");
    assert_eq!(a2.email.len(), 2);
    // Missing / null email → empty, never an error.
    let none: CpanAuthor = serde_json::from_str(r#"{"pauseid":"Y","email":null}"#).expect("should succeed");
    assert!(none.email.is_empty());
    let absent: CpanAuthor = serde_json::from_str(r#"{"pauseid":"Z"}"#).expect("should succeed");
    assert!(absent.email.is_empty());
}

#[test]
fn linked_profiles_become_platform_tagged_username_pivots() {
    // Verbatim shape of the live MetaCPAN `profile` array (RJBS/LEONT): handle
    // platforms (github/coderwall) → Username pivots; a purely-numeric id
    // (stackoverflow/linkedin user number) is NOT a handle and must be skipped.
    let mut author = make_author("rjbs", None, vec![], vec![], None, None);
    author.profile = vec![
        profile("github", "rjbs"),
        profile("coderwall", "rjbs"),
        profile("stackoverflow", "10478"), // numeric user id — skipped
        profile("linkedin", "39522422"),   // numeric user id — skipped
    ];
    let ents = build_entities(author, "scan-cpan-prof");

    let gh = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "rjbs" && e.has_tag("github"))
        .expect("github handle → Username pivot");
    assert!(gh.has_tag("cpan") && gh.has_tag("cpan-pivot"));
    assert_eq!(
        gh.evidence[0]
            .attributes
            .get("platform_handle")
            .map(String::as_str),
        Some("github:rjbs")
    );
    // coderwall handle also surfaces.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.has_tag("coderwall"))
    );
    // The numeric-only ids never mint a junk Username.
    assert!(
        ents.iter()
            .all(|e| e.value != "10478" && e.value != "39522422"),
        "numeric platform user ids must not become username pivots"
    );
    assert!(
        !ents
            .iter()
            .any(|e| e.has_tag("stackoverflow") || e.has_tag("linkedin")),
        "numeric-id platforms produce no pivot"
    );
}

#[test]
fn blog_url_becomes_url_and_domain() {
    let mut author = make_author("rjbs", None, vec![], vec![], None, None);
    author.blog = vec![CpanBlog {
        url: Some("https://rjbs.cloud/blog".to_string()),
    }];
    let ents = build_entities(author, "scan-cpan-blog");
    let url = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url && e.value == "https://rjbs.cloud/blog")
        .expect("blog URL entity");
    assert!(url.has_tag("cpan"));
    assert_eq!(
        url.evidence[0]
            .attributes
            .get("source_field")
            .map(String::as_str),
        Some("blog")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "rjbs.cloud")
    );
}
