use super::*;

/// Build an `SfUser` in the Allura `/rest/u/{h}` shape. The real / display
/// name lives on a `developers[]` record whose `username` matches the handle.
fn user_with(
    name: &str,
    dev_name: Option<&str>,
    url: Option<&str>,
    homepage: Option<&str>,
    socials: Vec<(&str, &str)>,
    creation_date: Option<&str>,
) -> SfUser {
    SfUser {
        name: name.to_string(),
        url: url.map(str::to_string),
        creation_date: creation_date.map(str::to_string),
        external_homepage: homepage.map(str::to_string),
        socialnetworks: socials
            .into_iter()
            .map(|(net, u)| SfSocial {
                accounturl: u.to_string(),
                socialnetwork: net.to_string(),
            })
            .collect(),
        developers: dev_name
            .map(|n| {
                vec![SfDeveloper {
                    username: name.to_string(),
                    name: n.to_string(),
                }]
            })
            .unwrap_or_default(),
    }
}

#[test]
fn emits_username_and_profile_url_from_url_field() {
    let user = user_with(
        "sfdev",
        None,
        Some("https://sourceforge.net/u/sfdev/"),
        None,
        vec![],
        None,
    );
    let ents = build_entities(user, "scan-sf-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "sfdev")
    );
    // trailing slash must be stripped
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://sourceforge.net/u/sfdev")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("should succeed");
    assert!(u.has_tag("sourceforge") && u.has_tag("public-profile"));
    assert!((u.confidence - 0.86).abs() < 0.01);
}

#[test]
fn falls_back_to_constructed_url_when_url_absent() {
    let user = user_with("sfdev", None, None, None, vec![], None);
    let ents = build_entities(user, "scan-sf-002");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://sourceforge.net/u/sfdev")
    );
}

#[test]
fn emits_person_from_matching_developer_name() {
    // The real name now lives on the developers[] record whose username
    // matches the handle — not on a top-level display_name.
    let user = user_with(
        "sfdev",
        Some("Source Forge Developer"),
        None,
        None,
        vec![],
        None,
    );
    let ents = build_entities(user, "scan-sf-003");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(
        p.is_some(),
        "must emit Person from the matching developer name"
    );
    assert_eq!(p.expect("should succeed").value, "Source Forge Developer");
    assert!(p.expect("should succeed").has_tag("sourceforge"));
}

#[test]
fn single_word_developer_name_does_not_emit_person() {
    let user = user_with("sfdev", Some("SfDev"), None, None, vec![], None);
    let ents = build_entities(user, "scan-sf-004");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn non_matching_developer_name_is_not_attributed() {
    // A developers[] record for a *different* username must not have its name
    // attributed to this handle.
    let mut user = user_with("sfdev", None, None, None, vec![], None);
    user.developers.push(SfDeveloper {
        username: "someone-else".to_string(),
        name: "Not This Person".to_string(),
    });
    let ents = build_entities(user, "scan-sf-005");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Person),
        "only the developer record matching the handle carries the account's name"
    );
}

#[test]
fn emits_homepage_url_and_domain() {
    // A real (non-reserved) homepage domain — `example.*` is rejected by the
    // domain extractor's reserved-domain guard, so use a plausible real one.
    let user = user_with(
        "sfdev",
        None,
        None,
        Some("https://jsummers.io"),
        vec![],
        None,
    );
    let ents = build_entities(user, "scan-sf-006");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://jsummers.io")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "jsummers.io")
    );
}

#[test]
fn emits_social_link_urls_but_skips_blank_placeholders() {
    // SF returns a fixed list of social networks, most with an empty
    // accounturl — only the real (http) ones become entities.
    let user = user_with(
        "sfdev",
        None,
        None,
        None,
        vec![
            ("Twitter", "https://twitter.com/sfdev"),
            ("Facebook", ""),
            ("LinkedIn", "not-a-url"),
        ],
        None,
    );
    let ents = build_entities(user, "scan-sf-007");
    let socials: Vec<_> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.has_tag("social-link"))
        .collect();
    assert_eq!(
        socials.len(),
        1,
        "only the one real http account URL is emitted"
    );
    assert_eq!(socials[0].value, "https://twitter.com/sfdev");
    assert_eq!(
        socials[0].evidence[0]
            .attributes
            .get("social_network")
            .map(String::as_str),
        Some("Twitter")
    );
}

#[test]
fn account_created_date_travels_as_evidence() {
    let user = user_with("sfdev", None, None, None, vec![], Some("2011-03-12"));
    let ents = build_entities(user, "scan-sf-008");
    let un = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("username entity present");
    assert_eq!(
        un.evidence[0]
            .attributes
            .get("account_created")
            .map(String::as_str),
        Some("2011-03-12")
    );
}

#[test]
fn empty_name_returns_no_entities() {
    let user = user_with("", None, None, None, vec![], None);
    assert!(build_entities(user, "scan-sf-009").is_empty());
}

#[test]
fn deserialises_the_real_rest_u_response_shape() {
    // Regression for the endpoint migration: the legacy
    // `/api/user/username={h}/json` endpoint was removed (now a 404 HTML page)
    // and keyed the real name as top-level `display_name`, the bio as `about`,
    // and the location as `location`. This body is trimmed verbatim from a real
    // `GET https://sourceforge.net/rest/u/jonelo` response, whose Allura shape
    // relocates the real name into `developers[]` and adds `creation_date` /
    // `external_homepage` / `socialnetworks[]`. Against the pre-fix `SfUser`
    // (which had `display_name`/`about`/`location` and no `developers`) this
    // body loses the real name entirely; against the fix it recovers it.
    let body = r#"{
        "shortname": "u/jonelo",
        "name": "jonelo",
        "_id": "4d7b8ba41be1ce29d7000364",
        "url": "https://sourceforge.net/u/jonelo/",
        "private": false,
        "creation_date": "2011-03-12",
        "external_homepage": "",
        "socialnetworks": [
            {"accounturl": "", "socialnetwork": "Twitter"},
            {"accounturl": "", "socialnetwork": "Facebook"}
        ],
        "status": "active",
        "developers": [
            {"username": "jonelo", "name": "Johann N. Löfflmann", "url": "https://sourceforge.net/u/jonelo/"}
        ]
    }"#;
    let user: SfUser = serde_json::from_str(body).expect("real rest/u body must deserialise");
    assert_eq!(user.name, "jonelo");
    assert_eq!(user.creation_date.as_deref(), Some("2011-03-12"));

    let ents = build_entities(user, "scan-sf-real");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "jonelo"),
        "the confirmed handle must be recovered from the real rest/u shape"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "Johann N. Löfflmann"),
        "the real name must be recovered from developers[].name"
    );
    // jonelo's homepage + social URLs are blank placeholders → no spurious URLs.
    assert!(
        !ents.iter().any(|e| e.has_tag("social-link")),
        "blank social placeholders must not become entities"
    );
}

#[test]
fn attack_techniques_matches_the_entities_this_module_now_produces() {
    // The Allura shape dropped the bio/location fields (and their
    // Email/Address/Coordinates entities, T1589.002/T1591.001). What remains:
    // the username (T1593.003), a Person from developers[].name (T1589.003),
    // and homepage/social URLs (T1593.001).
    let techniques = SourceforgeUser.attack_techniques();
    assert!(
        techniques.contains(&"T1593.003"),
        "Code Repositories: the module's own username discovery mechanism"
    );
    assert!(
        techniques.contains(&"T1589.003"),
        "Employee Names: developers[].name becomes a Person entity"
    );
    assert!(
        techniques.contains(&"T1593.001"),
        "Social Media: homepage + linked social-account URLs"
    );
    assert!(
        !techniques.contains(&"T1589.002") && !techniques.contains(&"T1591.001"),
        "email/location techniques dropped with the fields the Allura shape no longer returns"
    );
    for &id in techniques {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "{id} must be a catalogued Reconnaissance technique"
        );
    }
}
