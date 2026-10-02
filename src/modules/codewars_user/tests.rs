use super::*;

fn make_user(username: &str, name: Option<&str>, clan: Option<&str>, city: Option<&str>) -> CwUser {
    CwUser {
        username: username.to_string(),
        name: name.map(str::to_string),
        clan: clan.map(str::to_string),
        city: city.map(str::to_string),
    }
}

#[test]
fn emits_username_and_profile_url() {
    let user = make_user("kata_warrior", None, None, None);
    let ents = build_entities(user, "scan-cw-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "kata_warrior")
    );
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Url
            && e.value == "https://www.codewars.com/users/kata_warrior")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("should succeed");
    assert!(u.has_tag("codewars") && u.has_tag("public-profile"));
    // OD-19 cohort canon: single-source confirmed-account lookup = 0.85.
    assert!((u.confidence - confidence::HIGH_PLUSPLUS_PLUS).abs() < 0.01);
}

#[test]
fn emits_person_from_multi_word_name() {
    let user = make_user("k_dev", Some("Kim Developer"), None, None);
    let ents = build_entities(user, "scan-cw-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word name");
    assert_eq!(p.expect("should succeed").value, "Kim Developer");
    assert!(p.expect("should succeed").has_tag("codewars"));
    assert!((p.expect("should succeed").confidence - 0.68).abs() < 0.01);
}

#[test]
fn single_word_name_does_not_emit_person() {
    let user = make_user("k_dev", Some("Kim"), None, None);
    let ents = build_entities(user, "scan-cw-003");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_organisation_from_clan() {
    let user = make_user("coder99", None, Some("Hack The Planet"), None);
    let ents = build_entities(user, "scan-cw-004");
    let o = ents.iter().find(|e| e.kind == EntityKind::Organisation);
    assert!(o.is_some(), "must emit Organisation from clan field");
    assert_eq!(o.expect("should succeed").value, "Hack The Planet");
    assert!(
        o.expect("should succeed").has_tag("self-asserted")
            && o.expect("should succeed").has_tag("codewars")
    );
    assert!((o.expect("should succeed").confidence - 0.48).abs() < 0.01);
}

#[test]
fn emits_address_from_city() {
    let user = make_user("coder99", None, None, Some("Tokyo"));
    let ents = build_entities(user, "scan-cw-005");
    let a = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(a.is_some(), "must emit Address from city field");
    assert_eq!(a.expect("should succeed").value, "Tokyo");
    assert!(a.expect("should succeed").has_tag("self-asserted"));
}

#[test]
fn empty_clan_and_city_emit_no_org_or_address() {
    let user = make_user("coder99", None, Some(""), Some(""));
    let ents = build_entities(user, "scan-cw-006");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Organisation));
    assert!(ents.iter().all(|e| e.kind != EntityKind::Address));
}

#[test]
fn empty_username_returns_no_entities() {
    let user = make_user("", None, None, None);
    assert!(build_entities(user, "scan-cw-007").is_empty());
}

#[test]
fn attack_techniques_covers_every_entity_kind_this_module_produces() {
    // Mirrors the github_user/dockerhub_user regression: the override must
    // not replace the whole category default with a single technique when
    // the module's own `build_entities` constructs Person/Organisation/
    // Address/Coordinates in addition to the Username the Code Repositories
    // technique covers — every admitted entity's `attack:<ID>` provenance
    // tag is sourced directly from this list (core::engine::dispatch).
    let techniques = CodewarsUser.attack_techniques();
    assert!(
        techniques.contains(&"T1593.003"),
        "Code Repositories: the module's own username discovery mechanism"
    );
    assert!(
        techniques.contains(&"T1589.003"),
        "Employee Names: the real `name` field becomes a Person entity"
    );
    assert!(
        techniques.contains(&"T1591.001"),
        "Determine Physical Locations: `city` becomes Address/Coordinates"
    );
    assert!(
        techniques.contains(&"T1591.002"),
        "Business Relationships: `clan` becomes an Organisation entity"
    );
    for &id in techniques {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "{id} must be a catalogued Reconnaissance technique"
        );
    }
}

// ── What an answer is (REQ-CODEWARS-001) ───────────────────────────────

/// Codewars' documented User Object: the "Get User" example in the vendor's
/// API reference, with its per-language ranks trimmed.
const DOCUMENTED_USER: &str = r#"{
    "username": "some_user",
    "name": "Some Person",
    "honor": 544,
    "clan": "some clan",
    "leaderboardPosition": 134,
    "skills": ["ruby", "c#", ".net", "javascript", "coffeescript", "nodejs", "rails"],
    "ranks": {
        "overall": {"rank": -3, "name": "3 kyu", "color": "blue", "score": 2116},
        "languages": {}
    },
    "codeChallenges": {"totalAuthored": 3, "totalCompleted": 230}
}"#;

#[test]
fn a_body_without_a_username_is_not_a_codewars_user() {
    // Under `#[serde(default)]` both decoded as a user named "", which the
    // handle match then read as "no such user". The envelope is Codewars' own
    // error body, verbatim from a live 404.
    for body in ["{}", r#"{"success":false,"reason":"not found"}"#] {
        let Err(err) = serde_json::from_str::<CwUser>(body) else {
            panic!("{body} decoded as a Codewars user");
        };
        assert!(
            err.to_string().contains("missing field `username`"),
            "{body}: {err}"
        );
    }
    // Over-correction guard: the documented User Object still decodes, with
    // every field this struct does not read. Refusing the envelope by its
    // unknown keys (`deny_unknown_fields`) would refuse every real answer.
    let user: CwUser =
        serde_json::from_str(DOCUMENTED_USER).expect("the documented User Object decodes");
    assert_eq!(user.username, "some_user");
    assert!(user.city.is_none());
}

#[tokio::test]
async fn a_2xx_that_names_no_account_is_a_failure_not_no_such_user() {
    // The module's real request path against a loopback. Each of these came
    // back `Ok(empty)`, which coverage reads as "no Codewars account", for a
    // handle Codewars never answered about.
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::json(200, "{}"),
        Canned::json(200, r#"{"success":false,"reason":"Too many requests"}"#),
        Canned::json(200, r#"{"username":"","name":null,"clan":""}"#),
        Canned::json(200, r#"{"username":"  "}"#),
    ])
    .await;
    let client = reqwest::Client::new();
    for (shape, why) in [
        ("an empty object", "missing field `username`"),
        ("an error envelope", "missing field `username`"),
        ("an empty username", "blank `username`"),
        ("a whitespace username", "blank `username`"),
    ] {
        let Err(err) = lookup(&client, &base, "kata_warrior", "s").await else {
            panic!("{shape} is no answer about the handle, never \"no such user\"");
        };
        assert!(err.to_string().contains(why), "{shape}: {err}");
    }
}

#[tokio::test]
async fn a_404_or_another_accounts_record_is_a_clean_miss_that_mints_nothing() {
    // Over-correction guard. The 404 is Codewars' one documented miss (body
    // verbatim from a live lookup). The path takes "Username or ID", so an
    // ID-shaped handle answers with ANOTHER account: live, this ID is `g964`.
    // Neither is this handle's account, and neither is a failure.
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::json(404, r#"{"success":false,"reason":"not found"}"#),
        Canned::json(
            200,
            r#"{"id":"545207bac8e60b30fc000942","username":"g964","honor":488914}"#,
        ),
    ])
    .await;
    let client = reqwest::Client::new();
    let miss = lookup(&client, &base, "kata_warrior", "s")
        .await
        .expect("a 404 is the clean miss");
    assert!(miss.is_empty());
    let other = lookup(&client, &base, "545207bac8e60b30fc000942", "s")
        .await
        .expect("another account's record is a miss, not a failure");
    assert!(
        other.is_empty(),
        "g964's profile is not this handle's: {other:?}"
    );
}

#[tokio::test]
async fn the_documented_user_object_is_found_under_its_own_handle() {
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![Canned::json(200, DOCUMENTED_USER)]).await;
    let client = reqwest::Client::new();
    let hit = lookup(&client, &base, "some_user", "s")
        .await
        .expect("the documented profile decodes");
    assert!(
        hit.entities
            .iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "some_user")
    );
    // Production asks the documented Get User path.
    assert_eq!(API_BASE, "https://www.codewars.com/api/v1/users");
}
