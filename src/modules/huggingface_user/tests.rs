use super::*;

fn make_user(
    user: &str,
    fullname: Option<&str>,
    created_at: Option<&str>,
    orgs: Vec<(&str, Option<&str>)>,
) -> HfUser {
    HfUser {
        user: user.to_string(),
        fullname: fullname.map(str::to_string),
        created_at: created_at.map(str::to_string),
        orgs: orgs
            .into_iter()
            .map(|(n, f)| HfOrg {
                name: n.to_string(),
                fullname: f.map(str::to_string),
            })
            .collect(),
    }
}

#[test]
fn emits_username_and_profile_url() {
    let user = make_user("alice", None, None, vec![]);
    let ents = build_entities(user, "scan-hf-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "alice")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://huggingface.co/alice")
    );
}

#[test]
fn emits_person_from_multi_word_fullname() {
    let user = make_user("alice", Some("Alice Smith"), None, vec![]);
    let ents = build_entities(user, "scan-hf-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from two-word fullname");
    assert_eq!(p.expect("should succeed").value, "Alice Smith");
    assert!(p.expect("should succeed").has_tag("huggingface"));
}

#[test]
fn single_word_fullname_does_not_emit_person() {
    let user = make_user("alice", Some("Alice"), None, vec![]);
    let ents = build_entities(user, "scan-hf-003");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn account_created_date_travels_as_evidence() {
    // `createdAt` from the overview response is a genuine first-seen date; it
    // must ride along on the confirmed-username evidence, not be dropped.
    let user = make_user("alice", None, Some("2019-11-23T17:38:57.000Z"), vec![]);
    let ents = build_entities(user, "scan-hf-004");
    let un = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("username entity present");
    assert_eq!(
        un.evidence[0]
            .attributes
            .get("account_created")
            .map(String::as_str),
        Some("2019-11-23T17:38:57.000Z")
    );
}

#[test]
fn emits_org_using_fullname_when_available() {
    let user = make_user(
        "alice",
        None,
        None,
        vec![("huggingface", Some("Hugging Face Inc."))],
    );
    let ents = build_entities(user, "scan-hf-005");
    let org = ents.iter().find(|e| e.kind == EntityKind::Organisation);
    assert!(org.is_some(), "must emit Organisation for org membership");
    assert_eq!(org.expect("should succeed").value, "Hugging Face Inc.");
    assert!(org.expect("should succeed").has_tag("org-member"));
}

#[test]
fn empty_handle_returns_no_entities() {
    let user = make_user("", None, None, vec![]);
    assert!(build_entities(user, "scan-hf-006").is_empty());
}

#[test]
fn deserialises_the_real_overview_response_shape() {
    // Regression for the 2026 endpoint migration: the pre-2026 `/api/users/{h}`
    // response keyed the handle as `username` and now 404s for every real
    // user; the live `/api/users/{h}/overview` keys it as `user` (plus
    // `fullname`, `createdAt`, `orgs[]`). This body is trimmed verbatim from a
    // real `GET https://huggingface.co/api/users/julien-c/overview` response —
    // against the pre-fix `HfUser` (which expected `username`) the handle
    // deserialises empty and `build_entities` yields NOTHING, so this test
    // fails; against the fix it recovers the full profile.
    let body = r#"{
        "_id": "5dd96eb166059660ed1ee413",
        "user": "julien-c",
        "fullname": "Julien Chaumond",
        "type": "user",
        "isPro": true,
        "createdAt": "2019-11-23T17:38:57.000Z",
        "numModels": 53,
        "orgs": [
            {"id": "5e67bd5b1009063689407478", "name": "huggingface", "fullname": "Hugging Face"}
        ]
    }"#;
    let user: HfUser = serde_json::from_str(body).expect("real overview body must deserialise");
    assert_eq!(user.user, "julien-c");
    assert_eq!(user.fullname.as_deref(), Some("Julien Chaumond"));
    assert_eq!(user.created_at.as_deref(), Some("2019-11-23T17:38:57.000Z"));

    let ents = build_entities(user, "scan-hf-real");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "julien-c"),
        "the confirmed handle must be recovered from the real overview shape"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "Julien Chaumond"),
        "the fullname must still yield a Person"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Organisation && e.value == "Hugging Face"),
        "org membership must still be surfaced"
    );
}
