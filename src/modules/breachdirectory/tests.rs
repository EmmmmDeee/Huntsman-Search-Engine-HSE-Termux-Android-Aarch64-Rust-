use super::*;

#[test]
fn accepts_email_and_username_only() {
    let m = BreachDirectory;
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(m.accepts(&Target::new(TargetKind::Username, "someuser")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.test")));
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(BreachDirectory.cost(), ModuleCost::KeyGated));
}

#[test]
fn category_is_breach() {
    assert!(matches!(BreachDirectory.category(), ModuleCategory::Breach));
}

fn body(json: &str) -> BreachDirResp {
    serde_json::from_str(json).expect("should succeed")
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

#[test]
fn populated_response_tallies_sources_and_password_exposure() {
    let b = body(
        r#"{
          "success": true,
          "found": 3,
          "result": [
            {"has_password": true, "sources": ["Collection1", "Adobe"], "password": "hunter2", "sha1": "abc123", "hash": "def456"},
            {"has_password": false, "sources": ["Adobe"]},
            {"has_password": true, "sources": ["LinkedIn"]}
          ]
        }"#,
    );
    let e = build_breach_entity(EntityKind::Email, "victim@example.com", &b, "s");
    assert_eq!(e.kind, EntityKind::Email);
    assert!(e.has_tag(tags::BREACH));
    assert!(e.has_tag("breachdirectory"));
    assert!(e.has_tag(tags::PASSWORD_AT_RISK));
    // At least one recovered password/hash → the higher confidence tier.
    assert_eq!(e.confidence, confidence::HIGH);

    assert_eq!(attr(&e, "record_count"), Some("3"));
    assert_eq!(attr(&e, "password_exposed_count"), Some("2"));
    assert_eq!(attr(&e, "reported_found"), Some("3"));
    // top_n ranks by frequency: Adobe(2) before Collection1(1)/LinkedIn(1)
    // (ties broken alphabetically).
    assert_eq!(attr(&e, "sources"), Some("Adobe\u{d7}2, Collection1\u{d7}1, LinkedIn\u{d7}1"));

    // Never persist the actual leaked secret anywhere in the entity/evidence.
    for ev in &e.evidence {
        for (k, v) in &ev.attributes {
            assert_ne!(k.as_str(), "password");
            assert!(!v.contains("hunter2"));
            assert!(!v.contains("abc123"));
            assert!(!v.contains("def456"));
        }
    }
}

#[test]
fn no_password_exposure_omits_the_tag_and_uses_the_lower_confidence_tier() {
    let b = body(
        r#"{"success": true, "found": 1, "result": [{"has_password": false, "sources": ["SomeCorpus"]}]}"#,
    );
    let e = build_breach_entity(EntityKind::Username, "someuser", &b, "s");
    assert_eq!(e.kind, EntityKind::Username);
    assert!(!e.has_tag(tags::PASSWORD_AT_RISK));
    assert_eq!(e.confidence, confidence::MEDIUM_PLUS);
    assert_eq!(attr(&e, "password_exposed_count"), Some("0"));
    assert_eq!(attr(&e, "sources"), Some("SomeCorpus\u{d7}1"));
}

#[test]
fn missing_optional_fields_default_cleanly() {
    // A row with no `sources`, no `has_password`, and none of the optional
    // password/sha1/hash fields present at all — every field must default
    // rather than fail to deserialize.
    let b = body(r#"{"success": true, "found": 1, "result": [{}]}"#);
    let e = build_breach_entity(EntityKind::Email, "a@b.com", &b, "s");
    assert!(!e.has_tag(tags::PASSWORD_AT_RISK));
    assert_eq!(attr(&e, "record_count"), Some("1"));
    assert_eq!(attr(&e, "password_exposed_count"), Some("0"));
    // No sources at all → the attribute is omitted rather than emitted blank.
    assert_eq!(attr(&e, "sources"), None);
}

#[test]
fn deserializes_a_response_with_no_result_field_at_all() {
    // The RapidAPI gateway's own quota/error bodies (`{"message": "..."}`) carry
    // none of this shape's fields, and must still DECODE rather than fail to
    // parse — that part was always right, and is what this test is named for.
    //
    // REQ-SUCCESSFLAG-001 corrected what the old comment concluded from it:
    // "so `process()` can treat it as a clean miss". A quota notice is not a
    // clean miss; it is the provider refusing to answer, and reporting it as
    // CleanNegative asserts the identifier is in no known breach. `success` is
    // now `Option<bool>`, so ABSENT is distinguishable from the API saying
    // `false` — the distinction a `#[serde(default)] bool` erased.
    let b = body(r#"{"message": "You have exceeded the MONTHLY quota"}"#);
    assert_eq!(b.success, None, "an absent key must read as absent, not as false");
    assert_eq!(b.found, 0);
    assert!(b.result.is_empty());
}

/// REQ-SUCCESSFLAG-001. `process` decided with ONE expression —
/// `!body.success || body.result.is_empty()` — returning `Ok(empty)` for it, so
/// dispatch recorded `ModuleDone { found: 0 }` and `core::coverage` aggregated
/// every one of three different realities to `CleanNegative`: "queried, holds
/// nothing on this subject".
///
/// Tested off JSON **text**, not constructed structs: a struct literal can only
/// express presence, and an ABSENT `success` key is precisely the case the old
/// `#[serde(default)] bool` could not distinguish from the API saying it failed
/// (the rule REQ-FOFA-001 left behind).
#[test]
fn a_failure_an_unreadable_body_and_a_clean_miss_are_three_outcomes_not_one() {
    let v = |j: &str| classify(&serde_json::from_str::<BreachDirResp>(j).expect("decodes"));

    // The provider answered, and the answer was failure.
    assert!(matches!(v(r#"{"success":false,"result":[]}"#), BodyVerdict::ProviderFailed));
    // Not this API's shape at all — a gateway notice, a quota page.
    assert!(matches!(v(r#"{"message":"not subscribed"}"#), BodyVerdict::Uninterpretable));
    assert!(matches!(v(r#"{}"#), BodyVerdict::Uninterpretable));

    // ── The control that matters more than the rejections. ──
    // A genuine miss MUST still be a clean negative. A "fix" that turned every
    // empty answer into an error would satisfy the assertions above and destroy
    // this module's ability to report an honest absence — strictly worse than
    // the defect it replaced.
    assert!(matches!(v(r#"{"success":true,"result":[]}"#), BodyVerdict::CleanMiss));
    // And a real answer with rows is still data.
    assert!(matches!(v(r#"{"success":true,"result":[{"sources":["Collection#1"],"has_password":true}]}"#), BodyVerdict::Rows));
    // Weakest-condition check: rows present but `success` omitted is DATA, not
    // a refusal. Requiring `success` outright would be the fail-shut trade
    // REQ-FOFA-001 rejected.
    assert!(matches!(v(r#"{"result":[{"sources":["Collection#1"],"has_password":true}]}"#), BodyVerdict::Rows));
}
