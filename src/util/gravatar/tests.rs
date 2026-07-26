use super::*;

#[test]
fn hash_is_md5_of_trimmed_lowercased_email() {
    // The canonical gravatar.com documented example.
    assert_eq!(
        hash("  MyEmailAddress@example.com "),
        "0bc83cb571cd1c50ba6f3e8a78ef1346"
    );
    // Case- and whitespace-insensitive: both normalise to the same identifier.
    assert_eq!(
        hash("MyEmailAddress@example.com "),
        hash("  myemailaddress@EXAMPLE.com")
    );
}

#[test]
fn profile_parses_the_full_live_shape_including_accounts_and_photos() {
    // A real-shaped body: the union schema must accept `accounts` (the field
    // `contact_enrich`'s drifted copy lacked, T2.124) with a genuine JSON
    // boolean `verified` (T2.101), plus `photos` and `currentLocation`.
    let body = r#"{"entry":[{
        "hash":"h","profileUrl":"https://gravatar.com/matt","preferredUsername":"matt",
        "thumbnailUrl":"https://gravatar.com/avatar/h","displayName":"Matt D",
        "name":{"formatted":"Jordan Avery","givenName":"Jordan","familyName":"Avery"},
        "aboutMe":"bio","currentLocation":"Brisbane, QLD",
        "accounts":[{"shortname":"github","username":"javery","url":"https://github.com/javery","verified":true}],
        "urls":[{"value":"https://javery.dev","title":"Blog"}],
        "photos":[{"value":"https://gravatar.com/avatar/h"}]
    }]}"#;
    let profile: Profile = serde_json::from_str(body).expect("live shape must parse");
    let entry = profile.entry.into_iter().next().expect("one entry");
    assert_eq!(entry.preferred_username.as_deref(), Some("matt"));
    assert_eq!(entry.current_location.as_deref(), Some("Brisbane, QLD"));
    assert_eq!(entry.accounts.len(), 1);
    assert_eq!(entry.accounts[0].verified, Some(true));
    assert_eq!(entry.accounts[0].username.as_deref(), Some("javery"));
    assert_eq!(
        entry.photos.first().and_then(|p| p.value.as_deref()),
        Some("https://gravatar.com/avatar/h")
    );
    assert_eq!(entry.urls[0].title.as_deref(), Some("Blog"));
}

#[test]
fn account_verified_accepts_both_bool_and_legacy_string() {
    let b: Account = serde_json::from_value(serde_json::json!({"verified": true})).expect("should succeed");
    assert_eq!(b.verified, Some(true));
    let s: Account = serde_json::from_value(serde_json::json!({"verified": "false"})).expect("should succeed");
    assert_eq!(s.verified, Some(false));
    let none: Account = serde_json::from_value(serde_json::json!({})).expect("should succeed");
    assert_eq!(none.verified, None);
}
