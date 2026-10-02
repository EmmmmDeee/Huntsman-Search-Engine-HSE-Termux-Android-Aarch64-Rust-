use super::*;

/// REQ-CRED-001. Email only: a `Phone` is the `numverify` module's, which asks
/// the HTTPS gateway with the key in a header, once per target.
#[test]
fn accepts_email_only() {
    let m = ContactEnrich;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61412345678")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    assert!(
        !m.produces().contains(&EntityKind::Phone),
        "the validated Phone is minted by `numverify` now"
    );
}

/// A context whose client sends every request through a recording loopback
/// proxy with no answers queued, so any request is both seen and refused. It
/// carries a Numverify key, as an operator who configured one would.
async fn proxied_ctx_with_a_numverify_key()
-> (ModuleContext, crate::util::http::test_server::Requests) {
    use crate::util::http::test_server::serve_recording;
    let (proxy, requests) = serve_recording(Vec::new()).await;
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "s".into(),
        bus,
        http: reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy).expect("proxy url"))
            .build()
            .expect("client"),
        keys: std::collections::HashMap::from([(
            "HUNTSMAN_NUMVERIFY_KEY".to_string(),
            "nv-real-looking-key".to_string(),
        )]),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    (ctx, requests)
}

/// REQ-CRED-001. Even handed a `Phone` directly, with a Numverify key
/// configured, this module sends nothing anywhere. Its old leg put the key in
/// the query string, resent it over plaintext `http://` on any failure, and
/// could mark the shared pool key Invalid on the legacy host's `success:false`.
/// The email control below proves the proxy does see this module's requests.
#[tokio::test]
async fn a_phone_target_sends_no_request_even_with_a_numverify_key() {
    let (ctx, requests) = proxied_ctx_with_a_numverify_key().await;
    let result = ContactEnrich
        .process(&Target::new(TargetKind::Phone, "+61412345678"), &ctx)
        .await
        .expect("a Phone is not this module's to fail on");
    assert!(result.entities.is_empty(), "{:?}", result.entities);
    let heads = requests.lock().expect("request log").clone();
    assert!(
        heads.is_empty(),
        "no request may leave for a Phone: {heads:?}"
    );
}

/// REQ-CRED-001, the control and the over-correction guard. The same context
/// DOES see an `Email` lookup: exactly one request, to Gravatar, and no
/// Numverify key in it. Without this, the test above would also pass for a
/// proxy that records nothing, or for a module that stopped asking anyone.
#[tokio::test]
async fn an_email_target_still_asks_gravatar_and_carries_no_key() {
    let (ctx, requests) = proxied_ctx_with_a_numverify_key().await;
    ContactEnrich
        .process(&Target::new(TargetKind::Email, "x@example.com"), &ctx)
        .await
        .expect_err("the proxy refuses every request");
    let heads = requests.lock().expect("request log").clone();
    assert_eq!(heads.len(), 1, "one Gravatar lookup: {heads:?}");
    assert!(heads[0].contains("www.gravatar.com"), "{}", heads[0]);
    assert!(!heads[0].contains("nv-real-looking-key"), "{}", heads[0]);
}

#[test]
fn cost_is_free() {
    assert!(matches!(ContactEnrich.cost(), ModuleCost::Free));
}

#[test]
fn priority_and_timeout() {
    let m = ContactEnrich;
    assert_eq!(m.priority(), 85);
    assert_eq!(m.max_timeout_ms(), 6_000);
}

#[test]
fn parse_gravatar_response() {
    let raw = r#"{
      "entry": [{
        "displayName": "John Doe",
        "preferredUsername": "johndoe",
        "name": {"formatted": "John Doe"},
        "urls": [{"value": "https://example.com", "title": "Blog"}],
        "currentLocation": "NYC",
        "aboutMe": "dev",
        "photos": [{"value": "https://gravatar.com/avatar/abc"}]
      }]
    }"#;
    let r: ProfileResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(r.entry.len(), 1);
    let e = &r.entry[0];
    assert_eq!(e.display_name.as_deref(), Some("John Doe"));
    assert_eq!(e.current_location.as_deref(), Some("NYC"));
}

// ── build_email_entities (pure extraction) ─────────────────────────

fn gravatar(json: &str) -> ProfileEntry {
    let r: ProfileResp = serde_json::from_str(json).expect("fixture is valid ProfileResp JSON");
    r.entry
        .into_iter()
        .next()
        .expect("fixture carries an entry")
}
fn email_target(v: &str) -> Target {
    Target::new(TargetKind::Email, v)
}
fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
    ents.iter().find(|e| e.kind == kind)
}

#[test]
fn full_gravatar_yields_email_person_username_address_and_urls() {
    let entry = gravatar(
        r#"{ "entry": [{
            "displayName": "John Doe", "preferredUsername": "johndoe",
            "name": {"formatted": "John Doe"},
            "urls": [
                {"value": "https://example.com", "title": "Blog"},
                {"value": "ftp://nope", "title": "Bad"}
            ],
            "currentLocation": "Sydney NSW", "aboutMe": "dev",
            "photos": [{"value": "https://gravatar.com/avatar/abc"}]
        }] }"#,
    );
    let ents = build_email_entities(
        &entry,
        &email_target("x@example.com"),
        "x@example.com",
        "abc123",
        "s",
    );

    let email = of_kind(&ents, EntityKind::Email).expect("subject email");
    assert!(email.has_tag("gravatar"));
    let attr = |k: &str| email.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("md5"), Some("abc123"));
    assert_eq!(attr("profile_url"), Some("https://www.gravatar.com/abc123"));
    assert_eq!(attr("display_name"), Some("John Doe"));
    assert_eq!(attr("preferred_username"), Some("johndoe"));
    assert_eq!(attr("name"), Some("John Doe"));
    assert_eq!(attr("bio"), Some("dev"));
    assert_eq!(attr("avatar_url"), Some("https://gravatar.com/avatar/abc"));
    // The urls evidence string folds every entry with a value (title-prefixed).
    assert_eq!(
        attr("urls"),
        Some("Blog: https://example.com | Bad: ftp://nope")
    );

    let person = of_kind(&ents, EntityKind::Person).expect("person");
    assert_eq!(person.value, "John Doe");
    let user = of_kind(&ents, EntityKind::Username).expect("username");
    assert_eq!(user.value, "johndoe");

    let addr = of_kind(&ents, EntityKind::Address).expect("address");
    assert_eq!(addr.value, "Sydney NSW");
    assert!(addr.has_tag("geoint"));
    // The AU state token is recognised and tags the address as AU.
    assert!(addr.has_tag("au-state:NSW") && addr.has_tag("country:AU"));

    // Only the http(s) URL becomes a Url entity; the ftp link is dropped.
    let urls: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(urls, vec!["https://example.com"]);
}

#[test]
fn minimal_gravatar_yields_only_the_email() {
    // An entry with nothing usable still produces the subject email entity.
    let entry = gravatar(r#"{ "entry": [{}] }"#);
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Email);
    // Only md5 + profile_url evidence — no optional profile attributes.
    let keys: Vec<&str> = ents[0].evidence[0]
        .attributes
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, vec!["md5", "profile_url"]);
}

#[test]
fn single_word_or_short_name_yields_no_person() {
    // A formatted name without a space is not split into a Person.
    let entry = gravatar(r#"{ "entry": [{ "name": {"formatted": "Cher"} }] }"#);
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    assert!(of_kind(&ents, EntityKind::Person).is_none());
    // ...but it is still recorded as the `name` attribute on the email evidence.
    assert_eq!(
        ents[0].evidence[0]
            .attributes
            .get("name")
            .map(String::as_str),
        Some("Cher")
    );
}

#[test]
fn short_username_and_location_are_skipped() {
    // preferredUsername < 3 chars and location < 3 chars are both dropped.
    let entry =
        gravatar(r#"{ "entry": [{ "preferredUsername": "ab", "currentLocation": "NY" }] }"#);
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    assert!(of_kind(&ents, EntityKind::Username).is_none());
    assert!(of_kind(&ents, EntityKind::Address).is_none());
}

#[test]
fn non_au_location_yields_address_without_state_tags() {
    let entry = gravatar(r#"{ "entry": [{ "currentLocation": "Berlin, Germany" }] }"#);
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    let addr = of_kind(&ents, EntityKind::Address).expect("address");
    assert_eq!(addr.value, "Berlin, Germany");
    assert!(!addr.tags.iter().any(|t| t.starts_with("au-state:")));
    assert!(!addr.has_tag("country:AU"));
}

#[test]
fn gravatar_hash_normalises_email_per_spec() {
    // The official gravatar.com example: a trailing space + mixed case MUST be
    // trimmed and lowercased before MD5, yielding the documented hash. Hashing
    // the raw value (the bug) gives a different, never-resolving hash.
    assert_eq!(
        gravatar_hash("MyEmailAddress@example.com "),
        "0bc83cb571cd1c50ba6f3e8a78ef1346"
    );
    // Case + whitespace variants of the same address converge to one hash.
    assert_eq!(
        gravatar_hash("  myemailaddress@EXAMPLE.com"),
        "0bc83cb571cd1c50ba6f3e8a78ef1346"
    );
}

// ── Corpus attribution (SOURCE COUNT ≠ SOURCE INDEPENDENCE) ──────────────

#[test]
fn gravatar_derived_entities_are_attributed_to_the_gravatar_corpus() {
    // The standalone `gravatar` module fetches the same profile document. If
    // this module stamps its own name on what it mints, the two modules'
    // outputs merge into one entity carrying two "independent" sources for one
    // Gravatar row, and `c_effective` pays for corroboration that never
    // happened.
    let entry = gravatar(
        r#"{ "entry": [{ "preferredUsername": "cher", "name": {"formatted": "Cher"},
             "currentLocation": "Sydney, NSW", "urls": [{"value": "https://example.com/"}] }] }"#,
    );
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    assert!(
        ents.len() >= 3,
        "fixture must mint several entities: {}",
        ents.len()
    );
    for e in &ents {
        for ev in &e.evidence {
            assert_eq!(
                ev.source,
                crate::modules::gravatar::SRC,
                "{:?} {} carries evidence attributed to `{}` — a Gravatar row must name Gravatar",
                e.kind,
                e.value,
                ev.source
            );
        }
    }
}
