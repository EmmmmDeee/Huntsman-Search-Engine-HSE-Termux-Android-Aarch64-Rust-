use super::*;

#[test]
fn password_evidence_carries_the_typed_email_key_for_reused_secret_join() {
    // The reused-secret detector / AU-047 join on a typed `email`/`username`
    // evidence attribute, NOT the raw `identity`. A COMB email target's password
    // must therefore carry an `email` key so it can participate.
    let target = Target::new(TargetKind::Email, "jordan@example.com");
    let lines = vec!["jordan@example.com:hunter2longpw".to_string()];
    let ents = build_entities_from_lines(&lines, &target, "s");
    let pw = ents
        .iter()
        .find(|e| e.kind == EntityKind::Password)
        .expect("password entity");
    assert_eq!(
        pw.evidence[0].attributes.get("email").map(String::as_str),
        Some("jordan@example.com"),
        "the password must carry the typed `email` reused-secret join key"
    );
}

#[test]
fn username_target_password_carries_the_typed_username_key() {
    let target = Target::new(TargetKind::Username, "jordanx");
    let lines = vec!["jordanx:s3cretpassword".to_string()];
    let ents = build_entities_from_lines(&lines, &target, "s");
    let pw = ents
        .iter()
        .find(|e| e.kind == EntityKind::Password)
        .expect("password entity");
    assert_eq!(
        pw.evidence[0].attributes.get("username").map(String::as_str),
        Some("jordanx")
    );
    assert!(
        !pw.evidence[0].attributes.contains_key("email"),
        "a bare-username account must not carry an `email` key"
    );
}

#[test]
fn a_dirty_and_a_clean_spelling_of_the_same_domain_account_dedup_to_one_entity() {
    // Regression: `identity.to_ascii_lowercase()` case-folds but does not
    // strip a leading quote character some breach-dump exports leave on the
    // identity field — a realistic COMB artifact, not a contrived one (see
    // `core::entity::normalise`'s own Email-kind doc comment: "a CSV
    // `\"\"`-escaped quote that leaked into the seed"). A leading quote
    // survives `rsplit_once('@')`'s host-match gate (the quote sits on the
    // LOCAL side, not the host), so both spellings reach the dedup check —
    // but only the canonical form collapses them to one entity the way
    // `Entity::new` does internally.
    let target = Target::new(TargetKind::Domain, "example.com");
    let lines = vec![
        "dirty@example.com:pass1".to_string(),
        "\"dirty@example.com:pass2".to_string(),
    ];
    let ents = build_entities_from_lines(&lines, &target, "s");
    let emails: Vec<&Entity> = ents.iter().filter(|e| e.kind == EntityKind::Email).collect();
    assert_eq!(
        emails.len(),
        1,
        "a dirty and a clean spelling of the same domain account must dedup to one entity: {emails:?}"
    );
}

#[test]
fn split_line_splits_on_first_colon_only() {
    assert_eq!(split_line("user@x.com:pass:word"), Some(("user@x.com", "pass:word")));
    assert_eq!(split_line("alice:hunter2"), Some(("alice", "hunter2")));
    // No separator / empty identity → None.
    assert_eq!(split_line("noseparator"), None);
    assert_eq!(split_line(":orphan"), None);
}

#[test]
fn email_match_is_exact_not_substring() {
    // COMB returns substring hits; only the EXACT identity may be attributed.
    assert!(line_matches_target(
        "qwerty-zzz@nope.invalid",
        TargetKind::Email,
        "qwerty-zzz@nope.invalid"
    ));
    // A substring co-hit on a DIFFERENT host must be rejected — this is the
    // anti-fabrication core (the live `qwerty-zzz@bk.ru` stranger case).
    assert!(!line_matches_target(
        "qwerty-zzz@bk.ru",
        TargetKind::Email,
        "qwerty-zzz@nope.invalid"
    ));
    // Case-insensitive.
    assert!(line_matches_target(
        "Alice@Example.com",
        TargetKind::Email,
        "alice@example.com"
    ));
}

#[test]
fn domain_match_keys_on_host_exactly() {
    assert!(line_matches_target(
        "bob@example.com",
        TargetKind::Domain,
        "example.com"
    ));
    // A look-alike host must not match.
    assert!(!line_matches_target(
        "bob@example.com.attacker.net",
        TargetKind::Domain,
        "example.com"
    ));
    // Subdomain is a different host (exact-suffix is deliberately NOT used —
    // it would over-attribute).
    assert!(!line_matches_target(
        "bob@mail.example.com",
        TargetKind::Domain,
        "example.com"
    ));
}

#[test]
fn username_match_is_exact_localpart() {
    assert!(line_matches_target("john@gmail.com", TargetKind::Username, "john"));
    // `johnsmith` shares the `john` root but is a different identity.
    assert!(!line_matches_target("johnsmith@gmail.com", TargetKind::Username, "john"));
    // Bare token (no @) compares whole.
    assert!(line_matches_target("john", TargetKind::Username, "john"));
}

#[test]
fn accepts_only_credential_shaped_targets() {
    let m = CombSearch;
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    // FullName / IP are not credential identities in COMB.
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
}

#[test]
fn accepts_value_rejects_too_short_or_all_digit_seeds() {
    assert!(accepts_value(TargetKind::Email, "a@b.com"));
    assert!(!accepts_value(TargetKind::Email, "a@b")); // < 6
    assert!(accepts_value(TargetKind::Username, "alice"));
    assert!(!accepts_value(TargetKind::Username, "abc")); // < 4
    assert!(!accepts_value(TargetKind::Username, "12345")); // all digits
    assert!(accepts_value(TargetKind::Domain, "example.com"));
    assert!(!accepts_value(TargetKind::Domain, "ab")); // no dot, too short
}

#[test]
fn is_free_breach_module() {
    let m = CombSearch;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Breach);
    // Breach-default ATT&CK mapping is carried.
    assert!(m.attack_techniques().contains(&"T1589.001"));
    assert!(m.attack_techniques().contains(&"T1589.002"));
}

/// Live end-to-end proof against the REAL public COMB endpoint — no mock, no
/// fixture. Ignored by default (network + non-deterministic upstream); run with
/// `cargo test -p huntsman-search-engine comb_search_live -- --ignored --nocapture`.
/// Asserts the module fetches and parses genuine leaked-credential data and
/// strictly attributes only exact-host accounts on a domain target.
#[tokio::test]
#[ignore = "hits the live public COMB endpoint; run manually"]
async fn comb_search_live_fetches_real_credentials_for_a_domain() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let target = Target::new(TargetKind::Domain, "example.com");
    let result = CombSearch
        .process(&target, &ctx)
        .await
        .expect("live COMB query must not error");

    // Every Email entity must be an EXACT example.com account — never a
    // substring stranger from another host.
    for e in &result.entities {
        if e.kind == EntityKind::Email {
            assert!(
                e.value.to_ascii_lowercase().ends_with("@example.com"),
                "attributed a non-example.com account: {}",
                e.value
            );
            assert!(e.has_tag("comb") && e.has_tag(tags::BREACH));
        }
    }
    // The live index reliably carries example.com accounts, so we expect a hit;
    // if the upstream is down this is the one acceptable empty case.
    eprintln!(
        "comb_search live: {} entities ({} email, {} password)",
        result.entities.len(),
        result.entities.iter().filter(|e| e.kind == EntityKind::Email).count(),
        result.entities.iter().filter(|e| e.kind == EntityKind::Password).count(),
    );
}

#[test]
fn secret_echo_of_identity_is_classified_as_junk_upstream() {
    // The live `user@example.com:user@example.com` echo case is dropped by the
    // process() guard; here we pin the classification primitives it relies on.
    assert_eq!(
        classify_credential_field("hunter2"),
        CredentialField::Secret
    );
    assert_eq!(classify_credential_field("[fail]"), CredentialField::Sentinel);
    assert_eq!(
        classify_credential_field("user@example.com"),
        CredentialField::Email
    );
}

#[tokio::test]
async fn a_non_2xx_from_the_comb_endpoint_is_a_failed_lookup_and_a_200_without_lines_is_the_miss() {
    // Backlog #12. ProxyNova signals "not in COMB" as a 200 with `count: 0,
    // lines: []`; a 404 is the endpoint gone (or a WAF page) and a 5xx an
    // outage. Before this the request went through `fetch_json_or_404`, so a
    // 404 became `Ok(empty)` — recorded as a clean-negative breach claim about
    // the named subject. Real request path against a loopback server.
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::text(404, "<html>Not Found</html>"),
        Canned::text(503, "upstream unavailable"),
        Canned::json(200, r#"{"count":0,"lines":[]}"#),
    ])
    .await;
    let client = reqwest::Client::new();
    let endpoint = format!("{base}/comb");

    let err = query_comb(&client, &endpoint, "jordan@example.com")
        .await
        .expect_err("a 404 on a fixed endpoint is a failed lookup, not 'not in COMB'");
    assert!(err.to_string().contains("404"), "{err}");

    let err = query_comb(&client, &endpoint, "jordan@example.com")
        .await
        .expect_err("an outage is a failed lookup");
    assert!(err.to_string().contains("503"), "{err}");

    let miss = query_comb(&client, &endpoint, "jordan@example.com")
        .await
        .expect("a 200 with no lines is the genuine miss");
    assert!(miss.lines.is_empty());
}
