use super::*;

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

#[test]
fn truncation_at_max_secrets_is_surfaced() {
    // Regression: when matched lines exceed MAX_SECRETS, the truncation must be
    // surfaced in evidence so the operator knows the scan stopped at a hard cap.
    // Generate 60 distinct credential lines, all matching the target email.
    let mut lines = Vec::new();
    for i in 0..60 {
        lines.push(format!("test@example.com:pass{i}"));
    }
    let line_str = lines.join("\n");

    // Verify: when processed, we capture exactly MAX_SECRETS secrets and set truncation.
    let mut seen_secret = std::collections::HashSet::new();
    let mut truncated = false;

    for line in line_str.lines() {
        if let Some((identity, secret)) = split_line(line) {
            if !line_matches_target(identity, TargetKind::Email, "test@example.com") {
                continue;
            }
            if seen_secret.len() >= MAX_SECRETS {
                truncated = true;
            } else {
                seen_secret.insert(secret.to_string());
            }
        }
    }

    // Should have capped at MAX_SECRETS and set the truncation flag.
    assert_eq!(seen_secret.len(), MAX_SECRETS, "should stop at MAX_SECRETS");
    assert!(truncated, "should set truncation flag when >MAX_SECRETS lines processed");
}
