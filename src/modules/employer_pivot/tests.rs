use super::*;

// ── domain_for_target ────────────────────────────────────────────────────────

#[test]
fn domain_from_email_is_lowercased() {
    let t = Target::new(TargetKind::Email, "Alice@AcmeCorp.com");
    assert_eq!(domain_for_target(&t).as_deref(), Some("acmecorp.com"));
}

#[test]
fn domain_from_domain_target_is_lowercased() {
    let t = Target::new(TargetKind::Domain, "  AcmeCorp.COM  ");
    assert_eq!(domain_for_target(&t).as_deref(), Some("acmecorp.com"));
}

#[test]
fn username_target_returns_none() {
    let t = Target::new(TargetKind::Username, "alice");
    assert!(domain_for_target(&t).is_none());
}

#[test]
fn email_without_at_returns_none() {
    // rsplit_once('@') returns None for strings without '@'
    let t = Target::new(TargetKind::Email, "notanemail");
    assert!(domain_for_target(&t).is_none());
}

// ── extract_emails ───────────────────────────────────────────────────────────

#[test]
fn extracts_same_domain_emails_only() {
    let text = "Contact info@acme.com or sales@acme.com but ignore noise@example.com";
    let v = extract_emails(text, "acme.com");
    assert!(v.contains(&"info@acme.com".to_string()));
    assert!(v.contains(&"sales@acme.com".to_string()));
    assert!(!v.iter().any(|e| e.ends_with("@example.com")));
}

#[test]
fn extract_emails_lowercases_results() {
    let text = "Contact HR@Acme.com for more info.";
    let v = extract_emails(text, "acme.com");
    assert!(v.contains(&"hr@acme.com".to_string()));
}

#[test]
fn extract_emails_empty_text_returns_empty() {
    assert!(extract_emails("", "acme.com").is_empty());
}

#[test]
fn extract_emails_no_match_returns_empty() {
    let text = "Visit our website at www.acme.com for more info.";
    assert!(extract_emails(text, "acme.com").is_empty());
}

#[test]
fn extract_emails_subdomain_not_matched() {
    // "bob@mail.acme.com" does NOT match domain "acme.com"
    let text = "bounce at bob@mail.acme.com";
    let v = extract_emails(text, "acme.com");
    assert!(v.is_empty());
}

// ── extract_profile_urls ─────────────────────────────────────────────────────

#[test]
fn extracts_linkedin_and_facebook() {
    let text = "Follow us on https://www.linkedin.com/company/acme and \
                https://www.facebook.com/acmecorp for updates.";
    let urls = extract_profile_urls(text);
    assert!(
        urls.iter().any(|u| u.contains("linkedin.com")),
        "expected linkedin url in {urls:?}"
    );
    assert!(
        urls.iter().any(|u| u.contains("facebook.com")),
        "expected facebook url in {urls:?}"
    );
}

#[test]
fn extracts_instagram_twitter_youtube() {
    let text = "Find us at https://www.instagram.com/acme_inc, \
                https://x.com/acmeinc, and \
                https://www.youtube.com/acmechannel";
    let urls = extract_profile_urls(text);
    assert!(urls.iter().any(|u| u.contains("instagram.com")));
    assert!(urls.iter().any(|u| u.contains("x.com")));
    assert!(urls.iter().any(|u| u.contains("youtube.com")));
}

#[test]
fn trailing_punctuation_stripped() {
    let text = "See https://www.linkedin.com/company/acme. for info.";
    let urls = extract_profile_urls(text);
    assert!(
        urls.iter().any(|u| !u.ends_with('.')),
        "trailing dot not stripped: {urls:?}"
    );
}

#[test]
fn non_social_url_not_extracted() {
    let text = "Visit https://docs.acme.com/api for API docs.";
    let urls = extract_profile_urls(text);
    assert!(urls.is_empty(), "non-social URL must not be extracted: {urls:?}");
}

#[test]
fn extract_profile_urls_empty_text_returns_empty() {
    assert!(extract_profile_urls("").is_empty());
}

// ── canonical_address ────────────────────────────────────────────────────────

fn addr(
    level: Option<&str>,
    unit: Option<&str>,
    street_number: &str,
    street: &str,
    suburb: &str,
    state: &str,
    postcode: &str,
) -> address_au::AuAddress {
    address_au::AuAddress {
        full: format!("{street_number} {street}, {suburb} {state} {postcode}"),
        level: level.map(str::to_string),
        unit: unit.map(str::to_string),
        street_number: street_number.to_string(),
        street: street.to_string(),
        suburb: suburb.to_string(),
        state: state.to_string(),
        postcode: postcode.to_string(),
    }
}

#[test]
fn canonical_simple_no_level_no_unit() {
    let a = addr(None, None, "42", "Collins Street", "Melbourne", "VIC", "3000");
    assert_eq!(canonical_address(&a), "42 Collins Street, Melbourne VIC 3000");
}

#[test]
fn canonical_with_level_prefix() {
    let a = addr(Some("Level 5"), None, "10", "George Street", "Sydney", "NSW", "2000");
    assert_eq!(
        canonical_address(&a),
        "Level 5, 10 George Street, Sydney NSW 2000"
    );
}

#[test]
fn canonical_with_unit_slash() {
    let a = addr(None, Some("3"), "100", "Queen Street", "Brisbane", "QLD", "4000");
    assert_eq!(canonical_address(&a), "3/100 Queen Street, Brisbane QLD 4000");
}

#[test]
fn canonical_with_level_and_unit() {
    let a = addr(
        Some("Level 2"),
        Some("5"),
        "200",
        "Pitt Street",
        "Sydney",
        "NSW",
        "2000",
    );
    assert_eq!(
        canonical_address(&a),
        "Level 2, 5/200 Pitt Street, Sydney NSW 2000"
    );
}

// ── accepts ──────────────────────────────────────────────────────────────────

#[test]
fn accepts_email_and_domain_only() {
    let m = EmployerPivot;
    assert!(m.accepts(&Target::new(TargetKind::Email, "alice@acme.com")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "acme.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Alice Smith")));
}

// ── role-mailbox local-part gate (crate::util::domains::is_role_localpart —
//    employer_pivot's own is_role_email_local was unified onto this shared
//    detector so the catch-set can't drift between call sites) ─────────────

#[test]
fn role_email_local_parts_are_blocked() {
    let blocked = [
        "abuse",
        "admin",
        "administrator",
        "billing",
        "dns",
        "hostmaster",
        "info",
        "legal",
        "marketing",
        "noc",
        "noreply",
        "no-reply",
        "postmaster",
        "privacy",
        "sales",
        "security",
        "support",
        "sysadmin",
        "webmaster",
    ];
    for local in blocked {
        assert!(
            crate::util::domains::is_role_localpart(local),
            "'{local}' must be classified as a role email local-part"
        );
    }
}

#[test]
fn real_user_local_parts_not_blocked() {
    for local in ["alice", "bob.smith", "haigen", "jdoe", "h.bamford"] {
        assert!(
            !crate::util::domains::is_role_localpart(local),
            "'{local}' must NOT be classified as a role email local-part"
        );
    }
}

#[test]
fn role_email_check_is_now_case_insensitive_after_unification() {
    // The shared detector case-folds internally (unlike the old
    // employer_pivot-only check, which was deliberately case-sensitive) — a
    // real behaviour improvement: `Admin@company.com` routes to the same
    // mailbox as `admin@company.com` on every real mail system, so treating
    // the capitalised form as a genuine employee address was itself the bug.
    assert!(crate::util::domains::is_role_localpart("Admin"));
    assert!(crate::util::domains::is_role_localpart("DNS"));
    assert!(crate::util::domains::is_role_localpart("Hostmaster"));
}

#[test]
fn tech_is_no_longer_blocked_after_unification() {
    // "tech" was in employer_pivot's own role list but was deliberately NOT
    // carried into the shared crate-wide list — too short/generic a token to
    // safely reject everywhere a role-mailbox check now runs — so this one
    // local-part narrowly stops being excluded here. Documented, not
    // accidental (see util::domains::is_role_localpart's own comment).
    assert!(!crate::util::domains::is_role_localpart("tech"));
}

// ── fetch_failed ─────────────────────────────────────────────────────────────

#[test]
fn fetch_failed_true_when_the_homepage_never_answered_and_nothing_collected() {
    // T2.113: a total transport/HTTP failure on the homepage request — the
    // module's own dead-domain fast path never even attempts a sub-page.
    assert!(fetch_failed(false, false));
}

#[test]
fn fetch_failed_false_when_the_homepage_answered_even_with_no_content_collected() {
    // The homepage read fine (200) but every page was too short/had no
    // business info — a genuine, honest empty result, not an outage.
    assert!(!fetch_failed(true, false));
}

#[test]
fn fetch_failed_false_when_content_was_collected_regardless_of_the_homepage_flag() {
    // Defensive: even if a future change decoupled the two conditions, any
    // real collected content means the fetch attempt was not a total failure.
    assert!(!fetch_failed(false, true));
    assert!(!fetch_failed(true, true));
}

// ── module metadata ──────────────────────────────────────────────────────────

#[test]
fn module_metadata() {
    let m = EmployerPivot;
    assert_eq!(m.name(), "employer_pivot");
    assert!(!m.description().is_empty());
    assert_eq!(m.priority(), 92);
    assert_eq!(m.max_timeout_ms(), 12_000);
    assert!(!m.is_passive());
}
