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

// ── should_skip_pivot ─────────────────────────────────────────────────────────

#[test]
fn should_skip_pivot_blocks_every_previously_covered_role_local_part() {
    // Parity with the old, independently-maintained is_role_email_local list
    // (now consolidated onto util::domains::is_infrastructure_email) — every
    // word it covered must still be blocked, including the two case variants
    // ("noc"/"sysadmin"/"tech" newly merged into the shared list).
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
        "tech",
        "webmaster",
    ];
    for local in blocked {
        let t = Target::new(TargetKind::Email, format!("{local}@acme.com.au"));
        assert!(
            should_skip_pivot(&t, "acme.com.au"),
            "'{local}@acme.com.au' must be skipped as a role/infrastructure email"
        );
    }
}

#[test]
fn should_skip_pivot_does_not_block_a_real_employee_email_or_business_domain() {
    let email = Target::new(TargetKind::Email, "alice.smith@acmecorp.com.au");
    assert!(!should_skip_pivot(&email, "acmecorp.com.au"));
    let domain = Target::new(TargetKind::Domain, "acmecorp.com.au");
    assert!(!should_skip_pivot(&domain, "acmecorp.com.au"));
}

#[test]
fn should_skip_pivot_is_case_insensitive_unlike_the_old_helper() {
    // The old is_role_email_local was deliberately case-sensitive; consolidating
    // onto is_infrastructure_email (which lowercases before matching) is a
    // strict improvement — a role mailbox does not stop being one because of
    // its capitalisation, so this catches strictly more than before, never less.
    let t = Target::new(TargetKind::Email, "Admin@acme.com.au");
    assert!(should_skip_pivot(&t, "acme.com.au"));
}

#[test]
fn should_skip_pivot_blocks_a_nameserver_domain_target() {
    // The gap this fix closes: rdap_domain/whois both surface a scanned
    // domain's own nameservers as first-class Domain entities
    // (e.g. ns1.cloudflare.com), which — before this fix — had no guard at
    // all and would scrape the NAMESERVER PROVIDER's contact page and
    // attribute it to the scan subject.
    let ns = Target::new(TargetKind::Domain, "ns1.cloudflare.com");
    assert!(should_skip_pivot(&ns, "ns1.cloudflare.com"));
    let registrar = Target::new(TargetKind::Domain, "godaddy.com");
    assert!(should_skip_pivot(&registrar, "godaddy.com"));
}

#[test]
fn should_skip_pivot_blocks_an_infra_provider_email_with_a_non_role_local_part() {
    // A non-role local-part on an infrastructure-provider domain (the domain
    // check, not the local-part check) must still be caught — the old
    // is_role_email_local only ever inspected the local-part and would have
    // let this through.
    let t = Target::new(TargetKind::Email, "jane.doe@cloudflare.com");
    assert!(should_skip_pivot(&t, "cloudflare.com"));
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
