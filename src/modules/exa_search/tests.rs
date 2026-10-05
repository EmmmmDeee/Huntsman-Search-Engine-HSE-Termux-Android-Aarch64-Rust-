use super::*;

#[test]
fn accepts_identity_and_org_kinds() {
    let m = ExaSearch;
    for k in [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::FullName,
        TargetKind::Domain,
        TargetKind::Organisation,
        TargetKind::Phone,
    ] {
        assert!(m.accepts(&Target::new(k, "x")));
    }
    // Not for IPs, coords, ASNs.
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

#[test]
fn cost_is_keygated() {
    assert!(matches!(ExaSearch.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_metadata() {
    let m = ExaSearch;
    assert_eq!(m.name(), "exa_search");
    assert_eq!(m.priority(), 87);
    assert_eq!(m.max_timeout_ms(), 20_000);
    assert!(!m.description().is_empty());
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn email_regex_matches_standard_addresses() {
    assert!(EMAIL_RE.is_match("contact alice@example.com please"));
    assert!(EMAIL_RE.is_match("bob.smith+tag@sub.example.co.uk"));
}

#[test]
fn phone_regex_matches_intl_format() {
    assert!(PHONE_RE.is_match("+44 20 7946 0958"));
    assert!(PHONE_RE.is_match("+1-555-123-4567"));
}

// ── mine_snippet ─────────────────────────────────────────────────────────────

fn snippets_for_target(
    text: &str,
    target_kind: TargetKind,
    target_value: &str,
) -> Vec<Entity> {
    let mut r = ModuleResult::new();
    mine_snippet(text, "scan-1", "https://example.com/page", &target_kind, target_value, &mut r);
    r.entities
}

fn snippets(text: &str) -> Vec<Entity> {
    // Default to Email target for tests; use a generic email seed so emails
    // from the same domain are extracted but others are gated.
    snippets_for_target(text, TargetKind::Email, "test@example.com")
}

#[test]
fn mine_snippet_extracts_email() {
    // Email target matching the extracted email's domain.
    let ents = snippets_for_target(
        "Contact us at sales@acme.com for pricing.",
        TargetKind::Email,
        "alice@acme.com",
    );
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).expect("should succeed");
    assert_eq!(email.value, "sales@acme.com");
    assert!(email.has_tag("exa-search") && email.has_tag("web-scraped"));
    assert_eq!(
        email.evidence[0].attributes.get("source_url").map(String::as_str),
        Some("https://example.com/page")
    );
}

#[test]
fn mine_snippet_extracts_phone() {
    // Phone target: seed phone matches the text.
    let ents = snippets_for_target(
        "Call +61 2 9000 1234 for bookings.",
        TargetKind::Phone,
        "+61 2 9000 1234",
    );
    let phone = ents.iter().find(|e| e.kind == EntityKind::Phone);
    assert!(phone.is_some(), "expected a Phone entity");
    let phone = phone.expect("should succeed");
    assert!(phone.has_tag("exa-search") && phone.has_tag("web-scraped"));
}

#[test]
fn mine_snippet_rejects_too_few_digits() {
    // Only 6 digits — below the 7-digit minimum.
    let ents = snippets_for_target(
        "Short ref: 123456",
        TargetKind::Phone,
        "+61 2 1234",  // Phone seed with < 7 digits
    );
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Phone));
}

#[test]
fn mine_snippet_empty_text_yields_nothing() {
    assert!(snippets("").is_empty());
}

#[test]
fn mine_snippet_no_matches_yields_nothing() {
    assert!(snippets("No contact information here, just prose.").is_empty());
}

#[test]
fn mine_snippet_email_lowercased() {
    let ents = snippets_for_target(
        "Email ALICE@EXAMPLE.COM now.",
        TargetKind::Email,
        "bob@example.com",
    );
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).expect("should succeed");
    assert_eq!(email.value, "alice@example.com");
}

#[test]
fn mine_snippet_gates_email_on_domain_match() {
    // Email seed: extracts emails only from matching domain.
    let ents_match = snippets_for_target(
        "Contact alice@example.com or bob@example.com",
        TargetKind::Email,
        "owner@example.com",
    );
    let email_count = ents_match.iter().filter(|e| e.kind == EntityKind::Email).count();
    assert_eq!(email_count, 2, "emails on matching domain should be extracted");

    // Different domain: no extraction.
    let ents_nomatch = snippets_for_target(
        "Contact alice@other.com for help",
        TargetKind::Email,
        "owner@example.com",
    );
    assert!(!ents_nomatch.iter().any(|e| e.kind == EntityKind::Email),
            "emails from different domain should not be extracted");
}

#[test]
fn mine_snippet_gates_email_on_domain_seed() {
    // Domain seed: extracts emails from that domain.
    let ents = snippets_for_target(
        "Contact sales@example.com for pricing",
        TargetKind::Domain,
        "example.com",
    );
    let email = ents.iter().find(|e| e.kind == EntityKind::Email);
    assert!(email.is_some(), "email from domain seed should be extracted");
}

#[test]
fn mine_snippet_gates_email_for_fullname() {
    // FullName seed: emails not extracted (prevent namesake collision).
    let ents = snippets_for_target(
        "John Smith works at acme.com; email: alice@acme.com",
        TargetKind::FullName,
        "John Smith",
    );
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Email),
            "emails should not be extracted for FullName target");
}

#[test]
fn mine_snippet_gates_phone_on_appearance() {
    // Phone seed without appearing number: no extraction.
    let ents = snippets_for_target(
        "Call +61 2 9000 5555 for support",
        TargetKind::Phone,
        "+61 2 1234 5678",  // Different number
    );
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Phone),
            "phone not appearing in text should not be extracted");

    // Phone appearing in text: extraction.
    let ents_match = snippets_for_target(
        "Call +61 2 9000 1234 for support",
        TargetKind::Phone,
        "+61 2 9000 1234",
    );
    assert!(ents_match.iter().any(|e| e.kind == EntityKind::Phone),
            "phone appearing in text should be extracted");
}

#[test]
fn mine_snippet_gates_phone_for_fullname() {
    // FullName seed: phones not extracted (prevent namesake collision).
    let ents = snippets_for_target(
        "Jane Doe, +61 2 9000 1234",
        TargetKind::FullName,
        "Jane Doe",
    );
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Phone),
            "phones should not be extracted for FullName target");
}

#[test]
fn request_and_response_use_exas_documented_field_names() {
    // Backlog #20.
    let body = request_body("who is alice");
    assert_eq!(body["numResults"], NUM_RESULTS);
    assert_eq!(body["useAutoprompt"], true);
    assert_eq!(body["contents"]["text"]["maxCharacters"], 1000);
    for dead in ["num_results", "use_autoprompt"] {
        assert!(body.get(dead).is_none(), "{dead} is not an Exa parameter");
    }
    assert!(body["contents"]["text"].get("max_characters").is_none());
    let parsed: ExaResponse = serde_json::from_str(
        r#"{"results":[{"url":"https://example.org/a","publishedDate":"2024-05-01T00:00:00.000Z","author":"A"}]}"#,
    )
    .expect("decodes");
    assert_eq!(parsed.results[0].published_date.as_deref(), Some("2024-05-01T00:00:00.000Z"));
}
