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

fn snippets(text: &str) -> Vec<Entity> {
    let mut r = ModuleResult::new();
    mine_snippet(text, "scan-1", "https://example.com/page", &mut r);
    r.entities
}

#[test]
fn mine_snippet_extracts_email() {
    let ents = snippets("Contact us at sales@acme.com for pricing.");
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).expect("should succeed");
    assert_eq!(email.value, "sales@acme.com");
    assert!(email.has_tag("exa-search") && email.has_tag("web-scraped"));
    assert_eq!(
        email.evidence[0]
            .attributes
            .get("source_url")
            .map(String::as_str),
        Some("https://example.com/page")
    );
}

#[test]
fn mine_snippet_extracts_phone() {
    let ents = snippets("Call +61 2 9000 1234 for bookings.");
    let phone = ents.iter().find(|e| e.kind == EntityKind::Phone);
    assert!(phone.is_some(), "expected a Phone entity");
    let phone = phone.expect("should succeed");
    assert!(phone.has_tag("exa-search") && phone.has_tag("web-scraped"));
}

#[test]
fn mine_snippet_rejects_too_few_digits() {
    // Only 6 digits — below the 7-digit minimum.
    let ents = snippets("Short ref: 123456");
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
    let ents = snippets("Email ALICE@EXAMPLE.COM now.");
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).expect("should succeed");
    assert_eq!(email.value, "alice@example.com");
}

/// Drift guard: the key-pool service name MUST equal the canonical
/// `ServiceDef.name` for this module's key env var, or `report_key_exhausted`
/// marks a phantom service and rotation/dead-key memory silently break.
#[test]
fn key_service_matches_service_def() {
    let def = crate::util::service_defs::service_defs()
        .iter()
        .find(|d| d.env_var == KEY_ENV)
        .unwrap_or_else(|| panic!("no ServiceDef registers {KEY_ENV}"));
    assert_eq!(
        def.name, KEY_SERVICE,
        "KEY_SERVICE must equal the canonical ServiceDef.name for {KEY_ENV}"
    );
    assert!(crate::util::service_defs::is_poolable_service(KEY_SERVICE));
}
