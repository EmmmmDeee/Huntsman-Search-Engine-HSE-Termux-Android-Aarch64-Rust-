use crate::core::scan::{Target, TargetKind};

use super::Whois;
use super::client::find_referral;
use super::is_usable_contact_email;
use super::parse::{all_fields, field, parse_whois, starts_with_ascii_ci};
use super::registrant_location_parts;
use super::vcard_field;
use crate::core::module::Module;

#[test]
fn accepts_domain_and_ip() {
    let m = Whois;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn produces_declares_ip_address() {
    // Regression: `target.to_entity(...)` (dynamically kinded) can re-emit
    // an IpAddress target itself, but produces() never declared it.
    use crate::core::entity::EntityKind;
    assert!(Whois.produces().contains(&EntityKind::IpAddress));
}

#[test]
fn parses_referral() {
    let s = "refer:        whois.verisign-grs.com\nstatus:        ACTIVE";
    assert_eq!(find_referral(s).as_deref(), Some("whois.verisign-grs.com"));
}

#[test]
fn parses_field_case_insensitive() {
    let s = "Registrar: Example LLC\nCreation Date: 2020-01-01";
    assert_eq!(field(s, &["Registrar:"]).as_deref(), Some("Example LLC"));
    assert_eq!(
        field(s, &["Creation Date:", "created:"]).as_deref(),
        Some("2020-01-01")
    );
}

#[test]
fn parses_multiple_nameservers_deduplicated() {
    let s =
        "Name Server: NS1.EXAMPLE.COM\nName Server: NS2.EXAMPLE.COM\nName Server: NS1.EXAMPLE.COM";
    let ns = all_fields(s, &["Name Server:"]);
    assert_eq!(ns.len(), 2);
}

#[test]
fn parse_whois_extracts_typed_fields() {
    let s = "\
Registrar: Example Registrar LLC
Registrar IANA ID: 1234
Creation Date: 2020-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Updated Date: 2024-06-01T00:00:00Z
Registrant Organization: Example Org
Registrant Country: US
Registrant State/Province: NV
Registrant Email: owner@example.com
Admin Email: admin@example.com
Tech Email: tech@example.com
Registrar Abuse Contact Email: abuse@registrar.com
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
DNSSEC: unsigned
";
    let f = parse_whois(s);
    assert_eq!(f.registrar.as_deref(), Some("Example Registrar LLC"));
    assert_eq!(f.registrar_iana.as_deref(), Some("1234"));
    assert_eq!(f.created.as_deref(), Some("2020-01-01T00:00:00Z"));
    assert_eq!(f.expires.as_deref(), Some("2030-01-01T00:00:00Z"));
    assert_eq!(f.updated.as_deref(), Some("2024-06-01T00:00:00Z"));
    assert_eq!(f.registrant_org.as_deref(), Some("Example Org"));
    assert_eq!(f.registrant_country.as_deref(), Some("US"));
    assert_eq!(f.registrant_state.as_deref(), Some("NV"));
    assert_eq!(f.registrant_email.as_deref(), Some("owner@example.com"));
    assert_eq!(f.admin_email.as_deref(), Some("admin@example.com"));
    assert_eq!(f.tech_email.as_deref(), Some("tech@example.com"));
    assert_eq!(f.abuse_email.as_deref(), Some("abuse@registrar.com"));
    assert_eq!(f.nameservers, ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]);
    assert_eq!(f.statuses, ["clientTransferProhibited"]);
    assert_eq!(f.dnssec.as_deref(), Some("unsigned"));
}

#[test]
fn parse_whois_filters_non_at_email_placeholders() {
    // Registrant Email present but without '@' (REDACTED placeholder) → None.
    let f = parse_whois("Registrant Email: REDACTED FOR PRIVACY\nRegistrar: X");
    assert!(f.registrant_email.is_none());
    assert_eq!(f.registrar.as_deref(), Some("X"));
}

#[test]
fn registrant_email_never_falls_back_to_admin_or_tech() {
    // Regression: "Registrant Email:" used to share a multi-key lookup with
    // "Tech Email:"/"Admin Email:" as if they were dialect synonyms for the
    // same field (like registrar/created's genuine synonym lists) — but
    // they're a DIFFERENT role. A response with no published Registrant
    // Email (common post-GDPR) silently substituted the admin/tech
    // contact's address and evidenced it as "WHOIS registrant contact".
    let f = parse_whois("Admin Email: admin@example.com\nTech Email: tech@example.com\n");
    assert!(
        f.registrant_email.is_none(),
        "must not fall back to admin/tech email: {:?}",
        f.registrant_email
    );
    // The admin/tech contacts are still captured — under their own,
    // correct role.
    assert_eq!(f.admin_email.as_deref(), Some("admin@example.com"));
    assert_eq!(f.tech_email.as_deref(), Some("tech@example.com"));
}

#[test]
fn starts_with_ascii_ci_matches_prefix_ignoring_case() {
    assert!(starts_with_ascii_ci("Registrar: X", "registrar:"));
    // Case-insensitive in both directions.
    assert!(starts_with_ascii_ci("registrar: x", "REGISTRAR:"));
    // A different prefix does not match.
    assert!(!starts_with_ascii_ci("Registrar: X", "creation"));
    // Key longer than the line can never match (the length guard).
    assert!(!starts_with_ascii_ci("Reg", "registrar:"));
    // The empty key is a prefix of everything.
    assert!(starts_with_ascii_ci("anything", ""));
}

#[test]
fn vcard_field_extracts_fn_and_email() {
    // Standard vcardArray structure: ["vcard", [[name, params, type, value], ...]]
    let vc: serde_json::Value = serde_json::json!([
        "vcard",
        [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "Example Organisation Ltd"],
            ["email", {}, "text", "abuse@example.org"]
        ]
    ]);
    assert_eq!(
        vcard_field(&vc, "fn").as_deref(),
        Some("Example Organisation Ltd"),
        "fn field extracted"
    );
    assert_eq!(
        vcard_field(&vc, "email").as_deref(),
        Some("abuse@example.org"),
        "email field extracted"
    );
    assert!(
        vcard_field(&vc, "tel").is_none(),
        "missing field returns None"
    );
}

#[test]
fn vcard_field_returns_none_for_malformed_input() {
    let not_a_vcard = serde_json::json!({"key": "value"});
    assert!(vcard_field(&not_a_vcard, "fn").is_none());
    let empty_array = serde_json::json!([]);
    assert!(vcard_field(&empty_array, "fn").is_none());
}

#[test]
fn registrant_location_parts_drops_privacy_proxy_placeholders_via_shared_guard() {
    // Real values pass straight through, preserving order (state, country).
    assert_eq!(
        registrant_location_parts(Some("NV"), "US"),
        vec!["NV", "US"]
    );
    // "Data Protected" and "Withheld" contain neither "redacted" nor "privacy",
    // so the previous inline substring check let them become a fake registrant
    // Address; the shared whois guard rejects them. A real value in the same
    // record still survives.
    assert_eq!(
        registrant_location_parts(Some("Data Protected"), "Australia"),
        vec!["Australia"]
    );
    assert!(registrant_location_parts(Some("Redacted For Privacy"), "Withheld").is_empty());
    // Empty parts are dropped.
    assert_eq!(registrant_location_parts(Some(""), "US"), vec!["US"]);
}

#[test]
fn is_usable_contact_email_rejects_infra_and_privacy_proxy_but_keeps_real_addresses() {
    // Regression: Email was the one WHOIS contact field missing the
    // is_infrastructure_email gate the others (`registrant_location_parts`
    // above, org, name) already applied.
    assert!(
        !is_usable_contact_email("abuse@cloudflare.com"),
        "role + infra domain"
    );
    assert!(
        !is_usable_contact_email("dns@example.com"),
        "role local-part"
    );
    // Dedicated privacy-proxy forwarding mailboxes — a real (non-placeholder-
    // TEXT) address, so is_infrastructure_email alone doesn't catch these;
    // is_whois_privacy_placeholder's substring match does (it matches
    // anywhere in the string, not just name/org fields).
    assert!(!is_usable_contact_email("a1b2c3.protect@whoisguard.com"));
    assert!(!is_usable_contact_email("some.id@domainsbyproxy.com"));
    // A real, individually-addressed mailbox must survive both gates.
    assert!(is_usable_contact_email("jane.doe@example.com"));
}
