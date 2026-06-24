use crate::core::scan::{Target, TargetKind};

use super::Whois;
use super::client::find_referral;
use super::parse::{all_fields, field, parse_whois, starts_with_ascii_ci};
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
