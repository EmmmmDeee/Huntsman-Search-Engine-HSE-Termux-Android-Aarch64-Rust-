use crate::core::entity::EntityKind;
use crate::core::scan::{Target, TargetKind};

use super::Whois;
use super::build_entities;
use super::client::find_referral;
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

/// Characterization test for `build_entities` and its sub-helpers
/// (`build_domain_entity`, `emit_contact_emails`, `emit_registrant_identity`,
/// `emit_admin_tech_contacts`, `emit_contact_phones`, `emit_nameservers`) —
/// none of this WHOIS-fields-to-entity mapping had any test coverage before
/// this refactor split it out of `process()`. Exercises one of each entity
/// shape the mapping produces, including the role-mailbox filter (`admin@`/
/// `abuse@` dropped, `owner@`/`tech@` kept) and the registrant-address
/// Coordinates-before-Address push order.
#[test]
fn build_entities_maps_fields_to_expected_entities_in_order() {
    let response = "\
Registrar: Example Registrar LLC
Registrar IANA ID: 1234
Creation Date: 2020-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Updated Date: 2024-06-01T00:00:00Z
Registrant Name: Jane Smith
Registrant Organization: Example Org
Registrant Country: US
Registrant State/Province: New York
Registrant Email: owner@example.com
Admin Name: John Doe
Admin Organization: Example Admin Org
Admin Email: admin@example.com
Admin Phone: +14155552671
Tech Name: Tech Person
Tech Organization: Example Tech Org
Tech Email: tech@example.com
Registrar Abuse Contact Email: abuse@registrar.com
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
DNSSEC: unsigned
";
    let fields = parse_whois(response);
    let target = Target::new(TargetKind::Domain, "example.com");
    let result = build_entities(&target, "scan-1", response, &fields);

    let kinds: Vec<EntityKind> = result.entities.iter().map(|e| e.kind.clone()).collect();
    assert_eq!(
        kinds,
        vec![
            EntityKind::Domain,       // parent WHOIS entity
            EntityKind::Email,        // registrant: owner@example.com
            EntityKind::Email,        // tech: tech@example.com
            EntityKind::Organisation, // registrant org
            EntityKind::Person,       // registrant name
            EntityKind::Coordinates,  // geocoded registrant address (pushed before...)
            EntityKind::Address,      // ...the address entity itself
            EntityKind::Person,       // admin contact
            EntityKind::Person,       // tech contact
            EntityKind::Organisation, // admin org
            EntityKind::Organisation, // tech org
            EntityKind::Phone,        // admin phone
            EntityKind::Domain,       // ns1.example.com
            EntityKind::Domain,       // ns2.example.com
        ]
    );

    let domain_entity = &result.entities[0];
    assert!(
        domain_entity
            .tags
            .contains(&"status:clienttransferprohibited".to_string())
    );
    assert!(domain_entity.tags.contains(&"dnssec:unsigned".to_string()));

    // Role-mailbox filter: admin@/abuse@ (both role local-parts) are dropped,
    // leaving only the registrant and tech contacts.
    let emails: Vec<&str> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(emails, vec!["owner@example.com", "tech@example.com"]);

    assert_eq!(result.entities[3].value, "Example Org");
    assert_eq!(result.entities[4].value, "Jane Smith");
    assert_eq!(result.entities[6].value, "New York, US");

    let phone = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .expect("admin phone present");
    assert_eq!(phone.value, "+14155552671");

    let nameservers: Vec<&str> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.tags.iter().any(|t| t == "whois-ns"))
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(nameservers, vec!["ns1.example.com", "ns2.example.com"]);
}

/// With no actionable fields at all, `build_entities` must emit nothing —
/// the early-return guard that keeps a failed/empty WHOIS lookup from
/// producing a noise entity.
#[test]
fn build_entities_returns_empty_for_no_actionable_data() {
    let fields = parse_whois("");
    let target = Target::new(TargetKind::Domain, "example.com");
    let result = build_entities(&target, "scan-1", "", &fields);
    assert!(result.entities.is_empty());
}
