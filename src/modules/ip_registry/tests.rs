use crate::core::entity::{Entity, EntityKind};
use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

use super::types::{AsnResp, IpResp, RdapResp};
use super::{
    IpRegistry, build_asn_entities, build_bgp_ip_entities, build_rdap_entities, contact_emails,
};

fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
    ents.iter().find(|e| e.kind == kind)
}

#[test]
fn accepts_ip_and_asn() {
    let m = IpRegistry;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(m.accepts(&Target::new(TargetKind::Asn, "AS15169")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}

#[test]
fn priority_and_timeout() {
    let m = IpRegistry;
    assert_eq!(m.priority(), 23);
    assert_eq!(m.max_timeout_ms(), 8_000);
}

#[test]
fn parse_arin_rdap_response() {
    let raw = r#"{
      "handle":"NET-8-8-8-0-1",
      "name":"LVLT-GOGL-8-8-8",
      "country":"US",
      "startAddress":"8.8.8.0",
      "endAddress":"8.8.8.255",
      "ipVersion":"v4",
      "parentHandle":"NET-8-0-0-0-0",
      "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
      "events":[
        {"eventAction":"last changed","eventDate":"2014-03-14T16:52:05-04:00"},
        {"eventAction":"registration","eventDate":"2014-03-14T16:52:05-04:00"}
      ]
    }"#;
    let r: RdapResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.handle.as_deref(), Some("NET-8-8-8-0-1"));
    assert_eq!(r.country.as_deref(), Some("US"));
    assert_eq!(r.cidr0_cidrs.len(), 1);
    assert_eq!(r.events.len(), 2);
}

#[test]
fn parse_bgpview_asn_response() {
    let raw = r#"{
      "status": "ok",
      "data": {
        "name": "GOOGLE",
        "description_short": "Google LLC",
        "country_code": "US",
        "rir_allocation": {"rir_name": "ARIN", "date_allocated": "2000-03-30"},
        "email_contacts": ["noc@google.com"],
        "abuse_contacts": ["abuse@google.com"],
        "website": "https://about.google"
      }
    }"#;
    let r: AsnResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.status, "ok");
    let data = r.data.unwrap();
    assert_eq!(data.name.as_deref(), Some("GOOGLE"));
    assert_eq!(data.country_code.as_deref(), Some("US"));
}

// ── build_rdap_entities (pure) ──────────────────────────────────────

fn rdap(json: &str) -> RdapResp {
    serde_json::from_str(json).expect("valid RdapResp fixture")
}

#[test]
fn rdap_full_record_maps_cidr_country_and_events() {
    let body = rdap(
        r#"{
          "handle":"NET-8-8-8-0-1", "name":"LVLT-GOGL-8-8-8", "country":"us",
          "ipVersion":"v4", "parentHandle":"NET-8-0-0-0-0",
          "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
          "events":[{"eventAction":"last changed","eventDate":"2014-03-14"}]
        }"#,
    );
    let ents = build_rdap_entities(&body, "8.8.8.0", "s");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert_eq!(e.kind, EntityKind::IpAddress);
    assert!(e.has_tag("rdap"));
    assert!(e.has_tag("country:US"), "country tag is uppercased");

    let ev = &e.evidence[0];
    let attr = |k: &str| ev.attributes.get(k).map(String::as_str);
    assert_eq!(attr("handle"), Some("NET-8-8-8-0-1"));
    assert_eq!(attr("prefix"), Some("8.8.8.0/24"));
    assert_eq!(attr("ip_version"), Some("v4"));
    assert_eq!(attr("parent_handle"), Some("NET-8-0-0-0-0"));
    // The space in the action becomes an underscore in the key.
    assert_eq!(attr("event:last_changed"), Some("2014-03-14"));
}

#[test]
fn rdap_prefix_falls_back_to_address_range() {
    let body = rdap(r#"{ "startAddress":"8.8.8.0", "endAddress":"8.8.8.255" }"#);
    let ev = &build_rdap_entities(&body, "8.8.8.0", "s")[0].evidence[0];
    assert_eq!(
        ev.attributes.get("prefix").map(String::as_str),
        Some("8.8.8.0 – 8.8.8.255")
    );
}

#[test]
fn rdap_blank_country_adds_no_tag_or_attr() {
    let body = rdap(r#"{ "country":"" }"#);
    let e = &build_rdap_entities(&body, "1.2.3.4", "s")[0];
    assert!(!e.tags.iter().any(|t| t.starts_with("country:")));
    assert!(!e.evidence[0].attributes.contains_key("country"));
}

// ── build_bgp_ip_entities (pure) ────────────────────────────────────

fn ip_resp(json: &str) -> IpResp {
    serde_json::from_str(json).expect("valid IpResp fixture")
}

#[test]
fn bgp_ip_yields_announcing_asn() {
    let body = ip_resp(
        r#"{ "status":"ok", "data": { "prefixes": [
            { "prefix":"8.8.8.0/24", "asn": {
                "asn":15169, "name":"GOOGLE", "description":"Google LLC", "country_code":"US" } }
        ] } }"#,
    );
    let ents = build_bgp_ip_entities(&body, "8.8.8.8", "s");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert_eq!(e.value, "AS15169");
    assert!(e.has_tag("announcing"));
    let attr = |k: &str| e.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("asn_number"), Some("15169"));
    assert_eq!(attr("prefix"), Some("8.8.8.0/24"));
    assert_eq!(attr("handle"), Some("GOOGLE"));
    assert_eq!(attr("name"), Some("Google LLC"));
    assert_eq!(attr("country"), Some("US"));
}

#[test]
fn bgp_ip_not_ok_or_asnless_yields_nothing() {
    assert!(build_bgp_ip_entities(&ip_resp(r#"{"status":"error"}"#), "8.8.8.8", "s").is_empty());
    // A leading prefix with no ASN reference produces nothing.
    let no_asn =
        ip_resp(r#"{ "status":"ok", "data": { "prefixes": [ { "prefix":"8.8.8.0/24" } ] } }"#);
    assert!(build_bgp_ip_entities(&no_asn, "8.8.8.8", "s").is_empty());
}

// ── build_asn_entities + contact_emails (pure) ──────────────────────

fn asn_resp(json: &str) -> AsnResp {
    serde_json::from_str(json).expect("valid AsnResp fixture")
}

#[test]
fn asn_record_yields_registry_contacts_and_website() {
    let body = asn_resp(
        r#"{ "status":"ok", "data": {
            "name":"GOOGLE", "description_short":"Google LLC", "country_code":"US",
            "rir_allocation": {"rir_name":"ARIN", "date_allocated":"2000-03-30"},
            "email_contacts": ["noc@google.com"],
            "abuse_contacts": ["abuse@google.com"],
            "website": "https://about.google" } }"#,
    );
    let ents = build_asn_entities(&body, 15169, "s");
    // registry ASN + admin email + abuse email + website URL
    assert_eq!(ents.len(), 4);

    let asn = of_kind(&ents, EntityKind::Asn).unwrap();
    assert_eq!(asn.value, "AS15169");
    assert!(asn.has_tag("registered"));
    let attr = |k: &str| asn.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("handle"), Some("GOOGLE"));
    assert_eq!(attr("name"), Some("Google LLC"));
    assert_eq!(attr("rir"), Some("ARIN"));
    assert_eq!(attr("allocated"), Some("2000-03-30"));

    let emails: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(emails.len(), 2);
    assert!(emails.contains(&"noc@google.com") && emails.contains(&"abuse@google.com"));

    let url = of_kind(&ents, EntityKind::Url).unwrap();
    assert_eq!(url.value, "https://about.google");
    assert!(url.has_tag("asn-website"));
}

#[test]
fn asn_not_ok_or_dataless_yields_nothing() {
    assert!(build_asn_entities(&asn_resp(r#"{"status":"error"}"#), 1, "s").is_empty());
    assert!(build_asn_entities(&asn_resp(r#"{"status":"ok"}"#), 1, "s").is_empty());
}

#[test]
fn asn_non_http_website_yields_no_url_entity() {
    let body = asn_resp(r#"{ "status":"ok", "data": { "website": "ftp://files.example" } }"#);
    let ents = build_asn_entities(&body, 1, "s");
    assert!(
        of_kind(&ents, EntityKind::Url).is_none(),
        "a non-http(s) website must not become a Url entity"
    );
    // ...but it is still recorded as an attribute on the ASN evidence.
    let asn = of_kind(&ents, EntityKind::Asn).unwrap();
    assert_eq!(
        asn.evidence[0]
            .attributes
            .get("website")
            .map(String::as_str),
        Some("ftp://files.example")
    );
}

#[test]
fn contact_emails_skips_non_addresses_and_tags_role() {
    let list = vec!["good@example.com".to_string(), "not-an-email".to_string()];
    let ents = contact_emails(Some(&list), "abuse", "AS1", "1", "s");
    assert_eq!(ents.len(), 1, "the non-email string is dropped");
    assert_eq!(ents[0].value, "good@example.com");
    assert!(ents[0].has_tag("asn-contact") && ents[0].has_tag("role:abuse"));
    // None input is treated as an empty list.
    assert!(contact_emails(None, "admin", "AS1", "1", "s").is_empty());
}
