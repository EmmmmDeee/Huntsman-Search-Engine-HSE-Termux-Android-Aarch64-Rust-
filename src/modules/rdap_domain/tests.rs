use super::*;

#[test]
fn accepts_only_domain() {
    let m = RdapDomain;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

#[test]
fn priority_runs_after_whois() {
    // Whois (priority 32) is the canonical record holder; rdap fills
    // structured gaps after. Engine sorts highest-first.
    assert!(RdapDomain.priority() < 32);
}

#[test]
fn slugify_collapses_whitespace_and_lowercases() {
    assert_eq!(
        slugify("client transfer prohibited"),
        "client-transfer-prohibited"
    );
    assert_eq!(slugify("Active"), "active");
    assert_eq!(slugify("a  b   c"), "a-b-c");
    assert_eq!(slugify("no-spaces"), "no-spaces");
    assert_eq!(slugify(""), "");
}

fn resp(json: &str) -> RdapResp {
    serde_json::from_str(json).unwrap()
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

#[test]
fn domain_entity_slugs_status_groups_events_and_surfaces_roles() {
    let body = resp(
        r#"{
          "handle":"D-123",
          "status":["client transfer prohibited","active"],
          "events":[
            {"eventAction":"registration","eventDate":"1997-09-15"},
            {"eventAction":"transfer","eventDate":"2005-01-01"},
            {"eventAction":"transfer","eventDate":"2019-03-03"},
            {"eventAction":"last changed","eventDate":"2024-08-01"}
          ],
          "entities":[{"roles":["registrant","technical"]},{"roles":["registrant"]}],
          "nameservers":[{"ldhName":"ns1.example.com"},{"ldhName":"ns2.example.com"}],
          "secureDNS":{"delegationSigned":true}
        }"#,
    );
    let e = build_domain_entity("example.com", &body, "s");
    assert_eq!(e.kind, EntityKind::Domain);
    assert!(e.has_tag("rdap"));
    // Status phrases slugified into tags.
    assert!(e.has_tag("status:client-transfer-prohibited") && e.has_tag("status:active"));
    assert_eq!(attr(&e, "handle"), Some("D-123"));
    // Repeated `transfer` action → both dates grouped under one attr.
    assert_eq!(attr(&e, "event_transfer"), Some("2005-01-01,2019-03-03"));
    assert_eq!(attr(&e, "event_registration"), Some("1997-09-15"));
    // Slugified multi-word action key.
    assert_eq!(attr(&e, "event_last-changed"), Some("2024-08-01"));
    // Roles deduplicated + sorted; raw PII never present.
    assert_eq!(attr(&e, "contact_roles"), Some("registrant,technical"));
    // DNSSEC.
    assert!(e.has_tag("dnssec:signed"));
    assert_eq!(attr(&e, "dnssec_signed"), Some("true"));
    assert_eq!(
        attr(&e, "nameservers"),
        Some("ns1.example.com,ns2.example.com")
    );
}

#[test]
fn unsigned_dnssec_and_empty_record_degrade_cleanly() {
    let signed = build_domain_entity(
        "x.com",
        &resp(r#"{"secureDNS":{"delegationSigned":false}}"#),
        "s",
    );
    assert!(signed.has_tag("dnssec:unsigned"));

    // Bare record: only the base tag + summary, every optional attr omitted.
    let bare = build_domain_entity("x.com", &resp("{}"), "s");
    assert!(bare.has_tag("rdap"));
    assert_eq!(attr(&bare, "handle"), None);
    assert_eq!(attr(&bare, "status"), None);
    assert_eq!(attr(&bare, "contact_roles"), None);
    assert_eq!(attr(&bare, "nameservers"), None);
}

#[test]
fn ns_ip_entities_extracted_from_glue_records() {
    let body = resp(
        r#"{
          "nameservers":[{
            "ldhName":"ns1.example.net",
            "ipAddresses":{"v4":["192.0.2.1"],"v6":["2001:db8::1"]}
          }]
        }"#,
    );
    let ns = &body.nameservers[0];
    let ips = build_ns_ip_entities("example.com", ns, "s");
    assert_eq!(ips.len(), 2);
    assert_eq!(ips[0].kind, EntityKind::IpAddress);
    assert_eq!(ips[0].value, "192.0.2.1");
    assert!(ips[0].has_tag("rdap-ns-glue"));
    assert_eq!(attr(&ips[0], "nameserver"), Some("ns1.example.net"));
    assert_eq!(ips[1].value, "2001:db8::1");
}

#[test]
fn ns_ip_entities_skips_invalid_and_empty() {
    let body = resp(
        r#"{"nameservers":[{"ldhName":"ns.example.net","ipAddresses":{"v4":["not-an-ip",""]}}]}"#,
    );
    let ips = build_ns_ip_entities("example.com", &body.nameservers[0], "s");
    assert!(ips.is_empty());
}

#[test]
fn ns_ip_entities_absent_yields_empty() {
    let body = resp(r#"{"nameservers":[{"ldhName":"ns.example.net"}]}"#);
    let ips = build_ns_ip_entities("example.com", &body.nameservers[0], "s");
    assert!(ips.is_empty());
}

#[test]
fn ns_entity_tags_and_rejects_blank() {
    let ns = build_ns_entity("example.com", "NS1.Example.COM.", "s").unwrap();
    assert_eq!(ns.kind, EntityKind::Domain);
    // Entity::new normalises domains (lowercase, strip trailing dot).
    assert_eq!(ns.value, "ns1.example.com");
    assert!(ns.has_tag("rdap-ns") && ns.has_tag("ns"));
    assert_eq!(attr(&ns, "parent"), Some("example.com"));
    // Blank / whitespace name → no entity.
    assert!(build_ns_entity("example.com", "   ", "s").is_none());
}
