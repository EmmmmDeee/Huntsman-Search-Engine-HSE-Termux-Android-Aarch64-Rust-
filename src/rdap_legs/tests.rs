use super::*;
use crate::rdap::tests::{APNIC, DNS_BOOTSTRAP, GITHUB, IPV4_BOOTSTRAP};
use crate::sf_elements::{DataElement, Target, elements};
use crate::test_support::RoutedTransport;

fn github() -> RoutedTransport {
    RoutedTransport::new(&[
        ("https://data.iana.org/rdap/dns.json", 200, DNS_BOOTSTRAP),
        (
            "https://rdap.verisign.com/com/v1/domain/github.com",
            200,
            GITHUB,
        ),
    ])
}

/// The entity of `kind` the registry published as `value`.
fn find<'a>(entities: &'a [Entity], kind: &EntityKind, value: &str) -> &'a Entity {
    entities
        .iter()
        .find(|entity| entity.kind == *kind && entity.raw_value == value)
        .unwrap_or_else(|| panic!("no {kind:?} {value} in {entities:#?}"))
}

fn values<'a>(evidence: &'a Evidence, key: &str) -> Vec<&'a str> {
    evidence.attr_values(key).collect()
}

/// A domain's registration keeps everything the registry published on the domain, and the
/// registrar, name servers and published contacts become entities tied to it; a privacy
/// placeholder is listed, never an entity.
#[test]
fn a_domain_registration_is_the_whole_record_and_its_contacts() {
    let leg = domain(&github(), "github.com", "scan", 1);
    let outcome = leg.outcome.expect("an rdap row");
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);

    let record = &find(&leg.entities, &EntityKind::Domain, "github.com").evidence[0];
    assert_eq!(record.provenance.source, SOURCE);
    assert_eq!(
        record.summary,
        "Registration of github.com (RDAP), registrar MarkMonitor Inc., registrant GitHub, Inc., \
         registered 2007-10-09T18:20:50Z, expires 2026-10-09T18:20:50Z"
    );
    assert_eq!(
        record.attributes.get("whois").map(String::as_str),
        Some(GITHUB)
    );
    assert_eq!(values(record, "registrar"), ["MarkMonitor Inc."]);
    assert_eq!(values(record, "registrar_iana_id"), ["292"]);
    assert_eq!(values(record, "last_changed"), ["2024-09-07T09:16:32Z"]);
    assert_eq!(
        values(record, "ns"),
        ["dns1.p08.nsone.net", "ns-421.awsdns-52.com"]
    );
    assert_eq!(
        values(record, "abuse_email"),
        ["abusecomplaints@markmonitor.com"]
    );
    assert_eq!(values(record, "abuse_phone"), ["+1.2086851750"]);
    // Published as the registry published it, placeholder included.
    assert_eq!(values(record, "registrant_name"), ["REDACTED FOR PRIVACY"]);
    assert_eq!(values(record, "registrant_org"), ["GitHub, Inc."]);

    let registrar = find(&leg.entities, &EntityKind::Organisation, "MarkMonitor Inc.");
    assert!(registrar.has_tag(tags::REGISTRAR));
    let registrant = find(&leg.entities, &EntityKind::Organisation, "GitHub, Inc.");
    assert!(!registrant.has_tag(tags::REGISTRAR));
    assert_eq!(values(&registrant.evidence[0], "domain"), ["github.com"]);
    let abuse = find(
        &leg.entities,
        &EntityKind::Email,
        "abusecomplaints@markmonitor.com",
    );
    assert!(abuse.has_tag(tags::ABUSE_CONTACT));
    for host in ["dns1.p08.nsone.net", "ns-421.awsdns-52.com"] {
        let server = find(&leg.entities, &EntityKind::Domain, host);
        assert_eq!(values(&server.evidence[0], "domain"), ["github.com"]);
    }
    assert!(
        !leg.entities
            .iter()
            .any(|entity| rdap::is_redacted(&entity.value)),
        "a placeholder became an entity: {:#?}",
        leg.entities
    );
}

/// In a saved scan the record is Spiderfoot's `DOMAIN_WHOIS` and the registrar its
/// `DOMAIN_REGISTRAR`, both under the target.
#[test]
fn the_record_is_domain_whois_and_the_registrar_domain_registrar() {
    let leg = domain(&github(), "github.com", "scan", 1);
    let target = Target {
        value: "github.com",
        kind: "INTERNET_NAME",
    };
    let found = elements(target, &leg.entities, 1);
    let of = |kind: &str| -> Vec<&DataElement> {
        found
            .iter()
            .filter(|element| element.kind == kind)
            .collect()
    };
    let whois = of("DOMAIN_WHOIS");
    assert_eq!(whois.len(), 1, "{found:#?}");
    assert_eq!(whois[0].data, GITHUB);
    assert_eq!(whois[0].source.as_deref(), Some(found[1].id.as_str()));
    assert_eq!(
        of("DOMAIN_REGISTRAR")
            .iter()
            .map(|element| element.data.as_str())
            .collect::<Vec<_>>(),
        ["MarkMonitor Inc."]
    );
}

/// A host's registration is its registrable domain's.
#[test]
fn a_host_is_looked_up_as_its_registrable_domain() {
    let registry = github();
    let leg = domain(&registry, "api.github.com", "scan", 1);
    assert_eq!(
        registry.urls()[1],
        "https://rdap.verisign.com/com/v1/domain/github.com"
    );
    find(&leg.entities, &EntityKind::Domain, "github.com");
}

#[test]
fn an_address_registration_is_its_networks_record() {
    let registry = RoutedTransport::new(&[
        ("https://data.iana.org/rdap/ipv4.json", 200, IPV4_BOOTSTRAP),
        ("https://specific.test/ip/1.1.1.1", 200, APNIC),
    ]);
    let leg = ip(&registry, "1.1.1.1", "scan", 1);
    let record = &find(&leg.entities, &EntityKind::IpAddress, "1.1.1.1").evidence[0];
    assert_eq!(values(record, "prefix"), ["1.1.1.0/24"]);
    assert_eq!(values(record, "registered_name"), ["APNIC-LABS"]);
    assert_eq!(values(record, "country"), ["AU"]);
    assert_eq!(values(record, "network_type"), ["ASSIGNED PORTABLE"]);
    assert_eq!(values(record, "whois_server"), ["whois.apnic.net"]);
    let holder = find(
        &leg.entities,
        &EntityKind::Organisation,
        "APNIC Research and Development",
    );
    assert_eq!(values(&holder.evidence[0], "ip"), ["1.1.1.1"]);
    assert_eq!(
        record.summary,
        "Registration of 1.1.1.1 (RDAP), APNIC-LABS 1.1.1.0/24, registrant APNIC Research and \
         Development, registered 2011-08-10T23:12:35Z"
    );
    // The abuse desk is also the registrant's address: one entity, an evidence record per
    // contact that lists it.
    let desk: Vec<&Entity> = leg
        .entities
        .iter()
        .filter(|entity| entity.raw_value == "helpdesk@apnic.net")
        .collect();
    assert_eq!(desk.len(), 1, "{desk:#?}");
    assert!(desk[0].has_tag(tags::ABUSE_CONTACT) && desk[0].has_tag(tags::WHOIS_CONTACT));
    assert_eq!(desk[0].evidence.len(), 2);
    // `ORG-ARAD1-AP` is the organisation's RPSL handle, kept on the record, not a name.
    assert_eq!(values(record, "technical_org"), ["ORG-ARAD1-AP"]);
    assert!(
        !leg.entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Organisation
                && entity.raw_value.starts_with("ORG-")),
        "{:#?}",
        leg.entities
    );

    let target = Target {
        value: "1.1.1.1",
        kind: "IP_ADDRESS",
    };
    let found = elements(target, &leg.entities, 1);
    for kind in ["NETBLOCK_WHOIS", "NETBLOCK_MEMBER"] {
        assert!(
            found.iter().any(|element| element.kind == kind),
            "{kind} in {found:#?}"
        );
    }
}

/// A telephone published as a tel URI with an extension (RFC 9083 section 5.1's own example) is
/// the number before the extension; the record keeps it as published.
#[test]
fn a_telephone_extension_is_not_digits_of_the_number() {
    const EXTENSION: &str = r#"{"objectClassName":"domain","ldhName":"example.com","entities":[{"roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["tel",{"type":["work","voice"]},"uri","tel:+1-555-555-1234;ext=102"]]]}]}"#;
    let registry = RoutedTransport::new(&[
        ("https://data.iana.org/rdap/dns.json", 200, DNS_BOOTSTRAP),
        (
            "https://rdap.verisign.com/com/v1/domain/example.com",
            200,
            EXTENSION,
        ),
    ]);
    let leg = domain(&registry, "example.com", "scan", 1);
    let phones: Vec<&str> = leg
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Phone)
        .map(|entity| entity.raw_value.as_str())
        .collect();
    assert_eq!(phones, ["+15555551234"], "{:#?}", leg.entities);
    let record = &find(&leg.entities, &EntityKind::Domain, "example.com").evidence[0];
    assert_eq!(values(record, "abuse_phone"), ["+1-555-555-1234;ext=102"]);
}

/// Each leg's row carries a registry's `Retry-After`, an HTTP date counted from the scan's clock.
#[test]
fn every_leg_row_carries_a_dated_retry_after() {
    // Ninety seconds before Fri, 23 Oct 2026 12:00:00 GMT.
    const NOW: u64 = 1_792_756_710;
    let limited = || {
        crate::test_support::ScriptedTransport::new(vec![Ok(crate::http::Response {
            status: 429,
            headers: vec![("Retry-After".into(), "Fri, 23 Oct 2026 12:00:00 GMT".into())],
            body: b"{}".to_vec(),
            truncated: false,
        })])
    };
    let legs = [
        domain(&limited(), "github.com", "scan", NOW),
        ip(&limited(), "1.1.1.1", "scan", NOW),
        netblock(
            &limited(),
            crate::netblock::Netblock::parse("1.1.1.0/24").expect("block"),
            "scan",
            NOW,
        ),
        asn(&limited(), 13335, "scan", NOW),
    ];
    for leg in legs {
        let outcome = leg.outcome.expect("an rdap row");
        assert_eq!(outcome.kind, SourceOutcomeKind::RateLimited);
        assert_eq!(outcome.retry_after_secs, Some(90), "{outcome:?}");
    }
}

/// A local number is a number only in its `phone-context`, so a New Zealand mobile in local form
/// is not read as an Australian number; the record still keeps it as published.
#[test]
fn a_local_telephone_in_another_context_is_no_phone() {
    const LOCAL: &str = r#"{"objectClassName":"domain","ldhName":"example.com","entities":[{"roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["tel",{"type":["work","voice"]},"uri","tel:021-234-5678;phone-context=+64"],["tel",{},"uri","tel:021-234-5679;PHONE-CONTEXT=example.nz"]]]}]}"#;
    let registry = RoutedTransport::new(&[
        ("https://data.iana.org/rdap/dns.json", 200, DNS_BOOTSTRAP),
        (
            "https://rdap.verisign.com/com/v1/domain/example.com",
            200,
            LOCAL,
        ),
    ]);
    let leg = domain(&registry, "example.com", "scan", 1);
    assert!(
        leg.entities
            .iter()
            .all(|entity| entity.kind != EntityKind::Phone),
        "{:#?}",
        leg.entities
    );
    let record = &find(&leg.entities, &EntityKind::Domain, "example.com").evidence[0];
    assert_eq!(
        values(record, "abuse_phone"),
        [
            "021-234-5678;phone-context=+64",
            "021-234-5679;PHONE-CONTEXT=example.nz"
        ]
    );
}

#[test]
fn a_tel_number_drops_parameters_only_where_the_number_stands_alone() {
    assert_eq!(
        tel_number("+1-555-555-1234;ext=102"),
        Some("+1-555-555-1234")
    );
    assert_eq!(
        tel_number("+64-21-234-5678;phone-context=+64"),
        Some("+64-21-234-5678")
    );
    assert_eq!(tel_number("(02) 9999 0000"), Some("(02) 9999 0000"));
    assert_eq!(tel_number("02 9999 0000;ext=5"), Some("02 9999 0000"));
    assert_eq!(tel_number("021-234-5678;phone-context=+64"), None);
    assert_eq!(tel_number("021-234-5678;ext=5;phone-context=+64"), None);
}

/// Not registered is a validated zero; a TLD with no RDAP service is no answer, and says why.
#[test]
fn not_registered_is_a_zero_and_no_registry_is_not() {
    let registry = RoutedTransport::new(&[
        ("https://data.iana.org/rdap/dns.json", 200, DNS_BOOTSTRAP),
        ("https://rdap.verisign.com/", 404, "{}"),
    ]);
    let leg = domain(&registry, "no-such-name-zz.com", "scan", 1);
    assert!(leg.entities.is_empty(), "{:?}", leg.entities);
    let outcome = leg.outcome.expect("an rdap row");
    assert_eq!(outcome.kind, SourceOutcomeKind::ValidZero);
    assert_eq!(
        outcome.detail.as_deref(),
        Some("not registered at https://rdap.verisign.com/com/v1/domain/no-such-name-zz.com")
    );

    let leg = domain(&registry, "example.org", "scan", 1);
    let outcome = leg.outcome.expect("an rdap row");
    assert_eq!(outcome.kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(
        outcome.detail.as_deref(),
        Some("the IANA bootstrap names no RDAP service for .org")
    );
}

#[test]
fn event_actions_become_attribute_keys() {
    assert_eq!(event_key("last changed"), "last_changed");
    assert_eq!(event_key("Registration"), "registration");
    assert_eq!(
        event_key("last update of RDAP database"),
        "last_update_of_rdap_database"
    );
}
