use super::*;
use crate::test_support::RoutedTransport as Registry;

pub(crate) const DNS_BOOTSTRAP: &str = r#"{"services":[[["com","net"],["https://rdap.verisign.com/com/v1/"]],[["uk"],["https://rdap.nominet.uk/uk/"]],[["co.uk"],["http://only-http.test/couk","https://example.test/couk"]]]}"#;
pub(crate) const IPV4_BOOTSTRAP: &str = r#"{"services":[[["1.0.0.0/8"],["https://rdap.apnic.net/"]],[["1.1.0.0/16"],["https://specific.test"]],[["93.0.0.0/8"],["https://rdap.db.ripe.net/"]]]}"#;

/// Trimmed from Verisign's `github.com` answer: the registrar with its IANA id and nested abuse
/// contact, name servers, events and status, and a registrant a registry redacts.
pub(crate) const GITHUB: &str = r#"{"objectClassName":"domain","handle":"1264983250_DOMAIN_COM-VRSN","ldhName":"GITHUB.COM",
    "events":[{"eventAction":"registration","eventDate":"2007-10-09T18:20:50Z"},
              {"eventAction":"expiration","eventDate":"2026-10-09T18:20:50Z"},
              {"eventAction":"last changed","eventDate":"2024-09-07T09:16:32Z"}],
    "entities":[{"objectClassName":"entity","handle":"292","roles":["registrar"],
        "publicIds":[{"type":"IANA Registrar ID","identifier":"292"}],
        "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","MarkMonitor Inc."]]],
        "entities":[{"objectClassName":"entity","roles":["abuse"],
            "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text",""],["tel",{"type":"voice"},"uri","tel:+1.2086851750"],["email",{},"text","abusecomplaints@markmonitor.com"]]]}]},
      {"objectClassName":"entity","roles":["registrant"],
        "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","REDACTED FOR PRIVACY"],["org",{},"text","GitHub, Inc."],["adr",{},"text",["","","","","CA","","US"]]]]}],
    "nameservers":[{"objectClassName":"nameserver","ldhName":"DNS1.P08.NSONE.NET"},{"objectClassName":"nameserver","ldhName":"NS-421.AWSDNS-52.COM"}],
    "status":["client delete prohibited","client transfer prohibited"]}"#;

/// Trimmed from APNIC's answer for `1.1.1.1`.
pub(crate) const APNIC: &str = r#"{"objectClassName":"ip network","handle":"1.1.1.0 - 1.1.1.255","startAddress":"1.1.1.0","endAddress":"1.1.1.255","ipVersion":"v4","name":"APNIC-LABS","type":"ASSIGNED PORTABLE","country":"AU","parentHandle":"1.1.0.0 - 1.1.255.255","status":["active"],"port43":"whois.apnic.net",
    "cidr0_cidrs":[{"v4prefix":"1.1.1.0","length":24}],
    "events":[{"eventAction":"registration","eventDate":"2011-08-10T23:12:35Z"},{"eventAction":"last changed","eventDate":"2023-04-26T22:57:58Z"}],
    "entities":[{"handle":"ORG-ARAD1-AP","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","APNIC Research and Development"],["kind",{},"text","org"],["email",{},"text","helpdesk@apnic.net"],["adr",{"label":"6 Cordelia St"},"text",["","","","","","",""]]]]},
      {"handle":"AIC3-AP","roles":["technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","APNICRANDNET Infrastructure Contact"],["kind",{},"text","group"],["org",{},"text","ORG-ARAD1-AP"],["email",{},"text","research@apnic.net"]]]},
      {"handle":"IRT-APNICRANDNET-AU","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","IRT-APNICRANDNET-AU"],["kind",{},"text","group"],["email",{},"text","helpdesk@apnic.net"],["adr",{"label":"PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia"},"text",["","","","","","",""]]]]}]}"#;

fn registered(answer: Result<Answer, Failure>) -> Record {
    match answer {
        Ok(Answer::Registered(record)) => *record,
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_bootstrap_picks_the_longest_tld_and_the_longest_block() {
    let dns: Bootstrap = serde_json::from_str(DNS_BOOTSTRAP).expect("bootstrap");
    assert_eq!(
        service_for_domain(&dns, "github.com").as_deref(),
        Some("https://rdap.verisign.com/com/v1/")
    );
    // The longer suffix wins, and https is preferred within an entry.
    assert_eq!(
        service_for_domain(&dns, "bbc.co.uk").as_deref(),
        Some("https://example.test/couk/")
    );
    assert_eq!(service_for_domain(&dns, "notcom"), None);
    assert_eq!(service_for_domain(&dns, "example.org"), None);

    let ips: Bootstrap = serde_json::from_str(IPV4_BOOTSTRAP).expect("bootstrap");
    let ip = |raw: &str| raw.parse::<IpAddr>().expect("address");
    assert_eq!(
        service_for_ip(&ips, ip("1.1.1.1")).as_deref(),
        Some("https://specific.test/")
    );
    assert_eq!(
        service_for_ip(&ips, ip("1.2.3.4")).as_deref(),
        Some("https://rdap.apnic.net/")
    );
    assert_eq!(service_for_ip(&ips, ip("9.9.9.9")), None);
}

/// A domain record keeps everything it publishes: the body as published, the events, status,
/// name servers and each contact a role at a time, nested ones included.
#[test]
fn a_domain_record_keeps_everything_it_publishes() {
    let registry = Registry::new(&[
        ("https://data.iana.org/rdap/dns.json", 200, DNS_BOOTSTRAP),
        (
            "https://rdap.verisign.com/com/v1/domain/github.com",
            200,
            GITHUB,
        ),
    ]);
    let record = registered(lookup_domain(&registry, "GitHub.com."));
    assert_eq!(
        registry.urls(),
        [
            "https://data.iana.org/rdap/dns.json",
            "https://rdap.verisign.com/com/v1/domain/github.com"
        ]
    );
    assert_eq!(record.raw, GITHUB);
    assert_eq!(record.name.as_deref(), Some("github.com"));
    assert_eq!(record.event("registration"), Some("2007-10-09T18:20:50Z"));
    assert_eq!(record.event("Expiration"), Some("2026-10-09T18:20:50Z"));
    assert_eq!(
        record.nameservers,
        ["dns1.p08.nsone.net", "ns-421.awsdns-52.com"]
    );
    assert_eq!(record.status.len(), 2);

    let registrar = record.with_role("registrar").next().expect("registrar");
    assert_eq!(registrar.name.as_deref(), Some("MarkMonitor Inc."));
    assert_eq!(registrar.iana_id.as_deref(), Some("292"));
    let abuse = record
        .with_role("abuse")
        .next()
        .expect("nested abuse contact");
    assert_eq!(abuse.emails, ["abusecomplaints@markmonitor.com"]);
    assert_eq!(abuse.phones, ["+1.2086851750"]);
    assert_eq!(abuse.name, None);
    let registrant = record.with_role("registrant").next().expect("registrant");
    assert!(is_redacted(registrant.name.as_deref().unwrap_or_default()));
    assert_eq!(registrant.org.as_deref(), Some("GitHub, Inc."));
    assert_eq!(registrant.address.as_deref(), Some("CA, US"));
}

#[test]
fn a_network_record_keeps_its_range_blocks_and_contacts() {
    let registry = Registry::new(&[
        ("https://data.iana.org/rdap/ipv4.json", 200, IPV4_BOOTSTRAP),
        ("https://specific.test/ip/1.1.1.1", 200, APNIC),
    ]);
    let record = registered(lookup_ip(&registry, IpAddr::from([1, 1, 1, 1])));
    assert_eq!(record.name.as_deref(), Some("APNIC-LABS"));
    assert_eq!(record.cidrs, ["1.1.1.0/24"]);
    assert_eq!(record.start_address.as_deref(), Some("1.1.1.0"));
    assert_eq!(record.country.as_deref(), Some("AU"));
    assert_eq!(record.kind.as_deref(), Some("ASSIGNED PORTABLE"));
    assert_eq!(record.port43.as_deref(), Some("whois.apnic.net"));
    let abuse = record.with_role("abuse").next().expect("abuse");
    assert_eq!(abuse.emails, ["helpdesk@apnic.net"]);
    assert_eq!(
        abuse.address.as_deref(),
        Some("PO Box 3646 South Brisbane, QLD 4101 Australia")
    );
    let registrant = record.with_role("registrant").next().expect("registrant");
    assert_eq!(
        registrant.name.as_deref(),
        Some("APNIC Research and Development")
    );
    assert_eq!(registrant.kind.as_deref(), Some("org"));
}

/// 404 is "not registered there", a TLD the bootstrap does not cover has no registry to ask,
/// and every other failure is typed in the shared taxonomy.
#[test]
fn not_found_no_service_and_failures_are_told_apart() {
    let boot = ("https://data.iana.org/rdap/dns.json", 200, DNS_BOOTSTRAP);
    let answer = lookup_domain(
        &Registry::new(&[boot, ("https://rdap.verisign.com/", 404, "{}")]),
        "no-such-name-zz.com",
    );
    assert_eq!(answer, Ok(Answer::NotFound));
    let answer = lookup_domain(&Registry::new(&[boot]), "example.org");
    assert_eq!(
        answer,
        Ok(Answer::NoService(
            "the IANA bootstrap names no RDAP service for .org".into()
        ))
    );

    let cases = [
        (
            vec![boot, ("https://rdap.verisign.com/", 503, "busy")],
            SourceOutcomeKind::Upstream5xx,
        ),
        (
            vec![boot, ("https://rdap.verisign.com/", 429, "{}")],
            SourceOutcomeKind::RateLimited,
        ),
        (
            vec![boot, ("https://rdap.verisign.com/", 200, "[1]")],
            SourceOutcomeKind::SchemaDrift,
        ),
        (
            vec![("https://data.iana.org/", 200, "not json")],
            SourceOutcomeKind::SchemaDrift,
        ),
        (vec![boot], SourceOutcomeKind::ConnectFailure),
    ];
    for (routes, want) in cases {
        match lookup_domain(&Registry::new(&routes), "github.com") {
            Err(failure) => assert_eq!(failure.kind, want, "{failure:?}"),
            Ok(answer) => panic!("{want:?} accepted: {answer:?}"),
        }
    }
}

#[test]
fn privacy_placeholders_are_recognised() {
    for value in [
        "REDACTED FOR PRIVACY",
        "Data Redacted",
        "Not Disclosed",
        "Withheld for Privacy ehf",
    ] {
        assert!(is_redacted(value), "{value}");
    }
    assert!(!is_redacted("GitHub, Inc."));
}

#[test]
fn rpsl_handles_are_not_names() {
    assert!(is_rpsl_handle("ORG-NCC1-RIPE"));
    assert!(is_rpsl_handle("ORG-ARAD1-AP"));
    assert!(!is_rpsl_handle("ORG Systems Ltd"));
    assert!(!is_rpsl_handle("Google LLC"));
}

/// A structured jCard value, such as an organisation with its unit, keeps every part.
#[test]
fn a_structured_organisation_keeps_its_units() {
    let card: Value = serde_json::from_str(
        r#"["vcard",[["version",{},"text","4.0"],["org",{},"text",["Example Ltd","Network Operations"]],["tel",{"type":"voice"},"uri","tel:+44.2071234567"],["fn",{},"text",""]]]"#,
    )
    .expect("a jCard");
    let contact = vcard(&card);
    assert_eq!(
        contact.org.as_deref(),
        Some("Example Ltd, Network Operations")
    );
    assert_eq!(contact.phones, ["+44.2071234567"]);
    assert_eq!(contact.name, None);
}
