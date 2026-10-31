use super::*;
use crate::test_support::RoutedTransport as Registry;

pub(crate) const DNS_BOOTSTRAP: &str = r#"{"services":[[["com","net"],["https://rdap.verisign.com/com/v1/"]],[["uk"],["https://rdap.nominet.uk/uk/"]],[["co.uk"],["http://only-http.test/couk","https://example.test/couk"]]]}"#;
pub(crate) const IPV4_BOOTSTRAP: &str = r#"{"services":[[["1.0.0.0/8"],["https://rdap.apnic.net/"]],[["1.1.0.0/16"],["https://specific.test"]],[["93.0.0.0/8"],["https://rdap.db.ripe.net/"]]]}"#;

pub(crate) const ASN_BOOTSTRAP: &str = r#"{"services":[[["4608-4865","7467-7722"],["https://rdap.apnic.net/"]],[["1-1876","13312-15359"],["https://rdap.arin.net/registry/","http://rdap.arin.net/registry/"]],[["13335"],["https://specific.test/"]],[["2043"],["https://rdap.db.ripe.net/"]]]}"#;
/// Trimmed from ARIN's `AS13335` answer of 2026-10-15: the registrant with its abuse and
/// administrative contacts nested, a top-level abuse contact, events, status and remarks.
pub(crate) const CLOUDFLARE_AS: &str = r#"{"objectClassName":"autnum","handle":"AS13335","name":"CLOUDFLARENET","startAutnum":13335,"endAutnum":13335,"status":["active"],"port43":"whois.arin.net","events":[{"eventAction":"last changed","eventDate":"2017-02-17T18:04:32-05:00"},{"eventAction":"registration","eventDate":"2010-07-14T18:35:57-04:00"}],"remarks":[{"title":"Registration Comments","description":["All Cloudflare abuse reporting can be done via https://www.cloudflare.com/abuse"]}],"entities":[{"handle":"CLOUD14","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Cloudflare, Inc."],["adr",{"label":"101 Townsend Street\nSan Francisco\nCA\n94107\nUnited States"},"text",["","","","","","",""]],["kind",{},"text","org"]]],"entities":[{"handle":"ABUSE2916-ARIN","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["org",{},"text","Cloudflare, Inc."],["kind",{},"text","group"],["email",{},"text","abuse@cloudflare.com"],["tel",{"type":["work","voice"]},"text","+1-650-319-8930"]]]},{"handle":"ADMIN2521-ARIN","roles":["administrative","technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Admin"],["org",{},"text","Cloudflare, Inc."],["kind",{},"text","group"],["email",{},"text","rir@cloudflare.com"],["tel",{"type":["work","voice"]},"text","+1-650-319-8930"]]]}]},{"handle":"ABUSE2916-ARIN","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["org",{},"text","Cloudflare, Inc."],["kind",{},"text","group"],["email",{},"text","abuse@cloudflare.com"],["tel",{"type":["work","voice"]},"text","+1-650-319-8930"]]]}]}"#;

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

/// An AS number's service is the narrowest bootstrap range that holds it; a single number is a
/// range of one.
#[test]
fn an_as_number_is_looked_up_at_the_registry_for_its_range() {
    let asns: Bootstrap = serde_json::from_str(ASN_BOOTSTRAP).expect("bootstrap");
    assert_eq!(
        service_for_asn(&asns, 13335).as_deref(),
        Some("https://specific.test/")
    );
    assert_eq!(
        service_for_asn(&asns, 13336).as_deref(),
        Some("https://rdap.arin.net/registry/")
    );
    assert_eq!(
        service_for_asn(&asns, 4608).as_deref(),
        Some("https://rdap.apnic.net/")
    );
    assert_eq!(
        service_for_asn(&asns, 2043).as_deref(),
        Some("https://rdap.db.ripe.net/")
    );
    assert_eq!(service_for_asn(&asns, 1877), None);
}

#[test]
fn an_as_record_keeps_its_range_name_and_contacts() {
    let registry = Registry::new(&[
        ("https://data.iana.org/rdap/asn.json", 200, ASN_BOOTSTRAP),
        ("https://specific.test/autnum/13335", 200, CLOUDFLARE_AS),
    ]);
    let record = registered(lookup_asn(&registry, 13335, 1));
    assert_eq!(record.handle.as_deref(), Some("AS13335"));
    assert_eq!(record.name.as_deref(), Some("CLOUDFLARENET"));
    assert_eq!(record.autnums, Some((13335, 13335)));
    assert_eq!(record.raw, CLOUDFLARE_AS);
    assert_eq!(
        record.event("registration"),
        Some("2010-07-14T18:35:57-04:00")
    );
    let abuse: Vec<&Contact> = record.with_role("abuse").collect();
    assert!(
        abuse
            .iter()
            .all(|contact| contact.emails == ["abuse@cloudflare.com"])
    );
    let registrant = record.with_role("registrant").next().expect("registrant");
    assert_eq!(registrant.name.as_deref(), Some("Cloudflare, Inc."));

    let unserved = Registry::new(&[("https://data.iana.org/rdap/asn.json", 200, ASN_BOOTSTRAP)]);
    assert!(matches!(
        lookup_asn(&unserved, 1877, 1),
        Ok(Answer::NoService(why)) if why == "the IANA bootstrap names no RDAP service for AS1877"
    ));
    // A registry that writes the range as strings is read the same.
    assert_eq!(autnum(Some(&serde_json::json!("AS64500"))), Some(64500));
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
    let record = registered(lookup_domain(&registry, "GitHub.com.", 1));
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
    let record = registered(lookup_ip(&registry, IpAddr::from([1, 1, 1, 1]), 1));
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
        1,
    );
    assert_eq!(
        answer,
        Ok(Answer::NotFound(
            "https://rdap.verisign.com/com/v1/domain/no-such-name-zz.com".into()
        ))
    );
    let answer = lookup_domain(&Registry::new(&[boot]), "example.org", 1);
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
        // A status is typed as fetch types it.
        (
            vec![boot, ("https://rdap.verisign.com/", 401, "{}")],
            SourceOutcomeKind::AuthRequired,
        ),
        (
            vec![boot, ("https://rdap.verisign.com/", 408, "{}")],
            SourceOutcomeKind::TtfbTimeout,
        ),
        (
            vec![boot, ("https://rdap.verisign.com/", 600, "{}")],
            SourceOutcomeKind::ProtocolDrift,
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
        match lookup_domain(&Registry::new(&routes), "github.com", 1) {
            Err(failure) => assert_eq!(failure.kind, want, "{failure:?}"),
            Ok(answer) => panic!("{want:?} accepted: {answer:?}"),
        }
    }
}

fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    Response {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

/// A blocked egress is a refusal before sending (nothing left for the registry), not a
/// transport failure like the unrouted registry above.
#[test]
fn a_blocked_request_is_refused_before_sending() {
    let failure = lookup_domain(&crate::test_support::Refusing, "github.com", 1)
        .expect_err("a blocked request");
    assert_eq!(failure.kind, SourceOutcomeKind::RefusedBeforeSending);
}

/// A referral that ends in "not registered" names the registry that said so, not the one that
/// referred.
#[test]
fn a_referred_not_found_names_the_registry_that_answered() {
    let registry = crate::test_support::ScriptedTransport::new(vec![
        Ok(reply(200, &[], IPV4_BOOTSTRAP)),
        Ok(reply(
            301,
            &[("Location", "https://rdap.db.ripe.net/ip/1.2.3.4")],
            "",
        )),
        Ok(reply(404, &[], "{}")),
    ]);
    assert_eq!(
        lookup_ip(&registry, IpAddr::from([1, 2, 3, 4]), 1),
        Ok(Answer::NotFound(
            "https://rdap.db.ripe.net/ip/1.2.3.4".into()
        ))
    );
}

/// A regional registry that refers an address to the one holding it: the record names the
/// registry that answered, not the one that redirected.
#[test]
fn a_referred_record_names_the_registry_that_answered() {
    let registry = crate::test_support::ScriptedTransport::new(vec![
        Ok(reply(200, &[], IPV4_BOOTSTRAP)),
        Ok(reply(
            301,
            &[("Location", "https://rdap.db.ripe.net/ip/1.2.3.4")],
            "",
        )),
        Ok(reply(200, &[], APNIC)),
    ]);
    let record = registered(lookup_ip(&registry, IpAddr::from([1, 2, 3, 4]), 1));
    let asked: Vec<String> = registry
        .seen
        .borrow()
        .iter()
        .map(|request| request.url.clone())
        .collect();
    assert_eq!(
        asked,
        [
            "https://data.iana.org/rdap/ipv4.json",
            "https://rdap.apnic.net/ip/1.2.3.4",
            "https://rdap.db.ripe.net/ip/1.2.3.4"
        ]
    );
    assert_eq!(record.url, "https://rdap.db.ripe.net/ip/1.2.3.4");
    assert_eq!(record.raw, APNIC);
}

/// A registry's `Retry-After` on a 429 or 503 reaches the outcome row; an HTTP-date is counted
/// from the scan's clock.
#[test]
fn a_rate_limited_registry_keeps_its_retry_after() {
    let limited = |retry_after: &str, now_unix: u64| {
        let registry = crate::test_support::ScriptedTransport::new(vec![
            Ok(reply(200, &[], DNS_BOOTSTRAP)),
            Ok(reply(429, &[("Retry-After", retry_after)], "{}")),
        ]);
        match lookup_domain(&registry, "github.com", now_unix) {
            Err(failure) => failure,
            Ok(answer) => panic!("a 429 accepted: {answer:?}"),
        }
    };
    let failure = limited("120", 1);
    assert_eq!(failure.kind, SourceOutcomeKind::RateLimited);
    assert_eq!(failure.retry_after_secs, Some(120));
    assert_eq!(failure.outcome(1).retry_after_secs, Some(120));

    // Ninety seconds before Fri, 23 Oct 2026 12:00:00 GMT.
    let failure = limited("Fri, 23 Oct 2026 12:00:00 GMT", 1_792_756_710);
    assert_eq!(failure.outcome(1_792_756_710).retry_after_secs, Some(90));

    // A failure with no answer to read has no delay.
    let failure = lookup_domain(&Registry::new(&[]), "github.com", 1).expect_err("no route");
    assert_eq!(failure.outcome(1).retry_after_secs, None);
}

/// Ninety seconds before Fri, 23 Oct 2026 12:00:00 GMT.
const NOW: u64 = 1_792_756_710;
const IN_NINETY: &str = "Fri, 23 Oct 2026 12:00:00 GMT";

/// Every lookup counts an HTTP-date `Retry-After` from the scan's clock, from the IANA bootstrap
/// and from the registry alike.
#[test]
fn every_lookup_counts_a_dated_retry_after_from_the_scan_clock() {
    let limited = |status: u16| reply(status, &[("Retry-After", IN_NINETY)], "{}");
    type Lookup = fn(&crate::test_support::ScriptedTransport) -> Result<Answer, Failure>;
    let lookups: [(&str, Lookup, &str); 4] = [
        (
            "domain",
            |t| lookup_domain(t, "github.com", NOW),
            DNS_BOOTSTRAP,
        ),
        (
            "ip",
            |t| lookup_ip(t, IpAddr::from([1, 1, 1, 1]), NOW),
            IPV4_BOOTSTRAP,
        ),
        (
            "netblock",
            |t| {
                lookup_netblock(
                    t,
                    crate::netblock::Netblock::parse("1.1.1.0/24").expect("block"),
                    NOW,
                )
            },
            IPV4_BOOTSTRAP,
        ),
        ("asn", |t| lookup_asn(t, 13335, NOW), ASN_BOOTSTRAP),
    ];
    for (name, lookup, bootstrap) in lookups {
        for status in [429, 503] {
            let at_bootstrap =
                crate::test_support::ScriptedTransport::new(vec![Ok(limited(status))]);
            let at_registry = crate::test_support::ScriptedTransport::new(vec![
                Ok(reply(200, &[], bootstrap)),
                Ok(limited(status)),
            ]);
            for (hop, transport) in [("bootstrap", at_bootstrap), ("registry", at_registry)] {
                let failure = lookup(&transport).expect_err("a refusal is no answer");
                assert_eq!(
                    failure.retry_after_secs,
                    Some(90),
                    "{name} {hop} {status}: {failure:?}"
                );
            }
        }
    }
}

/// A status is typed as fetch types it: a 403 without a challenge page is the registry refusing a
/// request that carried no credential, and a 429 is a rate limit with its delay even when its body
/// reads as a challenge.
#[test]
fn a_registry_status_is_typed_as_fetch_types_it() {
    let refused = |status: u16, headers: &[(&str, &str)], body: &str| {
        let registry = crate::test_support::ScriptedTransport::new(vec![
            Ok(reply(200, &[], DNS_BOOTSTRAP)),
            Ok(reply(status, headers, body)),
        ]);
        lookup_domain(&registry, "github.com", 1).expect_err("a refusal is no answer")
    };
    assert_eq!(refused(403, &[], "{}").kind, SourceOutcomeKind::Upstream4xx);
    let challenged = refused(
        429,
        &[("Retry-After", "30")],
        r#"<html><div id="px-captcha"></div></html>"#,
    );
    assert_eq!(challenged.kind, SourceOutcomeKind::RateLimited);
    assert_eq!(challenged.retry_after_secs, Some(30));
    // A challenge page is a wall whatever its status: never "not registered" for a 404 and never a
    // record that does not parse for a 200. A 503 one keeps its delay.
    for status in [403, 404, 200, 503] {
        let walled = refused(
            status,
            &[("Retry-After", "45")],
            r#"<html><div id="px-captcha"></div></html>"#,
        );
        assert_eq!(walled.kind, SourceOutcomeKind::BotWaf, "{status}");
        assert_eq!(walled.detail, "challenge page", "{status}");
        let delay = (status == 503).then_some(45);
        assert_eq!(walled.retry_after_secs, delay, "{status}");
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
