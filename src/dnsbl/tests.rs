use std::collections::BTreeMap;
use std::sync::Mutex;

use super::*;
use crate::http::{Request, Response};

/// A system resolver over a fixed table: a name in it answers its addresses, a name listed as
/// down fails, and any other name does not exist. Every name asked is recorded.
struct Resolver {
    answers: BTreeMap<String, Vec<IpAddr>>,
    down: Vec<&'static str>,
    asked: Mutex<Vec<String>>,
}

impl Resolver {
    /// Every zone answering its test points as RFC 5782 asks.
    fn healthy() -> Self {
        let mut answers = BTreeMap::new();
        for zone in ZONES {
            let (name, answer) = match zone.test_domain {
                Some(domain) => (
                    format!("{domain}.{}", zone.zone),
                    if zone.source == "surbl" {
                        "127.0.0.254"
                    } else {
                        "127.0.1.2"
                    },
                ),
                None => (
                    format!("2.0.0.127.{}", zone.zone),
                    match zone.codes {
                        Codes::Exact(codes) => codes[0].0,
                        Codes::Bits(_) => "127.0.0.8",
                    },
                ),
            };
            answers.insert(name, vec![ip(answer)]);
        }
        Self {
            answers,
            down: Vec::new(),
            asked: Mutex::new(Vec::new()),
        }
    }

    fn with(mut self, name: &str, answers: &[&str]) -> Self {
        self.answers
            .insert(name.to_owned(), answers.iter().map(|a| ip(a)).collect());
        self
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }
}

impl Transport for Resolver {
    fn send(&self, _: &Request) -> Result<Response, TransportFailure> {
        panic!("a blocklist is asked over DNS, not HTTP")
    }

    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, TransportFailure> {
        self.asked.lock().expect("asked").push(name.to_owned());
        if self.down.iter().any(|zone| name.ends_with(zone)) {
            return Err(TransportFailure {
                kind: SourceOutcomeKind::DnsFailure,
                detail: "timed out".into(),
                blocked: false,
            });
        }
        Ok(self.answers.get(name).cloned().unwrap_or_default())
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("address")
}

fn row<'a>(rows: &'a [SourceExecutionOutcome], source: &str) -> &'a SourceExecutionOutcome {
    rows.iter()
        .find(|row| row.module == source)
        .unwrap_or_else(|| panic!("no {source} row in {rows:#?}"))
}

#[test]
fn addresses_and_domains_are_asked_as_each_list_names_them() {
    assert_eq!(reversed_labels(ip("192.0.2.10")), "10.2.0.192");
    assert_eq!(
        reversed_labels(ip("2001:db8::1")),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
    );
    let v4 = Subject::Address(ip("192.0.2.10"));
    let v6 = Subject::Address(ip("2001:db8::1"));
    let domain = Subject::Domain("example.com");
    let zones = |subject: Subject<'_>| -> Vec<&str> {
        ZONES
            .iter()
            .filter(|zone| subject.asked_by(zone))
            .map(|zone| zone.zone)
            .collect()
    };
    assert_eq!(
        zones(v4),
        [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl-1.uceprotect.net",
            "dnsbl-2.uceprotect.net",
            "dnsbl-3.uceprotect.net",
            "dnsbl.dronebl.org",
            "dnsbl.sorbs.net",
            "multi.surbl.org",
        ]
    );
    assert_eq!(zones(v6), ["zen.spamhaus.org", "dnsbl.dronebl.org"]);
    assert_eq!(zones(domain), ["dbl.spamhaus.org", "multi.surbl.org"]);
    assert_eq!(
        domain.query("dbl.spamhaus.org"),
        "example.com.dbl.spamhaus.org"
    );
}

/// A listed address is the list's verdict with its reason, on the address, from that list as its
/// own source; the lists that do not list it say so.
#[test]
fn each_listing_is_kept_with_its_list_zone_answer_and_reason() {
    let resolver = Resolver::healthy()
        .with("10.2.0.192.zen.spamhaus.org", &["127.0.0.2", "127.0.0.4"])
        .with("10.2.0.192.dnsbl.dronebl.org", &["127.0.0.19"])
        .with("10.2.0.192.multi.surbl.org", &["127.0.0.24"]);
    let (entities, rows) = check(&resolver, Subject::Address(ip("192.0.2.10")), "s", 1);

    let spamhaus = row(&rows, "spamhaus");
    assert_eq!(spamhaus.kind, SourceOutcomeKind::Success);
    assert_eq!(
        spamhaus.detail.as_deref(),
        Some("zen.spamhaus.org: listed (127.0.0.2 Spammer, 127.0.0.4 Proxies, Trojans, etc.)")
    );
    assert_eq!(row(&rows, "spamcop").kind, SourceOutcomeKind::ValidZero);
    let uce = row(&rows, "uceprotect");
    assert_eq!(
        uce.detail.as_deref(),
        Some(
            "dnsbl-1.uceprotect.net: not listed; dnsbl-2.uceprotect.net: not listed; \
             dnsbl-3.uceprotect.net: not listed"
        )
    );
    let listings: Vec<(&str, &str)> = entities
        .iter()
        .flat_map(|entity| &entity.evidence)
        .map(|evidence| {
            (
                evidence.provenance.source.as_str(),
                evidence.attributes["dnsbl"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        listings,
        [
            ("spamhaus", "Spamhaus (Zen) - Spammer"),
            ("spamhaus", "Spamhaus (Zen) - Proxies, Trojans, etc."),
            ("dronebl", "dronebl.org - Abused VPN Service"),
            ("surbl", "SURBL - Phishing, Malware"),
        ]
    );
    let first = &entities[0];
    assert_eq!(first.kind, EntityKind::IpAddress);
    assert!(first.has_tag(tags::MALICIOUS));
    assert_eq!(first.evidence[0].attributes["dnsbl_answer"], "127.0.0.2");
    assert_eq!(
        first.evidence[0].attributes["dnsbl_zone"],
        "zen.spamhaus.org"
    );
}

/// A zone that refuses the resolver, misses its test point, lists everything or does not answer
/// is never read as "not listed".
#[test]
fn an_untrustworthy_zone_says_why_instead_of_not_listed() {
    let mut resolver = Resolver::healthy()
        .with("2.0.0.127.zen.spamhaus.org", &["127.255.255.254"])
        .with("2.0.0.127.bl.spamcop.net", &[])
        .with("1.0.0.127.dnsbl.dronebl.org", &["127.0.0.3"])
        .with("10.2.0.192.dnsbl.sorbs.net", &["127.0.0.6"]);
    resolver.down.push("uceprotect.net");
    let (entities, rows) = check(&resolver, Subject::Address(ip("192.0.2.10")), "s", 1);

    let spamhaus = row(&rows, "spamhaus");
    assert_eq!(spamhaus.kind, SourceOutcomeKind::EntitlementDenied);
    assert!(
        spamhaus
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("refuses queries through public or open resolvers")),
        "{spamhaus:?}"
    );
    let spamcop = row(&rows, "spamcop");
    assert_eq!(spamcop.kind, SourceOutcomeKind::Inconclusive);
    assert!(
        spamcop
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("did not list its test point"))
    );
    let dronebl = row(&rows, "dronebl");
    assert!(
        dronebl
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("answers every name"))
    );
    assert_eq!(row(&rows, "uceprotect").kind, SourceOutcomeKind::DnsFailure);
    // The one trustworthy list that lists the address is the only listing.
    assert_eq!(row(&rows, "sorbs").kind, SourceOutcomeKind::Success);
    let sources: Vec<&str> = entities
        .iter()
        .map(|entity| entity.evidence[0].provenance.source.as_str())
        .collect();
    assert_eq!(sources, ["sorbs"]);
    // A refused test point stops the zone: the address itself is not asked there.
    assert!(
        !resolver
            .asked()
            .contains(&"10.2.0.192.zen.spamhaus.org".to_owned())
    );
}

#[test]
fn a_domain_is_asked_of_the_domain_lists_and_an_undocumented_code_is_kept() {
    let resolver = Resolver::healthy()
        .with("bad.example.dbl.spamhaus.org", &["127.0.1.4"])
        .with("bad.example.multi.surbl.org", &["127.0.0.2"]);
    let (entities, rows) = check(&resolver, Subject::Domain("bad.example"), "s", 1);
    assert_eq!(rows.len(), 2);
    let reasons: Vec<&str> = entities
        .iter()
        .flat_map(|entity| &entity.evidence)
        .map(|evidence| evidence.attributes["dnsbl"].as_str())
        .collect();
    assert_eq!(
        reasons,
        [
            "Spamhaus (DBL) - Phishing domain",
            "SURBL - undocumented answer 127.0.0.2",
        ]
    );
    assert!(entities.iter().all(|e| e.kind == EntityKind::Domain));
    assert!(
        !resolver
            .asked()
            .iter()
            .any(|name| name.starts_with("1.0.0.127.")),
        "a domain list has no 127.0.0.1 test point"
    );
}

/// In a saved scan a listing is both of Spiderfoot's elements, with its reason and the address.
#[test]
fn a_saved_scan_lists_the_address_as_blacklisted_and_malicious() {
    let resolver = Resolver::healthy().with("10.2.0.192.zen.spamhaus.org", &["127.0.0.2"]);
    let (entities, _) = check(&resolver, Subject::Address(ip("192.0.2.10")), "s", 1);
    let target = crate::sf_elements::Target {
        value: "192.0.2.10",
        kind: "IP_ADDRESS",
    };
    let found = crate::sf_elements::elements(target, &entities, 1);
    for kind in ["BLACKLISTED_IPADDR", "MALICIOUS_IPADDR"] {
        let element = found
            .iter()
            .find(|element| element.kind == kind)
            .unwrap_or_else(|| panic!("no {kind} in {found:#?}"));
        assert_eq!(element.data, "Spamhaus (Zen) - Spammer [192.0.2.10]");
        assert_eq!(element.module, "spamhaus");
        assert_eq!(element.source.as_ref(), Some(&found[1].id));
    }
}

#[test]
fn a_system_resolver_error_that_names_no_address_is_not_a_failure() {
    for no_address in [
        "failed to lookup address information: Name or service not known",
        "failed to lookup address information: No address associated with hostname",
        "failed to lookup address information: Name does not resolve",
        "failed to lookup address information: nodename nor servname provided, or not known",
    ] {
        assert!(crate::http::names_no_address(no_address), "{no_address}");
    }
    for failure in [
        "failed to lookup address information: Temporary failure in name resolution",
        "failed to lookup address information: Try again",
        "connection refused",
    ] {
        assert!(!crate::http::names_no_address(failure), "{failure}");
    }
}
