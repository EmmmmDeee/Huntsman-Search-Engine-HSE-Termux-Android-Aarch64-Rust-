use std::collections::BTreeMap;
use std::sync::Mutex;

use super::*;
use crate::dns_wire::tests::{Rdata, answer};
use crate::http::{Method, Response, TransportConfig, TransportFailure, UreqTransport};

/// What one filter answers for one name.
#[derive(Debug, Clone)]
enum Reply {
    /// These addresses, each as an A or AAAA record by its family.
    Addresses(Vec<&'static str>),
    /// This response code and no address, with an extended error when given.
    Code(u8, Option<u16>),
    /// These addresses with this extended error.
    Flagged(Vec<&'static str>, u16),
    /// An HTTP status instead of an answer.
    Http(u16),
    /// Nothing comes back.
    Down,
    /// An answer to a different name.
    Other,
}

/// The resolvers: what the unfiltered ones give each name (none of them answer when `None`),
/// and what a filter answers for a name it is set up for. A filter answers any other name as the
/// unfiltered resolvers do. Every filter question is recorded as (endpoint, name, type).
struct Net {
    unfiltered: Option<BTreeMap<&'static str, Vec<&'static str>>>,
    replies: BTreeMap<(String, &'static str), Reply>,
    asked: Mutex<Vec<(String, String, u16)>>,
}

impl Net {
    /// Every filter blocking its test point the way it says it blocks.
    fn healthy(unfiltered: &[(&'static str, &[&'static str])]) -> Self {
        let mut replies = BTreeMap::new();
        for filter in FILTERS {
            let Some(test) = filter.test else { continue };
            let reply = match filter.signal {
                Signal::Answers(blocks) => Reply::Addresses(vec![blocks[0]]),
                Signal::Coded(codes) => Reply::Addresses(vec![codes[0].0]),
                Signal::NoAddress => Reply::Code(NXDOMAIN, None),
            };
            replies.insert((filter.resolver.endpoint(), test), reply);
        }
        Self {
            unfiltered: Some(
                unfiltered
                    .iter()
                    .map(|(name, addresses)| (*name, addresses.to_vec()))
                    .collect(),
            ),
            replies,
            asked: Mutex::new(Vec::new()),
        }
    }

    fn with(mut self, endpoint: &str, name: &'static str, reply: Reply) -> Self {
        self.replies.insert((endpoint.to_owned(), name), reply);
        self
    }

    fn asked(&self) -> Vec<(String, String, u16)> {
        self.asked.lock().expect("asked").clone()
    }

    /// The unfiltered resolvers' JSON answer to `?name=…&type=…`.
    fn json(&self, url: &str) -> Result<Response, TransportFailure> {
        let Some(unfiltered) = &self.unfiltered else {
            return Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "refused".into(),
                blocked: false,
            });
        };
        let param = |key: &str| {
            url.split(['?', '&'])
                .find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
                .unwrap_or_default()
                .to_owned()
        };
        let (name, kind) = (param("name"), param("type"));
        let body = match unfiltered.get(name.as_str()) {
            None => r#"{"Status":3}"#.to_owned(),
            Some(addresses) => {
                let code = if kind == "AAAA" { 28 } else { 1 };
                let records: Vec<String> = addresses
                    .iter()
                    .filter(|a| a.contains(':') == (code == 28))
                    .map(|a| format!(r#"{{"type":{code},"data":"{a}"}}"#))
                    .collect();
                format!(r#"{{"Status":0,"Answer":[{}]}}"#, records.join(","))
            }
        };
        Ok(Response {
            status: 200,
            headers: vec![("content-type".into(), "application/dns-json".into())],
            body: body.into_bytes(),
            truncated: false,
        })
    }

    /// A filter's answer to the wire-form `query` sent to `endpoint`.
    fn wire(&self, endpoint: &str, query: &[u8]) -> Result<Result<Vec<u8>, u16>, TransportFailure> {
        let asked = dns_wire::question(query).expect("a question");
        self.asked.lock().expect("asked").push((
            endpoint.to_owned(),
            asked.name.clone(),
            asked.kind,
        ));
        let unfiltered = || {
            let known = self
                .unfiltered
                .as_ref()
                .and_then(|unfiltered| unfiltered.get(asked.name.as_str()));
            known.map_or(Reply::Code(NXDOMAIN, None), |addresses| {
                Reply::Addresses(
                    addresses
                        .iter()
                        .copied()
                        .filter(|a| a.contains(':') == (asked.kind == AAAA))
                        .collect(),
                )
            })
        };
        let reply = self
            .replies
            .iter()
            .find(|((at, name), _)| at == endpoint && name.eq_ignore_ascii_case(&asked.name))
            .map_or_else(unfiltered, |(_, reply)| reply.clone());
        let records = |addresses: &[&'static str]| -> Vec<(u16, Rdata<'static>)> {
            addresses
                .iter()
                .map(|a| (if a.contains(':') { AAAA } else { A }, Rdata::Address(a)))
                .collect()
        };
        Ok(Ok(match reply {
            Reply::Addresses(addresses) => answer(query, NOERROR, &records(&addresses), None),
            Reply::Code(rcode, extended) => answer(query, rcode, &[], extended.map(|c| (c, ""))),
            Reply::Flagged(addresses, code) => {
                answer(query, NOERROR, &records(&addresses), Some((code, "")))
            }
            Reply::Http(status) => return Ok(Err(status)),
            Reply::Down => {
                return Err(TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "connection refused".into(),
                    blocked: false,
                });
            }
            Reply::Other => {
                let other = dns_wire::query(0, "other.example", A).expect("query");
                answer(&other, NOERROR, &[(A, Rdata::Address("192.0.2.1"))], None)
            }
        }))
    }
}

impl Transport for Net {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.method == Method::Get {
            return self.json(&request.url);
        }
        assert_eq!(
            request.header_value("content-type"),
            Some("application/dns-message")
        );
        let endpoint = request.url.trim_start_matches("https://");
        Ok(match self.wire(endpoint, &request.body)? {
            Ok(body) => Response {
                status: 200,
                headers: vec![("content-type".into(), "application/dns-message".into())],
                body,
                truncated: false,
            },
            Err(status) => Response {
                status,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            },
        })
    }

    fn exchange_udp(
        &self,
        server: SocketAddr,
        message: &[u8],
    ) -> Result<Vec<u8>, TransportFailure> {
        assert_eq!(server.port(), 53);
        self.wire(&server.ip().to_string(), message)?
            .map_err(|_| panic!("UDP has no HTTP status"))
    }
}

/// The filters asked about `name`, against what the unfiltered resolvers say.
fn run(net: &Net, name: &str) -> (Vec<Entity>, Vec<SourceExecutionOutcome>) {
    check(net, name, &Unfiltered::ask(net, name), "s", 1)
}

fn row<'a>(rows: &'a [SourceExecutionOutcome], source: &str) -> &'a SourceExecutionOutcome {
    rows.iter()
        .find(|row| row.module == source)
        .unwrap_or_else(|| panic!("no {source} row in {rows:#?}"))
}

fn detail(rows: &[SourceExecutionOutcome], source: &str) -> String {
    row(rows, source).detail.clone().unwrap_or_default()
}

/// A blocked egress refuses every filter before sending, over `DoH` (`send`) and UDP
/// (`exchange_udp`) alike: each row is `refused_before_sending`, not `valid_zero` or a transport
/// failure, and the refusal never aborts the fan-out.
#[test]
fn a_blocked_egress_refuses_every_filter_before_sending() {
    let net = crate::test_support::Refusing;
    let (entities, rows) = check(
        &net,
        "example.com",
        &Unfiltered::ask(&net, "example.com"),
        "s",
        1,
    );
    assert!(entities.is_empty());
    assert!(!rows.is_empty());
    assert!(
        rows.iter()
            .all(|row| row.kind == SourceOutcomeKind::RefusedBeforeSending),
        "{rows:#?}"
    );
}

const SECURITY: &str = "security.cloudflare-dns.com/dns-query";
const FAMILY: &str = "family.cloudflare-dns.com/dns-query";
const ADGUARD: &str = "dns.adguard-dns.com/dns-query";
const CLEAN_SECURITY: &str = "doh.cleanbrowsing.org/doh/security-filter/";
const CLEAN_ADULT: &str = "doh.cleanbrowsing.org/doh/adult-filter/";
const CLEAN_FAMILY: &str = "doh.cleanbrowsing.org/doh/family-filter/";
const FOR_FAMILY: &str = "94.130.180.225";
const OPENDNS: &str = "doh.familyshield.opendns.com/dns-query";
const QUAD9: &str = "9.9.9.9";
const YANDEX: &str = "77.88.8.7";
const COMODO: &str = "8.26.56.26";

#[test]
fn a_name_no_filter_blocks_is_one_row_per_source_after_each_test_point() {
    let net = Net::healthy(&[("example.com", &["192.0.2.80"])]);
    let (entities, rows) = run(&net, "example.com");
    assert!(entities.is_empty());
    let sources: Vec<&str> = rows.iter().map(|row| row.module.as_str()).collect();
    assert_eq!(
        sources,
        [
            "adguard_dns",
            "cleanbrowsing",
            "cloudflaredns",
            "comodo",
            "dns_for_family",
            "opendns",
            "quad9",
            "yandexdns"
        ]
    );
    assert!(
        rows.iter()
            .all(|row| row.kind == SourceOutcomeKind::ValidZero)
    );
    assert_eq!(
        detail(&rows, "cloudflaredns"),
        format!("{SECURITY}: not blocked (192.0.2.80); {FAMILY}: not blocked (192.0.2.80)")
    );
    let asked = net.asked();
    for filter in FILTERS {
        let endpoint = filter.resolver.endpoint();
        let mine: Vec<&str> = asked
            .iter()
            .filter(|(at, _, _)| *at == endpoint)
            .map(|(_, name, _)| name.as_str())
            .collect();
        let expected: Vec<&str> = filter.test.into_iter().chain(["example.com"]).collect();
        assert_eq!(mine, expected, "{endpoint}");
    }
    assert!(asked.iter().all(|(_, _, kind)| *kind == A));
}

/// Each filter's block reads as it answers it: its own address (including the `0.0.0.0` that
/// `AdGuard`'s default filter and DNS for Family answer now), an `OpenDNS` or Yandex address that
/// names the reason, no address for a name that resolves elsewhere, or an extended error.
#[test]
fn each_filter_block_is_kept_with_its_reason_answer_and_records() {
    let name = "bad.example";
    let net = Net::healthy(&[(name, &["198.51.100.7"])])
        .with(ADGUARD, name, Reply::Addresses(vec!["0.0.0.0"]))
        .with(CLEAN_SECURITY, name, Reply::Code(NXDOMAIN, None))
        .with(SECURITY, name, Reply::Flagged(vec!["0.0.0.0"], 16))
        .with(COMODO, name, Reply::Code(NOERROR, None))
        .with(FOR_FAMILY, name, Reply::Addresses(vec!["0.0.0.0"]))
        .with(OPENDNS, name, Reply::Addresses(vec!["146.112.61.108"]))
        .with(QUAD9, name, Reply::Code(NXDOMAIN, Some(17)))
        .with(YANDEX, name, Reply::Addresses(vec!["93.158.134.250"]));
    let (entities, rows) = run(&net, name);

    // One block per filter, each on the name; a threat filter's block marks it malicious.
    assert!(
        entities
            .iter()
            .all(|e| e.kind == EntityKind::Domain && e.value == name && e.evidence.len() == 1)
    );
    let malicious: Vec<bool> = entities
        .iter()
        .map(|e| e.has_tag(tags::MALICIOUS))
        .collect();
    assert_eq!(
        malicious,
        [false, true, true, true, false, true, true, false]
    );
    let evidence: Vec<&Evidence> = entities.iter().flat_map(|e| &e.evidence).collect();
    let blocks: Vec<(&str, &str, &str, &str)> = evidence
        .iter()
        .map(|e| {
            (
                e.provenance.source.as_str(),
                e.attributes["dns_filter"].as_str(),
                e.attributes["dns_filter_answer"].as_str(),
                e.attributes["dns_filter_threat"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        blocks,
        [
            (
                "adguard_dns",
                "AdGuard - Default Filter",
                "0.0.0.0",
                "false"
            ),
            (
                "cleanbrowsing",
                "CleanBrowsing DNS - Security",
                "NXDOMAIN",
                "true"
            ),
            ("cloudflaredns", "CloudFlare - Malware", "0.0.0.0", "true"),
            ("comodo", "Comodo Secure DNS", "no address", "true"),
            ("dns_for_family", "DNS for Family", "0.0.0.0", "false"),
            ("opendns", "OpenDNS - Phishing", "146.112.61.108", "true"),
            ("quad9", "Quad9", "NXDOMAIN", "true"),
            ("yandexdns", "Yandex - Adult", "93.158.134.250", "false"),
        ]
    );
    let by = |source: &str| {
        evidence
            .iter()
            .find(|e| e.provenance.source == source)
            .expect("evidence")
    };
    let cloudflare = by("cloudflaredns");
    assert_eq!(
        cloudflare.attributes["dns_filter_extended_error"],
        "16 Censored"
    );
    assert_eq!(
        cloudflare.attributes["dns_filter_records"],
        "bad.example A 0.0.0.0"
    );
    assert_eq!(cloudflare.attributes["dns_filter_resolver"], SECURITY);
    assert_eq!(cloudflare.attributes["blocklists"], "CloudFlare - Malware");
    assert_eq!(
        by("cleanbrowsing").attributes["dns_filter_resolves_elsewhere"],
        "198.51.100.7"
    );
    assert_eq!(
        by("quad9").attributes["dns_filter_extended_error"],
        "17 Filtered"
    );
    assert!(!by("yandexdns").attributes.contains_key("blocklists"));
    assert_eq!(row(&rows, "cloudflaredns").kind, SourceOutcomeKind::Success);
    assert_eq!(
        detail(&rows, "cloudflaredns"),
        format!(
            "{SECURITY}: blocked as CloudFlare - Malware (0.0.0.0); {FAMILY}: not blocked (198.51.100.7)"
        )
    );
}

/// A filter that misses its test point, answers an error, answers another question or cannot be
/// reached is never read as "not blocked".
#[test]
fn an_untrustworthy_filter_says_why_instead_of_not_blocked() {
    let name = "example.org";
    let net = Net::healthy(&[(name, &["192.0.2.9"])])
        .with(
            ADGUARD,
            "doubleclick.net",
            Reply::Addresses(vec!["192.0.2.66"]),
        )
        .with(SECURITY, name, Reply::Code(2, None))
        .with(FAMILY, name, Reply::Http(503))
        .with(OPENDNS, name, Reply::Other)
        .with(CLEAN_SECURITY, "internetbadguys.com", Reply::Down)
        .with(CLEAN_ADULT, "exampleadultsite.com", Reply::Down)
        .with(CLEAN_FAMILY, "exampleadultsite.com", Reply::Down)
        // A network that answers port 53 itself answers the test point as any resolver would.
        .with(
            QUAD9,
            "isitblocked.org",
            Reply::Addresses(vec!["192.0.2.33"]),
        )
        .with(COMODO, name, Reply::Down);
    let (entities, rows) = run(&net, name);
    assert!(entities.is_empty());
    let adguard = detail(&rows, "adguard_dns");
    assert!(
        adguard.starts_with(&format!(
            "{ADGUARD}: did not block its test point doubleclick.net (answered 192.0.2.66)"
        )),
        "{adguard}"
    );
    // Its family filter not blocking the name says nothing of its default filter.
    assert_eq!(
        row(&rows, "adguard_dns").kind,
        SourceOutcomeKind::Inconclusive
    );
    assert_eq!(
        detail(&rows, "cloudflaredns"),
        format!("{SECURITY}: answered SERVFAIL; {FAMILY}: HTTP 503")
    );
    assert_eq!(
        row(&rows, "cloudflaredns").kind,
        SourceOutcomeKind::Inconclusive
    );
    assert_eq!(
        detail(&rows, "opendns"),
        format!("{OPENDNS}: answered another question")
    );
    let cleanbrowsing = row(&rows, "cleanbrowsing");
    assert_eq!(cleanbrowsing.kind, SourceOutcomeKind::ConnectFailure);
    assert!(detail(&rows, "cleanbrowsing").contains("no answer"));
    assert_eq!(
        detail(&rows, "quad9"),
        format!("{QUAD9}: did not block its test point isitblocked.org (answered 192.0.2.33)")
    );
    // Comodo's first server is down; its second answers, unverified for want of a test point,
    // though DNS for Family blocking its own shows UDP reaches the filters.
    assert_eq!(row(&rows, "comodo").kind, SourceOutcomeKind::ValidZero);
    assert_eq!(
        detail(&rows, "comodo"),
        format!(
            "{COMODO}: not blocked (192.0.2.9); unverified, no known test point, though UDP \
             reaches the filters (dns_for_family blocked its test point)"
        )
    );
    assert!(
        net.asked()
            .iter()
            .any(|(at, asked, _)| at == "8.20.247.20" && asked == name)
    );
}

/// A source says "not blocked" only when every filter of it asked says so: Cloudflare's family
/// filter not blocking a name says nothing of its malware filter, which did not answer, so the
/// row is inconclusive, not a clean negative.
#[test]
fn a_source_one_of_whose_filters_did_not_answer_is_no_clean_negative() {
    let name = "example.org";
    let net = Net::healthy(&[(name, &["192.0.2.9"])]).with(SECURITY, name, Reply::Http(503));
    let (entities, rows) = run(&net, name);
    assert!(entities.is_empty());
    assert_eq!(
        row(&rows, "cloudflaredns").kind,
        SourceOutcomeKind::Inconclusive
    );
    assert_eq!(
        detail(&rows, "cloudflaredns"),
        format!("{SECURITY}: HTTP 503; {FAMILY}: not blocked (192.0.2.9)")
    );
    // The sources whose every filter answered stand.
    assert_eq!(
        row(&rows, "cleanbrowsing").kind,
        SourceOutcomeKind::ValidZero
    );
}

/// A network that answers UDP port 53 itself answers every filter asked over UDP: each with a test
/// point misses it, and Comodo's answer, block or not, is kept but not read as its verdict.
#[test]
fn a_network_answering_port_53_itself_is_no_filters_verdict() {
    let name = "example.org";
    let mut net =
        Net::healthy(&[(name, &["192.0.2.9"])]).with(COMODO, name, Reply::Code(NXDOMAIN, None));
    for (endpoint, test) in [
        (QUAD9, "isitblocked.org"),
        (FOR_FAMILY, "exampleadultsite.com"),
        (YANDEX, "pornhub.com"),
    ] {
        net = net.with(endpoint, test, Reply::Addresses(vec!["192.0.2.33"]));
    }
    let (entities, rows) = run(&net, name);
    assert!(entities.is_empty(), "{entities:#?}");
    for source in ["quad9", "dns_for_family", "yandexdns", "comodo"] {
        assert_eq!(
            row(&rows, source).kind,
            SourceOutcomeKind::Inconclusive,
            "{source}"
        );
    }
    assert_eq!(
        detail(&rows, "comodo"),
        format!(
            "{COMODO}: answered blocked (NXDOMAIN), untrusted: no filter asked over UDP blocked \
             its test point, so this network may answer port 53 itself"
        )
    );
    // The filters asked over HTTPS are not the network's answer, and stand.
    assert_eq!(
        row(&rows, "cloudflaredns").kind,
        SourceOutcomeKind::ValidZero
    );
}

/// Without the unfiltered resolvers a missing answer cannot be read as a block, unless the filter
/// says it filtered the name; a name no resolver resolves is not blocked by having no address.
#[test]
fn a_missing_answer_is_a_block_only_against_a_name_that_resolves() {
    let mut net = Net::healthy(&[])
        .with(QUAD9, "gone.example", Reply::Code(NXDOMAIN, Some(17)))
        .with(CLEAN_SECURITY, "gone.example", Reply::Code(NXDOMAIN, None));
    let (entities, rows) = run(&net, "gone.example");
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].evidence.len(), 1);
    assert_eq!(entities[0].evidence[0].provenance.source, "quad9");
    assert!(detail(&rows, "cleanbrowsing").contains("NXDOMAIN; no resolver resolves it"));

    net.unfiltered = None;
    let (_, rows) = run(&net, "gone.example");
    assert!(
        detail(&rows, "cleanbrowsing")
            .contains("the unfiltered resolvers did not answer to compare"),
        "{rows:#?}"
    );
    assert_eq!(row(&rows, "quad9").kind, SourceOutcomeKind::Success);
}

#[test]
fn a_name_with_only_ipv6_addresses_is_asked_for_them() {
    let name = "v6.example";
    let net =
        Net::healthy(&[(name, &["2001:db8::5"])]).with(FAMILY, name, Reply::Addresses(vec!["::"]));
    let (entities, rows) = run(&net, name);
    assert_eq!(
        entities[0].evidence[0].attributes["dns_filter"],
        "CloudFlare - Family"
    );
    assert_eq!(
        entities[0].evidence[0].attributes["dns_filter_answer"],
        "::"
    );
    assert!(!entities[0].has_tag(tags::MALICIOUS));
    assert!(detail(&rows, "quad9").contains("not blocked (2001:db8::5)"));
    let kinds: Vec<u16> = net
        .asked()
        .into_iter()
        .filter(|(_, asked, _)| asked == name)
        .map(|(_, _, kind)| kind)
        .collect();
    assert_eq!(kinds.len(), FILTERS.len());
    assert!(kinds.iter().all(|kind| *kind == AAAA));
}

/// In a saved scan every block is Spiderfoot's blacklisted element, and a threat filter's block
/// its malicious element too.
#[test]
fn a_saved_scan_lists_each_block_as_blacklisted_and_threats_as_malicious() {
    let name = "bad.example";
    let net = Net::healthy(&[(name, &["198.51.100.7"])])
        .with(SECURITY, name, Reply::Addresses(vec!["0.0.0.0"]))
        .with(YANDEX, name, Reply::Addresses(vec!["93.158.134.250"]));
    let (entities, _) = run(&net, name);
    let target = crate::sf_elements::Target {
        value: name,
        kind: "INTERNET_NAME",
    };
    let found = crate::sf_elements::elements(target, &entities, 1);
    let of = |kind: &str| -> Vec<&str> {
        found
            .iter()
            .filter(|element| element.kind == kind)
            .map(|element| element.data.as_str())
            .collect()
    };
    assert_eq!(
        of("BLACKLISTED_INTERNET_NAME"),
        [
            "CloudFlare - Malware [bad.example]",
            "Yandex - Adult [bad.example]"
        ]
    );
    assert_eq!(
        of("MALICIOUS_INTERNET_NAME"),
        ["CloudFlare - Malware [bad.example]"]
    );
}

/// The real transport sends no UDP to an address the egress policy refuses, and a transport
/// without UDP fails every exchange.
#[test]
fn udp_goes_only_where_the_egress_policy_allows() {
    let transport = UreqTransport::new(&TransportConfig::default());
    let refused = transport
        .exchange_udp("10.0.0.1:53".parse().expect("addr"), b"x")
        .expect_err("refused");
    assert!(refused.blocked, "{refused:?}");
    let none = crate::test_support::ScriptedTransport::new(Vec::new())
        .exchange_udp("192.0.2.1:53".parse().expect("addr"), b"x")
        .expect_err("no UDP");
    assert!(!none.blocked);
    assert_eq!(none.kind, SourceOutcomeKind::ConnectFailure);
}

/// A domain lookup's own records stand for the unfiltered resolvers, so the domain is not asked
/// twice: its IPv4 addresses, else its IPv6 ones, else nowhere, unless a resolver failed.
#[test]
fn a_domain_lookups_own_records_are_its_unfiltered_answer() {
    use crate::dns::{QueryAnswer, QueryFailure, ResolveAnswer, ResolveError, resolver_config};
    let answer = |record_type, records: &[&str]| QueryAnswer {
        name: "example.com".into(),
        record_type,
        answer: ResolveAnswer {
            server: resolver_config().name_servers[0].clone(),
            records: records.iter().map(|r| (*r).to_owned()).collect(),
        },
    };
    let failure = |record_type, kind| QueryFailure {
        name: "example.com".into(),
        record_type,
        error: ResolveError {
            kind,
            detail: "timed out".into(),
        },
    };
    let records = |answers, failures| DomainDns {
        domain: "example.com".into(),
        answers,
        failures,
        spf: None,
        dmarc: None,
        tlsrpt: None,
    };
    let ip = |text: &str| text.parse::<IpAddr>().expect("ip");
    let both = records(
        vec![
            answer(RecordType::Aaaa, &["2001:db8::1"]),
            answer(RecordType::A, &["192.0.2.1"]),
            answer(RecordType::Mx, &["10 mx.example.com."]),
        ],
        Vec::new(),
    );
    assert_eq!(
        Unfiltered::from_records(&both),
        Unfiltered::Resolves(vec![ip("192.0.2.1")])
    );
    let v6 = records(
        vec![answer(RecordType::Aaaa, &["2001:db8::1"])],
        vec![failure(RecordType::A, ResolveErrorKind::Empty)],
    );
    assert_eq!(Unfiltered::from_records(&v6).kind(), AAAA);
    let gone = records(
        Vec::new(),
        vec![
            failure(RecordType::A, ResolveErrorKind::Empty),
            failure(RecordType::Aaaa, ResolveErrorKind::Empty),
        ],
    );
    assert_eq!(Unfiltered::from_records(&gone), Unfiltered::Nowhere);
    let down = records(
        Vec::new(),
        vec![failure(RecordType::A, ResolveErrorKind::Timeout)],
    );
    assert_eq!(
        Unfiltered::from_records(&down),
        Unfiltered::Unanswered("timed out".into())
    );
}
