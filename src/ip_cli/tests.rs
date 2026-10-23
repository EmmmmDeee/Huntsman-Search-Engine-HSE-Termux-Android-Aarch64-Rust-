use std::sync::Mutex;

use super::*;
use crate::http::{Request, Response, TransportFailure};
use crate::source_outcome::SourceOutcomeKind;

/// Every IP leg for `ip`, with no threat feed consulted: the feeds' own tests cover them.
fn run<T: Transport + ?Sized>(transport: &T, keys: &Keys, ip: &str, now_unix: u64) -> IpRun {
    super::run(transport, keys, &Feeds::none(), ip, now_unix)
}

const ABUSE_KEY: &str = "abuse-test-key-0123456789abcdef";
const VT_KEY: &str = "vt-test-key-0123456789abcdef0123";

const INTERNETDB: &str = r#"{"cpes":["cpe:/a:cloudflare:cloudflare"],"hostnames":["one.one.one.one"],"ip":"1.1.1.1","ports":[53,443],"tags":["cdn"],"vulns":["CVE-2023-0001"]}"#;
const RIPESTAT: &str = r#"{"status":"ok","data":{"announced":true,"asns":[{"asn":13335,"holder":"CLOUDFLARENET - Cloudflare, Inc."}],"resource":"1.1.1.0/24","block":{"desc":"APNIC (Status: ALLOCATED)"}}}"#;
const RIPESTAT_GEO: &str = r#"{"status":"ok","data":{"located_resources":[{"resource":"1.1.1.1","locations":[{"country":"AU","city":"Sydney","latitude":-33.87,"longitude":151.21,"covered_percentage":100.0}]}]}}"#;
const GREYNOISE_UNSEEN: &str = r#"{"ip":"1.1.1.1","noise":false,"riot":false,"message":"IP not observed scanning the internet."}"#;
const ABUSEIPDB: &str = r#"{"data":{"ipAddress":"1.1.1.1","abuseConfidenceScore":75,"countryCode":"AU","usageType":"Content Delivery Network","isp":"Cloudflare, Inc.","domain":"cloudflare.com","hostnames":[],"isTor":false,"isWhitelisted":false,"totalReports":12,"numDistinctUsers":5,"lastReportedAt":"2026-10-01T00:00:00+00:00"}}"#;
const VIRUSTOTAL: &str = r#"{"data":{"id":"1.1.1.1","type":"ip_address","attributes":{"last_analysis_stats":{"harmless":60,"malicious":1,"suspicious":0,"undetected":30},"reputation":5,"asn":13335,"as_owner":"CLOUDFLARENET","network":"1.1.1.0/24","country":"AU"}}}"#;

const PULSEDIVE_UNKNOWN: &str = r#"{"error":"Indicator not found."}"#;
const SHODAN: &str = r#"{"ip_str":"1.1.1.1","ports":[53,443],"hostnames":["one.one.one.one"],"domains":["one.one"],"org":"APNIC Research and Development","isp":"Cloudflare, Inc.","asn":"AS13335","tags":[],"country_code":"AU"}"#;
const URLSCAN_NONE: &str = r#"{"results":[],"total":0,"took":49,"has_more":false}"#;
const IPINFO: &str = r#"{"ip":"1.1.1.1","hostname":"one.one.one.one","city":"Brisbane","region":"Queensland","country":"AU","loc":"-27.4820,153.0136","org":"AS13335 Cloudflare, Inc.","postal":"9010","anycast":true}"#;
const SHODAN_KEY: &str = "shodan-test-key-0123456789abcdef";
/// The address's reverse zone, as the DNS JSON API answers its PTR query.
const PTR: &str = r#"{"Status":0,"Answer":[{"name":"1.1.1.1.in-addr.arpa.","type":12,"data":"one.one.one.one."}]}"#;

/// Answers by URL prefix and records every request.
struct Routes {
    routes: Vec<(&'static str, u16, &'static str)>,
    sent: Mutex<Vec<Request>>,
}

impl Routes {
    fn new(routes: Vec<(&'static str, u16, &'static str)>) -> Self {
        Self {
            routes,
            sent: Mutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<Request> {
        match self.sent.lock() {
            Ok(sent) => sent.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn hosts(&self) -> Vec<String> {
        self.sent()
            .iter()
            .map(|r| {
                r.url
                    .trim_start_matches("https://")
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }
}

impl Transport for Routes {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        match self.sent.lock() {
            Ok(mut sent) => sent.push(request.clone()),
            Err(poisoned) => poisoned.into_inner().push(request.clone()),
        }
        let Some((_, status, body)) = self
            .routes
            .iter()
            .find(|(prefix, _, _)| request.url.starts_with(prefix))
        else {
            return Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "no route".into(),
                blocked: false,
            });
        };
        Ok(Response {
            status: *status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        })
    }
}

fn keyless() -> Routes {
    Routes::new(vec![
        ("https://cloudflare-dns.com/", 200, PTR),
        (
            "https://data.iana.org/rdap/ipv4.json",
            200,
            r#"{"services":[[["1.0.0.0/8"],["https://rdap.apnic.net/"]]]}"#,
        ),
        (
            "https://rdap.apnic.net/ip/1.1.1.1",
            200,
            crate::rdap::tests::APNIC,
        ),
        ("https://internetdb.shodan.io/", 200, INTERNETDB),
        ("https://stat.ripe.net/data/geoloc/", 200, RIPESTAT_GEO),
        ("https://stat.ripe.net/", 200, RIPESTAT),
        ("https://api.greynoise.io/", 404, GREYNOISE_UNSEEN),
        ("https://api.abuseipdb.com/", 200, ABUSEIPDB),
        ("https://www.virustotal.com/", 200, VIRUSTOTAL),
        ("https://pulsedive.com/", 404, PULSEDIVE_UNKNOWN),
        (
            "https://app.netlas.io/",
            200,
            r#"{"ip":"1.1.1.1","type":"ip","domains":[],"domains_count":0,"source":[]}"#,
        ),
        (
            "https://otx.alienvault.com/",
            200,
            r#"{"indicator":"1.1.1.1","pulse_info":{"count":0,"pulses":[]},"validation":[]}"#,
        ),
        ("https://urlscan.io/", 200, URLSCAN_NONE),
        ("https://ipinfo.io/", 200, IPINFO),
        (
            "https://freeapi.robtex.com/",
            200,
            r#"{"status":"ok","pas":[]}"#,
        ),
        ("https://api.hackertarget.com/", 200, "No records found"),
        (
            "https://api.stopforumspam.org/",
            200,
            r#"{"success":1,"ip":{"value":"1.1.1.1","appears":0,"frequency":0}}"#,
        ),
        (
            "https://isc.sans.edu/",
            200,
            r#"{"ip":{"number":"1.1.1.1","count":null,"attacks":null}}"#,
        ),
        ("https://api.maltiverse.com/", 404, "{}"),
        ("https://api.phishstats.info/", 200, "[]"),
        ("https://api.shodan.io/", 200, SHODAN),
        (
            "https://api.mnemonic.no/",
            200,
            r#"{"responseCode":200,"count":0,"data":[]}"#,
        ),
    ])
}

fn keys() -> Keys {
    let text = format!(
        "{}={ABUSE_KEY}\n{}={VT_KEY}\n",
        abuseipdb::KEY_SLOT,
        virustotal::KEY_SLOT
    );
    match Keys::parse(&text) {
        Ok(keys) => keys,
        Err(error) => panic!("fixture keys parse: {error}"),
    }
}

fn printed(run: IpRun) -> (String, Report) {
    match run {
        IpRun::Printed { text, report } => (text, report),
        IpRun::Network(m) => panic!("network: {m}"),
        IpRun::Failed(m) => panic!("failed: {m}"),
    }
}

fn entity<'a>(report: &'a Report, kind: &EntityKind, value: &str) -> &'a Entity {
    report
        .entities
        .iter()
        .find(|e| e.kind == *kind && e.raw_value == value)
        .unwrap_or_else(|| panic!("no {kind:?} {value}"))
}

fn outcome(report: &Report, source: &str) -> SourceOutcomeKind {
    report
        .outcomes
        .iter()
        .find(|o| o.module == source)
        .map_or_else(|| panic!("no outcome for {source}"), |o| o.kind)
}

#[test]
fn keyless_legs_run_without_keys_and_keyed_legs_send_nothing() {
    let transport = keyless();
    let (text, report) = printed(run(&transport, &Keys::default(), "1.1.1.1", 1));
    assert_eq!(
        transport.hosts(),
        [
            "cloudflare-dns.com",
            "data.iana.org",
            "rdap.apnic.net",
            "api.mnemonic.no",
            "internetdb.shodan.io",
            "stat.ripe.net",
            "stat.ripe.net",
            "api.greynoise.io",
            "pulsedive.com",
            "app.netlas.io",
            "otx.alienvault.com",
            "urlscan.io",
            "ipinfo.io",
            "freeapi.robtex.com",
            "api.hackertarget.com",
            "api.stopforumspam.org",
            "isc.sans.edu",
            "api.maltiverse.com",
            "api.phishstats.info"
        ]
    );
    assert_eq!(outcome(&report, "internetdb"), SourceOutcomeKind::Success);
    assert_eq!(outcome(&report, "ripestat"), SourceOutcomeKind::Success);
    assert_eq!(outcome(&report, "greynoise"), SourceOutcomeKind::ValidZero);
    assert_eq!(outcome(&report, "pulsedive"), SourceOutcomeKind::ValidZero);
    assert_eq!(outcome(&report, "netlas"), SourceOutcomeKind::ValidZero);
    assert_eq!(outcome(&report, "otx"), SourceOutcomeKind::ValidZero);
    assert_eq!(outcome(&report, "urlscan"), SourceOutcomeKind::ValidZero);
    assert_eq!(outcome(&report, "ipinfo"), SourceOutcomeKind::Success);
    for source in [
        "robtex",
        "hackertarget",
        "stopforumspam",
        "isc",
        "maltiverse",
        "phishstats",
    ] {
        assert_eq!(outcome(&report, source), SourceOutcomeKind::ValidZero);
    }
    assert_eq!(outcome(&report, RESOLVE_SOURCE), SourceOutcomeKind::Success);
    assert_eq!(outcome(&report, "rdap"), SourceOutcomeKind::Success);
    assert_eq!(outcome(&report, "mnemonic"), SourceOutcomeKind::ValidZero);
    // The DNS blocklists are keyless and always asked; this transport has no system resolver.
    for source in [
        "spamhaus",
        "spamcop",
        "uceprotect",
        "dronebl",
        "sorbs",
        "surbl",
    ] {
        assert_eq!(
            outcome(&report, source),
            SourceOutcomeKind::DnsFailure,
            "{source}"
        );
    }
    assert_eq!(report.outcomes.len(), 23, "an unkeyed leg reports nothing");

    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(ip.has_tag(tags::VULNERABLE));
    let sources = ip.evidence_sources();
    assert!(sources.contains("internetdb") && sources.contains("ripestat"));
    // The extra geoloc request adds target evidence but not an extra success
    // outcome row for the same RIPEstat provider.
    assert!(ip.evidence.iter().any(|evidence| {
        evidence.provenance.source == "ripestat"
            && evidence
                .attributes
                .get("locations")
                .is_some_and(|locations| locations == "AU Sydney at -33.87,151.21 covering 100%")
    }));
    entity(&report, &EntityKind::Domain, "one.one.one.one");
    entity(&report, &EntityKind::Asn, "AS13335");
    entity(
        &report,
        &EntityKind::Organisation,
        "CLOUDFLARENET - Cloudflare, Inc.",
    );
    assert!(text.contains("internetdb\tsuccess"), "{text}");
}

/// An origin AS that is not a public AS number stays on the address's `RIPEstat` record but is
/// no AS entity, and neither is its holder an organisation, as `asn AS64512` refuses the number.
#[test]
fn a_reserved_origin_as_stays_on_the_address_and_is_no_entity() {
    let mut transport = keyless();
    for route in &mut transport.routes {
        if route.0 == "https://stat.ripe.net/" {
            route.2 = r#"{"status":"ok","data":{"announced":true,"asns":[{"asn":64512,"holder":"PRIVATE-USE"},{"asn":13335,"holder":"CLOUDFLARENET - Cloudflare, Inc."}],"resource":"1.1.1.0/24"}}"#;
        }
    }
    let (_, report) = printed(run(&transport, &Keys::default(), "1.1.1.1", 1));
    let asns: Vec<&str> = report
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Asn)
        .map(|e| e.raw_value.as_str())
        .collect();
    assert_eq!(asns, ["AS13335"]);
    assert!(
        !report
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.raw_value == "PRIVATE-USE")
    );
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(
        ip.evidence
            .iter()
            .flat_map(|evidence| evidence.attr_values("origin_asns"))
            .any(|asns| asns == "AS13335,AS64512")
    );
}

#[test]
fn keyed_legs_run_with_their_keys_in_their_own_headers() {
    let transport = keyless();
    let (_, report) = printed(run(&transport, &keys(), "1.1.1.1", 1));
    assert_eq!(outcome(&report, "abuseipdb"), SourceOutcomeKind::Success);
    assert_eq!(outcome(&report, "virustotal"), SourceOutcomeKind::Success);
    for request in transport.sent() {
        let abuse = request.headers.iter().any(|(_, v)| v.contains(ABUSE_KEY));
        let vt = request.headers.iter().any(|(_, v)| v.contains(VT_KEY));
        assert_eq!(
            abuse,
            request.url.starts_with("https://api.abuseipdb.com/"),
            "{}",
            request.url
        );
        assert_eq!(
            vt,
            request.url.starts_with("https://www.virustotal.com/"),
            "{}",
            request.url
        );
        assert!(!request.url.contains(ABUSE_KEY) && !request.url.contains(VT_KEY));
    }
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(ip.has_tag(tags::MALICIOUS));
    entity(&report, &EntityKind::Domain, "cloudflare.com");
}

#[test]
fn a_refused_key_is_reported_and_the_other_legs_still_answer() {
    let transport = Routes::new(vec![
        ("https://internetdb.shodan.io/", 200, INTERNETDB),
        ("https://stat.ripe.net/", 200, RIPESTAT),
        ("https://api.greynoise.io/", 404, GREYNOISE_UNSEEN),
        (
            "https://api.abuseipdb.com/",
            401,
            r#"{"errors":[{"status":401}]}"#,
        ),
        (
            "https://www.virustotal.com/",
            429,
            r#"{"error":{"code":"QuotaExceededError"}}"#,
        ),
    ]);
    let (text, report) = printed(run(&transport, &keys(), "1.1.1.1", 1));
    assert_eq!(
        outcome(&report, "abuseipdb"),
        SourceOutcomeKind::AuthRejected
    );
    assert_eq!(
        outcome(&report, "virustotal"),
        SourceOutcomeKind::RateLimited
    );
    assert!(!text.contains(ABUSE_KEY) && !text.contains(VT_KEY));
}

#[test]
fn a_non_public_address_is_refused_before_any_request() {
    for address in [
        "10.1.2.3",
        "192.168.0.10",
        "127.0.0.1",
        "fe80::1",
        "2001:db8::1",
    ] {
        let transport = keyless();
        assert!(
            matches!(run(&transport, &keys(), address, 1), IpRun::Failed(_)),
            "{address}"
        );
        assert!(transport.sent().is_empty(), "{address}");
    }
    assert!(IpArgs::parse(&["10.0.0.1".into()]).is_err());
}

/// No network at all is "no usable response" (exit 69) with the first reason, and only a request
/// the egress policy refused is a refusal (exit 77), as the CLI's exit codes say. Before, it
/// was the other way round: no network at all exited 77 and a refusal of every leg 69.
#[test]
fn no_network_at_all_fails_and_a_refusal_is_a_network_refusal() {
    let transport = Routes::new(Vec::new());
    match run(&transport, &Keys::default(), "8.8.8.8", 1) {
        IpRun::Failed(message) => assert_eq!(
            message,
            "no source answered for ip 8.8.8.8: internetdb: no response (ConnectFailure)"
        ),
        IpRun::Network(message) => panic!("network: {message}"),
        IpRun::Printed { text, .. } => panic!("printed: {text}"),
    }

    match run(&Refusing, &Keys::default(), "8.8.8.8", 1) {
        IpRun::Network(message) => {
            assert!(
                message.starts_with("internetdb: request refused"),
                "{message}"
            );
        }
        IpRun::Failed(message) => panic!("failed: {message}"),
        IpRun::Printed { text, .. } => panic!("printed: {text}"),
    }
}

/// Every request refused by the egress policy, as for a host that resolves to 0.0.0.0.
struct Refusing;

impl Transport for Refusing {
    fn send(&self, _: &Request) -> Result<Response, TransportFailure> {
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "egress-policy: destination (0.0.0.0) is not publicly routable".into(),
            blocked: true,
        })
    }
}

#[test]
fn args_canonicalise_the_address_and_take_save() {
    let parsed = IpArgs::parse(&[
        "[2606:4700:4700:0:0:0:0:1111]".into(),
        "--save".into(),
        "ip.json".into(),
    ]);
    assert_eq!(
        parsed.ok(),
        Some(IpArgs {
            ip: "2606:4700:4700::1111".into(),
            save: Some(PathBuf::from("ip.json")),
        })
    );
}

#[test]
fn a_configured_shodan_key_runs_shodan_with_the_key_only_in_its_query() {
    let transport = keyless();
    let keys = Keys::parse(&format!("{}={SHODAN_KEY}\n", crate::shodan::KEY_SLOT))
        .unwrap_or_else(|e| panic!("{e}"));
    let (_, report) = printed(run(&transport, &keys, "1.1.1.1", 1));
    assert_eq!(outcome(&report, "shodan"), SourceOutcomeKind::Success);
    let sent = transport.sent();
    let carrying: Vec<&str> = sent
        .iter()
        .filter(|r| {
            r.url.contains(SHODAN_KEY) || r.headers.iter().any(|(_, v)| v.contains(SHODAN_KEY))
        })
        .map(|r| r.url.as_str())
        .collect();
    assert_eq!(
        carrying,
        [format!(
            "https://api.shodan.io/shodan/host/1.1.1.1?key={SHODAN_KEY}"
        )]
    );
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(ip.evidence_sources().contains("shodan"));
    entity(&report, &EntityKind::Domain, "one.one");
}

/// The address's PTR records are asked first, over the `DoH` resolvers and the lookup's transport,
/// as Spiderfoot's `sfp_dnsresolve` reverse-resolves an address: every record is listed on the
/// address as published, and each name in canonical form is a domain pivot tagged `ptr`, the
/// address's own name in the saved scan. An address with no PTR record is a validated zero.
/// Before, no lookup asked the reverse zone itself.
#[test]
fn the_reverse_zone_names_the_address() {
    let mut transport = keyless();
    transport.routes[0] = (
        "https://cloudflare-dns.com/",
        200,
        r#"{"Status":0,"Answer":[{"type":12,"data":"one.one.one.one."},{"type":12,"data":"localhost."}]}"#,
    );
    let (_, report) = printed(run(&transport, &Keys::default(), "1.1.1.1", 1));
    let ptr = report
        .outcomes
        .iter()
        .find(|o| o.module == RESOLVE_SOURCE)
        .expect("a dnsresolve row");
    assert_eq!(ptr.kind, SourceOutcomeKind::Success);
    assert_eq!(ptr.found, Some(2));
    let request = &transport.sent()[0];
    assert!(
        request.url.contains("name=1.1.1.1.in-addr.arpa") && request.url.contains("type=PTR"),
        "{}",
        request.url
    );

    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    let listed: Vec<&str> = ip
        .evidence
        .iter()
        .filter(|e| e.provenance.source == RESOLVE_SOURCE)
        .flat_map(|e| e.attr_values("ptr"))
        .collect();
    assert_eq!(listed, ["one.one.one.one", "localhost"]);
    let name = entity(&report, &EntityKind::Domain, "one.one.one.one");
    assert!(name.has_tag(tags::PTR));
    let named = name
        .evidence
        .iter()
        .find(|e| e.provenance.source == RESOLVE_SOURCE)
        .expect("the PTR evidence");
    assert_eq!(named.attr_values("ip").collect::<Vec<_>>(), ["1.1.1.1"]);
    assert_eq!(
        named.attr_values("record_type").collect::<Vec<_>>(),
        ["PTR"]
    );
    assert!(
        !report.entities.iter().any(|e| e.value == "localhost"),
        "a name that is not a domain is listed, not a pivot"
    );

    let target = crate::sf_elements::Target {
        value: "1.1.1.1",
        kind: "IP_ADDRESS",
    };
    let elements = crate::sf_elements::elements(target, &report.entities, 1);
    let kinds: Vec<&str> = elements
        .iter()
        .filter(|element| element.data == "one.one.one.one" && element.module == RESOLVE_SOURCE)
        .map(|element| element.kind.as_str())
        .collect();
    assert_eq!(kinds, ["INTERNET_NAME"]);

    transport.routes[0] = ("https://cloudflare-dns.com/", 200, r#"{"Status":3}"#);
    let (_, report) = printed(run(&transport, &Keys::default(), "1.1.1.1", 1));
    assert_eq!(
        outcome(&report, RESOLVE_SOURCE),
        SourceOutcomeKind::ValidZero
    );
}
