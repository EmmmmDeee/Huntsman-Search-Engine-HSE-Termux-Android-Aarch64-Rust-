use std::sync::Mutex;

use super::*;
use crate::http::{Request, Response, TransportFailure};
use crate::source_outcome::SourceOutcomeKind;
use crate::test_support::Refusing;

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
        (
            "https://stat.ripe.net/data/rpki-validation/",
            200,
            crate::ripestat::tests::RPKI_VALID,
        ),
        (
            "https://stat.ripe.net/data/routing-history/",
            200,
            crate::ripestat::tests::ROUTING_HISTORY,
        ),
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

/// The indicator sources that answer for an IP only with a key, which a run without keys skips.
fn keyed_ip_sources_without_a_key() -> Vec<&'static str> {
    crate::indicator_legs::SOURCES
        .iter()
        .filter(|source| {
            source
                .kinds
                .iter()
                .any(|kind| kind.covers(crate::indicator_sources::Indicator::Ip("1.1.1.1")))
                && !source.api.wanted(&Keys::default())
        })
        .map(|source| source.api.source)
        .collect()
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
            // prefix-overview, geoloc, the covering prefix's RPKI state for AS13335, then its
            // routing history.
            "stat.ripe.net",
            "stat.ripe.net",
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
    // The keyed legs with no key sent nothing (no host above is theirs), and each leaves the row
    // saying it was not configured, as every other keyed leg does.
    let unkeyed = keyed_ip_sources_without_a_key();
    assert!(!unkeyed.is_empty());
    for source in &unkeyed {
        assert_eq!(
            outcome(&report, source),
            SourceOutcomeKind::NotConfigured,
            "{source}"
        );
    }
    assert_eq!(
        report.outcomes.len(),
        23 + unkeyed.len(),
        "every keyless leg reports once and every keyed one that it was not configured"
    );

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
    // Mnemonic has no route here: its failure is one row, not one per way it is reported.
    let mnemonic: Vec<_> = report
        .outcomes
        .iter()
        .filter(|o| o.module == "mnemonic")
        .collect();
    assert_eq!(mnemonic.len(), 1, "{mnemonic:?}");
    assert_eq!(mnemonic[0].kind, SourceOutcomeKind::ConnectFailure);
    assert!(!text.contains(ABUSE_KEY) && !text.contains(VT_KEY));
}

/// An IPv4 address written IPv4-mapped (`::ffff:1.1.1.1`) is that IPv4 address: every source is
/// sent exactly what `1.1.1.1` sends it, never a form a source may not index and so answer as an
/// address it holds nothing about.
#[test]
fn an_ipv4_mapped_address_is_looked_up_as_its_ipv4_address() {
    let asked = |address: &str| {
        let transport = keyless();
        let (_, report) = printed(run(&transport, &Keys::default(), address, 1));
        let urls: Vec<String> = transport.sent().into_iter().map(|r| r.url).collect();
        (urls, report)
    };
    let (plain, _) = asked("1.1.1.1");
    let (mapped, report) = asked("::ffff:1.1.1.1");
    assert!(!mapped.is_empty());
    assert_eq!(mapped, plain);
    assert!(
        report
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::IpAddress && e.value == "1.1.1.1")
    );
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
        // The reason is now the first transport-failure row in row order (PTR, then RDAP, then
        // Mnemonic), read by SourceReach, not Mnemonic's as a side channel.
        IpRun::Failed(message) => {
            assert_eq!(message, "no source answered for ip 8.8.8.8: rdap: no route");
        }
        IpRun::Network(message) => panic!("network: {message}"),
        IpRun::Printed { text, .. } => panic!("printed: {text}"),
    }

    match run(&Refusing, &Keys::default(), "8.8.8.8", 1) {
        IpRun::Network(message) => {
            assert!(
                message.starts_with("dnsresolve: no resolver answered the PTR query: refused:"),
                "{message}"
            );
        }
        IpRun::Failed(message) => panic!("failed: {message}"),
        IpRun::Printed { text, .. } => panic!("printed: {text}"),
    }
}

/// A scan that chose only `mnemonic` (`scans run 93.184.215.14 -m mnemonic`), where the egress
/// policy refuses Mnemonic, is a network refusal (exit 77) carrying Mnemonic's reason. Before,
/// the leg kept only its row and the lookup failed with no reason (exit 69).
#[test]
fn a_refused_mnemonic_leg_alone_is_a_network_refusal_with_its_reason() {
    let chosen = crate::module_selection::Selected::new(
        Refusing,
        crate::module_selection::Selection::only([crate::mnemonic::SOURCE]),
    );
    match run(&chosen, &Keys::default(), "93.184.215.14", 1) {
        IpRun::Network(message) => assert!(
            message.starts_with("mnemonic: request refused before sending: network: egress-policy"),
            "{message}"
        ),
        IpRun::Failed(message) => panic!("failed: {message}"),
        IpRun::Printed { text, .. } => panic!("printed: {text}"),
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

/// Each origin AS of the announced covering prefix carries its RPKI state, what the state means
/// and the ROAs it was judged against; an invalid state is also a tagged record on the address,
/// and a check that failed is said to have failed, never shown as an unknown state.
#[test]
fn origin_as_numbers_carry_their_rpki_state() {
    let transport = keyless();
    let (_, report) = printed(run(&transport, &Keys::default(), "1.1.1.1", 1));
    let rpki: Vec<String> = transport
        .sent()
        .iter()
        .map(|r| r.url.clone())
        .filter(|url| url.contains("rpki-validation"))
        .collect();
    assert_eq!(
        rpki,
        [
            "https://stat.ripe.net/data/rpki-validation/data.json?resource=AS13335&prefix=1.1.1.0%2F24"
        ]
    );
    let asn = entity(&report, &EntityKind::Asn, "AS13335");
    let attr = |name: &str| {
        asn.evidence
            .iter()
            .find_map(|e| e.attr_values(name).next())
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(attr("rpki_state"), "valid");
    assert_eq!(attr("rpki_roas"), "AS13335 1.1.1.0/24 max /24 (valid)");
    assert!(!entity(&report, &EntityKind::IpAddress, "1.1.1.1").has_tag(tags::RPKI_INVALID_ORIGIN));

    let mut invalid = keyless();
    let wrong_origin = crate::ripestat::tests::RPKI_VALID
        .replace(r#""status":"valid""#, r#""status":"invalid_asn""#);
    let wrong_origin: &'static str = Box::leak(wrong_origin.into_boxed_str());
    for route in &mut invalid.routes {
        if route.0.contains("rpki-validation") {
            route.2 = wrong_origin;
        }
    }
    let (_, report) = printed(run(&invalid, &Keys::default(), "1.1.1.1", 1));
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(ip.has_tag(tags::RPKI_INVALID_ORIGIN));
    assert!(
        ip.evidence
            .iter()
            .any(|e| e.summary.contains("RPKI invalid_asn: AS13335"))
    );

    let mut failing = keyless();
    for route in &mut failing.routes {
        if route.0.contains("rpki-validation") {
            route.1 = 500;
        }
    }
    let (_, report) = printed(run(&failing, &Keys::default(), "1.1.1.1", 1));
    let asn = entity(&report, &EntityKind::Asn, "AS13335");
    assert!(
        asn.evidence
            .iter()
            .any(|e| e.attr_values("rpki_check").any(|v| v.starts_with("failed"))),
        "{:?}",
        asn.evidence
    );
    assert!(
        !asn.evidence
            .iter()
            .any(|e| e.attr_values("rpki_state").next().is_some())
    );
}

/// An address no AS announces has no announcement to validate or trace: no RPKI or routing
/// history request is sent, even
/// when the answer still names an origin AS for the covering prefix.
#[test]
fn an_unannounced_address_asks_for_no_rpki_state_or_routing_history() {
    let mut transport = keyless();
    for route in &mut transport.routes {
        if route.0 == "https://stat.ripe.net/" {
            route.2 = r#"{"status":"ok","data":{"announced":false,"asns":[{"asn":13335,"holder":"CLOUDFLARENET - Cloudflare, Inc."}],"resource":"1.1.1.0/24","block":{"desc":"APNIC (Status: ALLOCATED)"}}}"#;
        }
    }
    let _ = run(&transport, &Keys::default(), "1.1.1.1", 1);
    assert!(
        !transport
            .sent()
            .iter()
            .any(|r| r.url.contains("rpki-validation") || r.url.contains("routing-history"))
    );
}

/// The address carries who else announced its covering prefix: every origin AS but the current
/// one that RIS peers saw announcing a prefix containing it, most recently seen first, tagged
/// `prefix_origin_history`; a history with no other origin says so, and a failed read is never
/// shown as an empty history.
#[test]
fn the_address_carries_the_other_origins_of_its_prefix() {
    let transport = keyless();
    let (_, report) = printed(run(&transport, &Keys::default(), "1.1.1.1", 1));
    assert!(transport.sent().iter().any(|r| r.url
        == "https://stat.ripe.net/data/routing-history/data.json?resource=1.1.1.0%2F24&min_peers=10"));
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(ip.has_tag(tags::PREFIX_ORIGIN_HISTORY));
    let history = ip
        .evidence
        .iter()
        .find(|e| e.attr_values("past_origins").next().is_some())
        .unwrap_or_else(|| panic!("{:?}", ip.evidence));
    let attr = |name: &str| {
        history
            .attr_values(name)
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    // AS13335 announces the prefix now, so it is not a past origin; AS64496's /25 does not
    // contain the address.
    assert_eq!(attr("past_origin_count"), "3");
    let past: Vec<&str> = history.attr_values("past_origins").collect();
    assert_eq!(past.len(), 3, "{past:?}");
    assert!(past[0].starts_with("AS226 1.1.1.0/24 2016-02-05T00:00:00Z"));
    assert!(
        past[1].starts_with("AS237 1.0.0.0/8,1.1.1.0/24 "),
        "{past:?}"
    );
    assert!(
        !past
            .iter()
            .any(|line| line.starts_with("AS13335 ") || line.starts_with("AS64496 ")),
        "{past:?}"
    );
    assert!(
        history.summary.contains("most recently AS226") && history.summary.contains("not proof")
    );

    let mut only_current = keyless();
    let single: &'static str = Box::leak(
        r#"{"status":"ok","data":{"by_origin":[{"origin":"13335","prefixes":[{"prefix":"1.1.1.0/24","timelines":[{"starttime":"2018-03-14T00:00:00","endtime":"2026-10-28T15:59:59","full_peers_seeing":300.0}]}]}],"query_starttime":"2000-08-01T00:00:00","query_endtime":"2026-10-28T16:00:00"}}"#
            .to_owned()
            .into_boxed_str(),
    );
    for route in &mut only_current.routes {
        if route.0.contains("routing-history") {
            route.2 = single;
        }
    }
    let (_, report) = printed(run(&only_current, &Keys::default(), "1.1.1.1", 1));
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(!ip.has_tag(tags::PREFIX_ORIGIN_HISTORY));
    assert!(
        ip.evidence
            .iter()
            .any(|e| e.attr_values("past_origin_count").any(|v| v == "0"))
    );

    let mut failing = keyless();
    for route in &mut failing.routes {
        if route.0.contains("routing-history") {
            route.1 = 500;
        }
    }
    let (_, report) = printed(run(&failing, &Keys::default(), "1.1.1.1", 1));
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(!ip.has_tag(tags::PREFIX_ORIGIN_HISTORY));
    assert!(ip.evidence.iter().any(|e| {
        e.attr_values("routing_history_check")
            .any(|v| v.starts_with("failed"))
    }));
    assert!(
        !ip.evidence
            .iter()
            .any(|e| e.attr_values("past_origin_count").next().is_some())
    );
}

/// At most `MAX_PAST_ORIGINS` past origins are listed, most recently seen first, and the count
/// says how many there were.
#[test]
fn past_origins_are_bounded_and_counted() {
    let origins: Vec<String> = (0..20)
        .map(|i| {
            format!(
                r#"{{"origin":"{}","prefixes":[{{"prefix":"1.1.1.0/24","timelines":[{{"starttime":"2001-01-{:02}T00:00:00","endtime":"2001-01-{:02}T23:59:59","full_peers_seeing":20.0}}]}}]}}"#,
                64500 + i,
                i + 1,
                i + 1
            )
        })
        .collect();
    let body: &'static str = Box::leak(
        format!(
            r#"{{"status":"ok","data":{{"by_origin":[{}]}}}}"#,
            origins.join(",")
        )
        .into_boxed_str(),
    );
    let mut transport = keyless();
    for route in &mut transport.routes {
        if route.0.contains("routing-history") {
            route.2 = body;
        }
    }
    let (_, report) = printed(run(&transport, &Keys::default(), "1.1.1.1", 1));
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    let history = ip
        .evidence
        .iter()
        .find(|e| e.attr_values("past_origins").next().is_some())
        .unwrap();
    let attr = |name: &str| {
        history
            .attr_values(name)
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(attr("past_origin_count"), "20");
    assert_eq!(
        attr("past_origins_listed"),
        crate::ripestat::MAX_PAST_ORIGINS.to_string()
    );
    assert_eq!(
        history.attr_values("past_origins").count(),
        crate::ripestat::MAX_PAST_ORIGINS
    );
    // The most recently seen (2001-01-20, AS64519) comes first.
    assert!(
        attr("past_origins").starts_with("AS64519 "),
        "{}",
        attr("past_origins")
    );
}
