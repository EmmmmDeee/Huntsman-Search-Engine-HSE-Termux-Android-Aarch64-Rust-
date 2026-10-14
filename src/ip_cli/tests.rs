use std::sync::Mutex;

use super::*;
use crate::http::{Request, Response, TransportFailure};
use crate::source_outcome::SourceOutcomeKind;

const ABUSE_KEY: &str = "abuse-test-key-0123456789abcdef";
const VT_KEY: &str = "vt-test-key-0123456789abcdef0123";

const INTERNETDB: &str = r#"{"cpes":["cpe:/a:cloudflare:cloudflare"],"hostnames":["one.one.one.one"],"ip":"1.1.1.1","ports":[53,443],"tags":["cdn"],"vulns":["CVE-2023-0001"]}"#;
const RIPESTAT: &str = r#"{"status":"ok","data":{"announced":true,"asns":[{"asn":13335,"holder":"CLOUDFLARENET - Cloudflare, Inc."}],"resource":"1.1.1.0/24","block":{"desc":"APNIC (Status: ALLOCATED)"}}}"#;
const GREYNOISE_UNSEEN: &str = r#"{"ip":"1.1.1.1","noise":false,"riot":false,"message":"IP not observed scanning the internet."}"#;
const ABUSEIPDB: &str = r#"{"data":{"ipAddress":"1.1.1.1","abuseConfidenceScore":75,"countryCode":"AU","usageType":"Content Delivery Network","isp":"Cloudflare, Inc.","domain":"cloudflare.com","hostnames":[],"isTor":false,"isWhitelisted":false,"totalReports":12,"numDistinctUsers":5,"lastReportedAt":"2026-10-01T00:00:00+00:00"}}"#;
const VIRUSTOTAL: &str = r#"{"data":{"id":"1.1.1.1","type":"ip_address","attributes":{"last_analysis_stats":{"harmless":60,"malicious":1,"suspicious":0,"undetected":30},"reputation":5,"asn":13335,"as_owner":"CLOUDFLARENET","network":"1.1.1.0/24","country":"AU"}}}"#;

const PULSEDIVE_UNKNOWN: &str = r#"{"error":"Indicator not found."}"#;
const SHODAN: &str = r#"{"ip_str":"1.1.1.1","ports":[53,443],"hostnames":["one.one.one.one"],"domains":["one.one"],"org":"APNIC Research and Development","isp":"Cloudflare, Inc.","asn":"AS13335","tags":[],"country_code":"AU"}"#;
const SHODAN_KEY: &str = "shodan-test-key-0123456789abcdef";

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
        ("https://internetdb.shodan.io/", 200, INTERNETDB),
        ("https://stat.ripe.net/", 200, RIPESTAT),
        ("https://api.greynoise.io/", 404, GREYNOISE_UNSEEN),
        ("https://api.abuseipdb.com/", 200, ABUSEIPDB),
        ("https://www.virustotal.com/", 200, VIRUSTOTAL),
        ("https://pulsedive.com/", 404, PULSEDIVE_UNKNOWN),
        ("https://api.shodan.io/", 200, SHODAN),
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
            "internetdb.shodan.io",
            "stat.ripe.net",
            "api.greynoise.io",
            "pulsedive.com"
        ]
    );
    assert_eq!(outcome(&report, "internetdb"), SourceOutcomeKind::Success);
    assert_eq!(outcome(&report, "ripestat"), SourceOutcomeKind::Success);
    assert_eq!(outcome(&report, "greynoise"), SourceOutcomeKind::ValidZero);
    assert_eq!(outcome(&report, "pulsedive"), SourceOutcomeKind::ValidZero);
    assert_eq!(report.outcomes.len(), 4, "an unkeyed leg reports nothing");

    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(ip.has_tag(tags::VULNERABLE));
    let sources = ip.evidence_sources();
    assert!(sources.contains("internetdb") && sources.contains("ripestat"));
    entity(&report, &EntityKind::Domain, "one.one.one.one");
    entity(&report, &EntityKind::Asn, "AS13335");
    entity(
        &report,
        &EntityKind::Organisation,
        "CLOUDFLARENET - Cloudflare, Inc.",
    );
    assert!(text.contains("internetdb\tsuccess"), "{text}");
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

#[test]
fn no_network_at_all_is_a_network_refusal() {
    let transport = Routes::new(Vec::new());
    assert!(matches!(
        run(&transport, &Keys::default(), "8.8.8.8", 1),
        IpRun::Network(_)
    ));
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
            "https://api.shodan.io/shodan/host/1.1.1.1?minify=true&key={SHODAN_KEY}"
        )]
    );
    let ip = entity(&report, &EntityKind::IpAddress, "1.1.1.1");
    assert!(ip.evidence_sources().contains("shodan"));
    entity(&report, &EntityKind::Domain, "one.one");
}
