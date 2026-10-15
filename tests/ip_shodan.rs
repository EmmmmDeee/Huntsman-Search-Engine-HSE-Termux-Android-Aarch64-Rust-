//! An `ip` lookup with a Shodan key keeps every service banner Shodan holds for the address, and
//! still answers when the whole answer is too long to read. These run `ip_cli::run`, the function
//! the `ip` command, `scan` and the web UI call, through a transport that answers Shodan's
//! documented host shape and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// The host fields Shodan recorded for `1.1.1.1` on 2026-10-14, without banners: what
/// `minify=true` answers.
const MINIFIED: &str = r#"{"city":"Brisbane","region_code":"QLD","tags":["vpn"],"isp":"Cloudflare, Inc.","longitude":153.0175,"latitude":-27.48159,"ports":[53,443,2082],"hostnames":["one.one.one.one"],"country_code":"AU","country_name":"Australia","domains":["one.one"],"org":"APNIC Research and Development","asn":"AS13335","ip_str":"1.1.1.1","data":[]}"#;

/// The same host with its banners, in Shodan's documented banner shape.
fn whole() -> String {
    let banners = [
        r#"{"_shodan":{"module":"https"},"timestamp":"2026-10-14T13:08:08.277809","port":443,"transport":"tcp","product":"CloudFlare","http":{"status":301,"title":"1.1.1.1 — The free app that makes your Internet faster.","server":"cloudflare"},"ssl":{"cert":{"subject":{"CN":"cloudflare-dns.com"},"issuer":{"O":"DigiCert Inc"}},"jarm":"27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c"}}"#,
        r#"{"_shodan":{"module":"dns-udp"},"timestamp":"2026-10-12T02:11:41.002113","port":53,"transport":"udp"}"#,
        r#"{"_shodan":{"module":"http"},"timestamp":"2026-10-13T20:45:00.000000","port":2082,"transport":"tcp","product":"nginx","version":"1.18.0","cpe23":["cpe:2.3:a:f5:nginx:1.18.0"],"vulns":{"CVE-2021-23017":{"verified":false,"cvss":7.7}}}"#,
    ];
    MINIFIED.replace(
        r#""data":[]"#,
        &format!(r#""data":[{}]"#, banners.join(",")),
    )
}

/// Answers Shodan's host endpoint; `cut` marks the whole answer as longer than the body limit.
struct OnlyShodan {
    cut: bool,
}

impl Transport for OnlyShodan {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let answer = |body: Vec<u8>, truncated: bool| {
            Ok(Response {
                status: 200,
                headers: Vec::new(),
                body,
                truncated,
            })
        };
        if request
            .url
            .starts_with("https://api.shodan.io/shodan/host/1.1.1.1?minify=true&")
        {
            return answer(MINIFIED.into(), false);
        }
        if request
            .url
            .starts_with("https://api.shodan.io/shodan/host/1.1.1.1?key=")
        {
            let mut body = whole().into_bytes();
            if self.cut {
                body.truncate(body.len() / 2);
            }
            return answer(body, self.cut);
        }
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "no route".into(),
            blocked: false,
        })
    }
}

fn entities(cut: bool) -> Vec<Entity> {
    let keys =
        Keys::parse("HUNTSMAN_SHODAN_KEY=shodan-test-key-0815").unwrap_or_else(|e| panic!("{e}"));
    match run(&OnlyShodan { cut }, &keys, "1.1.1.1", 1_760_000_000) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 1.1.1.1 did not print: {why}"),
    }
}

fn shodan(entities: &[Entity]) -> Evidence {
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "1.1.1.1")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "shodan")
        .cloned()
        .unwrap_or_else(|| panic!("no Shodan evidence: {:?}", address.evidence))
}

fn value<'a>(evidence: &'a Evidence, key: &str) -> Option<&'a str> {
    evidence.attributes.get(key).map(String::as_str)
}

#[test]
fn every_banner_shodan_holds_reaches_the_address() {
    let entities = entities(false);
    let shodan = shodan(&entities);
    assert_eq!(
        value(&shodan, "services"),
        Some("443/tcp CloudFlare,53/udp,2082/tcp nginx 1.18.0"),
        "{:?}",
        shodan.attributes
    );
    assert_eq!(value(&shodan, "cve_scores"), Some("CVE-2021-23017 7.7"));
    assert_eq!(value(&shodan, "tls_subjects"), Some("cloudflare-dns.com"));
    assert!(
        value(&shodan, "raw_banners").is_some_and(|raw| raw.contains(r#""port":2082"#)),
        "{:?}",
        shodan.attributes
    );
    for (kind, value) in [
        (EntityKind::Domain, "cloudflare-dns.com"),
        (EntityKind::Coordinates, "-27.481590,153.017500"),
    ] {
        assert!(
            entities.iter().any(|e| e.kind == kind && e.value == value),
            "no {kind:?} {value}: {entities:#?}"
        );
    }
}

#[test]
fn an_answer_past_the_body_limit_falls_back_to_the_host_without_banners() {
    let entities = entities(true);
    let shodan = shodan(&entities);
    assert_eq!(value(&shodan, "ports"), Some("53,443,2082"));
    assert!(
        value(&shodan, "banners_omitted").is_some_and(|why| why.contains("minify=true")),
        "{:?}",
        shodan.attributes
    );
    assert_eq!(value(&shodan, "raw_banners"), None);
}
