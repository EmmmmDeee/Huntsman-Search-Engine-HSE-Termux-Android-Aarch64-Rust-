//! An `ip` lookup keeps every scan urlscan.io lists for the address, and everything it says about
//! each. These run `ip_cli::run`, the function the `ip` command, `scan` and the web UI call,
//! through a transport that answers urlscan.io's search with twelve scans of pages on
//! `45.155.205.233`, in the recorded search-result shape, and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Twelve scans, each of a page on its own host name served by its own server.
fn urlscan_answer() -> String {
    let scans: Vec<String> = (0..12)
        .map(|n| {
            format!(
                r#"{{"task":{{"visibility":"public","method":"api","domain":"shop{n}.example","apexDomain":"shop{n}.example","time":"2026-10-{day:02}T12:00:00.000Z","uuid":"01a14002-71c5-77ee-a037-5e3fc6fd7d{n:02}","url":"https://shop{n}.example/login?session={n}"}},"stats":{{"uniqIPs":1,"requests":2}},"page":{{"server":"server-{n}","ip":"45.155.205.233","mimeType":"text/html","title":"Shop {n}","url":"https://shop{n}.example/login","status":"200","domain":"shop{n}.example","apexDomain":"shop{n}.example","asnname":"SELECTEL, RU","asn":"AS49505"}},"_id":"01a14002-71c5-77ee-a037-5e3fc6fd7d{n:02}","result":"https://urlscan.io/api/v1/result/01a14002-71c5-77ee-a037-5e3fc6fd7d{n:02}/","screenshot":"https://urlscan.io/screenshots/01a14002-71c5-77ee-a037-5e3fc6fd7d{n:02}.png"}}"#,
                day = n + 1,
            )
        })
        .collect();
    format!(
        r#"{{"results":[{}],"total":12,"took":40,"has_more":false,"search_date_limit_days":30}}"#,
        scans.join(",")
    )
}

struct OnlyUrlscan;

impl Transport for OnlyUrlscan {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url.starts_with("https://urlscan.io/api/v1/search/") {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: urlscan_answer().into_bytes(),
                truncated: false,
            });
        }
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "no route".into(),
            blocked: false,
        })
    }
}

fn entities() -> Vec<Entity> {
    match run(
        &OnlyUrlscan,
        &Keys::default(),
        "45.155.205.233",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => {
            panic!("ip 45.155.205.233 did not print: {why}")
        }
    }
}

#[test]
fn every_scan_urlscan_lists_reaches_the_address() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "45.155.205.233")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let urlscan = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "urlscan")
        .unwrap_or_else(|| panic!("no urlscan.io evidence: {:?}", address.evidence));
    let count = |key: &str| urlscan.attr_values(key).flat_map(|v| v.split(',')).count();
    for key in ["servers", "urls", "page_titles", "scan_ids", "screenshots"] {
        assert_eq!(count(key), 12, "{key}: {:?}", urlscan.attributes);
    }
    assert!(
        urlscan
            .attr_values("urls")
            .any(|v| v.contains("https://shop11.example/login?session=11")),
        "{:?}",
        urlscan.attributes
    );
    assert!(
        urlscan
            .attr_values("raw_scans")
            .any(|raw| raw.contains(r#""title":"Shop 11""#)),
        "{:?}",
        urlscan.attributes
    );
}

#[test]
fn every_scanned_host_is_a_domain_of_the_lookup() {
    let entities = entities();
    let domains = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.value.ends_with(".example"))
        .count();
    assert_eq!(domains, 12, "{entities:#?}");
}
