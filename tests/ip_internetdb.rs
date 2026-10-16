//! An `ip` lookup keeps every port and CVE Shodan `InternetDB` lists for the address. These run
//! `ip_cli::run`, the function the `ip` command, `scan` and the web UI call, through a transport
//! that answers `InternetDB`'s documented shape with 90 ports and 120 CVEs and refuses every
//! other host.

use huntsman_recon::entity::EntityKind;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

fn internetdb_answer() -> String {
    let ports: Vec<String> = (0..90).map(|n| (8000 + n).to_string()).collect();
    let vulns: Vec<String> = (0..120)
        .map(|n| format!(r#""CVE-2021-{:05}""#, 40_000 + n))
        .collect();
    format!(
        r#"{{"cpes":["cpe:/a:apache:http_server:2.4.29"],"hostnames":["old.example.org"],"ip":"45.33.32.156","ports":[{}],"tags":[],"vulns":[{}]}}"#,
        ports.join(","),
        vulns.join(",")
    )
}

struct OnlyInternetDb;

impl Transport for OnlyInternetDb {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://internetdb.shodan.io/45.33.32.156" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: internetdb_answer().into_bytes(),
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

#[test]
fn every_port_and_cve_internetdb_lists_reaches_the_address() {
    let entities = match run(
        &OnlyInternetDb,
        &Keys::default(),
        &Feeds::none(),
        "45.33.32.156",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("did not print: {why}"),
    };
    let evidence = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "45.33.32.156")
        .and_then(|e| {
            e.evidence
                .iter()
                .find(|ev| ev.provenance.source == "internetdb")
        })
        .unwrap_or_else(|| panic!("no InternetDB evidence: {entities:#?}"));
    let count = |key: &str| {
        evidence
            .attributes
            .get(key)
            .map_or(0, |v| v.split(',').count())
    };
    assert_eq!(count("ports"), 90, "{:?}", evidence.attributes);
    assert_eq!(count("vulns"), 120, "{:?}", evidence.attributes);
}
