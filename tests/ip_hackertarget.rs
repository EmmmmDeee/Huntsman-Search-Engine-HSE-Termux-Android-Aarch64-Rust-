//! An `ip` lookup keeps every domain `HackerTarget` finds hosted on the address. These run
//! `ip_cli::run`, the function the `ip` command, `scan` and the web UI call, through a transport
//! that answers `HackerTarget`'s reverse-IP list with sixty domains and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Sixty domains on `93.184.215.14`, one per line, as `reverseiplookup` answers.
fn reverse_ip_answer() -> String {
    let lines: Vec<String> = (0..60).map(|n| format!("shop-{n}.example.org")).collect();
    lines.join("\n")
}

struct OnlyHackerTarget;

impl Transport for OnlyHackerTarget {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://api.hackertarget.com/reverseiplookup/?q=93.184.215.14" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: reverse_ip_answer().into_bytes(),
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
        &OnlyHackerTarget,
        &Keys::default(),
        "93.184.215.14",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => {
            panic!("ip 93.184.215.14 did not print: {why}")
        }
    }
}

#[test]
fn every_domain_hackertarget_finds_on_the_address_is_kept() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "93.184.215.14")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let hackertarget = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "hackertarget")
        .unwrap_or_else(|| panic!("no HackerTarget evidence: {:?}", address.evidence));
    let names: Vec<&str> = hackertarget
        .attr_values("names")
        .flat_map(|v| v.split(','))
        .collect();
    assert_eq!(names.len(), 60, "{:?}", hackertarget.attributes);
    assert_eq!(names.last(), Some(&"shop-59.example.org"));
    assert!(
        hackertarget
            .attr_values("raw_answer")
            .any(|raw| raw.contains("shop-59.example.org")),
        "{:?}",
        hackertarget.attributes
    );
}
