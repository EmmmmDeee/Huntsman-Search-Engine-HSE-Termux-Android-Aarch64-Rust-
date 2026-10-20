//! An `ip` lookup keeps the text a source gives whole. These run `ip_cli::run`, the function
//! the `ip` command, `scan` and the web UI call, through a transport that answers as
//! `AlienVault` OTX did for `185.220.101.1` and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

/// The first ten pulse names OTX gave for `185.220.101.1` on 2026-10-15, in its order.
const PULSES: [&str; 10] = [
    "Webscanners 2018-02-09  thru current day",
    "Anonymization_Network | Oct 15, 2026 | Part 1/4",
    "IOC Records Provided by @NextRayAI",
    "Anonymization_Network | Oct 14, 2026 | Part 1/4",
    "Anonymization_Network | Oct 13, 2026 | Part 1/4",
    "Anonymization_Network | Oct 12, 2026 | Part 1/4",
    "Anonymization_Network | Oct 11, 2026 | Part 1/4",
    "Anonymization_Network | Oct 10, 2026 | Part 1/4",
    "Anonymization_Network | Oct 9, 2026 | Part 1/4",
    "Anonymization_Network | Oct 8, 2026 | Part 1/4",
];

/// OTX's answer for `185.220.101.1` on 2026-10-15, its pulses trimmed to their names.
fn otx_answer() -> String {
    let pulses: Vec<String> = PULSES
        .iter()
        .map(|name| format!(r#"{{"name":"{name}","tags":[]}}"#))
        .collect();
    format!(
        r#"{{"indicator":"185.220.101.1","type":"IPv4","asn":"AS60729 stiftung erneuerbare freiheit","country_code":"DE","pulse_info":{{"count":50,"pulses":[{}]}},"validation":[{{"source":"tor_exits","message":"IP Associated with Tor Exit Nodes","name":"IP Assosciated with Tor Exit Nodes"}}]}}"#,
        pulses.join(",")
    )
}

struct OnlyOtx;

impl Transport for OnlyOtx {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://otx.alienvault.com/api/v1/indicators/IPv4/185.220.101.1/general"
        {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: otx_answer().into_bytes(),
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
        &OnlyOtx,
        &Keys::default(),
        &Feeds::none(),
        "185.220.101.1",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => {
            panic!("ip 185.220.101.1 did not print: {why}")
        }
    }
}

#[test]
fn a_list_longer_than_a_line_reaches_the_address_whole() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "185.220.101.1")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let otx = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "otx")
        .unwrap_or_else(|| panic!("no OTX evidence: {:?}", address.evidence));
    let pulses: Vec<&str> = otx.attr_values("pulses").collect();
    let whole = PULSES.join(",");
    assert!(
        whole.chars().count() > 160,
        "the list must be longer than a line"
    );
    assert_eq!(pulses, [whole.as_str()]);
}
