//! An `ip` lookup with a `ThreatFox` key keeps every IOC `ThreatFox` names for the address, and
//! everything it says about each. These run `ip_cli::run`, the function the `ip` command, `scan`
//! and the web UI call, through a transport that answers `ThreatFox`'s documented `search_ioc`
//! shape with twelve IOCs on the address and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

/// Twelve IOCs on `94.103.84.81`, one port each, in the documented `search_ioc` record shape.
fn threatfox_answer() -> String {
    let records: Vec<String> = (0..12)
        .map(|n| {
            format!(
                r#"{{"id":"{id}","ioc":"94.103.84.81:{port}","threat_type":"botnet_cc","threat_type_desc":"Indicator that identifies a botnet command&control server (C&C)","ioc_type":"ip:port","ioc_type_desc":"ip:port combination that is used for botnet Command&control (C&C)","malware":"win.family_{n}","malware_printable":"Family {n}","malware_alias":null,"malware_malpedia":"https://malpedia.caad.fkie.fraunhofer.de/details/win.family_{n}","confidence_level":75,"first_seen":"2021-03-08 12:28:13 UTC","last_seen":null,"reference":"","reporter":"abuse_ch","tags":["family_{n}"],"malware_samples":[]}}"#,
                id = 100 + n,
                port = 8000 + n,
            )
        })
        .collect();
    format!(r#"{{"query_status":"ok","data":[{}]}}"#, records.join(","))
}

struct OnlyThreatFox;

impl Transport for OnlyThreatFox {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://threatfox-api.abuse.ch/api/v1/" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: threatfox_answer().into_bytes(),
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
    let keys = Keys::parse("HUNTSMAN_THREATFOX_KEY=threatfox-test-key-0815")
        .unwrap_or_else(|e| panic!("{e}"));
    match run(
        &OnlyThreatFox,
        &keys,
        &Feeds::none(),
        "94.103.84.81",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 94.103.84.81 did not print: {why}"),
    }
}

#[test]
fn every_ioc_threatfox_names_reaches_the_address() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "94.103.84.81")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let threatfox = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "threatfox")
        .unwrap_or_else(|| panic!("no ThreatFox evidence: {:?}", address.evidence));
    let count = |key: &str| {
        threatfox
            .attr_values(key)
            .flat_map(|v| v.split(','))
            .count()
    };
    assert_eq!(count("iocs"), 12, "{:?}", threatfox.attributes);
    assert_eq!(count("malware"), 12, "{:?}", threatfox.attributes);
    assert_eq!(count("malpedia"), 12, "{:?}", threatfox.attributes);
    assert_eq!(count("ioc_tags"), 12, "{:?}", threatfox.attributes);
    assert!(
        threatfox
            .attr_values("raw_iocs")
            .any(|raw| raw.contains(r#""ioc":"94.103.84.81:8011""#)),
        "{:?}",
        threatfox.attributes
    );
}
