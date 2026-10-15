//! An `ip` lookup keeps everything `IPinfo` says about where the address is: the position as a
//! coordinates entity, and the postcode and time zone on the address's own evidence. These run
//! `ip_cli::run`, the function the `ip` command, `scan` and the web UI call, through a transport
//! that answers as `IPinfo` did for `8.8.8.8` and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Recorded without a key for `8.8.8.8` on 2026-10-14.
const IPINFO: &str = r#"{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View","region":"California","country":"US","loc":"38.0088,-122.1175","org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles","readme":"https://ipinfo.io/missingauth","anycast":true}"#;

struct OnlyIpinfo;

impl Transport for OnlyIpinfo {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url.starts_with("https://ipinfo.io/8.8.8.8/json") {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: IPINFO.as_bytes().to_vec(),
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
    match run(&OnlyIpinfo, &Keys::default(), "8.8.8.8", 1_760_000_000) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 8.8.8.8 did not print: {why}"),
    }
}

#[test]
fn the_position_ipinfo_gives_is_a_coordinates_entity_of_the_lookup() {
    let entities = entities();
    let place = entities
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .unwrap_or_else(|| panic!("no coordinates entity: {entities:#?}"));
    assert_eq!(place.value, "38.008800,-122.117500");
    assert!(place.has_tag("geoint"), "{:?}", place.tags);
    assert!(
        place
            .evidence
            .iter()
            .any(|e| e.provenance.source == "ipinfo"
                && e.attr_values("ip").any(|ip| ip == "8.8.8.8")),
        "{:?}",
        place.evidence
    );
}

#[test]
fn the_postcode_and_time_zone_stay_on_the_address() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "8.8.8.8")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let ipinfo = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "ipinfo")
        .unwrap_or_else(|| panic!("no IPinfo evidence: {:?}", address.evidence));
    let attr = |key: &str| ipinfo.attr_values(key).collect::<Vec<_>>();
    assert_eq!(attr("postal_code"), ["94043"]);
    assert_eq!(attr("timezone"), ["America/Los_Angeles"]);
    assert_eq!(attr("coordinates"), ["38.008800,-122.117500"]);
}
