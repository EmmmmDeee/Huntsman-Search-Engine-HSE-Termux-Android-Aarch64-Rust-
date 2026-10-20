//! An `ip` lookup with an `IPQualityScore` key keeps everything IPQS says about where the address
//! is: the position as a coordinates entity, and the region, postcode and time zone on the
//! address's own evidence. These run `ip_cli::run`, the function the `ip` command, `scan` and the
//! web UI call, through a transport that answers as IPQS documents and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

/// The documented IP reputation response fields, filled for a Dutch address.
const IPQS: &str = r#"{"success":true,"message":"Success","fraud_score":12,"country_code":"NL","region":"North Holland","city":"Amsterdam","ISP":"Example Hosting","ASN":64500,"organization":"Example Hosting B.V.","is_crawler":false,"timezone":"Europe/Amsterdam","mobile":false,"host":"exit-12.example.net","proxy":false,"vpn":false,"tor":false,"active_vpn":false,"active_tor":false,"recent_abuse":false,"bot_status":false,"connection_type":"Data Center","abuse_velocity":"none","zip_code":"1012","latitude":52.37,"longitude":4.89,"request_id":"r0"}"#;

struct OnlyIpqs;

impl Transport for OnlyIpqs {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request
            .url
            .starts_with("https://www.ipqualityscore.com/api/json/ip?ip=1.2.3.4")
        {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: IPQS.as_bytes().to_vec(),
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
    let keys =
        Keys::parse("HUNTSMAN_IPQS_KEY=ipqs-test-key-0815").unwrap_or_else(|e| panic!("{e}"));
    match run(&OnlyIpqs, &keys, &Feeds::none(), "1.2.3.4", 1_760_000_000) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 1.2.3.4 did not print: {why}"),
    }
}

#[test]
fn the_position_ipqs_gives_is_a_coordinates_entity_of_the_lookup() {
    let entities = entities();
    let place = entities
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .unwrap_or_else(|| panic!("no coordinates entity: {entities:#?}"));
    assert_eq!(place.value, "52.370000,4.890000");
    assert!(place.has_tag("geoint"), "{:?}", place.tags);
    assert!(
        place
            .evidence
            .iter()
            .any(|e| e.provenance.source == "ipqs"
                && e.attr_values("ip").any(|ip| ip == "1.2.3.4")),
        "{:?}",
        place.evidence
    );
}

#[test]
fn the_region_postcode_and_time_zone_stay_on_the_address() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "1.2.3.4")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let ipqs = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "ipqs")
        .unwrap_or_else(|| panic!("no IPQS evidence: {:?}", address.evidence));
    let attr = |key: &str| ipqs.attr_values(key).collect::<Vec<_>>();
    assert_eq!(attr("region"), ["North Holland"]);
    assert_eq!(attr("postal_code"), ["1012"]);
    assert_eq!(attr("timezone"), ["Europe/Amsterdam"]);
    assert_eq!(attr("coordinates"), ["52.370000,4.890000"]);
}
