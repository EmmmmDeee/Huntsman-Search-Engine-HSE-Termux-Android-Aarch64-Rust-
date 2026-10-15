//! An `ip` lookup keeps every pulse `AlienVault` OTX lists for the address, and the place OTX
//! gives. These run `ip_cli::run`, the function the `ip` command, `scan` and the web UI call,
//! through a transport that answers as OTX did for `45.155.205.233` on 2026-10-15, with twelve
//! pulses, and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// OTX's answer for `45.155.205.233`: its place as recorded, and twelve pulses in the recorded
/// pulse shape.
fn otx_answer() -> String {
    let pulses: Vec<String> = (0..12)
        .map(|n| {
            format!(
                r#"{{"id":"61b886db3f57da33ac5045{n:02}","name":"Pulse {n}","description":"","created":"2021-12-14T11:58:18.325000","modified":"2022-01-13T00:05:19.097000","TLP":"white","author":{{"username":"AlienVault","id":"2"}},"tags":["tag-{n}"],"references":["https://example.org/report/{n}"],"targeted_countries":[],"attack_ids":[{{"id":"T1190","name":"Exploit Public-Facing Application","display_name":"T1190 - Exploit Public-Facing Application"}}],"industries":[],"malware_families":[],"adversary":""}}"#
            )
        })
        .collect();
    format!(
        r#"{{"reputation":0,"indicator":"45.155.205.233","type":"IPv4","pulse_info":{{"count":12,"pulses":[{}],"references":[],"related":{{"alienvault":{{"adversary":[],"malware_families":[],"industries":[]}},"other":{{"adversary":[],"malware_families":[],"industries":[]}}}}}},"false_positive":[],"validation":[],"asn":"AS49505 ooo network of data-centers selectel","city":"St Petersburg","region":"SPE","continent_code":"EU","latitude":59.8983,"postal_code":"190824","longitude":30.2618,"accuracy_radius":1000,"country_code":"RU","country_name":"Russian Federation"}}"#,
        pulses.join(",")
    )
}

struct OnlyOtx;

impl Transport for OnlyOtx {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://otx.alienvault.com/api/v1/indicators/IPv4/45.155.205.233/general"
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
    match run(&OnlyOtx, &Keys::default(), "45.155.205.233", 1_760_000_000) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => {
            panic!("ip 45.155.205.233 did not print: {why}")
        }
    }
}

#[test]
fn every_pulse_otx_lists_reaches_the_address() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "45.155.205.233")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let otx = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "otx")
        .unwrap_or_else(|| panic!("no OTX evidence: {:?}", address.evidence));
    let count = |key: &str| otx.attr_values(key).flat_map(|v| v.split(',')).count();
    assert_eq!(count("pulses"), 12, "{:?}", otx.attributes);
    assert_eq!(count("pulse_tags"), 12, "{:?}", otx.attributes);
    assert_eq!(count("pulse_ids"), 12, "{:?}", otx.attributes);
    assert_eq!(count("references"), 12, "{:?}", otx.attributes);
    assert!(
        otx.attr_values("raw_pulses")
            .any(|raw| raw.contains(r#""name":"Pulse 11""#)),
        "{:?}",
        otx.attributes
    );
    assert_eq!(
        otx.attr_values("city").collect::<Vec<_>>(),
        ["St Petersburg"]
    );
}

#[test]
fn the_city_position_otx_gives_is_a_coordinates_entity_of_the_lookup() {
    let entities = entities();
    let position = entities
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .unwrap_or_else(|| panic!("no Coordinates entity: {entities:#?}"));
    assert_eq!(position.value, "59.898300,30.261800");
    assert!(
        position
            .evidence
            .iter()
            .any(|e| e.provenance.source == "otx"),
        "{:?}",
        position.evidence
    );
}
