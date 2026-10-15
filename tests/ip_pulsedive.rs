//! An `ip` lookup keeps everything Pulsedive gives about an address. For `45.155.205.233`,
//! which Pulsedive knows without attributes (`"attributes":[]`, its spelling of an empty object),
//! that is the position and AS, which reach the lookup as entities, and the city, ISP and
//! retirement, which stay on the address. These run `ip_cli::run`, the function the `ip`
//! command, `scan` and the web UI call, through a transport that answers as Pulsedive did for
//! `45.155.205.233` and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, Report, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Recorded without a key for `45.155.205.233` on 2026-10-15.
const PULSEDIVE: &str = r#"{"qid":null,"iid":30377744,"indicator":"45.155.205.233","type":"ip","risk":"unknown","risk_recommended":"unknown","manualrisk":0,"retired":"No recent activity","stamp_added":"2021-12-13 13:50:44","stamp_updated":"2024-01-05 14:10:53","stamp_seen":"2023-10-03 06:58:19","stamp_probed":"2022-10-02 19:10:20","stamp_retired":"2024-01-05 14:10:53","recent":0,"submissions":4,"umbrella_rank":null,"umbrella_domain":null,"riskfactors":[],"redirects":{"from":[],"to":[]},"threats":[],"feeds":[],"comments":[],"attributes":[],"properties":{"geo":{"country":"Russian Federation","countrycode":"RU","region":"St.-Petersburg","city":"St Petersburg","lat":"59.9417","long":"30.3096","isp":"Proton66 OOO","org":"Proton66 OOO","asn":"AS198953"}}}"#;

struct OnlyPulsedive;

impl Transport for OnlyPulsedive {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request
            .url
            .starts_with("https://pulsedive.com/api/info.php?indicator=45.155.205.233")
        {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: PULSEDIVE.as_bytes().to_vec(),
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

fn report() -> Report {
    match run(
        &OnlyPulsedive,
        &Keys::default(),
        "45.155.205.233",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report,
        IpRun::Network(why) | IpRun::Failed(why) => {
            panic!("ip 45.155.205.233 did not print: {why}")
        }
    }
}

fn entity<'a>(entities: &'a [Entity], kind: &EntityKind) -> &'a Entity {
    entities
        .iter()
        .find(|e| &e.kind == kind)
        .unwrap_or_else(|| panic!("no {kind:?} entity: {entities:#?}"))
}

#[test]
fn an_address_without_attributes_keeps_its_geo_and_retirement() {
    let report = report();
    let pulsedive = report
        .outcomes
        .iter()
        .find(|o| o.module == "pulsedive")
        .unwrap_or_else(|| panic!("no pulsedive row: {:?}", report.outcomes));
    assert_eq!(pulsedive.kind, SourceOutcomeKind::Success, "{pulsedive:?}");
    let address = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "45.155.205.233")
        .unwrap_or_else(|| panic!("no address entity: {:#?}", report.entities));
    let evidence = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "pulsedive")
        .unwrap_or_else(|| panic!("no Pulsedive evidence: {:?}", address.evidence));
    let attr = |key: &str| evidence.attr_values(key).collect::<Vec<_>>();
    assert_eq!(attr("retired"), ["No recent activity"]);
    assert_eq!(attr("city"), ["St Petersburg"]);
    assert_eq!(attr("isp"), ["Proton66 OOO"]);
}

#[test]
fn the_position_and_as_pulsedive_gives_are_entities_of_the_lookup() {
    let report = report();
    let place = entity(&report.entities, &EntityKind::Coordinates);
    assert_eq!(place.value, "59.941700,30.309600");
    assert!(place.has_tag("geoint"), "{:?}", place.tags);
    let asn = entity(&report.entities, &EntityKind::Asn);
    assert!(asn.value.eq_ignore_ascii_case("AS198953"), "{}", asn.value);
    assert!(
        asn.evidence
            .iter()
            .any(|e| e.provenance.source == "pulsedive"),
        "{:?}",
        asn.evidence
    );
}
