//! An `ip` lookup keeps everything `StopForumSpam` says about a reported address: its origin AS
//! as an ASN entity of the lookup, and the AS and country on the address's own evidence. These
//! run `ip_cli::run`, the function the `ip` command, `scan` and the web UI call, through a
//! transport that answers as `StopForumSpam` did for `185.220.101.1` and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Recorded without a key for `185.220.101.1` on 2026-10-15.
const STOPFORUMSPAM: &str = r#"{"success":1,"ip":{"value":"185.220.101.1","appears":1,"frequency":92,"lastseen":"2026-10-14 23:38:15","torexit":1,"asn":60729,"country":"de","confidence":95.34}}"#;

struct OnlyStopForumSpam;

impl Transport for OnlyStopForumSpam {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request
            .url
            .starts_with("https://api.stopforumspam.org/api?ip=185.220.101.1&json")
        {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: STOPFORUMSPAM.as_bytes().to_vec(),
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
        &OnlyStopForumSpam,
        &Keys::default(),
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
fn the_origin_as_stopforumspam_gives_is_an_asn_entity_of_the_lookup() {
    let entities = entities();
    let asn = entities
        .iter()
        .find(|e| e.kind == EntityKind::Asn && e.value.eq_ignore_ascii_case("AS60729"))
        .unwrap_or_else(|| panic!("no AS60729 entity: {entities:#?}"));
    assert!(
        asn.evidence
            .iter()
            .any(|e| e.provenance.source == "stopforumspam"),
        "{:?}",
        asn.evidence
    );
}

#[test]
fn the_as_and_country_stay_on_the_address() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "185.220.101.1")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let report = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "stopforumspam")
        .unwrap_or_else(|| panic!("no StopForumSpam evidence: {:?}", address.evidence));
    let attr = |key: &str| report.attr_values(key).collect::<Vec<_>>();
    assert_eq!(attr("reports"), ["92"]);
    assert_eq!(attr("asn"), ["AS60729"]);
    assert_eq!(attr("country"), ["DE"]);
}
