//! An email lookup keeps every breach name `XposedOrNot` lists for the address. These run
//! `indicator_legs::run`, which `email --keys`, `scan` and the web UI's email lookups call for an
//! address, through a transport that answers `XposedOrNot`'s `check-email` shape with 60 breaches
//! and refuses every other host.

use huntsman_recon::entity::EntityKind;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::indicator_legs;
use huntsman_recon::indicator_sources::Indicator;
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

fn xposedornot_answer() -> String {
    let names: Vec<String> = (0..60).map(|n| format!(r#""Breach{n:02}""#)).collect();
    format!(r#"{{"breaches":[[{}]]}}"#, names.join(","))
}

struct OnlyXposedOrNot;

impl Transport for OnlyXposedOrNot {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://api.xposedornot.com/v1/check-email/test%40example.com" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: xposedornot_answer().into_bytes(),
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
fn every_breach_xposedornot_lists_reaches_the_address() {
    let legs = indicator_legs::run(
        &OnlyXposedOrNot,
        &Keys::default(),
        Indicator::Email("test@example.com"),
        "email-scan",
        1_760_000_000,
    );
    let address = legs
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .unwrap_or_else(|| panic!("no address entity: {:#?}", legs.entities));
    let evidence = address
        .evidence
        .iter()
        .find(|ev| ev.provenance.source == "xposed_or_not")
        .unwrap_or_else(|| panic!("no XposedOrNot evidence: {:?}", address.evidence));
    let breaches: Vec<&str> = evidence
        .attr_values("breaches")
        .flat_map(|v| v.split(','))
        .collect();
    assert_eq!(breaches.len(), 60, "{:?}", evidence.attributes);
    assert_eq!(breaches.last(), Some(&"Breach59"));
    assert!(
        !address.tags.iter().any(|t| t == "truncated"),
        "{:?}",
        address.tags
    );
}
