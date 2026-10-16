//! An `ip` lookup keeps every name Robtex's passive DNS has seen on the address, and everything
//! else Robtex says about it. These run `ip_cli::run`, the function the `ip` command, `scan` and
//! the web UI call, through a transport that answers as Robtex did for `1.1.1.1` on 2026-10-15
//! (thirty passive names in the recorded shape) and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

const NAMES: usize = 30;

fn robtex_answer() -> String {
    let names: Vec<String> = (0..NAMES)
        .map(|n| format!(r#"{{"o":"site{n}.example.org","t":1792078550}}"#))
        .collect();
    format!(
        r#"{{"status":"ok","city":"","country":"","as":13335,"bgproute":"1.1.1.0/24","asname":"Cloudflare","asdesc":"CLOUDFLARENET","whoisdesc":"Cloudflare, Inc.","routedesc":"Cloudflare","pas":[{}]}}"#,
        names.join(",")
    )
}

struct OnlyRobtex;

impl Transport for OnlyRobtex {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://freeapi.robtex.com/ipquery/1.1.1.1" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: robtex_answer().into_bytes(),
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
        &OnlyRobtex,
        &Keys::default(),
        &Feeds::none(),
        "1.1.1.1",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 1.1.1.1 did not print: {why}"),
    }
}

#[test]
fn every_passive_name_robtex_lists_is_a_domain_of_the_lookup() {
    let entities = entities();
    let names = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.value.ends_with(".example.org"))
        .count();
    assert_eq!(names, NAMES, "{entities:#?}");
}

#[test]
fn the_route_and_as_descriptions_reach_the_address() {
    let entities = entities();
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "1.1.1.1")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let robtex = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "robtex")
        .unwrap_or_else(|| panic!("no Robtex evidence: {:?}", address.evidence));
    let one = |key: &str| robtex.attr_values(key).collect::<Vec<_>>().join("; ");
    assert_eq!(one("whois_description"), "Cloudflare, Inc.");
    assert_eq!(one("as_description"), "CLOUDFLARENET");
    assert_eq!(one("route_description"), "Cloudflare");
    assert_eq!(
        robtex
            .attr_values("passive_names")
            .flat_map(|v| v.split(','))
            .count(),
        NAMES
    );
}
