//! An `ip` lookup keeps everything `RIPEstat` says about the address: every origin AS of the
//! covering prefix, the related prefixes, the registry block and the whole answer. These run
//! `ip_cli::run`, the function the `ip` command, `scan` and the web UI call, through a transport
//! that answers `RIPEstat`'s `prefix-overview` shape and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// `8.8.8.8` as `RIPEstat` answered it on 2026-10-15, with ten origin AS numbers, as a prefix
/// announced from many networks (MOAS) has.
fn ripestat_answer() -> String {
    let asns: Vec<String> = (0..10)
        .map(|n| format!(r#"{{"asn":{},"holder":"Origin {n}"}}"#, 15_169 + n))
        .collect();
    format!(
        r#"{{"messages":[["warning","Given resource is not announced but result has been aligned to first-level less-specific (8.8.8.0/24)."]],"see_also":[{{"relation":"less-specific","resource":"8.0.0.0/9"}}],"status":"ok","data":{{"is_less_specific":true,"announced":true,"asns":[{}],"related_prefixes":["8.0.0.0/9","8.0.0.0/12"],"resource":"8.8.8.0/24","block":{{"resource":"8.0.0.0/8","desc":"Administered by ARIN","name":"IANA IPv4 Address Space Registry"}}}}}}"#,
        asns.join(",")
    )
}

struct OnlyRipestat;

impl Transport for OnlyRipestat {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://stat.ripe.net/data/prefix-overview/data.json?resource=8.8.8.8" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: ripestat_answer().into_bytes(),
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
    match run(&OnlyRipestat, &Keys::default(), "8.8.8.8", 1_760_000_000) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 8.8.8.8 did not print: {why}"),
    }
}

fn ripestat(entities: &[Entity]) -> Evidence {
    entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "8.8.8.8")
        .and_then(|e| {
            e.evidence
                .iter()
                .find(|ev| ev.provenance.source == "ripestat")
        })
        .cloned()
        .unwrap_or_else(|| panic!("no RIPEstat evidence on the address: {entities:#?}"))
}

#[test]
fn every_origin_as_ripestat_names_is_kept() {
    let entities = entities();
    let evidence = ripestat(&entities);
    let origins = evidence
        .attributes
        .get("origin_asns")
        .map_or(0, |v| v.split(',').count());
    assert_eq!(origins, 10, "{:?}", evidence.attributes);
    let asns = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Asn)
        .count();
    assert_eq!(asns, 10, "{entities:#?}");
}

#[test]
fn the_related_prefixes_registry_block_and_whole_answer_reach_the_address() {
    let evidence = ripestat(&entities());
    let value = |key: &str| evidence.attributes.get(key).map(String::as_str);
    assert_eq!(
        value("related_prefixes"),
        Some("8.0.0.0/9,8.0.0.0/12"),
        "{:?}",
        evidence.attributes
    );
    assert_eq!(value("block_resource"), Some("8.0.0.0/8"));
    assert_eq!(
        value("block_registry"),
        Some("IANA IPv4 Address Space Registry")
    );
    assert_eq!(value("see_also"), Some("less-specific 8.0.0.0/9"));
    assert_eq!(value("less_specific"), Some("true"));
    assert!(
        value("raw_answer").is_some_and(|raw| raw.contains(r#""asn":15178"#)),
        "{:?}",
        evidence.attributes
    );
}
