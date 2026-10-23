//! An `ip` lookup keeps everything `RIPEstat` says about the address: every origin AS of the
//! covering prefix, the related prefixes, the registry block and the whole answer. These run
//! `ip_cli::run`, the function the `ip` command, `scan` and the web UI call, through a transport
//! that answers `RIPEstat`'s `prefix-overview` shape and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, Report, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

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

/// `1.120.0.1` as `RIPEstat` answered it on 2026-10-23: Telstra's consumer space.
const TELSTRA: &str = r#"{"status":"ok","data":{"is_less_specific":true,"announced":true,"asns":[{"asn":1221,"holder":"ASN-TELSTRA - Telstra Limited"}],"related_prefixes":[],"resource":"1.120.0.0/13","block":{"resource":"1.0.0.0/8","desc":"APNIC (Status: ALLOCATED)","name":"IANA IPv4 Address Space Registry"}}}"#;

/// A holder whose name, not its handle, carries a common word one AU operator is named.
const NOT_AN_OPERATOR: &str = r#"{"status":"ok","data":{"is_less_specific":false,"announced":true,"asns":[{"asn":397213,"holder":"ACME-NET - Space that used to belong to Acme"}],"related_prefixes":[],"resource":"198.51.0.0/16","block":{"resource":"198.0.0.0/8","desc":"ARIN","name":"IANA IPv4 Address Space Registry"}}}"#;

/// An address no AS announces, in a registry block `RIPEstat` names.
const UNANNOUNCED: &str = r#"{"status":"ok","data":{"is_less_specific":false,"announced":false,"asns":[],"related_prefixes":[],"resource":"44.31.0.1","type":"prefix","block":{"resource":"44.0.0.0/8","desc":"ARDC (Status: ALLOCATED)","name":"IANA IPv4 Address Space Registry"}}}"#;

struct OnlyRipestat;

impl Transport for OnlyRipestat {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let body = match request.url.as_str() {
            "https://stat.ripe.net/data/prefix-overview/data.json?resource=8.8.8.8" => {
                ripestat_answer()
            }
            "https://stat.ripe.net/data/prefix-overview/data.json?resource=44.31.0.1" => {
                UNANNOUNCED.to_owned()
            }
            "https://stat.ripe.net/data/prefix-overview/data.json?resource=1.120.0.1" => {
                TELSTRA.to_owned()
            }
            "https://stat.ripe.net/data/prefix-overview/data.json?resource=8.9.10.11" => {
                NOT_AN_OPERATOR.to_owned()
            }
            _ => String::new(),
        };
        if !body.is_empty() {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: body.into_bytes(),
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

fn report(ip: &str) -> Report {
    match run(
        &OnlyRipestat,
        &Keys::default(),
        &Feeds::none(),
        ip,
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip {ip} did not print: {why}"),
    }
}

fn entities() -> Vec<Entity> {
    report("8.8.8.8").entities
}

fn ripestat(entities: &[Entity]) -> Evidence {
    ripestat_on(entities, "8.8.8.8")
}

fn ripestat_on(entities: &[Entity], ip: &str) -> Evidence {
    entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == ip)
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

#[test]
fn an_unannounced_address_keeps_the_registry_block_that_holds_it() {
    let report = report("44.31.0.1");
    let evidence = ripestat_on(&report.entities, "44.31.0.1");
    assert_eq!(evidence.summary, "Not announced; registry block 44.0.0.0/8");
    let value = |key: &str| evidence.attributes.get(key).map(String::as_str);
    assert_eq!(value("announced"), Some("false"));
    assert_eq!(value("registry_block"), Some("ARDC (Status: ALLOCATED)"));
    let outcome = report
        .outcomes
        .iter()
        .find(|o| o.module == "ripestat")
        .unwrap_or_else(|| panic!("no RIPEstat outcome: {:?}", report.outcomes));
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);
}

/// An address an Australian consumer provider's AS announces says so, with the operator; a
/// common word in a holder's free-text name does not make it one.
#[test]
fn an_australian_consumer_providers_address_is_tagged_with_its_operator() {
    let telstra = report("1.120.0.1");
    let address = telstra
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "1.120.0.1")
        .expect("the address");
    assert!(address.has_tag("au-consumer-isp"), "{:?}", address.tags);
    assert!(
        address
            .evidence
            .iter()
            .any(|ev| ev.attributes.get("network_operator").map(String::as_str) == Some("Telstra")),
        "{:#?}",
        address.evidence
    );

    let other = report("8.9.10.11");
    let address = other
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "8.9.10.11")
        .expect("the address");
    assert!(!address.has_tag("au-consumer-isp"), "{:?}", address.tags);
    // The origin is a public AS, so it was read, and only its holder's name failed to match.
    assert!(
        other
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Asn && e.raw_value == "AS397213"),
        "{:#?}",
        other.entities
    );
}
