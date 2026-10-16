//! An `ip` lookup keeps everything Netlas holds for the address. These run `ip_cli::run`, the
//! function the `ip` command, `scan` and the web UI call, through a transport that answers as
//! Netlas did for `1.1.1.1` on 2026-10-15 (twenty fingerprinted programs in the recorded shape,
//! WHOIS text left out) and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

fn netlas_answer() -> String {
    let software: Vec<String> = (0..20)
        .map(|n| {
            format!(
                r#"{{"tag":[{{"name":"program_{n}","fullname":"Program {n}","category":["Category {n}"]}}],"uri":"http://1.1.1.1:{port}/"}}"#,
                port = 8000 + n
            )
        })
        .collect();
    format!(
        r#"{{"ip":"1.1.1.1","type":"ip","ports":[{{"protocol":"https","prot4":"tcp","port":443,"prot7":"http"}},{{"protocol":"dns_udp","prot4":"udp","port":53,"prot7":"dns"}}],"ptr":["one.one.one.one"],"domains":[],"domains_count":39071,"privacy":{{"is_vpn":false,"is_proxy":false,"is_tor":false}},"organization":"ORG-ARAD1-AP","geo":{{"is_anycast":true,"ip":"1.1.1.0/24","registered_country":"AU"}},"software":[{}],"ioc":[],"whois":{{"abuse":"helpdesk@apnic.net","net":{{"country":"AU","address":"PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia","range":"1.1.1.0 - 1.1.1.255","handle":"AA1412-AP","organization":"ORG-ARAD1-AP","name":"APNIC-LABS","cidr":["1.1.1.0/24"],"contacts":{{"emails":["resolver-abuse@cloudflare.com","helpdesk@apnic.net","research@apnic.net"],"phones":["+61-7-38583100"]}}}},"asn":{{"number":["13335"],"registry":"apnic","country":"AU","name":"CLOUDFLARENET - Cloudflare","cidr":"1.1.1.0/24"}}}}}}"#,
        software.join(",")
    )
}

struct OnlyNetlas;

impl Transport for OnlyNetlas {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://app.netlas.io/api/host/1.1.1.1/" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: netlas_answer().into_bytes(),
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
        &OnlyNetlas,
        &Keys::default(),
        &Feeds::none(),
        "1.1.1.1",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 1.1.1.1 did not print: {why}"),
    }
}

fn netlas_evidence(entities: &[Entity]) -> &huntsman_recon::entity::Evidence {
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "1.1.1.1")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "netlas")
        .unwrap_or_else(|| panic!("no Netlas evidence: {:?}", address.evidence))
}

#[test]
fn every_program_netlas_fingerprinted_reaches_the_address() {
    let entities = entities();
    let netlas = netlas_evidence(&entities);
    let count = |key: &str| netlas.attr_values(key).flat_map(|v| v.split(',')).count();
    for key in ["software", "software_categories", "software_uris"] {
        assert_eq!(count(key), 20, "{key}: {:?}", netlas.attributes);
    }
    assert!(
        netlas
            .attr_values("raw_answer")
            .any(|raw| raw.contains(r#""fullname":"Program 19""#)),
        "{:?}",
        netlas.attributes
    );
}

#[test]
fn the_network_whois_and_its_contacts_reach_the_address() {
    let entities = entities();
    let netlas = netlas_evidence(&entities);
    let one = |key: &str| netlas.attr_values(key).collect::<Vec<_>>().join("; ");
    assert_eq!(one("net_phones"), "+61-7-38583100");
    assert_eq!(
        one("net_emails"),
        "resolver-abuse@cloudflare.com,helpdesk@apnic.net,research@apnic.net"
    );
    assert_eq!(
        one("net_address"),
        "PO Box 3646 South Brisbane, QLD 4101 Australia"
    );
    assert_eq!(one("abuse_email"), "helpdesk@apnic.net");
    assert_eq!(one("organization"), "ORG-ARAD1-AP");
    assert_eq!(one("port_services"), "443/tcp/https,53/udp/dns_udp");
}
