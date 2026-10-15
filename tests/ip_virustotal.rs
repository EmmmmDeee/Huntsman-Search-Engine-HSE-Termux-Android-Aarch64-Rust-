//! An `ip` lookup with a `VirusTotal` key keeps everything `VirusTotal` answers about the
//! address: each engine that flagged it, its registry context, the WHOIS text, the last HTTPS
//! certificate (its names become pivots) and the whole answer. These run `ip_cli::run`, the
//! function the `ip` command, `scan` and the web UI call, through a transport that answers
//! `VirusTotal`'s documented address object and refuses every other host.

use huntsman_recon::entity::{Entity, EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Shaped as the v3 `ip_addresses/{ip}` object of the `VirusTotal` API reference.
const ANSWER: &str = r#"{"data":{"id":"1.1.1.1","type":"ip_address","links":{"self":"https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1"},"attributes":{
    "last_analysis_stats":{"harmless":60,"malicious":1,"suspicious":0,"undetected":30,"timeout":0},
    "last_analysis_results":{"CRDF":{"category":"malicious","engine_name":"CRDF","method":"blacklist","result":"malicious"},"Webroot":{"category":"harmless","engine_name":"Webroot","method":"blacklist","result":"clean"}},
    "reputation":20,"asn":13335,"as_owner":"CLOUDFLARENET","network":"1.1.1.0/24","country":"AU","continent":"OC","regional_internet_registry":"APNIC",
    "tags":["anycast"],
    "total_votes":{"harmless":120,"malicious":4},
    "whois":"inetnum: 1.1.1.0 - 1.1.1.255\nnetname: APNIC-LABS\ndescr: APNIC and Cloudflare DNS Resolver project",
    "whois_date":1759000000,
    "last_https_certificate":{"subject":{"CN":"cloudflare-dns.com","O":"Cloudflare, Inc."},"issuer":{"C":"US","O":"DigiCert Inc"},"validity":{"not_after":"2026-01-21 23:59:59","not_before":"2025-01-02 00:00:00"},"thumbprint_sha256":"73b8ed5becf1ba6493d2e2215a42dfdc7877e91e311ff5e59fb43d094871e699","extensions":{"subject_alternative_name":["cloudflare-dns.com","*.cloudflare-dns.com","one.one.one.one","1.1.1.1"]}},
    "jarm":"27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c"}}}"#;

struct OnlyVirusTotal;

impl Transport for OnlyVirusTotal {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: ANSWER.into(),
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
    let keys = Keys::parse("HUNTSMAN_VIRUSTOTAL_KEY=virustotal-test-key-0815")
        .unwrap_or_else(|e| panic!("{e}"));
    match run(&OnlyVirusTotal, &keys, "1.1.1.1", 1_760_000_000) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip 1.1.1.1 did not print: {why}"),
    }
}

fn virustotal(entities: &[Entity]) -> Evidence {
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "1.1.1.1")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "virustotal")
        .cloned()
        .unwrap_or_else(|| panic!("no VirusTotal evidence: {:?}", address.evidence))
}

fn values<'a>(evidence: &'a Evidence, key: &str) -> Vec<&'a str> {
    evidence.attr_values(key).collect()
}

#[test]
fn every_verdict_registry_and_whois_line_reaches_the_address() {
    let entities = entities();
    let vt = virustotal(&entities);
    assert_eq!(
        values(&vt, "flagged_by"),
        ["CRDF: malicious"],
        "{:?}",
        vt.attributes
    );
    assert_eq!(values(&vt, "regional_internet_registry"), ["APNIC"]);
    assert_eq!(values(&vt, "continent"), ["OC"]);
    assert_eq!(values(&vt, "tags"), ["anycast"]);
    assert_eq!(values(&vt, "total_votes_malicious"), ["4"]);
    assert_eq!(values(&vt, "whois_date_unix"), ["1759000000"]);
    assert_eq!(
        values(&vt, "whois"),
        [
            "inetnum: 1.1.1.0 - 1.1.1.255",
            "netname: APNIC-LABS",
            "descr: APNIC and Cloudflare DNS Resolver project"
        ]
    );
    assert_eq!(
        values(&vt, "certificate_subject"),
        ["CN=cloudflare-dns.com, O=Cloudflare, Inc."]
    );
    assert!(
        vt.attributes
            .get("raw_answer")
            .is_some_and(|raw| raw.contains(r#""Webroot""#)),
        "{:?}",
        vt.attributes
    );
}

#[test]
fn the_names_on_the_certificate_at_the_address_are_pivots() {
    let entities = entities();
    for name in ["cloudflare-dns.com", "one.one.one.one"] {
        let entity = entities
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == name)
            .unwrap_or_else(|| panic!("no domain {name}: {entities:#?}"));
        assert!(
            entity
                .evidence
                .iter()
                .any(|e| e.provenance.source == "virustotal"),
            "{name} is not VirusTotal's: {entity:#?}"
        );
    }
    // An address on the certificate is not a host name.
    assert!(
        !entities
            .iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "1.1.1.1"),
        "{entities:#?}"
    );
}
