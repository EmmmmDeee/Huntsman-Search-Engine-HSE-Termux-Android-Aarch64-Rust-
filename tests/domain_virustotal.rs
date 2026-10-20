//! A `domain` lookup with a `VirusTotal` key keeps everything `VirusTotal` answers about the
//! domain: each engine that flagged it, every category, the WHOIS text, the last DNS records and
//! HTTPS certificate (their addresses and names become pivots) and the whole answer. These run
//! `domain_cli::run`, the function the `domain` command, `scan` and the web UI call, through a
//! transport that answers `VirusTotal`'s documented domain object and refuses every other host.

use huntsman_recon::domain_cli::{DomainRun, run};
use huntsman_recon::entity::{Entity, EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

/// Shaped as the v3 `domains/{domain}` object of the `VirusTotal` API reference.
const ANSWER: &str = r#"{"data":{"id":"example.com","type":"domain","links":{"self":"https://www.virustotal.com/api/v3/domains/example.com"},"attributes":{
    "last_analysis_stats":{"harmless":66,"malicious":1,"suspicious":1,"undetected":24,"timeout":0},
    "last_analysis_results":{"Kaspersky":{"category":"malicious","engine_name":"Kaspersky","method":"blacklist","result":"phishing"},"Sophos":{"category":"suspicious","engine_name":"Sophos","method":"blacklist","result":"suspicious"},"Google Safebrowsing":{"category":"harmless","engine_name":"Google Safebrowsing","method":"blacklist","result":"clean"}},
    "categories":{"Forcepoint ThreatSeeker":"reference materials","BitDefender":"computersandsoftware","Sophos":"information technology","alphaMountain.ai":"Information Technology, Phishing","Xcitium Verdict Cloud":"media sharing","Webroot":"Computer and Internet Info","Comodo Valkyrie Verdict":"mobile communications","Dr.Web":"online shopping","Emsisoft":"parked","Kaspersky":"phishing"},
    "reputation":-3,"registrar":"RESERVED-Internet Assigned Numbers Authority","creation_date":808372800,"expiration_date":1786060800,"tld":"com",
    "popularity_ranks":{"Majestic":{"rank":7,"timestamp":1760000000},"Tranco":{"rank":122,"timestamp":1760000000}},
    "total_votes":{"harmless":12,"malicious":3},
    "tags":["parking"],
    "whois":"Domain Name: EXAMPLE.COM\nRegistrar: RESERVED-Internet Assigned Numbers Authority\nName Server: A.IANA-SERVERS.NET\nName Server: B.IANA-SERVERS.NET",
    "last_dns_records":[{"type":"A","value":"93.184.215.14","ttl":300},{"type":"AAAA","value":"2606:2800:21f:cb07:6820:80da:af6b:8b2c","ttl":300},{"type":"NS","value":"a.iana-servers.net","ttl":86400},{"type":"MX","priority":10,"value":"mx.example.net","ttl":300},{"type":"TXT","value":"v=spf1 -all","ttl":86400}],
    "last_dns_records_date":1760000300,
    "last_https_certificate":{"subject":{"CN":"www.example.org"},"issuer":{"C":"US","O":"DigiCert Inc","CN":"DigiCert Global G3 TLS ECC SHA384 2020 CA1"},"validity":{"not_after":"2025-03-01 23:59:59","not_before":"2024-01-30 00:00:00"},"serial_number":"075bcef30689c8addf13e51af4afe187","thumbprint":"4da25a6d5ef62c5f95c7bd0a73ea3c177b36999d","thumbprint_sha256":"455943cf819425761d1f950263ebf54755d8d684c25535943976f488bc79d23b","extensions":{"subject_alternative_name":["www.example.org","example.net","example.edu","*.example.edu"]}},
    "crowdsourced_context":[{"source":"ArcSight Threat Intelligence","title":"Phishing kit host","severity":"high","details":"seen in a lure","timestamp":1760000000}],
    "jarm":"29d29d00029d29d00042d43d00041d5de67cc9954cc85372523050f20b5007","last_analysis_date":1760000123}}}"#;

struct OnlyVirusTotal;

impl Transport for OnlyVirusTotal {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://www.virustotal.com/api/v3/domains/example.com" {
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
    match run(
        &OnlyVirusTotal,
        &keys,
        &Feeds::none(),
        "example.com",
        1_760_000_000,
    ) {
        DomainRun::Printed { report, .. } => report.entities,
        DomainRun::Network(why) | DomainRun::Failed(why) => {
            panic!("domain example.com did not print: {why}")
        }
    }
}

fn virustotal(entities: &[Entity]) -> Evidence {
    let domain = entities
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "example.com")
        .unwrap_or_else(|| panic!("no domain entity: {entities:#?}"));
    domain
        .evidence
        .iter()
        .find(|e| e.provenance.source == "virustotal" && e.attributes.contains_key("malicious"))
        .cloned()
        .unwrap_or_else(|| panic!("no VirusTotal evidence: {:?}", domain.evidence))
}

fn values<'a>(evidence: &'a Evidence, key: &str) -> Vec<&'a str> {
    evidence.attr_values(key).collect()
}

#[test]
fn every_verdict_category_and_whois_line_reaches_the_domain() {
    let entities = entities();
    let vt = virustotal(&entities);
    assert_eq!(
        values(&vt, "flagged_by"),
        ["Kaspersky: phishing", "Sophos: suspicious"],
        "{:?}",
        vt.attributes
    );
    assert_eq!(
        vt.attributes.get("categories").map(String::as_str),
        Some(
            "computer and internet info,computersandsoftware,information technology,\
             information technology, phishing,media sharing,mobile communications,\
             online shopping,parked,phishing,reference materials"
        )
    );
    assert_eq!(
        values(&vt, "whois"),
        [
            "Domain Name: EXAMPLE.COM",
            "Registrar: RESERVED-Internet Assigned Numbers Authority",
            "Name Server: A.IANA-SERVERS.NET",
            "Name Server: B.IANA-SERVERS.NET"
        ]
    );
    assert_eq!(
        values(&vt, "popularity_ranks"),
        ["Majestic 7", "Tranco 122"]
    );
    assert_eq!(values(&vt, "total_votes_malicious"), ["3"]);
    assert_eq!(values(&vt, "expiration_date_unix"), ["1786060800"]);
    assert_eq!(
        values(&vt, "certificate_sha256"),
        ["455943cf819425761d1f950263ebf54755d8d684c25535943976f488bc79d23b"]
    );
    assert_eq!(
        values(&vt, "crowdsourced_context"),
        ["ArcSight Threat Intelligence | Phishing kit host | high | seen in a lure"]
    );
    assert!(
        vt.attributes
            .get("raw_answer")
            .is_some_and(|raw| raw.contains(r#""Google Safebrowsing""#)),
        "{:?}",
        vt.attributes
    );
}

#[test]
fn the_last_dns_records_and_certificate_names_are_pivots() {
    let entities = entities();
    let vt = virustotal(&entities);
    assert_eq!(
        values(&vt, "dns_records"),
        [
            "A 93.184.215.14 ttl 300",
            "AAAA 2606:2800:21f:cb07:6820:80da:af6b:8b2c ttl 300",
            "NS a.iana-servers.net ttl 86400",
            "MX 10 mx.example.net ttl 300",
            "TXT v=spf1 -all ttl 86400"
        ]
    );
    assert_eq!(
        values(&vt, "ip"),
        ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]
    );
    for (kind, value) in [
        (EntityKind::IpAddress, "93.184.215.14"),
        (
            EntityKind::IpAddress,
            "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
        ),
        (EntityKind::Domain, "a.iana-servers.net"),
        (EntityKind::Domain, "mx.example.net"),
        (EntityKind::Domain, "example.org"),
        (EntityKind::Domain, "example.net"),
        (EntityKind::Domain, "example.edu"),
    ] {
        let entity = entities
            .iter()
            .find(|e| e.kind == kind && e.value == value)
            .unwrap_or_else(|| panic!("no {kind:?} {value}: {entities:#?}"));
        assert!(
            entity
                .evidence
                .iter()
                .any(|e| e.provenance.source == "virustotal"),
            "{value} is not VirusTotal's: {entity:#?}"
        );
    }
}
