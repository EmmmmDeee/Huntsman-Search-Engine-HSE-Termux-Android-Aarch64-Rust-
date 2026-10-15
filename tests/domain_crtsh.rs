//! A `domain` lookup keeps every certificate crt.sh logs for a name, not only the first. These
//! run `domain_cli::run`, the function the `domain` command, `scan` and the web UI call, through
//! a transport that answers crt.sh's documented JSON rows and refuses every other host.

use huntsman_recon::domain_cli::{DomainRun, run};
use huntsman_recon::entity::{Entity, EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Three certificates naming `api.example.com`, from two CAs, in crt.sh's JSON row shape.
const CRTSH: &str = r#"[
 {"issuer_ca_id":295815,"issuer_name":"C=US, O=Let's Encrypt, CN=R10","common_name":"api.example.com","name_value":"api.example.com","id":9001,"entry_timestamp":"2026-01-01T01:00:00.123","not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"04aa","result_count":1},
 {"issuer_ca_id":245,"issuer_name":"C=US, O=\"Cloudflare, Inc.\", CN=Cloudflare TLS Issuing ECC CA 3","common_name":"api.example.com","name_value":"api.example.com\nmail.example.com","id":9002,"entry_timestamp":"2026-06-01T01:00:00.456","not_before":"2026-06-01T00:00:00","not_after":"2026-09-01T00:00:00","serial_number":"0bbb","result_count":2},
 {"issuer_ca_id":295815,"issuer_name":"C=US, O=Let's Encrypt, CN=R10","common_name":"api.example.com","name_value":"api.example.com","id":9003,"entry_timestamp":"2026-09-01T01:00:00.789","not_before":"2026-09-01T00:00:00","not_after":"2026-12-01T00:00:00","serial_number":"05cc","result_count":1}
]"#;

struct OnlyCrtSh;

impl Transport for OnlyCrtSh {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url.starts_with("https://crt.sh/?q=") {
            return Ok(Response {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: CRTSH.as_bytes().to_vec(),
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

fn evidence(entities: &[Entity], name: &str) -> Evidence {
    entities
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == name)
        .and_then(|e| e.evidence.iter().find(|ev| ev.provenance.source == "crtsh"))
        .cloned()
        .unwrap_or_else(|| panic!("no crt.sh evidence for {name}: {entities:#?}"))
}

#[test]
fn every_certificate_crtsh_logs_for_a_name_reaches_it() {
    let entities = match run(&OnlyCrtSh, &Keys::default(), "example.com", 1_760_000_000) {
        DomainRun::Printed { report, .. } => report.entities,
        DomainRun::Network(why) | DomainRun::Failed(why) => panic!("did not print: {why}"),
    };
    let api = evidence(&entities, "api.example.com");
    let value = |key: &str| api.attributes.get(key).map(String::as_str);
    assert_eq!(value("certificates"), Some("3"), "{:?}", api.attributes);
    assert_eq!(value("cert_ids"), Some("9001,9002,9003"));
    assert_eq!(value("cert_serials"), Some("04aa,0bbb,05cc"));
    assert_eq!(
        api.attr_values("issuers").collect::<Vec<_>>(),
        [
            "C=US, O=Let's Encrypt, CN=R10",
            "C=US, O=\"Cloudflare, Inc.\", CN=Cloudflare TLS Issuing ECC CA 3",
        ]
    );
    assert_eq!(value("issuer_ca_ids"), Some("295815,245"));
    assert_eq!(value("first_not_before"), Some("2026-01-01T00:00:00"));
    assert_eq!(value("last_not_after"), Some("2026-12-01T00:00:00"));
    assert_eq!(value("first_logged"), Some("2026-01-01T01:00:00.123"));
    assert_eq!(value("last_logged"), Some("2026-09-01T01:00:00.789"));
    let mail = evidence(&entities, "mail.example.com");
    assert_eq!(
        mail.attributes.get("cert_ids").map(String::as_str),
        Some("9002")
    );
}
