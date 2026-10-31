//! A `domain` lookup keeps every certificate crt.sh logs for a name, not only the first. These
//! run `domain_cli::run`, the function the `domain` command, `scan` and the web UI call, through
//! a transport that answers crt.sh's documented JSON rows and refuses every other host.

use huntsman_recon::domain_cli::{DomainRun, run};
use huntsman_recon::entity::{Entity, EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use huntsman_recon::threat_feeds::Feeds;

/// Three certificates naming `api.example.com`, from two CAs, in crt.sh's JSON row shape.
const CRTSH: &str = r#"[
 {"issuer_ca_id":295815,"issuer_name":"C=US, O=Let's Encrypt, CN=R10","common_name":"api.example.com","name_value":"api.example.com","id":9001,"entry_timestamp":"2026-01-01T01:00:00.123","not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"04aa","result_count":1},
 {"issuer_ca_id":245,"issuer_name":"C=US, O=\"Cloudflare, Inc.\", CN=Cloudflare TLS Issuing ECC CA 3","common_name":"api.example.com","name_value":"api.example.com\nmail.example.com","id":9002,"entry_timestamp":"2026-06-01T01:00:00.456","not_before":"2026-06-01T00:00:00","not_after":"2026-09-01T00:00:00","serial_number":"0bbb","result_count":2},
 {"issuer_ca_id":295815,"issuer_name":"C=US, O=Let's Encrypt, CN=R10","common_name":"api.example.com","name_value":"api.example.com","id":9003,"entry_timestamp":"2026-09-01T01:00:00.789","not_before":"2026-09-01T00:00:00","not_after":"2026-12-01T00:00:00","serial_number":"05cc","result_count":1}
]"#;

/// A transport that answers crt.sh with its JSON rows and refuses every other host.
struct OnlyCrtSh(&'static str);

impl Transport for OnlyCrtSh {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url.starts_with("https://crt.sh/?q=") {
            return Ok(Response {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: self.0.as_bytes().to_vec(),
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
    let entities = match run(
        &OnlyCrtSh(CRTSH),
        &Keys::default(),
        &Feeds::none(),
        "example.com",
        1_760_000_000,
    ) {
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

/// crt.sh writes `-1` for the issuing CA it has no record of, naming it "Issuer Not Found", as it
/// did for a certificate of example.com on 2026-10-31. That row is a certificate like any other:
/// the lookup keeps it and every other row. Before, `-1` failed to decode as a CA id and the
/// whole answer was discarded, so the domain's certificate log read as inconclusive.
#[test]
fn a_certificate_whose_issuer_crtsh_has_no_record_of_is_kept_with_every_other() {
    const ISSUER_NOT_FOUND: &str = r#"[
 {"issuer_ca_id":-1,"issuer_name":"Issuer Not Found","common_name":"example.com","name_value":"example.com\nlegacy.example.com","id":8506962125,"entry_timestamp":"2023-01-27T01:21:18.507","not_before":"2023-01-27T01:21:18","not_after":"2033-01-24T01:21:18","serial_number":"1ac1e693c87d36563a92ca145c87bbc26fd49f4c","result_count":3},
 {"issuer_ca_id":295815,"issuer_name":"C=US, O=Let's Encrypt, CN=R10","common_name":"api.example.com","name_value":"api.example.com","id":9001,"entry_timestamp":"2026-01-01T01:00:00.123","not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"04aa","result_count":1}
]"#;
    let report = match run(
        &OnlyCrtSh(ISSUER_NOT_FOUND),
        &Keys::default(),
        &Feeds::none(),
        "example.com",
        1_760_000_000,
    ) {
        DomainRun::Printed { report, .. } => report,
        DomainRun::Network(why) | DomainRun::Failed(why) => panic!("did not print: {why}"),
    };
    let crtsh = report
        .outcomes
        .iter()
        .find(|outcome| outcome.module == "crtsh")
        .expect("a crtsh row");
    assert_eq!(crtsh.kind, SourceOutcomeKind::Success, "{crtsh:?}");
    let legacy = evidence(&report.entities, "legacy.example.com");
    assert_eq!(
        legacy.attributes.get("issuers").map(String::as_str),
        Some("Issuer Not Found")
    );
    assert_eq!(legacy.attributes.get("issuer_ca_ids"), None);
    let api = evidence(&report.entities, "api.example.com");
    assert_eq!(
        api.attributes.get("issuer_ca_ids").map(String::as_str),
        Some("295815")
    );
}
