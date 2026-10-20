//! A `phone` lookup with a Numverify key keeps everything Numverify answers about the number: its
//! local and international formats, the country prefix, code and name, the location, carrier and
//! line type, and the whole answer. This runs `phone_cli::run_keyed`, the function the `phone`
//! command, `scan` and the web UI call, through a transport that answers Numverify's documented
//! `validate` shape and refuses every other host.

use huntsman_recon::entity::EntityKind;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Keys;
use huntsman_recon::phone_cli::{PhoneRun, run_keyed};
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// The `validate` example of the Number Verification API documentation.
const ANSWER: &str = r#"{"valid":true,"number":"14158586273","local_format":"4158586273","international_format":"+14158586273","country_prefix":"+1","country_code":"US","country_name":"United States of America","location":"Novato","carrier":"AT&T Mobility LLC","line_type":"mobile"}"#;

struct OnlyNumverify;

impl Transport for OnlyNumverify {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://api.apilayer.com/number_verification/validate?number=14158586273"
        {
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

#[test]
fn every_field_numverify_answers_reaches_the_number() {
    let keys = Keys::parse("HUNTSMAN_NUMVERIFY_KEY=numverify-test-key-0123456789")
        .unwrap_or_else(|e| panic!("{e}"));
    let report = match run_keyed(&OnlyNumverify, &keys, "+1 415 858 6273", 1_760_000_000) {
        PhoneRun::Printed { report, .. } => report,
        PhoneRun::Failed(why) => panic!("phone did not print: {why}"),
    };
    let numverify = report
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Phone)
        .flat_map(|e| &e.evidence)
        .find(|e| e.provenance.source == "numverify")
        .unwrap_or_else(|| panic!("no Numverify evidence: {:#?}", report.entities));
    let value = |key: &str| numverify.attributes.get(key).map(String::as_str);
    assert_eq!(
        value("international_format"),
        Some("+14158586273"),
        "{:?}",
        numverify.attributes
    );
    assert_eq!(value("local_format"), Some("4158586273"));
    assert_eq!(value("country_prefix"), Some("+1"));
    assert_eq!(value("country_name"), Some("United States of America"));
    assert_eq!(value("carrier"), Some("AT&T Mobility LLC"));
    let json = |text: &str| {
        serde_json::from_str::<serde_json::Value>(text).unwrap_or_else(|e| panic!("{e}: {text}"))
    };
    assert_eq!(value("raw_answer").map(json), Some(json(ANSWER)));
}
