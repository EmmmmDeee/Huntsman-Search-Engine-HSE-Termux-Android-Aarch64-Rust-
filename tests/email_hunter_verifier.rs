//! An address checked with a Hunter key keeps everything Hunter's verifier answers: its verdict
//! and result, each deliverability check, every public page that carries the address with when it
//! was seen there, and the whole answer. This runs `indicator_legs::run`, which the `email`
//! command, `scan` and the web UI call for an address, through a transport that answers Hunter's
//! documented `email-verifier` shape and refuses every other host.

use huntsman_recon::entity::{EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::indicator_legs;
use huntsman_recon::indicator_sources::Indicator;
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// The `email-verifier` example of the Hunter v2 documentation, with a second page.
const ANSWER: &str = r#"{"data":{"status":"valid","result":"deliverable","_deprecation_notice":"Using result is deprecated, use status instead","score":100,"email":"patrick@stripe.com","regexp":true,"gibberish":false,"disposable":false,"webmail":false,"mx_records":true,"smtp_server":true,"smtp_check":true,"accept_all":false,"block":false,"sources":[{"domain":"beta.paperbook.app","uri":"http://beta.paperbook.app/x","extracted_on":"2020-12-01","last_seen_on":"2021-01-12","still_on_page":true},{"domain":"news.example","uri":"https://news.example/a,b","extracted_on":"2019-03-02","last_seen_on":"2019-06-30","still_on_page":false}]},"meta":{"params":{"email":"patrick@stripe.com"}}}"#;

struct OnlyHunterVerifier;

impl Transport for OnlyHunterVerifier {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://api.hunter.io/v2/email-verifier?email=patrick%40stripe.com" {
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

fn hunter() -> Evidence {
    let keys =
        Keys::parse("HUNTSMAN_HUNTER_KEY=hunter-test-key-0815").unwrap_or_else(|e| panic!("{e}"));
    let legs = indicator_legs::run(
        &OnlyHunterVerifier,
        &keys,
        Indicator::Email("patrick@stripe.com"),
        "email-scan",
        1_760_000_000,
    );
    legs.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .flat_map(|e| &e.evidence)
        .find(|e| e.provenance.source == "hunter")
        .cloned()
        .unwrap_or_else(|| panic!("no Hunter evidence: {:#?}", legs.entities))
}

#[test]
fn every_check_and_page_the_verifier_answers_reaches_the_address() {
    let hunter = hunter();
    let value = |key: &str| hunter.attributes.get(key).map(String::as_str);
    assert_eq!(
        value("result"),
        Some("deliverable"),
        "{:?}",
        hunter.attributes
    );
    assert_eq!(value("format_valid"), Some("true"));
    assert_eq!(value("mx_records"), Some("true"));
    assert_eq!(value("smtp_server"), Some("true"));
    assert_eq!(value("smtp_check"), Some("true"));
    assert_eq!(value("gibberish"), Some("false"));
    assert_eq!(value("blocked"), Some("false"));
    assert_eq!(
        hunter.attr_values("source_pages").collect::<Vec<_>>(),
        [
            "http://beta.paperbook.app/x | first seen 2020-12-01 | last seen 2021-01-12 | still on the page",
            "https://news.example/a,b | first seen 2019-03-02 | last seen 2019-06-30 | no longer on the page"
        ]
    );
    let json = |text: &str| {
        serde_json::from_str::<serde_json::Value>(text).unwrap_or_else(|e| panic!("{e}: {text}"))
    };
    assert_eq!(value("raw_answer").map(json), Some(json(ANSWER)));
}
