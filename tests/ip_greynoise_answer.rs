//! An `ip` lookup keeps everything `GreyNoise` Community answers about the address: the flags,
//! classification and name, the visualizer link, `GreyNoise`'s message and the whole answer. This
//! runs `ip_cli::run`, the function the `ip` command, `scan` and the web UI call, through a
//! transport that answers `GreyNoise`'s recorded community shape and refuses every other host.

use huntsman_recon::entity::EntityKind;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip_cli::{IpRun, run};
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// Recorded without a key for `71.6.135.131` on 2026-10-14.
const ANSWER: &str = r#"{"ip":"71.6.135.131","noise":true,"riot":false,"classification":"benign","name":"Shodan.io","link":"https://viz.greynoise.io/ip/71.6.135.131","last_seen":"2026-10-14","message":"Success"}"#;

struct OnlyGreyNoise;

impl Transport for OnlyGreyNoise {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://api.greynoise.io/v3/community/71.6.135.131" {
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
fn the_link_message_and_whole_answer_reach_the_address() {
    let entities = match run(
        &OnlyGreyNoise,
        &Keys::default(),
        "71.6.135.131",
        1_760_000_000,
    ) {
        IpRun::Printed { report, .. } => report.entities,
        IpRun::Network(why) | IpRun::Failed(why) => panic!("ip did not print: {why}"),
    };
    let address = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "71.6.135.131")
        .unwrap_or_else(|| panic!("no address entity: {entities:#?}"));
    let greynoise = address
        .evidence
        .iter()
        .find(|e| e.provenance.source == "greynoise")
        .unwrap_or_else(|| panic!("no GreyNoise evidence: {:?}", address.evidence));
    let value = |key: &str| greynoise.attributes.get(key).map(String::as_str);
    assert_eq!(
        value("link"),
        Some("https://viz.greynoise.io/ip/71.6.135.131"),
        "{:?}",
        greynoise.attributes
    );
    assert_eq!(value("message"), Some("Success"));
    let json = |text: &str| {
        serde_json::from_str::<serde_json::Value>(text).unwrap_or_else(|e| panic!("{e}: {text}"))
    };
    assert_eq!(value("raw_answer").map(json), Some(json(ANSWER)));
}
