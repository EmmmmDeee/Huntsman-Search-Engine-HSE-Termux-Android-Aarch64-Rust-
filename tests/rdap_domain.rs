use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::rdap_domain::{lookup_domain, parse_domain_record};
use huntsman_recon::source_outcome::SourceOutcomeKind;

struct Fake {
    script: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    seen: RefCell<Vec<Request>>,
}

impl Fake {
    fn new(script: Vec<Result<Response, TransportFailure>>) -> Self {
        Self {
            script: RefCell::new(script.into()),
            seen: RefCell::default(),
        }
    }
}

impl Transport for Fake {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        self.script
            .borrow_mut()
            .pop_front()
            .expect("unexpected extra RDAP request")
    }
}

fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        headers: vec![],
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

const FIXTURE: &str = r#"{
  "ldhName": "EXAMPLE.COM.",
  "handle": "2336799_DOMAIN_COM-VRSN",
  "status": ["client transfer prohibited", "client transfer prohibited"],
  "events": [
    {"eventAction":"registration", "eventDate":"1995-08-14T04:00:00Z"},
    {"eventAction":"expiration", "eventDate":"2030-08-13T04:00:00Z"}
  ],
  "nameservers": [
    {"ldhName":"A.IANA-SERVERS.NET."},
    {"ldhName":"b.iana-servers.net"},
    {"ldhName":"a.iana-servers.net"}
  ],
  "secureDNS": {"delegationSigned": true},
  "entities": [{
    "roles":["registrar"],
    "publicIds":[{"type":"IANA Registrar ID","identifier":"376"}],
    "vcardArray":["vcard", [["fn", {}, "text", "Sensitive Contact Name"]]]
  }]
}"#;

#[test]
fn parser_extracts_public_structured_fields_without_contact_pii() {
    let record = parse_domain_record("example.com", FIXTURE.as_bytes()).expect("parse RDAP");

    assert_eq!(record.domain, "example.com");
    assert_eq!(record.handle.as_deref(), Some("2336799_DOMAIN_COM-VRSN"));
    assert_eq!(record.statuses, vec!["client transfer prohibited"]);
    assert_eq!(
        record.nameservers,
        vec!["a.iana-servers.net", "b.iana-servers.net"]
    );
    assert_eq!(record.dnssec_signed, Some(true));
    assert_eq!(record.registrar_iana_id.as_deref(), Some("376"));
    assert_eq!(
        record.events.get("registration").map(String::as_str),
        Some("1995-08-14T04:00:00Z")
    );

    let json = serde_json::to_string(&record).expect("serialize");
    assert!(!json.contains("Sensitive Contact Name"));
    assert!(!json.contains("vcard"));
}

#[test]
fn parser_rejects_response_bound_to_another_domain() {
    let wrong = FIXTURE.replace("EXAMPLE.COM.", "other.example");
    let error = parse_domain_record("example.com", wrong.as_bytes()).expect_err("mismatch");
    assert!(error.to_string().contains("mismatch"));
}

#[test]
fn lookup_uses_one_keyless_rdap_request_and_parses_200() {
    let fake = Fake::new(vec![Ok(response(200, FIXTURE))]);
    let lookup = lookup_domain(&fake, "Example.COM.", 1_700_000_000).expect("lookup");

    assert_eq!(fake.seen.borrow().len(), 1);
    let request = &fake.seen.borrow()[0];
    assert_eq!(request.url, "https://rdap.org/domain/example.com");
    assert!(request.headers.is_empty());
    assert_eq!(lookup.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(
        lookup.record.as_ref().map(|r| r.domain.as_str()),
        Some("example.com")
    );
}

#[test]
fn challenge_page_is_not_parsed_as_registration_data() {
    let fake = Fake::new(vec![Ok(response(
        200,
        "<html><title>Just a moment...</title>Cloudflare</html>",
    ))]);
    let lookup = lookup_domain(&fake, "example.com", 1).expect("lookup");
    assert_eq!(lookup.outcome.kind, SourceOutcomeKind::BotWaf);
    assert!(lookup.record.is_none());
}

#[test]
fn invalid_domain_never_reaches_transport() {
    let fake = Fake::new(vec![]);
    for domain in [
        "https://example.com",
        "example.com/path",
        "-bad.example",
        "bad..example",
    ] {
        assert!(lookup_domain(&fake, domain, 1).is_err(), "{domain}");
    }
    assert_eq!(fake.seen.borrow().len(), 0);
}
