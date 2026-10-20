//! A source keeps every other indicator it names. These run `indicator_legs::run`, the one place
//! the `ip`, `domain`, `email` and `phone` lookups, `scan` and the web UI run their sources,
//! through a transport that answers `SecurityTrails`' documented subdomain listing with eighty
//! subdomains and refuses every other host.

use huntsman_recon::entity::EntityKind;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::indicator_legs;
use huntsman_recon::indicator_sources::Indicator;
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

const SUBDOMAINS: usize = 80;

struct OnlySecurityTrails;

impl Transport for OnlySecurityTrails {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request
            .url
            .starts_with("https://api.securitytrails.com/v1/domain/example.com/")
        {
            let labels: Vec<String> = (0..SUBDOMAINS).map(|n| format!("\"host{n}\"")).collect();
            let body = format!(
                r#"{{"endpoint":"/v1/domain/example.com/subdomains","meta":{{"limit_reached":false}},"subdomain_count":{SUBDOMAINS},"subdomains":[{}]}}"#,
                labels.join(",")
            );
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

#[test]
fn every_subdomain_a_source_names_is_an_entity_of_the_lookup() {
    let keys = Keys::parse("HUNTSMAN_SECTRAILS_KEY=sectrails-test-key-0815")
        .unwrap_or_else(|e| panic!("{e}"));
    let legs = indicator_legs::run(
        &OnlySecurityTrails,
        &keys,
        Indicator::Domain("example.com"),
        "scan-every-pivot",
        1_760_000_000,
    );
    let subdomains: Vec<&str> = legs
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.value.ends_with(".example.com"))
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(subdomains.len(), SUBDOMAINS, "{subdomains:?}");
    assert!(subdomains.contains(&"host79.example.com"), "{subdomains:?}");
    let outcome = legs
        .outcomes
        .iter()
        .find(|o| o.module == "securitytrails")
        .unwrap_or_else(|| panic!("no SecurityTrails outcome: {:?}", legs.outcomes));
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);
    assert!(
        outcome.found.is_some_and(|found| found > SUBDOMAINS),
        "{outcome:?}"
    );
}
