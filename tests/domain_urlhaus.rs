//! A domain lookup with an abuse.ch key keeps every malware URL `URLhaus` lists for the host, with
//! every tag, reporter and blocklist verdict, and the whole answer. These run
//! `indicator_legs::run`, which `domain`, `ip`, `scan` and the web UI call for a host, through a
//! transport that answers `URLhaus`'s documented `host` shape with 12 URLs and refuses every other
//! host.

use huntsman_recon::entity::{EntityKind, Evidence};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::indicator_legs;
use huntsman_recon::indicator_sources::Indicator;
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;

/// The documented `host` answer (`URLhaus` API reference) with 12 URLs, each with its own tag.
fn answer() -> String {
    let urls: Vec<String> = (0..12)
        .map(|n| {
            format!(
                r#"{{"id":"{id}","urlhaus_reference":"https://urlhaus.abuse.ch/url/{id}/","url":"http://vektorex.com/drop/{n},x.exe","url_status":"{status}","date_added":"2026-10-{day:02} 03:29:03 UTC","threat":"malware_download","reporter":"reporter{r}","larted":"true","takedown_time_seconds":null,"tags":["family{n:02}"]}}"#,
                id = 121_300 + n,
                status = if n == 0 { "online" } else { "offline" },
                day = n + 1,
                r = n % 3,
            )
        })
        .collect();
    format!(
        r#"{{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/vektorex.com/","host":"vektorex.com","firstseen":"2019-01-15 07:09:01 UTC","url_count":"12","blacklists":{{"spamhaus_dbl":"abused_legit_malware","surbl":"not listed"}},"urls":[{}]}}"#,
        urls.join(",")
    )
}

struct OnlyUrlhaus;

impl Transport for OnlyUrlhaus {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        if request.url == "https://urlhaus-api.abuse.ch/v1/host/" {
            return Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: answer().into_bytes(),
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

fn urlhaus() -> Evidence {
    let keys =
        Keys::parse("HUNTSMAN_ABUSECH_KEY=abusech-test-key-0815").unwrap_or_else(|e| panic!("{e}"));
    let legs = indicator_legs::run(
        &OnlyUrlhaus,
        &keys,
        Indicator::Domain("vektorex.com"),
        "domain-scan",
        1_760_000_000,
    );
    let host = legs
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "vektorex.com")
        .unwrap_or_else(|| panic!("no host entity: {:#?}", legs.entities));
    host.evidence
        .iter()
        .find(|ev| ev.provenance.source == "urlhaus")
        .cloned()
        .unwrap_or_else(|| panic!("no URLhaus evidence: {:?}", host.evidence))
}

#[test]
fn every_url_urlhaus_lists_reaches_the_host() {
    let urlhaus = urlhaus();
    let urls: Vec<&str> = urlhaus.attr_values("urls").collect();
    assert_eq!(urls.len(), 12, "{:?}", urlhaus.attributes);
    assert_eq!(urls[11], "http://vektorex.com/drop/11,x.exe");
    let tags: Vec<&str> = urlhaus
        .attr_values("malware_tags")
        .flat_map(|v| v.split(','))
        .collect();
    assert_eq!(tags.len(), 12, "{:?}", urlhaus.attributes);
    assert_eq!(
        urlhaus.attributes.get("reporters").map(String::as_str),
        Some("reporter0,reporter1,reporter2")
    );
    assert_eq!(
        urlhaus
            .attr_values("blocklist_verdicts")
            .collect::<Vec<_>>(),
        ["spamhaus_dbl: abused_legit_malware", "surbl: not listed"]
    );
    assert_eq!(
        urlhaus.attributes.get("reference").map(String::as_str),
        Some("https://urlhaus.abuse.ch/host/vektorex.com/")
    );
    assert_eq!(urlhaus.attr_values("url_references").count(), 12);
    assert!(
        urlhaus
            .attributes
            .get("raw_answer")
            .is_some_and(|raw| raw.contains(r#""larted":"true""#)),
        "{:?}",
        urlhaus.attributes
    );
}
