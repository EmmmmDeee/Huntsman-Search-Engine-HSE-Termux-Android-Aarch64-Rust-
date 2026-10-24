use std::sync::Mutex;

use super::*;
use crate::http::{Request, Response, TransportFailure};
use crate::source_outcome::SourceOutcomeKind;

/// Records Mnemonic gave for `example.com` on 2026-10-15: two addresses, an IPv6 address it types
/// `a`, a reverse-zone record and two outside names that answered with the domain.
const EXAMPLE_COM: &str = r#"{"responseCode":200,"limit":500,"offset":0,"count":997,"metaData":{},"messages":[],"data":[
{"createdTimestamp":1775811501901,"lastUpdatedTimestamp":1792081705732,"times":17328,"tlp":"white","query":"example.com","answer":"104.20.23.154","minTtl":1,"maxTtl":300,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":0,"firstSeenTimestamp":0,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1775811502008,"lastUpdatedTimestamp":1792081705537,"times":17328,"tlp":"white","query":"example.com","answer":"172.66.147.243","minTtl":1,"maxTtl":300,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":0,"firstSeenTimestamp":0,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1775815951594,"lastUpdatedTimestamp":1792080789302,"times":927,"tlp":"white","query":"example.com","answer":"2606:4700:10::ac42:93f3","minTtl":300,"maxTtl":300,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":0,"firstSeenTimestamp":0,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1784048421402,"lastUpdatedTimestamp":1784092108111,"times":2,"tlp":"white","query":"130.251.184.91.in-addr.arpa","answer":"example.com","minTtl":3600,"maxTtl":3600,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":0,"firstSeenTimestamp":0,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1779360988850,"lastUpdatedTimestamp":1779379970512,"times":4,"tlp":"white","query":"62ad.com","answer":"example.com","minTtl":1799,"maxTtl":1799,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":0,"firstSeenTimestamp":0,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1729925914474,"lastUpdatedTimestamp":1729990456044,"times":8,"tlp":"white","query":"crescendo.jactrajano.info","answer":"example.com","minTtl":600,"maxTtl":600,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":0,"firstSeenTimestamp":0,"rrclass":"in","rrtype":"a"}
],"size":6}"#;

/// Records Mnemonic gave for `github.com` on 2026-10-15, with seen times set, and two names it
/// was made to hold: a CNAME under the domain to a CDN, and an MX record.
const GITHUB_COM: &str = r#"{"responseCode":200,"limit":500,"offset":0,"count":5,"data":[
{"createdTimestamp":1587398775521,"lastUpdatedTimestamp":1792078878924,"times":61525,"tlp":"white","query":"gist.github.com","answer":"github.com","minTtl":30,"maxTtl":3600,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":1792076032639,"firstSeenTimestamp":1587398678769,"rrclass":"in","rrtype":"cname"},
{"createdTimestamp":1486246448069,"lastUpdatedTimestamp":1791906077619,"times":774,"tlp":"white","query":"patch-diff.githubusercontent.com","answer":"github.com","minTtl":29,"maxTtl":30,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":1791878747241,"firstSeenTimestamp":1486246373441,"rrclass":"in","rrtype":"cname"},
{"createdTimestamp":1708335749125,"lastUpdatedTimestamp":1792080879398,"times":3289301,"tlp":"white","query":"github.com","answer":"4.208.26.197","minTtl":1,"maxTtl":61,"customer":null,"flags":["partialResult"],"lastSeenTimestamp":1792080739854,"firstSeenTimestamp":1708335651462,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1,"lastUpdatedTimestamp":2,"times":3,"tlp":"white","query":"docs.github.com","answer":"github.github.io","minTtl":60,"maxTtl":60,"flags":[],"lastSeenTimestamp":1792000000000,"firstSeenTimestamp":1700000000000,"rrclass":"in","rrtype":"cname"},
{"createdTimestamp":1,"lastUpdatedTimestamp":2,"times":3,"tlp":"white","query":"github.com","answer":"10 aspmx.l.google.com.","minTtl":60,"maxTtl":60,"flags":[],"lastSeenTimestamp":1792000000000,"firstSeenTimestamp":1700000000000,"rrclass":"in","rrtype":"mx"}
],"size":5}"#;

/// Records Mnemonic gave for `93.184.215.14` on 2026-10-15, and a reverse-zone record.
const ADDRESS: &str = r#"{"responseCode":200,"limit":500,"offset":0,"count":4,"data":[
{"createdTimestamp":1713506774583,"lastUpdatedTimestamp":1736953819008,"times":79630,"tlp":"white","query":"example.org","answer":"93.184.215.14","minTtl":3,"maxTtl":3600,"customer":null,"flags":[],"lastSeenTimestamp":1736910339299,"firstSeenTimestamp":1713506665533,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1713478209845,"lastUpdatedTimestamp":1736928500204,"times":11688,"tlp":"white","query":"example.com","answer":"93.184.215.14","minTtl":1,"maxTtl":3600,"customer":null,"flags":[],"lastSeenTimestamp":1736884763267,"firstSeenTimestamp":1713478195121,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1713553448619,"lastUpdatedTimestamp":1736872939628,"times":2198,"tlp":"white","query":"www.example.com","answer":"93.184.215.14","minTtl":759,"maxTtl":3600,"customer":null,"flags":[],"lastSeenTimestamp":1736848062628,"firstSeenTimestamp":1713553412026,"rrclass":"in","rrtype":"a"},
{"createdTimestamp":1,"lastUpdatedTimestamp":2,"times":1,"tlp":"white","query":"14.215.184.93.in-addr.arpa","answer":"example.net","minTtl":60,"maxTtl":60,"flags":[],"lastSeenTimestamp":0,"firstSeenTimestamp":0,"rrclass":"in","rrtype":"ptr"}
],"size":4}"#;

const EMPTY: &str = r#"{"responseCode":200,"limit":0,"offset":0,"count":0,"metaData":{},"messages":[{"message":null,"messageTemplate":"object.not.found","type":"INFO"}],"data":[],"size":0}"#;

/// Each URL's status and body, every URL asked recorded; any other URL is unreachable.
struct Net {
    pages: Vec<(String, u16, String)>,
    asked: Mutex<Vec<String>>,
}

impl Net {
    fn with(pages: &[(&str, u16, &str)]) -> Self {
        Self {
            pages: pages
                .iter()
                .map(|(url, status, body)| ((*url).to_owned(), *status, (*body).to_owned()))
                .collect(),
            asked: Mutex::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }
}

impl Transport for Net {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.asked.lock().expect("asked").push(request.url.clone());
        self.pages
            .iter()
            .find(|(url, _, _)| *url == request.url)
            .map(|(_, status, body)| Response {
                status: *status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                truncated: false,
            })
            .ok_or(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "offline".into(),
                blocked: false,
            })
    }
}

fn page(query: &str, n: usize) -> String {
    format!(
        "https://api.mnemonic.no/pdns/v3/{query}?limit={PAGE}&offset={}",
        n * PAGE
    )
}

fn values(entities: &[Entity]) -> Vec<(EntityKind, &str)> {
    entities
        .iter()
        .map(|e| (e.kind.clone(), e.raw_value.as_str()))
        .collect()
}

fn attr<'a>(entity: &'a Entity, key: &str) -> Option<&'a str> {
    entity
        .evidence
        .iter()
        .find_map(|e| e.attributes.get(key).map(String::as_str))
}

#[test]
fn a_record_line_keeps_everything_and_reads_unset_seen_times_from_the_record_times() {
    let body: Page = serde_json::from_str(EXAMPLE_COM).expect("page");
    assert_eq!(
        body.data[0].line(),
        "example.com a 104.20.23.154 (seen 2026-04-10T08:58:21Z to 2026-10-15T16:28:25Z; \
         17328 times; TTL 1-300; class in; TLP white; partialResult)"
    );
    let github: Page = serde_json::from_str(GITHUB_COM).expect("page");
    assert_eq!(
        github.data[0].first_seen().as_deref(),
        Some("2020-04-20T16:04:38Z")
    );
    assert_eq!(
        github.data[0].last_seen().as_deref(),
        Some("2026-10-15T14:53:52Z")
    );
}

#[test]
fn a_domain_keeps_every_record_and_its_names_and_addresses_become_entities() {
    let net = Net::with(&[(&page("github.com", 0), 200, GITHUB_COM)]);
    let leg = domain(&net, "github.com", "s", 1);
    let outcome = leg.outcome.expect("a row");
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(outcome.found, Some(5));
    assert_eq!(
        values(&leg.entities),
        [
            (EntityKind::Domain, "github.com"),
            (EntityKind::Domain, "gist.github.com"),
            (EntityKind::IpAddress, "4.208.26.197"),
            (EntityKind::Domain, "docs.github.com"),
            (EntityKind::Domain, "github.github.io"),
            (EntityKind::Domain, "aspmx.l.google.com"),
        ]
    );
    let seed = &leg.entities[0];
    let all = attr(seed, "passive_dns").expect("every record");
    assert_eq!(all.split(" | ").count(), 5);
    assert!(all.contains("patch-diff.githubusercontent.com cname github.com"));
    assert!(all.contains("github.com mx 10 aspmx.l.google.com."));
    assert_eq!(attr(seed, "passive_dns_records"), Some("5"));
    let address = &leg.entities[2];
    assert_eq!(attr(address, "domain"), Some("github.com"));
    assert_eq!(attr(address, "rrtype"), Some("a"));
    assert_eq!(attr(address, "times"), Some("3289301"));
    assert_eq!(attr(address, "first_seen"), Some("2024-02-19T09:40:51Z"));
    assert_eq!(net.asked(), [page("github.com", 0)]);
}

#[test]
fn reverse_zone_and_outside_names_stay_on_the_domain_only() {
    let net = Net::with(&[(&page("example.com", 0), 200, EXAMPLE_COM)]);
    let leg = domain(&net, "example.com", "s", 1);
    assert_eq!(
        values(&leg.entities),
        [
            (EntityKind::Domain, "example.com"),
            (EntityKind::IpAddress, "104.20.23.154"),
            (EntityKind::IpAddress, "172.66.147.243"),
            (EntityKind::IpAddress, "2606:4700:10::ac42:93f3"),
        ]
    );
    let seed = &leg.entities[0];
    assert!(
        seed.evidence[0]
            .summary
            .starts_with("Mnemonic passive DNS holds 997 records for example.com; the first 6")
    );
    let all = attr(seed, "passive_dns").expect("every record");
    assert!(all.contains("130.251.184.91.in-addr.arpa a example.com"));
    assert!(all.contains("crescendo.jactrajano.info a example.com"));
    // Six of 997 is a short page, so no second page is asked.
    assert_eq!(net.asked().len(), 1);
}

#[test]
fn an_address_gives_each_name_that_answered_with_it() {
    let net = Net::with(&[(&page("93.184.215.14", 0), 200, ADDRESS)]);
    let leg = ip(&net, "93.184.215.14", "s", 1);
    assert_eq!(
        values(&leg.entities),
        [
            (EntityKind::IpAddress, "93.184.215.14"),
            (EntityKind::Domain, "example.org"),
            (EntityKind::Domain, "example.com"),
            (EntityKind::Domain, "www.example.com"),
        ]
    );
    let site = &leg.entities[2];
    assert_eq!(attr(site, "ip"), Some("93.184.215.14"));
    assert_eq!(attr(site, "last_seen"), Some("2025-01-14T19:59:23Z"));
    assert!(
        attr(&leg.entities[0], "passive_dns")
            .is_some_and(|all| all.contains("14.215.184.93.in-addr.arpa ptr example.net"))
    );
}

#[test]
fn a_full_page_asks_the_next_and_stops_at_two() {
    let record = |n: usize| {
        format!(r#"{{"query":"h{n}.example.com","answer":"192.0.2.1","rrtype":"a","times":1}}"#)
    };
    let full = |from: usize| {
        let rows: Vec<String> = (from..from + PAGE).map(record).collect();
        format!(r#"{{"count":1500,"data":[{}]}}"#, rows.join(","))
    };
    let (first, second) = (full(0), full(PAGE));
    let net = Net::with(&[
        (&page("example.com", 0), 200, &first),
        (&page("example.com", 1), 200, &second),
    ]);
    let answers = lookup(&net, "example.com", 1).expect("answers");
    assert_eq!(answers.records.len(), 2 * PAGE);
    assert_eq!(answers.count, 1500);
    assert_eq!(answers.cut_short, None);
    assert_eq!(net.asked().len(), MAX_PAGES);

    // A second page that cannot be read keeps the first and says why.
    let net = Net::with(&[(&page("example.com", 0), 200, &first)]);
    let answers = lookup(&net, "example.com", 1).expect("answers");
    assert_eq!(answers.records.len(), PAGE);
    assert!(
        answers
            .cut_short
            .as_deref()
            .is_some_and(|why| why.starts_with("page 2 could not be read"))
    );
}

#[test]
fn nothing_held_is_a_valid_zero_and_a_failure_is_its_own_row() {
    let net = Net::with(&[(&page("example.net", 0), 200, EMPTY)]);
    let leg = domain(&net, "example.net", "s", 1);
    assert_eq!(
        leg.outcome.map(|o| o.kind),
        Some(SourceOutcomeKind::ValidZero)
    );
    assert!(leg.entities.is_empty());

    // A leg that got no response carries the failure on its own row; there is no side channel.
    let leg = domain(&Net::with(&[]), "example.net", "s", 1);
    let outcome = leg.outcome.expect("a row");
    assert_eq!(outcome.kind, SourceOutcomeKind::ConnectFailure);
    assert!(leg.entities.is_empty());

    let net = Net::with(&[(&page("example.net", 0), 503, "busy")]);
    let outcome = domain(&net, "example.net", "s", 1).outcome.expect("a row");
    assert_eq!(outcome.http_status, Some(503));
}

#[test]
fn a_host_is_a_canonical_name_and_never_a_reverse_zone_or_wildcard_name() {
    assert_eq!(host(" Example.COM. ").as_deref(), Some("example.com"));
    assert_eq!(host("gist.github.com").as_deref(), Some("gist.github.com"));
    for name in [
        "*.example.com",
        "a%b.example.com",
        "130.251.184.91.in-addr.arpa",
        "x.in-addr.ARPA.",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        "arpa.",
        "com",
        "",
    ] {
        assert_eq!(host(name), None, "{name:?}");
    }
}
