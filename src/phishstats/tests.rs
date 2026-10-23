use super::*;
use crate::http::{Request, Response, TransportFailure};
use crate::source_outcome::SourceOutcomeKind;

/// Recorded for `23.54.189.18` on 2026-10-15 (the two newest reports).
const REPORTS: &str = r#"[{"id":11918014,"url":"https://www.att.com/activearmorapp?_branch_match_id=1639368897458990702&utm_source=AT%26T%20App&_branch_referrer=H4sIAAAAAAAAA8soKSkottLXT0wuySxLTSzKzS%2FSzS%2FKTM%2FM00ssKdFLzs%2FV9wtL8U6KLCzzMUqyrytKTUstKsrMS49PKsovL04tsnXOKMrPTQUAZUf3KkgAAAA%3D","redirect_url":"https://67ifs.app.link/NVdKbYqvL2b","ip":"23.54.189.18","countrycode":"US","countryname":"United States","regioncode":"NJ","regionname":"New Jersey","city":"Piscataway","zipcode":"08854","latitude":"40.5511","longitude":"-74.4606","asn":"AS20940","bgp":"23.32.0.0/11","isp":"AKAMAI-ASN1 Akamai International B.V.","title":"Access Denied","date":"2026-10-15T19:57:22.000Z","date_update":null,"hash":"51590630102c563c4e46ddf231e2323ba1c13f24a2de53de3b96e91e024588a3","score":null,"host":"att.com","domain":"att","tld":"com","domain_registered_n_days_ago":14783,"screenshot":null,"abuse_contact":"abuse@akamai.com, abuse@att.net","ssl_issuer":"CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US","ssl_subject":"CN=*.att.com,O=AT&T Services\\, Inc.,L=Dallas,ST=Texas,C=US","rank_host":5060,"rank_domain":null,"n_times_seen_ip":74,"n_times_seen_host":135,"n_times_seen_domain":135,"http_code":403,"http_server":"AkamaiGHost","google_safebrowsing":null,"virus_total":null,"abuse_ch_malware":null,"vulns":null,"ports":"80, 443","os":null,"tags":"cdn","technology":null,"page_text":null,"ssl_fingerprint":"74C528E9A9DF7A2DC72D929E70EBA8489ED63AFF2359380B338C932E9DDA3026"},{"id":11917939,"url":"https://www.att.com/activearmorapp?_branch_match_id=1639251852273539667&utm_source=AT%26T%20App&_branch_referrer=H4sIAAAAAAAAA8soKSkottLXT0wuySxLTSzKzS%2FSzS%2FKTM%2FM00ssKdFLzs%2FV9wtL8U6KLCzzMUqyrytKTUstKsrMS49PKsovL04tsnXOKMrPTQUAZUf3KkgAAAA%3D","redirect_url":"https://67ifs.app.link/NVdKbYqvL2b","ip":"23.54.189.18","countrycode":"US","countryname":"United States","regioncode":"NJ","regionname":"New Jersey","city":"Piscataway","zipcode":"08854","latitude":"40.5511","longitude":"-74.4606","asn":"AS20940","bgp":"23.32.0.0/11","isp":"AKAMAI-ASN1 Akamai International B.V.","title":"Access Denied","date":"2026-10-15T12:12:17.000Z","date_update":null,"hash":"4be8facecd806efb76656bf9435f7e9fd65b4a1794422ca92f69ec92e41f84b0","score":null,"host":"att.com","domain":"att","tld":"com","domain_registered_n_days_ago":14783,"screenshot":null,"abuse_contact":"abuse@akamai.com, abuse@att.net","ssl_issuer":"CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US","ssl_subject":"CN=*.att.com,O=AT&T Services\\, Inc.,L=Dallas,ST=Texas,C=US","rank_host":5060,"rank_domain":null,"n_times_seen_ip":73,"n_times_seen_host":134,"n_times_seen_domain":134,"http_code":403,"http_server":"AkamaiGHost","google_safebrowsing":null,"virus_total":null,"abuse_ch_malware":null,"vulns":null,"ports":"80, 443","os":null,"tags":"cdn","technology":null,"page_text":null,"ssl_fingerprint":"74C528E9A9DF7A2DC72D929E70EBA8489ED63AFF2359380B338C932E9DDA3026"}]"#;

fn rows(body: &str) -> Vec<Map<String, Value>> {
    decode_page(body.as_bytes(), Indicator::Ip("23.54.189.18"))
        .unwrap_or_else(|error| panic!("recorded body must decode: {error:?}"))
}

fn attr<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    finding
        .attrs
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
}

#[test]
fn reported_urls_make_the_address_malicious_and_keep_every_field() {
    let found = finding(&rows(REPORTS), false).unwrap_or_else(|| panic!("two reports"));
    assert_eq!(
        found.summary,
        "PhishStats: 2 phishing URLs reported on the address, latest on 2026-10-15T19:57:22.000Z"
    );
    assert_eq!(found.tags, [tags::MALICIOUS, "phishing"]);
    assert_eq!(attr(&found, "malicious"), Some("2"));
    assert_eq!(attr(&found, "more_reports"), None);
    let reports: Vec<String> = rows(REPORTS).iter().filter_map(report).collect();
    assert_eq!(reports.len(), 2);
    for field in [
        "redirect_url=https://67ifs.app.link/NVdKbYqvL2b",
        "title=Access Denied",
        "http_server=AkamaiGHost",
        "ssl_fingerprint=74C528E9A9DF7A2DC72D929E70EBA8489ED63AFF2359380B338C932E9DDA3026",
        "n_times_seen_ip=74",
        "abuse_contact=abuse@akamai.com, abuse@att.net",
        "bgp=23.32.0.0/11",
    ] {
        assert!(
            reports[0].contains(field),
            "{field} missing from {}",
            reports[0]
        );
    }
    assert!(reports[0].starts_with("https://www.att.com/activearmorapp?"));
    assert!(!reports[0].contains("ip=23.54.189.18"), "{}", reports[0]);
    assert!(
        attr(&found, "phishing_urls").is_some_and(|kept| reports.join(" | ").starts_with(kept))
    );
    // The two reports share a host, which is one pivot.
    assert_eq!(found.pivots.len(), 1);
    assert_eq!(found.pivots[0].kind, PivotKind::Domain);
    assert_eq!(found.pivots[0].value, "att.com");
}

#[test]
fn no_reports_is_a_valid_zero_and_a_full_last_page_says_there_are_more() {
    assert!(finding(&rows("[]"), false).is_none());
    let found = finding(&rows(REPORTS), true).unwrap_or_else(|| panic!("two reports"));
    assert_eq!(attr(&found, "more_reports"), Some("true"));
}

#[test]
fn a_report_on_another_address_or_not_a_list_is_refused() {
    assert!(matches!(
        decode_page(REPORTS.as_bytes(), Indicator::Ip("192.0.2.9")),
        Err(LegError::Decode(_))
    ));
    assert!(matches!(
        decode_page(b"{}", Indicator::Ip("192.0.2.9")),
        Err(LegError::Decode(_))
    ));
}

#[test]
fn pages_count_from_zero_and_only_an_address_has_one() {
    assert_eq!(
        url(Indicator::Ip("192.0.2.9"), 0).as_deref(),
        Some(
            "https://api.phishstats.info/api/phishing?_where=(ip,eq,192.0.2.9)&_sort=-id&_size=100&_p=0"
        )
    );
    assert!(url(Indicator::Domain("example.org"), 0).is_none());
}

/// Each page URL's status and body; any other URL is unreachable.
struct Pages(Vec<(String, u16, String)>);

impl Transport for Pages {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.0
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

fn page_url(page: usize) -> String {
    url(Indicator::Ip("23.54.189.18"), page).unwrap_or_else(|| panic!("an address has pages"))
}

#[test]
fn a_later_page_that_fails_keeps_the_reports_read_and_says_where_it_stopped() {
    let full: Vec<String> = (0..PAGE)
        .map(|n| {
            format!(
                r#"{{"id":{n},"url":"https://phish{n}.example/","ip":"23.54.189.18","host":"phish.example"}}"#
            )
        })
        .collect();
    let transport = Pages(vec![
        (page_url(0), 200, format!("[{}]", full.join(","))),
        (page_url(1), 429, String::new()),
    ]);
    let found = lookup(
        &transport,
        &Keys::default(),
        Indicator::Ip("23.54.189.18"),
        1,
    )
    .unwrap_or_else(|error| panic!("the first page was read: {error:?}"))
    .unwrap_or_else(|| panic!("a full page of reports"));
    assert_eq!(found.tags, [tags::MALICIOUS, "phishing"]);
    assert_eq!(attr(&found, "malicious"), Some("100"));
    assert_eq!(attr(&found, "more_reports"), Some("true"));
    assert_eq!(
        attr(&found, "cut_short"),
        Some("page 2 could not be read: rate or quota limit reached (HTTP 429)")
    );
    // The first page's failure still fails the lookup.
    let first = Pages(vec![(page_url(0), 429, String::new())]);
    assert!(matches!(
        lookup(&first, &Keys::default(), Indicator::Ip("23.54.189.18"), 1),
        Err(LegError::RateLimited { .. })
    ));
}

#[test]
fn a_later_page_that_fails_after_pages_with_no_report_fails_the_lookup() {
    // A full page of rows with no `url` holds no report, so there is nothing to keep.
    let unreported: Vec<String> = (0..PAGE)
        .map(|n| format!(r#"{{"id":{n},"ip":"23.54.189.18","host":"phish.example"}}"#))
        .collect();
    let transport = Pages(vec![
        (page_url(0), 200, format!("[{}]", unreported.join(","))),
        (page_url(1), 429, String::new()),
    ]);
    assert!(matches!(
        lookup(
            &transport,
            &Keys::default(),
            Indicator::Ip("23.54.189.18"),
            1
        ),
        Err(LegError::RateLimited { .. })
    ));
}
