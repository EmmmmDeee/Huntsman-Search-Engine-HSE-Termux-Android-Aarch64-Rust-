use super::*;

/// Recorded for `45.148.10.99` on 2026-10-15: four threat feeds and SSH and web honeypot activity.
const LISTED: &str = r#"{"ip":{"number":"45.148.10.99","count":null,"attacks":null,"maxdate":null,"mindate":null,"updated":null,"comment":null,"maxrisk":null,"asabusecontact":"abuse@vegatele.com","as":48090,"asname":"PPTECHNOLOGY","ascountry":"GB","assize":256,"network":"45.148.10.0\/24","threatfeeds":{"blocklistde22":{"lastseen":"2026-02-06","firstseen":"2020-02-14"},"blocklistde25":{"lastseen":"2026-02-06","firstseen":"2020-09-18"},"ciarmy":{"lastseen":"2026-02-06","firstseen":"2020-02-17"},"emergincompromised":{"lastseen":"2026-02-06","firstseen":"2020-02-14"}},"ssh":{"attempts":983,"usernames":10,"passwords":20,"start":"2020-02-12","end":"2020-02-17"},"weblogs":{"count":5,"avgauthors":1,"avgurls":3,"avguser_agents":3,"firstseen":"2026-02-04","lastseen":"2026-02-04"}}}"#;
/// Recorded for `1.12.229.231` on 2026-10-15: the network and cloud only.
const NETWORK_ONLY: &str = r#"{"ip":{"number":"1.12.229.231","count":null,"attacks":null,"maxdate":null,"mindate":null,"updated":null,"comment":null,"maxrisk":null,"asabusecontact":"ipas@cnnic.cn","as":45090,"asname":"TENCENT-NET-AP Shenzhen Tencent Computer Systems Company Limited","ascountry":"CN","assize":12058880,"network":"1.12.192.0\/18","cloud":"tencent","clouddetails":null}}"#;

fn finding(body: &str, ip: &str) -> Finding {
    decode(body.as_bytes(), Indicator::Ip(ip))
        .ok()
        .flatten()
        .unwrap_or_else(|| panic!("recorded body must decode"))
}

fn attr<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    finding
        .attrs
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
}

#[test]
fn honeypot_activity_is_malicious_and_every_feed_and_count_is_kept() {
    let found = finding(LISTED, "45.148.10.99");
    assert_eq!(
        found.summary,
        "ISC: 0 reports against 0 targets, listed by 4 threat feeds"
    );
    assert_eq!(found.tags, [tags::MALICIOUS]);
    assert_eq!(attr(&found, "malicious"), Some("988"));
    assert_eq!(
        attr(&found, "threat_feeds"),
        Some(
            "blocklistde22 (2020-02-14..2026-02-06),blocklistde25 (2020-09-18..2026-02-06),\
             ciarmy (2020-02-17..2026-02-06),emergincompromised (2020-02-14..2026-02-06)"
        )
    );
    assert_eq!(
        attr(&found, "ssh"),
        Some("attempts=983, end=2020-02-17, passwords=20, start=2020-02-12, usernames=10")
    );
    assert_eq!(
        attr(&found, "weblogs"),
        Some(
            "avgauthors=1, avgurls=3, avguser_agents=3, count=5, firstseen=2026-02-04, \
             lastseen=2026-02-04"
        )
    );
    assert_eq!(attr(&found, "network"), Some("45.148.10.0/24"));
    assert_eq!(attr(&found, "abuse_contact"), Some("abuse@vegatele.com"));
    assert_eq!(attr(&found, "asn"), Some("48090"));
    assert_eq!(found.pivots.len(), 1);
    assert_eq!(found.pivots[0].kind, PivotKind::Asn);
    assert_eq!(found.pivots[0].value, "AS48090");
}

#[test]
fn an_address_with_only_its_network_comes_back_unmarked() {
    let found = finding(NETWORK_ONLY, "1.12.229.231");
    assert!(found.tags.is_empty());
    assert_eq!(attr(&found, "malicious"), None);
    assert_eq!(attr(&found, "cloud"), Some("tencent"));
    assert_eq!(attr(&found, "network"), Some("1.12.192.0/18"));
    assert_eq!(attr(&found, "as_country"), Some("CN"));
}

#[test]
fn reports_count_and_an_empty_record_is_a_valid_zero() {
    let reported = r#"{"ip":{"number":"192.0.2.9","count":"12","attacks":3,"mindate":"2026-10-01","maxdate":"2026-10-14","maxrisk":4,"comment":"scanner"}}"#;
    let found = finding(reported, "192.0.2.9");
    assert_eq!(
        found.summary,
        "ISC: 12 reports against 3 targets, listed by 0 threat feeds"
    );
    assert_eq!(attr(&found, "malicious"), Some("12"));
    assert_eq!(attr(&found, "first_reported"), Some("2026-10-01"));
    assert_eq!(attr(&found, "risk"), Some("4"));
    let empty = r#"{"ip":{"number":"192.0.2.9","count":null,"attacks":null}}"#;
    assert!(matches!(
        decode(empty.as_bytes(), Indicator::Ip("192.0.2.9")),
        Ok(None)
    ));
}

#[test]
fn an_answer_on_another_address_or_not_the_shape_is_refused() {
    assert!(matches!(
        decode(NETWORK_ONLY.as_bytes(), Indicator::Ip("192.0.2.9")),
        Err(LegError::Decode(_))
    ));
    assert!(matches!(
        decode(b"<html>", Indicator::Ip("192.0.2.9")),
        Err(LegError::Decode(_))
    ));
    assert_eq!(
        url(Indicator::Ip("192.0.2.9")).as_deref(),
        Some("https://isc.sans.edu/api/ip/192.0.2.9?json")
    );
    assert!(url(Indicator::Domain("example.org")).is_none());
}
