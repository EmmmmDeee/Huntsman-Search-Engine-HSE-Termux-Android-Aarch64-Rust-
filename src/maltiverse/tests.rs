use super::*;

/// Recorded for `1.12.229.231` on 2026-10-15 (the first three blacklist entries).
const IP: &str = r#"{"as_name":"AS45090 Tencent Cloud Computing beijing Co., Ltd.","as_number":"45090","blacklist":[{"count":26,"description":"Suspicious Host","first_seen":"2026-05-25 20:27:40","labels":["anomalous-activity"],"last_seen":"2026-06-05 03:15:47","ref":[21745],"source":"AbuseIPDB"},{"count":46,"description":"ET CINS Active Threat Intelligence Poor Reputation IP TCP","first_seen":"2026-06-30 11:01:02","labels":["malicious-activity"],"last_seen":"2026-10-12 11:01:02","ref":[21745],"source":"Emerging Threats"},{"count":48,"description":"ET CINS Active Threat Intelligence Poor Reputation IP UDP","first_seen":"2026-06-24 11:01:05","labels":["malicious-activity"],"last_seen":"2026-10-12 11:01:04","ref":[21745],"source":"Emerging Threats"}],"city":"Guangzhou","classification":"malicious","country_code":"CN","creation_time":"2026-05-26 01:19:35","ip_addr":"1.12.229.231","ip_version":4,"is_cdn":false,"is_cnc":false,"is_distributing_malware":false,"is_hosting":false,"is_iot_threat":false,"is_known_attacker":true,"is_known_scanner":false,"is_mining_pool":false,"is_open_proxy":false,"is_sinkhole":false,"is_tor_node":false,"is_vpn_node":false,"location":{"lat":23.12911,"lon":113.264385},"modification_time":"2026-10-12 20:00:50","number_of_blacklisted_domains_resolving":0,"number_of_domains_resolving":0,"number_of_offline_malicious_urls_allocated":0,"number_of_online_malicious_urls_allocated":0,"number_of_whitelisted_domains_resolving":0,"postal_code":"510030","registrant_name":"Tencent Cloud Computing beijing Co., Ltd.","scoring_executed_time":"2026-05-26 01:19:44","type":"ip"}"#;
/// Recorded for `example.org` on 2026-10-15 (two blacklist entries, two resolutions).
const HOST: &str = r#"{"as_name":"AS15133 MCI Communications Services, Inc. d/b/a Verizon Business","as_number":"15133","blacklist":[{"count":1,"description":"Malware Download","first_seen":"2023-09-26 11:20:58","labels":["malicious-activity"],"last_seen":"2023-09-26 11:20:58","source":"URLhaus Abuse.ch"},{"count":1,"description":"Safe Site","first_seen":"2022-07-14 23:26:28","labels":["benign"],"last_seen":"2022-07-16 01:16:49","source":"Cisco Umbrella"}],"classification":"whitelist","creation_time":"2018-06-21 13:00:36","domain":"example.org","domain_consonants":6,"domain_lenght":11,"entropy":3.2776134368191165,"hostname":"example.org","is_alive":true,"is_cnc":false,"is_distributing_malware":false,"is_iot_threat":false,"is_mining_pool":false,"is_open_proxy":false,"is_phishing":false,"is_storing_phishing":false,"is_tor_node":false,"is_vpn_node":false,"last_online_time":"2025-05-24 01:39:15","modification_time":"2025-05-24 01:39:16","number_of_offline_malicious_urls_allocated":1,"number_of_online_malicious_urls_allocated":0,"resolved_ip":[{"ip_addr":"93.184.216.34","timestamp":"2018-06-21 13:00:36"},{"ip_addr":"2600:1406:bc00:17::6007:810d","timestamp":"2025-05-24 01:39:15"}],"scoring_executed_time":"2025-05-24 01:39:16","tag":["darkgate"],"tld":"org","type":"hostname"}"#;

fn finding(body: &str, indicator: Indicator<'_>) -> Finding {
    decode(body.as_bytes(), indicator)
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
fn a_malicious_address_keeps_every_listing_flag_and_place() {
    let found = finding(IP, Indicator::Ip("1.12.229.231"));
    assert_eq!(
        found.summary,
        "Maltiverse: classified malicious, on 3 blacklists"
    );
    assert_eq!(found.tags, [tags::MALICIOUS]);
    assert_eq!(attr(&found, "malicious"), Some("1"));
    let record: Value = serde_json::from_str(IP).expect("recorded body");
    let listings: Vec<String> = record["blacklist"]
        .as_array()
        .expect("blacklist")
        .iter()
        .filter_map(listing)
        .collect();
    assert_eq!(
        listings,
        [
            "AbuseIPDB: Suspicious Host (anomalous-activity; 26 sightings; \
             2026-05-25 20:27:40..2026-06-05 03:15:47; ref 21745)",
            "Emerging Threats: ET CINS Active Threat Intelligence Poor Reputation IP TCP \
             (malicious-activity; 46 sightings; 2026-06-30 11:01:02..2026-10-12 11:01:02; ref 21745)",
            "Emerging Threats: ET CINS Active Threat Intelligence Poor Reputation IP UDP \
             (malicious-activity; 48 sightings; 2026-06-24 11:01:05..2026-10-12 11:01:04; ref 21745)",
        ]
    );
    assert!(attr(&found, "blacklist").is_some_and(
        |kept| listings.join(" | ").starts_with(kept) && kept.starts_with(&listings[0])
    ));
    assert_eq!(attr(&found, "flags"), Some("known attacker"));
    assert_eq!(attr(&found, "city"), Some("Guangzhou"));
    assert_eq!(attr(&found, "location"), Some("23.12911,113.264385"));
    assert_eq!(attr(&found, "postal_code"), Some("510030"));
    assert_eq!(attr(&found, "hosting"), Some("false"));
    assert_eq!(found.pivots.len(), 1);
    assert_eq!(found.pivots[0].kind, PivotKind::Asn);
    assert_eq!(found.pivots[0].value, "AS45090");
}

#[test]
fn a_host_name_keeps_its_resolutions_as_pivots_and_is_not_marked_when_whitelisted() {
    let found = finding(HOST, Indicator::Domain("example.org"));
    assert_eq!(
        found.summary,
        "Maltiverse: classified whitelist, on 2 blacklists"
    );
    assert!(found.tags.is_empty());
    assert_eq!(attr(&found, "malicious"), None);
    assert_eq!(attr(&found, "maltiverse_tags"), Some("darkgate"));
    assert_eq!(
        attr(&found, "resolved"),
        Some(
            "93.184.216.34 (2018-06-21 13:00:36) | 2600:1406:bc00:17::6007:810d (2025-05-24 01:39:15)"
        )
    );
    let ips: Vec<&str> = found
        .pivots
        .iter()
        .filter(|pivot| pivot.kind == PivotKind::Ip)
        .map(|pivot| pivot.value.as_str())
        .collect();
    assert_eq!(ips, ["93.184.216.34", "2600:1406:bc00:17::6007:810d"]);
}

#[test]
fn suspicious_is_marked_and_another_indicator_is_refused() {
    let suspicious = r#"{"ip_addr":"192.0.2.9","classification":"suspicious","blacklist":[],"is_tor_node":true,"is_vpn_node":true}"#;
    let found = finding(suspicious, Indicator::Ip("192.0.2.9"));
    assert_eq!(found.tags, ["suspicious"]);
    assert_eq!(attr(&found, "flags"), Some("Tor node,VPN node"));
    assert!(matches!(
        decode(IP.as_bytes(), Indicator::Ip("192.0.2.9")),
        Err(LegError::Decode(_))
    ));
    assert!(matches!(
        decode(b"[]", Indicator::Ip("192.0.2.9")),
        Err(LegError::Decode(_))
    ));
}

#[test]
fn ip_and_host_build_their_urls() {
    assert_eq!(
        url(Indicator::Ip("192.0.2.9")).as_deref(),
        Some("https://api.maltiverse.com/ip/192.0.2.9")
    );
    assert_eq!(
        url(Indicator::Domain("example.org")).as_deref(),
        Some("https://api.maltiverse.com/hostname/example.org")
    );
    assert!(url(Indicator::Email("a@example.org")).is_none());
}
