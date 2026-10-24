use super::*;

/// Recorded for `1.1.1.1` on 2026-10-14 (`minify=true`).
const HOST: &str = r#"{"city": "Brisbane", "region_code": "QLD", "os": null, "tags": ["vpn"], "ip": 16843009, "isp": "Cloudflare, Inc.", "area_code": null, "longitude": 153.0175, "last_update": "2026-10-14T13:08:08.277809", "ports": [161, 2082, 80, 53, 443], "latitude": -27.48159, "hostnames": ["one.one.one.one", "wifi.sl.se"], "country_code": "AU", "country_name": "Australia", "domains": ["sl.se", "one.one"], "org": "APNIC Research and Development", "data": [], "asn": "AS13335", "ip_str": "1.1.1.1"}"#;

/// The recorded host fields for `1.1.1.1` with three service banners in Shodan's documented
/// banner shape (no key here to record a whole answer). The `2082` banner carries two CVEs.
const FULL: &str = r#"{"city": "Brisbane", "region_code": "QLD", "postal_code": "4101", "dma_code": null, "os": null, "tags": ["vpn"], "ip": 16843009, "isp": "Cloudflare, Inc.", "area_code": null, "longitude": 153.0175, "last_update": "2026-10-14T13:08:08.277809", "ports": [53, 443, 2082], "latitude": -27.48159, "hostnames": ["one.one.one.one"], "country_code": "AU", "country_name": "Australia", "domains": ["one.one"], "org": "APNIC Research and Development", "asn": "AS13335", "ip_str": "1.1.1.1", "vulns": ["CVE-2021-23017", "CVE-2023-44487"], "data": [
 {"_shodan": {"module": "https", "crawler": "c1", "id": "a1", "ptr": true, "region": "eu", "options": {}}, "hash": -1102841010, "timestamp": "2026-10-14T13:08:08.277809", "port": 443, "transport": "tcp", "product": "CloudFlare", "cpe23": ["cpe:2.3:a:cloudflare:cloudflare"], "cpe": ["cpe:/a:cloudflare:cloudflare"], "hostnames": ["one.one.one.one"], "domains": ["one.one"], "ip_str": "1.1.1.1", "data": "HTTP/1.1 301 Moved Permanently\r\nServer: cloudflare\r\nLocation: https://one.one.one.one/\r\n\r\n",
  "http": {"status": 301, "title": "1.1.1.1 — The free app that makes your Internet faster.", "server": "cloudflare", "location": "https://one.one.one.one/", "components": {"Cloudflare": {"categories": ["CDN"]}, "HTTP/3": {"categories": []}}, "waf": "Cloudflare (Cloudflare Inc.)", "favicon": {"hash": -1291082897, "location": "https://1.1.1.1:443/favicon.ico"}},
  "ssl": {"cert": {"subject": {"CN": "cloudflare-dns.com", "O": "Cloudflare, Inc."}, "issuer": {"C": "US", "O": "DigiCert Inc", "CN": "DigiCert Global G2 TLS RSA SHA256 2020 CA1"}, "expires": "20270115235959Z", "issued": "20260116000000Z", "fingerprint": {"sha1": "0c9f2f8b", "sha256": "4c2f1b9e"}}, "versions": ["TLSv1.2", "TLSv1.3", "-SSLv3"], "jarm": "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c", "ja3s": "eb1d94daa7e0344597e756a1fb6e7054"},
  "cloud": {"provider": "Cloudflare", "region": null, "service": null}},
 {"_shodan": {"module": "dns-udp", "crawler": "c2", "id": "a2", "ptr": true, "region": "na", "options": {}}, "timestamp": "2026-10-12T02:11:41.002113", "port": 53, "transport": "udp", "dns": {"recursive": true, "resolver_hostname": null}, "ip_str": "1.1.1.1", "data": "\nRecursion: enabled"},
 {"_shodan": {"module": "http", "crawler": "c3", "id": "a3", "ptr": true, "region": "eu", "options": {}}, "timestamp": "2026-10-13T20:45:00.000000", "port": 2082, "transport": "tcp", "product": "nginx", "version": "1.18.0", "cpe23": ["cpe:2.3:a:f5:nginx:1.18.0"], "ip_str": "1.1.1.1", "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
  "http": {"status": 200, "title": "Welcome to nginx!", "server": "nginx/1.18.0"},
  "vulns": {"CVE-2021-23017": {"verified": false, "cvss": 7.7, "summary": "A security issue in nginx resolver.", "references": ["https://nginx.org/en/security_advisories.html"]}, "CVE-2023-44487": {"verified": false, "cvss": 7.5, "kev": true, "summary": "HTTP/2 rapid reset.", "references": []}}}
]}"#;

/// Recorded for `example.com` on 2026-10-14 (records trimmed to eight).
const DNS: &str = r#"{"domain":"example.com","tags":["dmarc","ipv6","spf"],"subdomains":["_dmarc","k2._domainkey","www"],"data":[{"subdomain":"","type":"A","options":{"ttl":300},"value":"104.20.23.154","last_seen":"2026-10-14T09:39:50.360000"},{"subdomain":"","type":"A","options":{"ttl":300},"value":"172.66.147.243","last_seen":"2026-10-14T09:39:50.360000"},{"subdomain":"","type":"AAAA","options":{"ttl":300},"value":"2606:4700:10::6814:179a","last_seen":"2026-10-14T09:37:37.893000"},{"subdomain":"","type":"MX","options":{"priority":0,"ttl":300},"value":"","last_seen":"2026-10-14T07:09:08.020000"},{"subdomain":"","type":"NS","options":{"ttl":84887},"value":"elliott.ns.cloudflare.com","last_seen":"2026-10-13T22:12:02.444000"},{"subdomain":"","type":"TXT","options":{"ttl":300},"value":"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9","last_seen":"2026-10-14T07:03:17.936000"}],"more":false}"#;
/// Shodan's documented answer for an address it has nothing on (HTTP 404).
const NO_INFO: &str = r#"{"error": "No information available for that IP."}"#;

fn ip(body: &str, ip: &str) -> Finding {
    decode(Answer::Body(body.into()), Indicator::Ip(ip))
        .ok()
        .flatten()
        .unwrap_or_else(|| panic!("answer for {ip} must decode"))
}

fn value<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    finding
        .attrs
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
}

fn pivots(finding: &Finding, kind: PivotKind) -> Vec<&str> {
    finding
        .pivots
        .iter()
        .filter(|p| p.kind == kind)
        .map(|p| p.value.as_str())
        .collect()
}

#[test]
fn a_recorded_host_gives_ports_org_place_and_pivots() {
    let finding = ip(HOST, "1.1.1.1");
    assert!(finding.summary.contains("5 open port(s)"));
    assert_eq!(value(&finding, "ports"), Some("53,80,161,443,2082"));
    assert_eq!(value(&finding, "asn"), Some("AS13335"));
    assert_eq!(finding.tags, ["vpn"]);
    assert_eq!(
        pivots(&finding, PivotKind::Domain),
        ["one.one.one.one", "wifi.sl.se", "sl.se", "one.one"]
    );
    assert_eq!(pivots(&finding, PivotKind::Asn), ["AS13335"]);
    assert_eq!(value(&finding, "country_name"), Some("Australia"));
    assert_eq!(value(&finding, "region"), Some("QLD"));
    assert_eq!(value(&finding, "city"), Some("Brisbane"));
    assert_eq!(
        value(&finding, "coordinates"),
        Some("-27.481590,153.017500")
    );
    assert_eq!(
        pivots(&finding, PivotKind::Coordinates),
        ["-27.481590,153.017500"]
    );
    assert!(value(&finding, "raw_host").is_some_and(|raw| raw.contains(r#""region_code":"QLD""#)));
    assert_eq!(
        value(&finding, "raw_banners"),
        None,
        "a minified answer has none"
    );
}

#[test]
fn every_banner_is_read_out_and_kept_whole() {
    let finding = ip(FULL, "1.1.1.1");
    let expected = [
        (
            "services",
            "443/tcp CloudFlare,53/udp,2082/tcp nginx 1.18.0",
        ),
        ("products", "CloudFlare,nginx 1.18.0"),
        (
            "cpes",
            "cpe:2.3:a:cloudflare:cloudflare,cpe:/a:cloudflare:cloudflare,cpe:2.3:a:f5:nginx:1.18.0",
        ),
        ("modules", "https,dns-udp,http"),
        (
            "http_titles",
            "1.1.1.1 — The free app that makes your Internet faster.,Welcome to nginx!",
        ),
        ("http_servers", "cloudflare,nginx/1.18.0"),
        ("http_redirects", "https://one.one.one.one/"),
        ("http_components", "Cloudflare,HTTP/3"),
        ("waf", "Cloudflare (Cloudflare Inc.)"),
        ("favicon_hashes", "-1291082897"),
        ("tls_subjects", "cloudflare-dns.com"),
        (
            "tls_issuers",
            "DigiCert Inc,DigiCert Global G2 TLS RSA SHA256 2020 CA1",
        ),
        ("tls_expires", "20270115235959Z"),
        ("tls_fingerprints", "4c2f1b9e"),
        ("tls_versions", "TLSv1.2,TLSv1.3,-SSLv3"),
        (
            "jarm",
            "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
        ),
        ("ja3s", "eb1d94daa7e0344597e756a1fb6e7054"),
        ("cloud_providers", "Cloudflare"),
        ("cve_scores", "CVE-2021-23017 7.7,CVE-2023-44487 7.5"),
        ("kev_vulns", "CVE-2023-44487"),
        ("max_cvss", "7.7"),
        ("first_banner", "2026-10-12T02:11:41.002113"),
        ("newest_banner", "2026-10-14T13:08:08.277809"),
        ("postal_code", "4101"),
        ("vulns", "CVE-2021-23017,CVE-2023-44487"),
    ];
    for (key, want) in expected {
        assert_eq!(
            value(&finding, key),
            Some(want),
            "{key}: {:?}",
            finding.attrs
        );
    }
    assert_eq!(value(&finding, "verified_vulns"), None);
    assert!(finding.tags.contains(&tags::VULNERABLE));
    let banners: Vec<Value> = value(&finding, "raw_banners")
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    assert_eq!(banners.len(), 3);
    assert_eq!(banners[2]["vulns"]["CVE-2021-23017"]["cvss"], 7.7);
    let host: Value = value(&finding, "raw_host")
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    assert_eq!(host["postal_code"], "4101");
    assert!(host.get("data").is_none(), "the banners are kept once");
    assert_eq!(
        pivots(&finding, PivotKind::Domain),
        ["one.one.one.one", "one.one", "cloudflare-dns.com"]
    );
}

#[test]
fn a_banner_without_details_is_still_a_service_and_a_wildcard_name_is_its_domain() {
    let body = r#"{"ip_str":"8.8.8.8","ports":[853],"data":[{"port":853,"ssl":{"cert":{"subject":{"CN":"*.dns.google"}}}},{"port":"not a port","product":"x"}]}"#;
    let finding = ip(body, "8.8.8.8");
    assert_eq!(value(&finding, "services"), Some("853/tcp"));
    assert_eq!(value(&finding, "products"), Some("x"));
    assert_eq!(pivots(&finding, PivotKind::Domain), ["dns.google"]);
    assert!(
        decode(
            Answer::Body(br#"{"ip_str":"8.8.8.8","data":{}}"#.to_vec()),
            Indicator::Ip("8.8.8.8")
        )
        .is_err(),
        "banners that are not a list are not the documented shape"
    );
}

#[test]
fn a_certificate_naming_an_address_is_kept_but_is_not_a_domain_pivot() {
    let body = r#"{"ip_str":"8.8.8.8","ports":[443,8443],"data":[{"port":443,"ssl":{"cert":{"subject":{"CN":"192.168.1.1"}}}},{"port":8443,"ssl":{"cert":{"subject":{"CN":" 2001:db8::1 "}}}}]}"#;
    let finding = ip(body, "8.8.8.8");
    assert_eq!(
        value(&finding, "tls_subjects"),
        Some("192.168.1.1,2001:db8::1")
    );
    assert!(
        pivots(&finding, PivotKind::Domain).is_empty(),
        "{:?}",
        finding.pivots
    );
}

#[test]
fn banner_text_is_cleaned_before_it_is_joined_and_a_flag_is_kept() {
    let body = r#"{"ip_str":"8.8.8.8","ports":[443,80],"data":[{"port":443,"product":"nginx ","version":"1.18.0"},{"port":80,"product":" ","version":"2.4"},{"port":8080,"product":"x","http":{"waf":true}}]}"#;
    let finding = ip(body, "8.8.8.8");
    assert_eq!(
        value(&finding, "services"),
        Some("443/tcp nginx 1.18.0,80/tcp 2.4,8080/tcp x")
    );
    assert_eq!(value(&finding, "products"), Some("nginx 1.18.0,2.4,x"));
    assert_eq!(value(&finding, "waf"), Some("true"));
}

#[test]
fn a_mis_shaped_answer_names_no_body_value() {
    for (body, indicator) in [
        (
            r#"{"ip_str":"8.8.8.8","ports":["443"],"data":[]}"#,
            Indicator::Ip("8.8.8.8"),
        ),
        (
            r#"{"domain":"example.com","subdomains":"www"}"#,
            Indicator::Domain("example.com"),
        ),
    ] {
        let detail = match decode(Answer::Body(body.into()), indicator) {
            Err(error) => error.outcome(&API, 1).detail.unwrap_or_default(),
            Ok(found) => panic!("decoded {found:?}"),
        };
        assert_eq!(detail, "shodan: unexpected response shape: data error");
    }
}

#[test]
fn a_position_without_a_city_is_kept_but_is_not_a_pivot() {
    let body = r#"{"ip_str":"8.8.8.8","ports":[53],"latitude":37.751,"longitude":-97.822,"country_code":"US","city":null,"data":[]}"#;
    let finding = ip(body, "8.8.8.8");
    assert_eq!(value(&finding, "coordinates"), Some("37.751000,-97.822000"));
    assert_eq!(value(&finding, "city"), None);
    assert!(pivots(&finding, PivotKind::Coordinates).is_empty());
}

#[test]
fn a_recorded_dns_answer_keeps_every_record_and_gives_targets() {
    let finding = decode(Answer::Body(DNS.into()), Indicator::Domain("example.com"))
        .ok()
        .flatten()
        .unwrap_or_else(|| panic!("recorded dns must decode"));
    let pivots: Vec<(PivotKind, &str)> = finding
        .pivots
        .iter()
        .map(|p| (p.kind, p.value.as_str()))
        .collect();
    assert!(pivots.contains(&(PivotKind::Domain, "www.example.com")));
    assert!(pivots.contains(&(PivotKind::Ip, "104.20.23.154")));
    assert!(pivots.contains(&(PivotKind::Ip, "2606:4700:10::6814:179a")));
    assert!(pivots.contains(&(PivotKind::Domain, "elliott.ns.cloudflare.com")));
    assert!(
        !pivots.iter().any(|(_, v)| v.starts_with("_k2n1")),
        "TXT is not a pivot"
    );
    assert_eq!(
        value(&finding, "records"),
        Some(
            "example.com A 104.20.23.154,example.com A 172.66.147.243,example.com AAAA 2606:4700:10::6814:179a,example.com MX,example.com NS elliott.ns.cloudflare.com,example.com TXT _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"
        )
    );
    assert_eq!(
        value(&finding, "subdomains"),
        Some("_dmarc.example.com,k2._domainkey.example.com,www.example.com")
    );
    assert_eq!(
        value(&finding, "last_seen"),
        Some("2026-10-14T09:39:50.360000")
    );
    let raw: Value = value(&finding, "raw_answer")
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    assert_eq!(raw["data"][4]["options"]["ttl"], 84887);
}

#[test]
fn a_404_is_nothing_known_and_another_subject_is_refused() {
    assert_eq!(
        decode(
            Answer::NotFound(NO_INFO.into()),
            Indicator::Ip("203.0.113.9")
        ),
        Ok(None)
    );
    assert!(decode(Answer::Body(HOST.into()), Indicator::Ip("8.8.8.8")).is_err());
    assert!(decode(Answer::Body(DNS.into()), Indicator::Domain("example.org")).is_err());
}

#[test]
fn a_404_page_is_a_path_shodan_lacks_not_a_zero() {
    // What Shodan served on 2026-10-15 for a path it does not have.
    const PAGE: &str = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1> The resource could not be found.<br/><br/> /shodan/nosuch/8.8.8.8 </body></html>";
    for indicator in [Indicator::Ip("8.8.8.8"), Indicator::Domain("example.com")] {
        assert_eq!(
            decode(Answer::NotFound(PAGE.into()), indicator),
            Err(LegError::Unexpected(404))
        );
        assert_eq!(
            decode(Answer::NotFound(Vec::new()), indicator),
            Err(LegError::Unexpected(404))
        );
    }
}

#[test]
fn the_url_asks_for_the_banners_and_never_holds_the_key() {
    assert_eq!(
        url(Indicator::Ip("1.1.1.1")),
        Some("https://api.shodan.io/shodan/host/1.1.1.1".into())
    );
    assert_eq!(
        minified_url("1.1.1.1"),
        "https://api.shodan.io/shodan/host/1.1.1.1?minify=true"
    );
    assert_eq!(
        url(Indicator::Domain("example.com")),
        Some("https://api.shodan.io/dns/domain/example.com".into())
    );
}
