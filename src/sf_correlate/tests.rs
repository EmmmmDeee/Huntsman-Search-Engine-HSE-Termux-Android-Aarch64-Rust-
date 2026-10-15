use serde_json::Value;

use super::*;

fn element(id: &str, kind: &str, data: &str, source: Option<&str>, module: &str) -> DataElement {
    DataElement {
        id: id.to_owned(),
        kind: kind.to_owned(),
        data: data.to_owned(),
        source: source.map(str::to_owned),
        module: module.to_owned(),
        confidence: 100,
        created: 0,
        fp: false,
        entity: None,
        raw: Value::Null,
    }
}

fn root(target: &str) -> Vec<DataElement> {
    vec![
        element("root", "ROOT", target, None, "huntsman"),
        element("target", "INTERNET_NAME", target, Some("root"), "huntsman"),
    ]
}

fn shipped_rule(id: &str) -> &'static Rule {
    shipped()
        .iter()
        .find(|rule| rule.id == id)
        .unwrap_or_else(|| panic!("{id} is not shipped"))
}

fn findings(id: &str, elements: &[DataElement]) -> Vec<Finding> {
    run(std::slice::from_ref(shipped_rule(id)), elements)
}

#[test]
fn every_shipped_rule_reads() {
    for (id, yaml) in SHIPPED {
        let rule =
            Rule::parse(id, yaml, "spiderfoot").unwrap_or_else(|failure| panic!("{failure}"));
        assert!(
            !rule.name.is_empty() && !rule.description.is_empty(),
            "{id}"
        );
    }
    assert_eq!(shipped().len(), 37);
    let ids: BTreeSet<&str> = shipped().iter().map(|rule| rule.id.as_str()).collect();
    assert_eq!(ids.len(), 37);
}

#[test]
fn shipped_rules_are_spiderfoots_files_unchanged() {
    let rule = shipped_rule("multiple_malicious");
    assert_eq!(rule.risk, Risk::High);
    assert_eq!(rule.origin, "spiderfoot");
    assert!(rule.yaml.starts_with("id: multiple_malicious\n"));
    assert_eq!(
        rule.name,
        "An IP, host, subnet or email address was considered malicious by multiple sources"
    );
}

#[test]
fn an_entity_flagged_by_two_sources_is_correlated_once() {
    let mut elements = root("example.org");
    elements.extend([
        element("ip", "IP_ADDRESS", "203.0.113.9", Some("target"), "dns"),
        element(
            "m1",
            "MALICIOUS_IPADDR",
            "otx [203.0.113.9]",
            Some("ip"),
            "otx",
        ),
        element(
            "m2",
            "BLACKLIST_IPADDR",
            "spamhaus [203.0.113.9]",
            Some("ip"),
            "dnsbl",
        ),
        element(
            "m3",
            "MALICIOUS_INTERNET_NAME",
            "urlhaus [example.org]",
            Some("target"),
            "urlhaus",
        ),
    ]);
    let found = findings("multiple_malicious", &elements);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].title,
        "Entity considered malicious by multiple sources: 203.0.113.9"
    );
    assert_eq!(found[0].elements, ["m1", "m2"]);
    assert_eq!(found[0].risk, Risk::High);
    // Stable across runs, distinct per bucket.
    assert_eq!(found, findings("multiple_malicious", &elements));
}

#[test]
fn not_patterns_drop_what_they_name() {
    let mut elements = root("example.org");
    elements.extend([
        element(
            "net",
            "NETBLOCK_OWNER",
            "203.0.113.0/24",
            Some("target"),
            "ripestat",
        ),
        element("m1", "MALICIOUS_NETBLOCK", "a", Some("net"), "otx"),
        element("m2", "MALICIOUS_NETBLOCK", "b", Some("net"), "urlhaus"),
        element(
            "aff",
            "AFFILIATE_IPADDR",
            "198.51.100.1",
            Some("target"),
            "dns",
        ),
        element("m3", "MALICIOUS_AFFILIATE_IPADDR", "a", Some("aff"), "otx"),
        element(
            "m4",
            "MALICIOUS_AFFILIATE_IPADDR",
            "b",
            Some("aff"),
            "urlhaus",
        ),
    ]);
    // A subnet source and affiliates are left to their own rules.
    assert!(findings("multiple_malicious", &elements).is_empty());
    let affiliate = findings("multiple_malicious_affiliate", &elements);
    assert_eq!(affiliate.len(), 1);
    assert!(affiliate[0].title.ends_with(": 198.51.100.1"));
}

#[test]
fn an_exposed_database_port_fires_per_port() {
    let mut elements = root("example.org");
    elements.extend([
        element("ip", "IP_ADDRESS", "203.0.113.9", Some("target"), "dns"),
        element(
            "p1",
            "TCP_PORT_OPEN",
            "203.0.113.9:3306",
            Some("ip"),
            "internetdb",
        ),
        element(
            "p2",
            "TCP_PORT_OPEN",
            "203.0.113.9:443",
            Some("ip"),
            "internetdb",
        ),
        element(
            "p3",
            "TCP_PORT_OPEN",
            "203.0.113.9:27017",
            Some("ip"),
            "internetdb",
        ),
    ]);
    let found = findings("database_exposed", &elements);
    let titles: Vec<&str> = found.iter().map(|finding| finding.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Database server exposed to the Internet: 203.0.113.9:3306",
            "Database server exposed to the Internet: 203.0.113.9:27017",
        ]
    );
    assert_ne!(found[0].id, found[1].id);
}

#[test]
fn false_positives_are_left_out() {
    let mut elements = root("example.org");
    let mut port = element(
        "p1",
        "TCP_PORT_OPEN",
        "203.0.113.9:3306",
        Some("target"),
        "internetdb",
    );
    port.fp = true;
    elements.push(port);
    assert!(findings("database_exposed", &elements).is_empty());
}

#[test]
fn a_spiderfoot_module_name_matches_the_source_doing_its_work() {
    let mut elements = root("example.org");
    elements.extend([
        element(
            "h1",
            "INTERNET_NAME",
            "dev.example.org",
            Some("target"),
            "crtsh",
        ),
        element(
            "h2",
            "INTERNET_NAME",
            "www.example.org",
            Some("target"),
            "crtsh",
        ),
        element(
            "h3",
            "INTERNET_NAME",
            "www.example.org",
            Some("target"),
            "hackertarget",
        ),
        // Resolving a host is not finding it elsewhere.
        element(
            "h4",
            "INTERNET_NAME",
            "dev.example.org",
            Some("target"),
            "dns",
        ),
    ]);
    let found = findings("host_only_from_certificatetransparency", &elements);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].title,
        "Host found only in certificate transparency: dev.example.org"
    );
    assert_eq!(found[0].elements, ["h1"]);
}

#[test]
fn outliers_need_enough_buckets_to_be_rare() {
    let mut elements = root("example.org");
    for index in 0..19 {
        elements.push(element(
            &format!("c{index}"),
            "COUNTRY_NAME",
            "Australia",
            Some("target"),
            "ipinfo",
        ));
    }
    elements.push(element(
        "odd",
        "COUNTRY_NAME",
        "Iceland",
        Some("target"),
        "ipinfo",
    ));
    let found = findings("outlier_country", &elements);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].title, "Outlier country found: Iceland");
    // Eleven countries average under the noisy 10%: nothing stands out.
    let mut noisy = root("example.org");
    for index in 0..11 {
        noisy.push(element(
            &format!("n{index}"),
            "COUNTRY_NAME",
            &format!("Country {index}"),
            Some("target"),
            "ipinfo",
        ));
    }
    assert!(findings("outlier_country", &noisy).is_empty());
}

#[test]
fn match_all_to_first_publishes_only_the_named_collection() {
    let mut elements = root("example.org");
    elements.extend([
        element(
            "net",
            "NETBLOCK_OWNER",
            "203.0.113.0/24",
            Some("target"),
            "ripestat",
        ),
        element("in", "IP_ADDRESS", "203.0.113.77", Some("net"), "ripestat"),
        element(
            "edit",
            "WIKIPEDIA_PAGE_EDIT",
            "Some page",
            Some("in"),
            "wikipedia_edits",
        ),
        element("out", "IP_ADDRESS", "198.51.100.7", Some("target"), "dns"),
        element(
            "edit2",
            "WIKIPEDIA_PAGE_EDIT",
            "Other page",
            Some("out"),
            "wikipedia_edits",
        ),
    ]);
    let found = findings("egress_ip_from_wikipedia", &elements);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].title,
        "Wikipedia edit from IP within target-owned network: 203.0.113.77"
    );
    assert_eq!(found[0].elements, ["in"]);
}

#[test]
fn entity_scope_climbs_to_the_nearest_entity() {
    let mut elements = root("example.org");
    elements.extend([
        element(
            "host",
            "INTERNET_NAME",
            "old.example.org",
            Some("target"),
            "crtsh",
        ),
        element("cert", "SSL_CERTIFICATE_RAW", "cert", Some("host"), "tls"),
        element(
            "exp",
            "SSL_CERTIFICATE_EXPIRED",
            "old.example.org",
            Some("cert"),
            "tls",
        ),
        element("code", "HTTP_CODE", "500", Some("host"), "http"),
        element("ok", "HTTP_CODE", "200", Some("host"), "http"),
        element(
            "vuln",
            "VULNERABILITY_GENERAL",
            "CVE-2020-0001",
            Some("host"),
            "internetdb",
        ),
    ]);
    let found = findings("stale_host", &elements);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].title,
        "Potentially stale/unmaintained host: old.example.org"
    );
    assert_eq!(found[0].elements, ["exp", "code", "vuln"]);
    // Two kinds of sign are not enough.
    elements.retain(|element| element.id != "vuln");
    assert!(findings("stale_host", &elements).is_empty());
}

#[test]
fn a_user_rule_replaces_or_disables_a_shipped_one() {
    let dir = std::env::temp_dir().join(format!("hse-sf-rules-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("outlier_country.yaml"), "enabled: false\n").unwrap();
    std::fs::write(
        dir.join("database_exposed.yaml"),
        "id: database_exposed\nversion: 1\nmeta:\n  name: Any open port\n  description: Every open port.\n  risk: LOW\ncollections:\n  - collect:\n      - method: exact\n        field: type\n        value: TCP_PORT_OPEN\nheadline: \"Open: {data}\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("broken.yaml"), "id: broken\nmeta: [flow]\n").unwrap();
    std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
    let (rules, errors) = with_dir(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(rules.len(), 36);
    assert!(rules.iter().all(|rule| rule.id != "outlier_country"));
    let replaced = rules
        .iter()
        .find(|rule| rule.id == "database_exposed")
        .unwrap();
    assert_eq!(replaced.risk, Risk::Low);
    assert!(replaced.origin.ends_with("database_exposed.yaml"));
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].rule, "broken");
    let mut elements = root("example.org");
    elements.push(element(
        "p",
        "TCP_PORT_OPEN",
        "203.0.113.9:443",
        Some("target"),
        "internetdb",
    ));
    let found = run(&rules, &elements);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].title, "Open: 203.0.113.9:443");
}

#[test]
fn a_missing_rule_directory_adds_nothing() {
    let (rules, errors) = with_dir(Path::new("/nonexistent/hse-rules"));
    assert_eq!(rules.len(), 37);
    assert!(errors.is_empty());
}

#[test]
fn rules_outside_the_contract_are_refused() {
    let base = "id: r\nversion: 1\nmeta:\n  name: n\n  description: d\n  risk: LOW\n";
    let collect = |field: &str, method: &str, value: &str| {
        format!(
            "{base}collections:\n  - collect:\n      - method: {method}\n        field: {field}\n        value: {value}\n"
        )
    };
    let cases = [
        (
            "id: other\nmeta:\n  name: n\n  description: d\n  risk: LOW\n".to_owned(),
            "does not match",
        ),
        (
            collect("type", "exact", "NOT_A_TYPE") + "headline: h\n",
            "unknown type",
        ),
        (
            collect("source.type", "exact", "ROOT") + "headline: h\n",
            "first method",
        ),
        (
            collect("data", "regex", "(?=x)") + "headline: h\n",
            "lookaround",
        ),
        (
            collect("type", "exact", "ROOT")
                + "analysis:\n  - method: both_collections\nheadline: h\n",
            "unknown analysis",
        ),
        (collect("type", "exact", "ROOT"), "headline"),
        (format!("{base}surprise: 1\n"), "unexpected component"),
    ];
    for (yaml, reason) in cases {
        let failure = Rule::parse("r", &yaml, "test").unwrap_err();
        assert!(failure.reason.contains(reason), "{reason}: {failure}");
    }
}

#[test]
fn subnets_read_like_netaddr() {
    assert!(in_subnet("203.0.113.77", "203.0.113.0/24"));
    assert!(!in_subnet("203.0.114.1", "203.0.113.0/24"));
    assert!(in_subnet("203.0.113.77", "203.0.113.77"));
    assert!(in_subnet("10.1.2.3", "0.0.0.0/0"));
    assert!(in_subnet("2001:db8::1", "2001:db8::/32"));
    assert!(!in_subnet("203.0.113.77", "2001:db8::/32"));
    assert!(!in_subnet("not an ip", "203.0.113.0/24"));
    assert!(!in_subnet("203.0.113.77", "203.0.113.0/33"));
}
