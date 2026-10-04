use huntsman_recon::http::Response;
use huntsman_recon::ip::providers::rdap::{RdapBootstrap, RdapProvider};
use huntsman_recon::ip::{IpObservationKind, IpProvider, IpProviderParseError, IpTarget};

fn response(body: &str) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

#[test]
fn bootstrap_selects_longest_ipv4_service() {
    let bootstrap = RdapBootstrap::parse(
        br#"{
            "version":"1.0",
            "services":[
                [["0.0.0.0/0"],["https://fallback.example/rdap/"]],
                [["1.0.0.0/8"],["https://rdap.apnic.net/"]]
            ]
        }"#,
    )
    .expect("bootstrap");
    let target = IpTarget::parse("1.1.1.1").expect("target");
    assert_eq!(
        bootstrap.base_url_for(target.address),
        Some("https://rdap.apnic.net/")
    );
}

#[test]
fn bootstrap_selects_ipv6_service() {
    let bootstrap = RdapBootstrap::parse(
        br#"{
            "version":"1.0",
            "services":[
                [["2001:200::/23"],["https://rdap.apnic.net/"]],
                [["2a00::/12"],["https://rdap.db.ripe.net/"]]
            ]
        }"#,
    )
    .expect("bootstrap");
    let target = IpTarget::parse("2001:200::1").expect("target");
    assert_eq!(
        bootstrap.base_url_for(target.address),
        Some("https://rdap.apnic.net/")
    );
}

#[test]
fn malformed_or_schema_drifted_bootstrap_fails_closed() {
    assert!(matches!(
        RdapBootstrap::parse(b"{broken"),
        Err(IpProviderParseError::Parse(_))
    ));
    assert!(matches!(
        RdapBootstrap::parse(br#"{"version":"1.0"}"#),
        Err(IpProviderParseError::Schema(_))
    ));
}

#[test]
fn rdap_provider_plans_canonical_ip_lookup() {
    let provider = RdapProvider::new("https://rdap.apnic.net/").expect("provider");
    let target = IpTarget::parse("2606:4700:4700:0:0:0:0:1111").expect("target");
    let actions = provider.plan(&target);
    assert_eq!(actions.len(), 1);
    assert_eq!(
        actions[0].request.url,
        "https://rdap.apnic.net/ip/2606:4700:4700::1111"
    );
    assert_eq!(actions[0].lineage_family, "rdap.apnic.net");
}

#[test]
fn network_object_becomes_allocation_observation_with_registry_context() {
    let provider = RdapProvider::new("https://rdap.apnic.net/").expect("provider");
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    let body = r#"{
        "objectClassName":"ip network",
        "handle":"1.1.1.0 - 1.1.1.255",
        "startAddress":"1.1.1.0",
        "endAddress":"1.1.1.255",
        "ipVersion":"v4",
        "name":"APNIC-LABS",
        "type":"ASSIGNED PORTABLE",
        "country":"AU",
        "parentHandle":"1.0.0.0 - 1.255.255.255",
        "events":[
            {"eventAction":"registration","eventDate":"2011-08-10T23:12:04Z"},
            {"eventAction":"last changed","eventDate":"2023-12-27T04:11:53Z"}
        ],
        "entities":[
            {"handle":"ORG-ARAD1-AP","roles":["registrant"]}
        ],
        "notices":[
            {"title":"Terms of Service","description":["Use subject to registry terms"]}
        ]
    }"#;
    let observations = provider
        .parse(&action, &response(body), 1_800_000_000)
        .expect("RDAP network object");
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(observation.kind, IpObservationKind::Allocation);
    assert_eq!(observation.source_family, "rdap.apnic.net");
    assert_eq!(
        observation.attributes.get("start_address").map(String::as_str),
        Some("1.1.1.0")
    );
    assert_eq!(
        observation.attributes.get("end_address").map(String::as_str),
        Some("1.1.1.255")
    );
    assert_eq!(
        observation.attributes.get("name").map(String::as_str),
        Some("APNIC-LABS")
    );
    assert_eq!(
        observation.attributes.get("country").map(String::as_str),
        Some("AU")
    );
    assert!(
        observation
            .attributes
            .get("entities")
            .is_some_and(|value| value.contains("ORG-ARAD1-AP"))
    );
    assert!(
        observation
            .attributes
            .get("notices")
            .is_some_and(|value| value.contains("Terms of Service"))
    );
    assert!(observation.observed_at_unix.is_some());
}

#[test]
fn malformed_or_wrong_object_class_network_response_fails_closed() {
    let provider = RdapProvider::new("https://rdap.apnic.net/").expect("provider");
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    assert!(matches!(
        provider.parse(&action, &response("{broken"), 123),
        Err(IpProviderParseError::Parse(_))
    ));
    assert!(matches!(
        provider.parse(
            &action,
            &response(r#"{"objectClassName":"domain","ldhName":"example.com"}"#),
            123
        ),
        Err(IpProviderParseError::Schema(_))
    ));
}
