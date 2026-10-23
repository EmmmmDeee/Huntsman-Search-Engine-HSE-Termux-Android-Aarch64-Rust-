use super::*;
use crate::rdap::tests::{APNIC, IPV4_BOOTSTRAP};
use crate::sf_elements::{DataElement, Target, elements};
use crate::test_support::RoutedTransport;

/// The netblock lookup, with no threat feed consulted: the feeds' own tests cover them.
fn run<T: Transport + ?Sized + Sync>(transport: &T, netblock: &str, now_unix: u64) -> NetblockRun {
    super::run(transport, &Feeds::none(), netblock, now_unix)
}

const RIPESTAT: &str = r#"{"status":"ok","data":{"announced":true,"asns":[{"asn":13335,"holder":"CLOUDFLARENET - Cloudflare, Inc."}],"resource":"1.1.1.0/24","block":{"desc":"APNIC (Status: ALLOCATED)"}}}"#;
/// The one address of the block whose reverse zone names it.
const NAMED: &str = r#"{"Status":0,"Answer":[{"name":"1.1.1.1.in-addr.arpa.","type":12,"data":"one.one.one.one."}]}"#;
/// Every other address: the reverse zone has no such name.
const UNNAMED: &str = r#"{"Status":3}"#;

fn registry(dns: &'static str) -> RoutedTransport {
    RoutedTransport::new(&[
        (
            "https://cloudflare-dns.com/dns-query?name=1.1.1.1.in-addr.arpa",
            200,
            NAMED,
        ),
        ("https://cloudflare-dns.com/", 200, dns),
        ("https://data.iana.org/rdap/ipv4.json", 200, IPV4_BOOTSTRAP),
        ("https://specific.test/ip/1.1.1.0/30", 200, APNIC),
        ("https://stat.ripe.net/", 200, RIPESTAT),
    ])
}

fn printed(run: NetblockRun) -> Report {
    match run {
        NetblockRun::Printed { report, .. } => report,
        NetblockRun::Network(message) | NetblockRun::Failed(message) => panic!("{message}"),
    }
}

/// The entity of `kind` found as `value`.
fn find<'a>(report: &'a Report, kind: &EntityKind, value: &str) -> &'a Entity {
    report
        .entities
        .iter()
        .find(|entity| entity.kind == *kind && entity.raw_value == value)
        .unwrap_or_else(|| panic!("no {kind:?} {value} in {:#?}", report.entities))
}

fn outcome<'a>(report: &'a Report, source: &str) -> &'a SourceExecutionOutcome {
    report
        .outcomes
        .iter()
        .find(|outcome| outcome.module == source)
        .unwrap_or_else(|| panic!("no {source} row in {:#?}", report.outcomes))
}

/// A block is its registration, the prefix and AS that route it, and the names its reverse zone
/// gives its addresses: each address with a PTR record is in the block, each name the address's.
#[test]
fn a_block_is_its_registration_routing_and_the_names_of_its_addresses() {
    let transport = registry(UNNAMED);
    let report = printed(run(&transport, "1.1.1.2/30", 1));

    let block = find(&report, &EntityKind::Netblock, "1.1.1.0/30");
    let sources: Vec<&str> = block
        .evidence
        .iter()
        .map(|evidence| evidence.provenance.source.as_str())
        .collect();
    assert_eq!(sources, ["rdap", "ripestat"]);
    assert_eq!(
        block.evidence[0]
            .attributes
            .get("whois")
            .map(String::as_str),
        Some(APNIC)
    );
    let asn = find(&report, &EntityKind::Asn, "AS13335");
    assert_eq!(
        asn.evidence[0].attr_values("netblock").collect::<Vec<_>>(),
        ["1.1.1.0/30"]
    );

    let named: Vec<&Entity> = report
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::IpAddress)
        .collect();
    assert_eq!(named.len(), 1, "{named:#?}");
    let address = &named[0].evidence[0];
    assert_eq!(
        address.attr_values("netblock").collect::<Vec<_>>(),
        ["1.1.1.0/30"]
    );
    assert_eq!(
        address.attr_values("ptr").collect::<Vec<_>>(),
        ["one.one.one.one"]
    );
    let name = find(&report, &EntityKind::Domain, "one.one.one.one");
    assert!(name.has_tag(tags::PTR));
    assert_eq!(
        name.evidence[0].attr_values("ip").collect::<Vec<_>>(),
        ["1.1.1.1"]
    );

    for source in ["rdap", "ripestat", "dnsresolve"] {
        assert!(outcome(&report, source).kind.is_accepted(), "{source}");
    }
    assert_eq!(
        outcome(&report, "dnsresolve").detail.as_deref(),
        Some("1 of 4 addresses in 1.1.1.0/30 have PTR records")
    );
    let asked = transport
        .urls()
        .iter()
        .filter(|url| url.contains(".in-addr.arpa"))
        .count();
    assert_eq!(asked, 4, "{:?}", transport.urls());
}

/// An origin AS that is not a public AS number stays on the block's `RIPEstat` record but is no
/// AS entity, and neither is its holder an organisation, as `asn AS23456` refuses the number.
#[test]
fn a_reserved_origin_as_stays_on_the_block_and_is_no_entity() {
    let mut transport = registry(UNNAMED);
    for route in &mut transport.routes {
        if route.0 == "https://stat.ripe.net/" {
            route.2 = r#"{"status":"ok","data":{"announced":true,"asns":[{"asn":23456,"holder":"AS-TRANS"},{"asn":13335,"holder":"CLOUDFLARENET - Cloudflare, Inc."}],"resource":"1.1.1.0/24"}}"#;
        }
    }
    let report = printed(run(&transport, "1.1.1.2/30", 1));
    let asns: Vec<&str> = report
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Asn)
        .map(|entity| entity.raw_value.as_str())
        .collect();
    assert_eq!(asns, ["AS13335"]);
    assert!(
        !report
            .entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Organisation && entity.raw_value == "AS-TRANS")
    );
    let block = find(&report, &EntityKind::Netblock, "1.1.1.0/30");
    assert!(
        block
            .evidence
            .iter()
            .flat_map(|evidence| evidence.attr_values("origin_asns"))
            .any(|asns| asns == "AS13335,AS23456")
    );
}

/// In a saved scan the block is the `NETBLOCK_OWNER` target: its record is its `NETBLOCK_WHOIS`,
/// each named address an `IP_ADDRESS` found from it, and each name that address's
/// `INTERNET_NAME`.
#[test]
fn a_saved_scan_hangs_the_addresses_off_the_block_and_the_names_off_the_addresses() {
    let report = printed(run(&registry(UNNAMED), "1.1.1.0/30", 1));
    let target = Target {
        value: "1.1.1.0/30",
        kind: "NETBLOCK_OWNER",
    };
    let found = elements(target, &report.entities, 1);
    let one = |kind: &str, data: &str| -> &DataElement {
        found
            .iter()
            .find(|element| element.kind == kind && element.data == data)
            .unwrap_or_else(|| panic!("no {kind} {data} in {found:#?}"))
    };
    let block = one("NETBLOCK_OWNER", "1.1.1.0/30");
    assert_eq!(
        one("NETBLOCK_WHOIS", APNIC).source.as_ref(),
        Some(&block.id)
    );
    assert_eq!(
        one("BGP_AS_MEMBER", "AS13335").source.as_ref(),
        Some(&block.id)
    );
    let address = one("IP_ADDRESS", "1.1.1.1");
    assert_eq!(address.source.as_ref(), Some(&block.id));
    assert_eq!(
        one("INTERNET_NAME", "one.one.one.one").source.as_ref(),
        Some(&address.id)
    );
}

/// A block of more than 256 addresses is not swept, and its row says so; nothing is asked.
#[test]
fn a_block_larger_than_a_slash_24_is_not_swept_and_says_why() {
    let transport = registry(UNNAMED);
    let report = printed(run(&transport, "1.1.0.0/23", 1));
    let row = outcome(&report, "dnsresolve");
    assert_eq!(row.kind, SourceOutcomeKind::Inconclusive);
    assert!(
        row.detail
            .as_deref()
            .is_some_and(|detail| detail.starts_with("1.1.0.0/23 holds 2^9 addresses")),
        "{row:?}"
    );
    assert!(
        !transport
            .urls()
            .iter()
            .any(|url| url.contains("in-addr.arpa")),
        "{:?}",
        transport.urls()
    );
}

/// Resolvers that never answer stop the sweep after a few addresses.
#[test]
fn an_outage_stops_the_sweep_after_a_few_addresses() {
    let transport = RoutedTransport::new(&[
        ("https://data.iana.org/rdap/ipv4.json", 200, IPV4_BOOTSTRAP),
        ("https://specific.test/", 404, "{}"),
        ("https://stat.ripe.net/", 200, RIPESTAT),
    ]);
    let report = printed(run(&transport, "1.1.1.0/24", 1));
    let row = outcome(&report, "dnsresolve");
    assert!(!row.kind.is_accepted(), "{row:?}");
    assert!(
        row.detail
            .as_deref()
            .is_some_and(|detail| detail.starts_with("no resolver answered: ")),
        "{row:?}"
    );
    let asked: std::collections::BTreeSet<String> = transport
        .urls()
        .iter()
        .filter_map(|url| url.split("name=").nth(1))
        .map(|name| name.split('&').next().unwrap_or_default().to_owned())
        .collect();
    assert!(
        asked.len() < dns::ASK_FAILURES_BEFORE_ABORT + dns::ASK_WORKERS + 1,
        "{} addresses asked",
        asked.len()
    );
    // An unregistered block is a validated zero, not a failure.
    assert_eq!(outcome(&report, "rdap").kind, SourceOutcomeKind::ValidZero);
}

/// A private or documentation block, or a bare address, is refused before any request.
#[test]
fn a_block_that_is_not_public_is_refused_before_any_request() {
    for raw in ["10.0.0.0/8", "192.0.2.0/24", "1.1.1.1"] {
        let transport = registry(UNNAMED);
        assert!(
            matches!(run(&transport, raw, 1), NetblockRun::Failed(_)),
            "{raw}"
        );
        assert!(transport.urls().is_empty(), "{raw}");
        assert!(
            matches!(
                NetblockArgs::parse(&[raw.to_owned()]),
                Err(Error::InvalidValue(_))
            ),
            "{raw}"
        );
    }
    let args = NetblockArgs::parse(&["1.1.1.7/24".to_owned()]).expect("a public block");
    assert_eq!(args.netblock, "1.1.1.0/24");
}

/// [`registry`], with `RIPEstat` giving `routing` for the block.
fn routed(routing: &'static str) -> RoutedTransport {
    RoutedTransport::new(&[
        ("https://cloudflare-dns.com/", 200, UNNAMED),
        ("https://data.iana.org/rdap/ipv4.json", 200, IPV4_BOOTSTRAP),
        ("https://specific.test/ip/1.1.1.0/30", 200, APNIC),
        ("https://stat.ripe.net/", 200, routing),
    ])
}

/// The block's `ripestat` record.
fn routing_record(report: &Report) -> &Evidence {
    find(report, &EntityKind::Netblock, "1.1.1.0/30")
        .evidence
        .iter()
        .find(|evidence| evidence.provenance.source == ripestat::SOURCE)
        .unwrap_or_else(|| panic!("no ripestat record in {:#?}", report.entities))
}

/// `RIPEstat` for a block inside a longer announced prefix, with its related prefixes, its
/// `see_also` resources and a message.
const ALIGNED: &str = r#"{"messages":[["warning","Given resource is not announced but result has been aligned to first-level less-specific (1.1.1.0/24)."]],"see_also":[{"relation":"less-specific","resource":"1.1.0.0/23"}],"status":"ok","data":{"is_less_specific":true,"announced":true,"asns":[{"asn":13335,"holder":"CLOUDFLARENET - Cloudflare, Inc."}],"related_prefixes":["1.1.0.0/23"],"resource":"1.1.1.0/24","type":"prefix","block":{"resource":"1.0.0.0/8","desc":"APNIC (Status: ALLOCATED)","name":"IANA IPv4 Address Space Registry"}}}"#;

/// A block's routing record holds everything `RIPEstat` said, as an address's does.
#[test]
fn a_block_keeps_everything_ripestat_says() {
    let report = printed(run(&routed(ALIGNED), "1.1.1.0/30", 1));
    let record = routing_record(&report);
    let held = |key: &str| record.attributes.get(key).map(String::as_str);
    assert_eq!(record.summary, "Announced by AS13335");
    assert_eq!(held("prefix"), Some("1.1.1.0/24"));
    assert_eq!(held("origin_asns"), Some("AS13335"));
    assert_eq!(held("related_prefixes"), Some("1.1.0.0/23"));
    assert_eq!(held("see_also"), Some("less-specific 1.1.0.0/23"));
    assert_eq!(held("less_specific"), Some("true"));
    assert_eq!(held("block_resource"), Some("1.0.0.0/8"));
    assert_eq!(
        held("block_registry"),
        Some("IANA IPv4 Address Space Registry")
    );
    assert_eq!(
        held("messages"),
        Some(
            "warning: Given resource is not announced but result has been aligned to first-level less-specific (1.1.1.0/24)."
        )
    );
    let raw = held("raw_answer").unwrap_or_else(|| panic!("no raw_answer: {record:#?}"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(raw).ok(),
        serde_json::from_str::<serde_json::Value>(ALIGNED).ok()
    );
}

/// `RIPEstat` for a block no AS announces: only the registry block it sits in.
const UNANNOUNCED: &str = r#"{"status":"ok","data":{"is_less_specific":false,"announced":false,"asns":[],"related_prefixes":[],"resource":"1.1.1.0/30","type":"prefix","block":{"resource":"1.0.0.0/8","desc":"APNIC (Status: ALLOCATED)","name":"IANA IPv4 Address Space Registry"}}}"#;

/// A block no AS announces still has the registry block `RIPEstat` names, not a zero.
#[test]
fn an_unannounced_block_keeps_its_registry_block() {
    let report = printed(run(&routed(UNANNOUNCED), "1.1.1.0/30", 1));
    let record = routing_record(&report);
    assert_eq!(record.summary, "Not announced; registry block 1.0.0.0/8");
    assert_eq!(
        record.attributes.get("announced").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        record.attributes.get("registry_block").map(String::as_str),
        Some("APNIC (Status: ALLOCATED)")
    );
    let row = outcome(&report, ripestat::SOURCE);
    assert_eq!(row.kind, SourceOutcomeKind::Success, "{row:?}");
}
