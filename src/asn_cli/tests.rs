use super::*;
use crate::rdap::tests::{ASN_BOOTSTRAP, CLOUDFLARE_AS};
use crate::ripestat::tests::{NEIGHBOURS, OVERVIEW, PREFIXES};
use crate::sf_elements::{DataElement, Target, elements};
use crate::source_outcome::SourceOutcomeKind;
use crate::tags;
use crate::test_support::RoutedTransport;

const RDAP: [(&str, u16, &str); 2] = [
    ("https://data.iana.org/rdap/asn.json", 200, ASN_BOOTSTRAP),
    ("https://specific.test/autnum/13335", 200, CLOUDFLARE_AS),
];

fn registry(neighbours: (u16, &'static str)) -> RoutedTransport {
    RoutedTransport::new(&[
        RDAP[0],
        RDAP[1],
        ("https://stat.ripe.net/data/as-overview/", 200, OVERVIEW),
        (
            "https://stat.ripe.net/data/announced-prefixes/",
            200,
            PREFIXES,
        ),
        (
            "https://stat.ripe.net/data/asn-neighbours/",
            neighbours.0,
            neighbours.1,
        ),
    ])
}

fn printed(run: AsnRun) -> Report {
    match run {
        AsnRun::Printed { report, .. } => report,
        AsnRun::Network(message) | AsnRun::Failed(message) => panic!("{message}"),
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

fn values<'a>(entity: &'a Entity, key: &str) -> Vec<&'a str> {
    entity
        .evidence
        .iter()
        .flat_map(|evidence| evidence.attr_values(key))
        .collect()
}

/// An AS is its registration, its holder and registry block, every prefix it announces with
/// every window it was seen, and every neighbour with its side.
#[test]
fn an_as_is_its_registration_holder_prefixes_and_neighbours() {
    let report = printed(run(&registry((200, NEIGHBOURS)), "as13335", 1));

    let asn = find(&report, &EntityKind::Asn, "AS13335");
    let sources: std::collections::BTreeSet<&str> = asn
        .evidence
        .iter()
        .map(|evidence| evidence.provenance.source.as_str())
        .collect();
    assert_eq!(sources, ["rdap", "ripestat"].into());
    assert_eq!(values(asn, "whois"), [CLOUDFLARE_AS]);
    assert_eq!(values(asn, "autnum_range"), ["AS13335"]);
    assert_eq!(values(asn, "registry_block"), ["13312-15359"]);
    let holder = find(
        &report,
        &EntityKind::Organisation,
        "CLOUDFLARENET - Cloudflare, Inc.",
    );
    assert_eq!(values(holder, "asn"), ["AS13335"]);
    let abuse = find(&report, &EntityKind::Email, "abuse@cloudflare.com");
    assert!(abuse.has_tag(tags::ABUSE_CONTACT));

    let block = find(&report, &EntityKind::Netblock, "104.28.238.0/24");
    assert_eq!(values(block, "announced_by"), ["AS13335"]);
    assert_eq!(
        values(block, "seen"),
        [
            "2026-10-01T08:00:00/2026-10-03T00:00:00",
            "2026-10-07T16:00:00/2026-10-15T08:00:00"
        ]
    );
    find(&report, &EntityKind::Netblock, "2400:cb00:618::/48");

    let downstream = find(&report, &EntityKind::Asn, "AS13414");
    assert_eq!(values(downstream, "neighbour_of"), ["AS13335"]);
    assert_eq!(values(downstream, "relation"), ["right"]);
    assert_eq!(values(downstream, "v6_peers"), ["31"]);

    assert_eq!(outcome(&report, "rdap").kind, SourceOutcomeKind::Success);
    let routing = outcome(&report, "ripestat");
    assert_eq!(routing.kind, SourceOutcomeKind::Success);
    assert_eq!(
        routing.detail.as_deref(),
        Some(
            "as-overview: held by CLOUDFLARENET - Cloudflare, Inc.; announced-prefixes: 1 IPv4 \
             and 1 IPv6 from 2026-10-01T08:00:00 to 2026-10-15T08:00:00; asn-neighbours: 1 \
             left, 1 right, 1 uncertain on 2026-10-15T00:00:00"
        )
    );
}

/// In a saved scan of the AS (`13335`, as Spiderfoot writes a `BGP_AS_OWNER`), every announced
/// prefix is a block it owns, each neighbour an AS it is not, and the AS is never its own member.
#[test]
fn a_saved_scan_hangs_every_announced_block_off_the_as() {
    let report = printed(run(&registry((200, NEIGHBOURS)), "13335", 1));
    let target = Target {
        value: "13335",
        kind: "BGP_AS_OWNER",
    };
    let found = elements(target, &report.entities, 1);
    let one = |kind: &str, data: &str| -> &DataElement {
        found
            .iter()
            .find(|element| element.kind == kind && element.data == data)
            .unwrap_or_else(|| panic!("no {kind} {data} in {found:#?}"))
    };
    let root = &found[1].id;
    for (kind, data) in [
        ("NETBLOCK_OWNER", "104.28.238.0/24"),
        ("NETBLOCKV6_OWNER", "2400:cb00:618::/48"),
        ("BGP_AS_MEMBER", "AS13414"),
        ("NETBLOCK_WHOIS", CLOUDFLARE_AS),
    ] {
        assert_eq!(one(kind, data).source.as_ref(), Some(root), "{kind} {data}");
    }
    assert!(
        !found
            .iter()
            .any(|element| element.kind == "BGP_AS_MEMBER" && element.data == "AS13335"),
        "{found:#?}"
    );
}

/// A call that fails is named on the row, and what the others found is still reported.
#[test]
fn a_failed_call_is_named_and_the_rest_still_reported() {
    let report = printed(run(&registry((503, "{}")), "AS13335", 1));
    let routing = outcome(&report, "ripestat");
    assert_eq!(routing.kind, SourceOutcomeKind::Success);
    let detail = routing.detail.as_deref().unwrap_or_default();
    assert!(detail.contains("; asn-neighbours failed: "), "{detail}");
    assert!(
        !report
            .entities
            .iter()
            .any(|entity| entity.raw_value == "AS13414")
    );
    find(&report, &EntityKind::Netblock, "104.28.238.0/24");

    let silent = RoutedTransport::new(&[
        RDAP[0],
        ("https://specific.test/", 404, "{}"),
        ("https://stat.ripe.net/", 500, "{}"),
    ]);
    let report = printed(run(&silent, "AS13335", 1));
    assert_eq!(outcome(&report, "rdap").kind, SourceOutcomeKind::ValidZero);
    let routing = outcome(&report, "ripestat");
    assert!(!routing.kind.is_accepted(), "{routing:?}");
    assert_eq!(
        routing
            .detail
            .as_deref()
            .unwrap_or_default()
            .matches(" failed: ")
            .count(),
        3,
        "{routing:?}"
    );
}

/// A reserved, private-use or documentation AS number is refused before any request.
#[test]
fn a_reserved_as_number_is_refused_before_any_request() {
    for raw in [
        "AS0",
        "AS23456",
        "AS64512",
        "65535",
        "AS4200000001",
        "AS1.5",
    ] {
        let transport = registry((200, NEIGHBOURS));
        assert!(
            matches!(run(&transport, raw, 1), AsnRun::Failed(_)),
            "{raw}"
        );
        assert!(transport.urls().is_empty(), "{raw}");
        assert!(
            matches!(
                AsnArgs::parse(&[raw.to_owned()]),
                Err(Error::InvalidValue(_))
            ),
            "{raw}"
        );
    }
    for raw in ["13335", "asn13335", "AS13335"] {
        let args = AsnArgs::parse(&[raw.to_owned()]).expect("a public AS");
        assert_eq!(args.asn, "AS13335");
    }
}
