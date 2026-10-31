use super::*;
use crate::http::{Request, Response, TransportFailure};
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
        // These RDAP/RIPEstat tests mock no PeeringDB record, so the peeringdb leg is a clean
        // valid_zero that adds no entities; its own profile folding is covered separately below.
        // The route is pinned to the `net?asn=` endpoint so it cannot shadow a `netixlan?net_id=`
        // request (RoutedTransport matches by prefix, and "netixlan" starts with "net").
        ("https://www.peeringdb.com/api/net?asn=", 404, "{}"),
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

/// The `PeeringDB` profile folds onto the same AS entity the RDAP and `RIPEstat` legs emit (so one
/// AS scan corroborates its holder across registries), and its operator organisation and website
/// surface as pivots beside the `RIPEstat` holder.
#[test]
fn a_peeringdb_profile_folds_onto_the_as() {
    const NET: &str = r#"{"data":[{"id":5,"asn":13335,"name":"Cloudflare","website":"https://www.cloudflare.com","irr_as_set":"AS-CLOUDFLARE","info_type":"Content","ix_count":0,"fac_count":0}],"meta":{}}"#;
    let transport = RoutedTransport::new(&[
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
            200,
            NEIGHBOURS,
        ),
        ("https://www.peeringdb.com/api/net?asn=", 200, NET),
    ]);
    let report = printed(run(&transport, "AS13335", 1));

    // The AS entity carries peeringdb evidence beside rdap and ripestat: the three legs fold onto
    // the one `AS13335` entity by UID.
    let asn = find(&report, &EntityKind::Asn, "AS13335");
    let sources: std::collections::BTreeSet<&str> = asn
        .evidence
        .iter()
        .map(|evidence| evidence.provenance.source.as_str())
        .collect();
    assert_eq!(sources, ["peeringdb", "rdap", "ripestat"].into());
    assert_eq!(values(asn, "irr_as_set"), ["AS-CLOUDFLARE"]);

    // The operator organisation and its website pivot surface from the profile.
    find(&report, &EntityKind::Organisation, "Cloudflare");
    assert!(
        report
            .entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Domain
                && entity.raw_value.ends_with("cloudflare.com")),
        "{:#?}",
        report.entities
    );
    assert_eq!(
        outcome(&report, "peeringdb").kind,
        SourceOutcomeKind::Success
    );
}

/// A reserved neighbour in an AS path is no AS of its own; a public one beside it still is.
#[test]
fn a_reserved_neighbour_is_no_as() {
    const RESERVED: &str = r#"{"status":"ok","data":{"resource":"13335","query_starttime":"2026-10-15T00:00:00","neighbour_counts":{"left":2,"right":1,"unique":3,"uncertain":0},"neighbours":[{"asn":23456,"type":"left","power":5,"v4_peers":5,"v6_peers":0},{"asn":64512,"type":"left","power":2,"v4_peers":2,"v6_peers":0},{"asn":13414,"type":"right","power":12,"v4_peers":40,"v6_peers":31}]}}"#;
    let report = printed(run(&registry((200, RESERVED)), "as13335", 1));
    let ases: Vec<&str> = report
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Asn)
        .map(|entity| entity.raw_value.as_str())
        .collect();
    assert!(ases.contains(&"AS13414"), "{ases:?}");
    assert!(
        !ases
            .iter()
            .any(|asn| *asn == "AS23456" || *asn == "AS64512"),
        "{ases:?}"
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

/// The one `ripestat` row is refused before sending only when every call was refused; a call that
/// reached a server and then failed wins over a held refusal, so the source is not mislabelled as
/// refused. This locks the first-non-refusal selection in `routing_entities`.
#[test]
fn the_ripestat_row_is_refused_only_when_every_call_was_refused() {
    let refused =
        || crate::api_leg::LegError::Refused("network: egress-policy: blocked".to_owned());

    // Every call refused before sending: the one row is a refusal.
    let all_refused = Routing {
        overview: Err(refused()),
        prefixes: Err(refused()),
        neighbours: Err(refused()),
    };
    let mut report = Report::default();
    routing_entities(&mut report, "AS13335", "scan", &all_refused, 1);
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(
        report.outcomes[0].kind,
        SourceOutcomeKind::RefusedBeforeSending
    );

    // One call reached a server (HTTP 503) beside two refusals: the row keeps the reached-server
    // kind, because the source was reachable.
    let mixed = Routing {
        overview: Err(refused()),
        prefixes: Err(crate::api_leg::LegError::Server(503)),
        neighbours: Err(refused()),
    };
    let mut report = Report::default();
    routing_entities(&mut report, "AS13335", "scan", &mixed, 1);
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Upstream5xx);
}

/// The one `ripestat` row says the AS has nothing only when every call answered so: an AS that
/// announces no prefix and has no neighbour, with its overview unanswered, is inconclusive, since
/// the overview may name a holder the others do not; with every call answered it is a clean zero.
#[test]
fn the_ripestat_row_is_no_clean_zero_while_a_call_went_unanswered() {
    let routing = |overview| Routing {
        overview,
        prefixes: Ok(Prefixes::default()),
        neighbours: Ok(Neighbours::default()),
    };
    let mut report = Report::default();
    let unanswered = routing(Err(crate::api_leg::LegError::Server(503)));
    routing_entities(&mut report, "AS64496", "scan", &unanswered, 1);
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Inconclusive);
    let detail = report.outcomes[0].detail.as_deref().unwrap_or_default();
    assert!(detail.contains("as-overview failed: "), "{detail}");

    let mut report = Report::default();
    let answered = routing(Ok(AsOverview::default()));
    routing_entities(&mut report, "AS64496", "scan", &answered, 1);
    assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
    assert_eq!(report.outcomes[0].http_status, Some(200));
}

/// When no call answered, the lookup ends from its one ripestat row (and the RDAP row) through
/// `SourceReach`: a request refused before sending is a refusal (exit 77), and no response at
/// all is "no usable response" (exit 69) with the first reason in row order.
#[test]
fn no_source_answered_is_a_refusal_or_no_response_from_its_rows() {
    match run(&crate::test_support::Refusing, "AS13335", 1) {
        AsnRun::Network(message) => assert!(message.contains("egress-policy"), "{message}"),
        AsnRun::Failed(message) => panic!("failed: {message}"),
        AsnRun::Printed { text, .. } => panic!("printed: {text}"),
    }
    match run(&RoutedTransport::new(&[]), "AS13335", 1) {
        AsnRun::Failed(message) => assert!(
            message.starts_with("no source answered for AS13335: "),
            "{message}"
        ),
        AsnRun::Network(message) => panic!("network: {message}"),
        AsnRun::Printed { text, .. } => panic!("printed: {text}"),
    }
}

/// Answers as [`registry`] does, except that the call whose path holds `.1` panics.
struct PanicsOn(RoutedTransport, String);

impl Transport for PanicsOn {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        assert!(!request.url.contains(&self.1), "the transport broke");
        self.0.send(request)
    }
}

/// A call that panics is an answer that could not be read: it is named on the row, and the other
/// calls and the registration are still reported, whichever of the three calls it is.
#[test]
fn a_call_that_panics_is_named_and_the_rest_still_reported() {
    const OVERVIEW_SAID: &str = "as-overview: held by CLOUDFLARENET - Cloudflare, Inc.";
    const PREFIXES_SAID: &str = "announced-prefixes: 1 IPv4 and 1 IPv6 from 2026-10-01T08:00:00 \
                                 to 2026-10-15T08:00:00";
    const NEIGHBOURS_SAID: &str = "asn-neighbours: 1 left, 1 right, 1 uncertain on \
                                   2026-10-15T00:00:00";
    for (call, said) in [
        ("as-overview", [PREFIXES_SAID, NEIGHBOURS_SAID]),
        ("announced-prefixes", [OVERVIEW_SAID, NEIGHBOURS_SAID]),
        ("asn-neighbours", [OVERVIEW_SAID, PREFIXES_SAID]),
    ] {
        let transport = PanicsOn(registry((200, NEIGHBOURS)), format!("/{call}/"));
        let report = printed(run(&transport, "AS13335", 1));
        let routing = outcome(&report, "ripestat");
        assert_eq!(routing.kind, SourceOutcomeKind::Success, "{call}");
        assert_eq!(
            routing.detail.as_deref(),
            Some(format!("{}; {}; {call} failed: the call panicked", said[0], said[1]).as_str()),
        );
        let asn = find(&report, &EntityKind::Asn, "AS13335");
        assert_eq!(
            values(asn, "registry_block").is_empty(),
            call == "as-overview",
            "{call}"
        );
        assert_eq!(
            report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Netblock),
            call != "announced-prefixes",
            "{call}: {:#?}",
            report.entities
        );
        assert_eq!(
            report
                .entities
                .iter()
                .any(|entity| entity.raw_value == "AS13414"),
            call != "asn-neighbours",
            "{call}: {:#?}",
            report.entities
        );
        assert_eq!(
            outcome(&report, "rdap").kind,
            SourceOutcomeKind::Success,
            "{call}"
        );
    }
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
