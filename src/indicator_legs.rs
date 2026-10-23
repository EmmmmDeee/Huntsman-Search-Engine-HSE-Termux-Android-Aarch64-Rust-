//! Runs every applicable [`SOURCES`] entry for one IP or domain and folds the
//! findings into entities and outcomes, for the `ip` and `domain` front-ends.
//!
//! A finding becomes evidence on the queried indicator itself, with its tags; each pivot becomes
//! its own entity, but only in canonical form: a pivot address or AS number that is not public,
//! or a pivot domain or email that does not parse, is dropped rather than recorded as provider
//! text. Every source that runs leaves exactly one outcome: success with its count, the
//! provider's "nothing known" as a valid zero, or the typed failure.

use crate::canonical::{
    canonical_asn, canonical_coordinates, canonical_domain, canonical_email, canonical_ip,
};
use crate::concurrent::{self, Job};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::http::Transport;
use crate::indicator_sources::{DynTransport, Finding, Indicator, PivotKind, Source};
use crate::keys::Keys;
use crate::source_outcome::SourceExecutionOutcome;
use crate::{
    hackertarget, hudsonrock, hunter, ipinfo, ipqs, isc, kickbox, leakix, maltiverse, netlas,
    opencellid, otx, phishstats, pulsedive, robtex, securitytrails, shodan, stopforumspam, submd,
    tags, threatfox, urlhaus, urlscan, whoxy, xposedornot,
};

/// Every indicator source, in the order a lookup runs them.
pub const SOURCES: &[Source] = &[
    shodan::INTEL,
    pulsedive::INTEL,
    netlas::INTEL,
    otx::INTEL,
    urlscan::INTEL,
    ipinfo::INTEL,
    robtex::INTEL,
    hackertarget::INTEL,
    submd::INTEL,
    opencellid::INTEL,
    stopforumspam::INTEL,
    isc::INTEL,
    maltiverse::INTEL,
    phishstats::INTEL,
    kickbox::INTEL,
    xposedornot::INTEL,
    leakix::INTEL,
    threatfox::INTEL,
    urlhaus::INTEL,
    ipqs::INTEL,
    whoxy::INTEL,
    securitytrails::INTEL,
    hunter::VERIFY,
    hudsonrock::INTEL,
];

/// Confidence of the queried indicator.
const SEED_CONFIDENCE: f64 = 0.90;
/// Confidence of an indicator a provider ties to it.
const PIVOT_CONFIDENCE: f64 = 0.60;

/// One source's answer: what it found, nothing, or why it could not say.
type Answer = Result<Option<Finding>, crate::api_leg::LegError>;

/// What the indicator legs produced.
#[derive(Debug, Default)]
pub struct Legs {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    /// The first "no response" failure, for a front-end that got nothing else.
    pub network: Option<String>,
}

/// The sources that run for `indicator` with `keys`, in order. **Pure.**
#[must_use]
pub fn planned(indicator: Indicator<'_>, keys: &Keys) -> Vec<&'static Source> {
    SOURCES
        .iter()
        .filter(|s| s.applies(indicator, keys))
        .collect()
}

/// Run every source that applies to `indicator` and that the transport's lookup asks.
#[must_use]
pub fn run<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    indicator: Indicator<'_>,
    scan_id: &str,
    now_unix: u64,
) -> Legs {
    let transport = DynTransport(transport);
    let sources: Vec<&'static Source> = planned(indicator, keys)
        .into_iter()
        .filter(|source| transport.runs_module(source.api.source))
        .collect();
    // Each source asks its own provider, so through a transport threads may share they are all
    // asked at once and the lookup takes as long as the slowest; through one they cannot, one
    // after another. Either way the answers are folded in the sources' order, so the report is
    // the same.
    let answers: Vec<Answer> = match transport.shared() {
        Some(shared) => concurrent::all(
            sources
                .iter()
                .map(|source| {
                    let lookup = source.lookup;
                    Box::new(move || lookup(shared, keys, indicator, now_unix)) as Job<'_, Answer>
                })
                .collect(),
        ),
        None => sources
            .iter()
            .map(|source| (source.lookup)(&transport, keys, indicator, now_unix))
            .collect(),
    };
    let mut legs = Legs::default();
    for (source, answer) in sources.into_iter().zip(answers) {
        let api = source.api;
        match answer {
            Ok(Some(finding)) => {
                let count = fold(&mut legs.entities, indicator, scan_id, api.source, finding);
                legs.outcomes.push(
                    SourceExecutionOutcome::success(api.source, now_unix, count)
                        .with_http_status(200),
                );
            }
            Ok(None) => legs
                .outcomes
                .push(SourceExecutionOutcome::valid_zero(api.source, now_unix)),
            Err(err) => {
                if let crate::api_leg::LegError::Transport(_) = err {
                    legs.network
                        .get_or_insert_with(|| format!("{}: {err}", api.source));
                }
                legs.outcomes.push(err.outcome(api, now_unix));
            }
        }
    }
    legs
}

/// The entity kind and canonical value of a pivot, or `None` to drop it. **Pure.**
fn pivot_entity(kind: PivotKind, value: &str) -> Option<(EntityKind, String)> {
    match kind {
        PivotKind::Domain => {
            canonical_domain(value.trim_end_matches('.')).map(|v| (EntityKind::Domain, v))
        }
        PivotKind::Ip => canonical_ip(value).map(|v| (EntityKind::IpAddress, v)),
        PivotKind::Email => canonical_email(value).map(|v| (EntityKind::Email, v)),
        PivotKind::Asn => canonical_asn(value).map(|v| (EntityKind::Asn, v)),
        PivotKind::Organisation => {
            let name = value.trim();
            (!name.is_empty()).then(|| (EntityKind::Organisation, name.to_owned()))
        }
        PivotKind::Coordinates => {
            canonical_coordinates(value).map(|v| (EntityKind::Coordinates, v))
        }
    }
}

/// Fold one finding into `entities`; returns the number of entities it touched. **Pure.**
fn fold(
    entities: &mut Vec<Entity>,
    indicator: Indicator<'_>,
    scan_id: &str,
    source: &str,
    finding: Finding,
) -> usize {
    let (seed_kind, seed_attr) = match indicator {
        Indicator::Ip(_) => (EntityKind::IpAddress, "ip"),
        Indicator::Domain(_) => (EntityKind::Domain, "domain"),
        Indicator::Email(_) => (EntityKind::Email, "email"),
        Indicator::Phone(_) => (EntityKind::Phone, "phone"),
        Indicator::Cell(_) => (EntityKind::Other, "cell"),
        Indicator::MacAddress(_) => (EntityKind::MacAddress, "mac"),
    };
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(source, scan_id),
        finding.summary,
    );
    for (key, value) in finding.attrs {
        evidence = evidence.with_attr(key, value);
    }
    push_entity(
        entities,
        seed_kind.clone(),
        indicator.value(),
        SEED_CONFIDENCE,
        scan_id,
        evidence,
        &finding.tags,
    );
    let mut count = 1;
    for pivot in finding.pivots {
        let Some((kind, value)) = pivot_entity(pivot.kind, &pivot.value) else {
            continue;
        };
        if kind == seed_kind && value.eq_ignore_ascii_case(indicator.value()) {
            continue;
        }
        let evidence = Evidence::new(EvidenceProvenance::for_scan(source, scan_id), pivot.summary)
            .with_attr(seed_attr, indicator.value());
        // A position is geographic intelligence, as the `network` lookup tags its positions.
        let pivot_tags: &[&str] = if kind == EntityKind::Coordinates {
            &[tags::GEOINT]
        } else {
            &[]
        };
        push_entity(
            entities,
            kind,
            &value,
            PIVOT_CONFIDENCE,
            scan_id,
            evidence,
            pivot_tags,
        );
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, Response, TransportFailure};
    use crate::indicator_sources::IndicatorKind;
    use crate::source_outcome::SourceOutcomeKind;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Offline(Mutex<Vec<String>>);

    impl Transport for Offline {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request.url.clone());
            Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "offline".into(),
                blocked: false,
            })
        }
    }

    fn all_keys() -> Keys {
        let text = SOURCES
            .iter()
            .filter_map(|s| s.api.key)
            .fold(String::new(), |mut text, k| {
                text.push_str(k.slot);
                text.push_str("=k-0123456789abcdef\n");
                text
            });
        Keys::parse(&text).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn without_keys_only_keyless_sources_run_and_each_leaves_one_outcome() {
        let transport = Offline::default();
        let legs = run(
            &transport,
            &Keys::default(),
            Indicator::Ip("1.1.1.1"),
            "s",
            1,
        );
        let ran: Vec<&str> = legs.outcomes.iter().map(|o| o.module.as_str()).collect();
        assert_eq!(
            ran,
            [
                "pulsedive",
                "netlas",
                "otx",
                "urlscan",
                "ipinfo",
                "robtex",
                "hackertarget",
                "stopforumspam",
                "isc",
                "maltiverse",
                "phishstats"
            ]
        );
        assert!(legs.network.is_some());
        assert_eq!(transport.0.lock().map_or(0, |v| v.len()), 11);
    }

    /// A transport threads may share whose every answer is an empty document after `delay`, so
    /// no source's circuit opens and each one really sends; it counts what was sent.
    struct SlowShared {
        sent: Mutex<usize>,
        delay: std::time::Duration,
    }

    impl Transport for SlowShared {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            std::thread::sleep(self.delay);
            *self
                .sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
            Ok(Response {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: b"{}".to_vec(),
                truncated: false,
            })
        }

        fn shared(&self) -> Option<&(dyn Transport + Sync)> {
            Some(self)
        }
    }

    fn modules(legs: &Legs) -> Vec<&str> {
        legs.outcomes.iter().map(|o| o.module.as_str()).collect()
    }

    /// Through a transport threads may share, every leg is asked at once: a dozen legs that each
    /// wait 200 ms answer in well under a second, not their sum, and in the same order.
    #[test]
    fn through_a_shared_transport_the_legs_are_asked_at_once_in_order() {
        let keys = all_keys();
        let indicator = Indicator::Domain("example.com");
        let sequential = run(&Offline::default(), &keys, indicator, "s", 1);
        let slow = SlowShared {
            sent: Mutex::new(0),
            delay: std::time::Duration::from_millis(200),
        };
        let started = std::time::Instant::now();
        let shared = run(&slow, &keys, indicator, "s", 1);
        let took = started.elapsed();
        let asked = shared.outcomes.len();
        assert!(asked >= 10, "{:?}", modules(&shared));
        assert_eq!(modules(&shared), modules(&sequential));
        let sent = *slow
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(sent >= asked, "{sent} requests for {asked} legs");
        assert!(
            took < std::time::Duration::from_millis(1_000),
            "{asked} legs of 200 ms took {took:?}"
        );
    }

    /// A shared transport is still held to the scan's chosen modules: the others send nothing.
    #[test]
    fn a_shared_selection_still_asks_only_the_chosen_modules() {
        let slow = SlowShared {
            sent: Mutex::new(0),
            delay: std::time::Duration::ZERO,
        };
        let chosen = crate::module_selection::Selected::new(
            slow,
            crate::module_selection::Selection::only(["otx", "robtex"]),
        );
        assert!(chosen.shared().is_some());
        let legs = run(
            &chosen,
            &all_keys(),
            Indicator::Domain("example.com"),
            "s",
            1,
        );
        assert_eq!(modules(&legs), ["otx", "robtex"]);
    }

    #[test]
    fn every_configured_key_runs_its_source() {
        let keys = all_keys();
        for kind in [
            IndicatorKind::Ip,
            IndicatorKind::Domain,
            IndicatorKind::Email,
            IndicatorKind::Phone,
            IndicatorKind::Cell,
            IndicatorKind::MacAddress,
        ] {
            let indicator = sample(kind);
            let legs = run(&Offline::default(), &keys, indicator, "s", 1);
            let expected: Vec<&str> = SOURCES
                .iter()
                .filter(|s| s.kinds.iter().any(|kind| kind.covers(indicator)))
                .map(|s| s.api.source)
                .collect();
            let ran: Vec<&str> = legs.outcomes.iter().map(|o| o.module.as_str()).collect();
            assert_eq!(ran, expected, "{indicator:?}");
        }
    }

    #[test]
    fn an_ipv4_only_source_runs_for_ipv4_and_never_for_ipv6() {
        let keys = all_keys();
        let ran = |ip: &'static str| -> Vec<String> {
            run(&Offline::default(), &keys, Indicator::Ip(ip), "s", 1)
                .outcomes
                .into_iter()
                .map(|o| o.module)
                .collect()
        };
        let v4 = ran("1.1.1.1");
        let v6 = ran("2606:4700:4700::1111");
        for source in [hackertarget::SOURCE, netlas::SOURCE, isc::SOURCE] {
            assert!(v4.iter().any(|m| m == source), "{source} skipped IPv4");
            assert!(!v6.iter().any(|m| m == source), "{source} ran for IPv6");
        }
        assert!(
            v6.iter().any(|m| m == otx::SOURCE),
            "an any-address source still runs"
        );
    }

    #[test]
    fn every_source_answers_for_some_indicator_and_labels_are_unique() {
        let mut labels: Vec<&str> = SOURCES.iter().map(|s| s.api.source).collect();
        assert!(SOURCES.iter().all(|s| !s.kinds.is_empty()));
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), before, "two sources share an outcome label");
    }

    #[test]
    fn a_key_required_source_applies_only_with_its_key() {
        for source in SOURCES {
            let Some(key) = source.api.key else { continue };
            let indicator = sample(source.kinds[0]);
            assert_eq!(
                source.applies(indicator, &Keys::default()),
                !key.required,
                "{}",
                source.api.source
            );
            let keys = Keys::parse(&format!("{}=k-0123456789abcdef\n", key.slot))
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(source.applies(indicator, &keys), "{}", source.api.source);
        }
    }

    fn sample(kind: IndicatorKind) -> Indicator<'static> {
        match kind {
            IndicatorKind::Ip | IndicatorKind::Ipv4 => Indicator::Ip("1.1.1.1"),
            IndicatorKind::Domain => Indicator::Domain("example.com"),
            IndicatorKind::Email => Indicator::Email("ada@example.com"),
            IndicatorKind::Phone => Indicator::Phone("+61412345678"),
            IndicatorKind::Cell => Indicator::Cell("505:1:1000:12345"),
            IndicatorKind::MacAddress => Indicator::MacAddress("aa:bb:cc:dd:ee:ff"),
        }
    }

    #[test]
    fn pivots_are_kept_only_in_canonical_form() {
        let finding = [
            (PivotKind::Ip, "10.0.0.1"),
            (PivotKind::Ip, "8.8.8.8"),
            (PivotKind::Domain, "ns1.example.net."),
            (PivotKind::Domain, "not a domain"),
            (PivotKind::Asn, "as13335"),
            (PivotKind::Asn, "AS64512"),
            (PivotKind::Asn, "ASN 15169"),
            (PivotKind::Email, "nope"),
            (PivotKind::Ip, "1.1.1.1"),
        ]
        .into_iter()
        .fold(
            Finding::new("s").attr("k", "v").tag("malicious"),
            |finding, (kind, value)| finding.pivot(kind, value, "p"),
        );
        let mut entities = Vec::new();
        let count = fold(&mut entities, Indicator::Ip("1.1.1.1"), "s", "x", finding);
        let values: Vec<&str> = entities.iter().map(|e| e.raw_value.as_str()).collect();
        // A private-use AS number is dropped, as a private address is; `ASN 15169` is AS15169.
        assert_eq!(
            values,
            [
                "1.1.1.1",
                "8.8.8.8",
                "ns1.example.net",
                "AS13335",
                "AS15169"
            ]
        );
        assert_eq!(count, 5);
        assert!(entities[0].tags.iter().any(|t| t == "malicious"));
    }
}
