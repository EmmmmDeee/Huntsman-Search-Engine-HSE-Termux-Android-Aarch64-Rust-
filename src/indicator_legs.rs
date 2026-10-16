//! Runs every applicable [`SOURCES`] entry for one IP or domain and folds the
//! findings into entities and outcomes, for the `ip` and `domain` front-ends.
//!
//! A finding becomes evidence on the queried indicator itself, with its tags; each pivot becomes
//! its own entity, but only in canonical form: a pivot address that is not public, or a pivot
//! domain or email that does not parse, is dropped rather than recorded as provider text. Every
//! source that runs leaves exactly one outcome: success with its count, the provider's "nothing
//! known" as a valid zero, or the typed failure.

use crate::canonical::{canonical_domain, canonical_email, canonical_ip};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::http::Transport;
use crate::indicator_sources::{DynTransport, Finding, Indicator, PivotKind, Source};
use crate::keys::Keys;
use crate::source_outcome::SourceExecutionOutcome;
use crate::{
    hackertarget, submd, opencellid, mozilla_location, hunter, ipinfo, ipqs, isc, kickbox, leakix, maltiverse, netlas, otx, phishstats,
    pulsedive, robtex, securitytrails, shodan, stopforumspam, threatfox, urlhaus, urlscan, whoxy,
    xposedornot,
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
    mozilla_location::INTEL,
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
];

/// Confidence of the queried indicator.
const SEED_CONFIDENCE: f64 = 0.90;
/// Confidence of an indicator a provider ties to it.
const PIVOT_CONFIDENCE: f64 = 0.60;

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
    let mut legs = Legs::default();
    for source in planned(indicator, keys) {
        if !transport.runs_module(source.api.source) {
            continue;
        }
        let api = source.api;
        match (source.lookup)(&transport, keys, indicator, now_unix) {
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
        PivotKind::Asn => {
            let digits = value.trim().trim_start_matches(['A', 'S', 'a', 's']);
            let asn: u32 = digits.parse().ok().filter(|n| *n > 0)?;
            Some((EntityKind::Asn, format!("AS{asn}")))
        }
        PivotKind::Organisation => {
            let name = value.trim();
            (!name.is_empty()).then(|| (EntityKind::Organisation, name.to_owned()))
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
        push_entity(
            entities,
            kind,
            &value,
            PIVOT_CONFIDENCE,
            scan_id,
            evidence,
            &[],
        );
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, Response, TransportFailure};
    use crate::indicator_sources::{IndicatorKind, Pivot};
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
                .filter(|s| s.kinds.contains(&indicator.kind()))
                .map(|s| s.api.source)
                .collect();
            let ran: Vec<&str> = legs.outcomes.iter().map(|o| o.module.as_str()).collect();
            assert_eq!(ran, expected, "{indicator:?}");
        }
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
            IndicatorKind::Ip => Indicator::Ip("1.1.1.1"),
            IndicatorKind::Domain => Indicator::Domain("example.com"),
            IndicatorKind::Email => Indicator::Email("ada@example.com"),
            IndicatorKind::Phone => Indicator::Phone("+61412345678"),
            IndicatorKind::Cell => Indicator::Cell("505:1:1000:12345"),
            IndicatorKind::MacAddress => Indicator::MacAddress("aa:bb:cc:dd:ee:ff"),
        }
    }

    #[test]
    fn pivots_are_kept_only_in_canonical_form() {
        let finding = Finding {
            summary: "s".into(),
            attrs: vec![("k", "v".into())],
            tags: vec!["malicious"],
            pivots: [
                (PivotKind::Ip, "10.0.0.1"),
                (PivotKind::Ip, "8.8.8.8"),
                (PivotKind::Domain, "ns1.example.net."),
                (PivotKind::Domain, "not a domain"),
                (PivotKind::Asn, "as13335"),
                (PivotKind::Email, "nope"),
                (PivotKind::Ip, "1.1.1.1"),
            ]
            .into_iter()
            .map(|(kind, value)| Pivot {
                kind,
                value: value.into(),
                summary: "p",
            })
            .collect(),
        };
        let mut entities = Vec::new();
        let count = fold(&mut entities, Indicator::Ip("1.1.1.1"), "s", "x", finding);
        let values: Vec<&str> = entities.iter().map(|e| e.raw_value.as_str()).collect();
        assert_eq!(values, ["1.1.1.1", "8.8.8.8", "ns1.example.net", "AS13335"]);
        assert_eq!(count, 4);
        assert!(entities[0].tags.iter().any(|t| t == "malicious"));
    }
}
