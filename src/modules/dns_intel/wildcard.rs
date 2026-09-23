//! DNS wildcard-record detection — a catch-all `*.zone A x.x.x.x` record
//! makes EVERY possible subdomain label "resolve", which turns both
//! [`super::brute::brute_subdomains`] and [`super::permute::permute_subdomains`]
//! into 100% false-positive generators: every dictionary/permutation
//! candidate answers through the catch-all and gets reported as a
//! discovered subdomain. Confirmed live against a real wildcard zone
//! (`blogspot.com`): two unrelated, guaranteed-nonexistent random labels
//! both resolved to the same IP.
//!
//! Detection: resolve two GUID-derived canary labels no legitimate zone
//! would ever configure. Such a label resolves ONLY through a wildcard, so
//! either canary resolving proves one, whatever it resolves to. What the pair
//! decides is whether the wildcard can be FILTERED: a candidate answering with
//! exactly the catch-all's IP set is its noise and is dropped (`blogspot.com`);
//! but when the two canaries resolve to different sets, the catch-all's answer
//! changes per name — a CDN or PaaS ingress: `herokuapp.com` gave the two
//! canaries different CNAME targets and disjoint IP sets through one provider —
//! and no candidate can be told apart from it by its answer. See [`Wildcard`].

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::util::dns::shared_resolver;

/// Two unrelated, GUID-derived labels. Fixed (not random-per-run) so a
/// wildcard fingerprint is reproducible across scans of the same zone —
/// randomising per-run would make the "same catch-all IP set" comparison
/// this module runs against unusable for regression testing.
const CANARY_LABELS: [&str; 2] = [
    "hse-wildcard-canary-7f3a9c1e2b8d",
    "hse-wildcard-canary-4d6e0a5c9f17",
];

/// What one canary lookup established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Canary {
    /// It resolved, to this IP set: the zone has a wildcard.
    Resolved(BTreeSet<String>),
    /// NXDOMAIN, or no address: the zone does not answer for names it lacks.
    NoSuchName,
    /// SERVFAIL, REFUSED, timeout: nothing established.
    Failed,
}

/// What a zone's wildcard record means for a hostname-enumeration pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Wildcard {
    /// Both canaries came back "no such name": no wildcard, so every candidate
    /// that resolves is a real record.
    Absent,
    /// A canary resolved to this IP set and the other did not contradict it
    /// with a different one: a catch-all, and a candidate answering with
    /// exactly this set is its noise.
    CatchAll(BTreeSet<String>),
    /// Both canaries resolved, to different IP sets: a wildcard whose answer
    /// changes per name, so no candidate can be told apart from it.
    Unstable,
    /// A canary failed and neither resolved: whether there is a wildcard is
    /// not known.
    Unknown,
}

/// The canary pair's verdict. Pure.
///
/// It was "both resolve to the identical set, or no wildcard". Two canaries
/// that resolved to DIFFERENT sets — which proves a wildcard — read as none,
/// and so did one canary that timed out. Either way nothing was filtered, and
/// every dictionary word under the wildcard was emitted as a discovered
/// subdomain at high confidence and re-dispatched into the scan.
pub(super) fn wildcard_verdict(a: Canary, b: Canary) -> Wildcard {
    match (a, b) {
        (Canary::Resolved(x), Canary::Resolved(y)) if x != y => Wildcard::Unstable,
        (Canary::Resolved(ips), _) | (_, Canary::Resolved(ips)) => Wildcard::CatchAll(ips),
        (Canary::NoSuchName, Canary::NoSuchName) => Wildcard::Absent,
        _ => Wildcard::Unknown,
    }
}

impl Wildcard {
    /// The catch-all IP set a candidate must differ from to be a real record,
    /// when there is one to filter ([`Wildcard::CatchAll`]).
    pub(super) fn fingerprint(&self) -> Option<Arc<BTreeSet<String>>> {
        match self {
            Self::CatchAll(ips) => Some(Arc::new(ips.clone())),
            _ => None,
        }
    }

    /// Whether `hits` names that resolved — catch-all noise already removed —
    /// out of `candidates` tried can be reported as discovered hosts. Pure.
    ///
    /// Under [`Wildcard::Absent`] they all can, and under
    /// [`Wildcard::Unstable`] none can. Under a [`Wildcard::CatchAll`] or an
    /// [`Wildcard::Unknown`] they can while they are a minority of the
    /// candidates: a zone's real records are a handful of a generic dictionary,
    /// and a wildcard answers for all of it. A majority means the catch-all is
    /// answering with sets its fingerprint does not match (another upstream
    /// answered, or only one canary sampled it), or the canaries failed on a
    /// zone that has one.
    pub(super) fn leaves_hits_distinguishable(&self, hits: usize, candidates: usize) -> bool {
        match self {
            Self::Absent => true,
            Self::Unstable => false,
            Self::CatchAll(_) | Self::Unknown => hits * 2 <= candidates,
        }
    }
}

/// Resolve both canaries concurrently against `zone` and read the pair.
pub(super) async fn detect_wildcard(zone: &str) -> Wildcard {
    let resolver = shared_resolver();
    let (a, b) = tokio::join!(
        resolver.lookup_ip(format!("{}.{zone}", CANARY_LABELS[0])),
        resolver.lookup_ip(format!("{}.{zone}", CANARY_LABELS[1])),
    );
    wildcard_verdict(canary(a), canary(b))
}

/// Read one canary lookup.
fn canary(
    lookup: std::result::Result<
        hickory_resolver::lookup_ip::LookupIp,
        hickory_resolver::net::NetError,
    >,
) -> Canary {
    match lookup {
        Ok(found) => {
            let ips: BTreeSet<String> = found.iter().map(|ip| ip.to_string()).collect();
            if ips.is_empty() {
                Canary::NoSuchName
            } else {
                Canary::Resolved(ips)
            }
        }
        Err(e) if e.is_no_records_found() => Canary::NoSuchName,
        Err(_) => Canary::Failed,
    }
}

/// Pure comparison, independently unit-tested: true iff `ips` is a non-empty
/// exact match for the wildcard catch-all fingerprint, meaning this
/// candidate resolved to nothing more than the zone's own wildcard noise and
/// must be discarded rather than reported as a discovered subdomain.
pub(super) fn is_wildcard_noise(ips: &BTreeSet<String>, fingerprint: &BTreeSet<String>) -> bool {
    !ips.is_empty() && ips == fingerprint
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ips: &[&str]) -> BTreeSet<String> {
        ips.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn exact_match_is_noise() {
        let fp = set(&["1.2.3.4"]);
        assert!(is_wildcard_noise(&set(&["1.2.3.4"]), &fp));
    }

    #[test]
    fn different_ip_is_not_noise() {
        let fp = set(&["1.2.3.4"]);
        assert!(!is_wildcard_noise(&set(&["5.6.7.8"]), &fp));
    }

    #[test]
    fn superset_or_subset_is_not_noise() {
        // A real subdomain hosted alongside the wildcard's IP (e.g. a
        // load-balanced record sharing one address with the catch-all) is
        // NOT indistinguishable noise unless its ENTIRE IP set matches —
        // partial overlap is still a distinct, reportable finding.
        let fp = set(&["1.2.3.4"]);
        assert!(!is_wildcard_noise(&set(&["1.2.3.4", "5.6.7.8"]), &fp));
    }

    #[test]
    fn empty_ip_set_is_never_noise() {
        let fp = set(&["1.2.3.4"]);
        assert!(!is_wildcard_noise(&set(&[]), &fp));
    }
}
