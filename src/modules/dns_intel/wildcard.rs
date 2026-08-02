//! DNS wildcard-record detection — a catch-all `*.zone A x.x.x.x` record
//! makes EVERY possible subdomain label "resolve", which turns both
//! [`super::brute::brute_subdomains`] and [`super::permute::permute_subdomains`]
//! into 100% false-positive generators: every dictionary/permutation
//! candidate answers with the identical catch-all IP set and gets reported
//! as a discovered subdomain. Confirmed live against a real wildcard zone
//! (`blogspot.com`): two unrelated, guaranteed-nonexistent random labels
//! both resolved to the same IP.
//!
//! Detection: resolve two GUID-derived canary labels no legitimate zone
//! would ever configure. If BOTH resolve and agree on the exact same
//! non-empty IP set, the zone has wildcard DNS and that IP set is the
//! catch-all fingerprint — requiring agreement between two *unrelated*
//! random labels (rather than trusting a single lookup) rules out a
//! one-off coincidental registration.

use std::collections::BTreeSet;

use crate::util::dns::shared_resolver;

/// Two unrelated, GUID-derived labels. Fixed (not random-per-run) so a
/// wildcard fingerprint is reproducible across scans of the same zone —
/// randomising per-run would make the "same catch-all IP set" comparison
/// this module runs against unusable for regression testing.
const CANARY_LABELS: [&str; 2] = [
    "hse-wildcard-canary-7f3a9c1e2b8d",
    "hse-wildcard-canary-4d6e0a5c9f17",
];

/// Resolve both canaries concurrently against `zone`. Returns the shared IP
/// fingerprint iff both resolve to the identical non-empty IP set — a zone
/// with no wildcard record answers NXDOMAIN (or a lookup error) for at least
/// one of two random labels, so `None` is the overwhelmingly common, safe
/// default: a transient resolver hiccup on either canary also yields `None`,
/// which only means no filtering happens (identical to today's unguarded
/// behaviour), never a false suppression of real results.
pub(super) async fn detect_wildcard(zone: &str) -> Option<BTreeSet<String>> {
    let resolver = shared_resolver();
    let (a, b) = tokio::join!(
        resolver.lookup_ip(format!("{}.{zone}", CANARY_LABELS[0])),
        resolver.lookup_ip(format!("{}.{zone}", CANARY_LABELS[1])),
    );
    let to_set = |lookup: hickory_resolver::lookup_ip::LookupIp| -> BTreeSet<String> {
        lookup.iter().map(|ip| ip.to_string()).collect()
    };
    let set_a = to_set(a.ok()?);
    let set_b = to_set(b.ok()?);
    if set_a.is_empty() || set_b.is_empty() {
        return None;
    }
    (set_a == set_b).then_some(set_a)
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
