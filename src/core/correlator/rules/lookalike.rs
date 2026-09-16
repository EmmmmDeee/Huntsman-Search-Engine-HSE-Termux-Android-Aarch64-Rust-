//! AU-118 — Look-alike domain impersonation.
//!
//! When a scan surfaces two DISTINCT registrable domains whose brand labels are
//! visual or typo look-alikes — `paypal.com` alongside `paypa1.com`,
//! `google.com` alongside `g00gle.net`, `amazon.com` alongside `arnazon.co` —
//! one is almost certainly impersonating the other: a phishing / brand-abuse
//! domain standing up beside the genuine one. This is the correlation-layer
//! counterpart to the `typosquat` module (which *generates* permutations of a
//! seed to probe): here we compare every pair of domains the whole scan actually
//! discovered, catching a look-alike that arrived through infrastructure,
//! breach, or crawl evidence rather than from a seed permutation — the
//! cross-source impersonation view SpiderFoot's dnstwist module cannot give,
//! because it only expands the seed.
//!
//! Delegates the "do these look alike?" decision to the pure, offline
//! [`crate::util::confusable`] primitive (homoglyph skeleton OR single edit,
//! both gated on a minimum label length), and folds each domain to its
//! registrable form via [`registrable_domain`] first — so a brand's own
//! TLD variants (`paypal.com` / `paypal.net`, same label) never fire, only a
//! genuinely different look-alike label does.
//!
//! Severity **High**: a look-alike domain is a strong, actionable
//! impersonation / phishing signal.

use super::*;
use crate::util::confusable::is_lookalike;
use crate::util::domains::registrable_domain;

/// True when `e` is a domain the `typosquat` module GENERATED as a permutation
/// of the seed rather than one the scan independently discovered. AU-118 is the
/// cross-source impersonation view (see this module's doc): a generated sibling
/// is not a discovery, and pairing two siblings of the same original asserts an
/// impersonation relationship that does not exist. A permutation a SECOND source
/// also surfaced (crt.sh, a crawl, breach evidence) is a genuine discovery and
/// stays in scope, so the test is "typosquat is the ONLY evidence source", not
/// "carries the typosquat tag".
///
/// Uses [`Entity::corroborating_sources`], not the raw [`Entity::evidence_sources`]:
/// a re-scan of the same seed recalls this exact generated domain from the local
/// database ([`crate::core::entity::RECALL_SOURCE`]) and unconditionally stamps a
/// `"recall"` evidence record on it regardless of entity kind. `evidence_sources`
/// would then read `{"typosquat", "recall"}`, `all(|s| *s == "typosquat")` would
/// go false, and a ROUTINE RE-SCAN would silently defeat this exclusion —
/// `corroborating_sources` strips `recall` (provenance, not an independent
/// observation — [`crate::core::entity::is_non_corroborating_source`]) so the
/// check still reads "typosquat is the only REAL source" after a recall.
fn is_generated_permutation(e: &Entity) -> bool {
    e.has_tag("typosquat") && e.corroborating_sources().iter().all(|s| *s == "typosquat")
}

/// True when two brand labels are identical once their ASCII digits are removed
/// — they differ ONLY in a numeric component. Two members of one operator's
/// numbered infrastructure series (`awsdns-52` / `awsdns-62`, the AWS Route 53
/// nameserver parents of a single hosted zone; `ns1` / `ns2`; `mx1` / `mx2`)
/// are the SAME operator's enumerated hosts, not one brand impersonating
/// another — yet [`is_lookalike`] sees a single-character edit and fires. A live
/// `redcross.org.au` scan flagged the org's own `awsdns-52.org` / `awsdns-62.net`
/// nameservers as "phishing / brand-abuse infrastructure" at High this way
/// (REQ-ATTR-004). A homoglyph or typo that substitutes a digit for a LETTER
/// (`paypa1` for `paypal`, `g00gle` for `google`) leaves the digit-stripped
/// forms UNEQUAL, so those real impersonations still fire.
fn differ_only_in_digits(a: &str, b: &str) -> bool {
    let without_digits =
        |s: &str| -> String { s.chars().filter(|c| !c.is_ascii_digit()).collect() };
    without_digits(a) == without_digits(b)
}

/// AU-118 — Look-alike domain impersonation.
///
/// Entity-only: folds the `Domain` entities to distinct registrable domains and
/// emits one High correlation per pair whose brand labels are confusable. Each
/// finding's `entity_uids` carries the Domain entities of both sides, in entity
/// order, so the SPA can render the impersonating/impersonated pair. A domain
/// whose only evidence source is the `typosquat` generator is excluded
/// ([`is_generated_permutation`]) — pairing two of the module's own permutations
/// would manufacture an impersonation claim the scan never discovered.
pub(in crate::core::correlator) fn rule_au_118_lookalike_domain_impersonation(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::BTreeMap;

    // registrable domain -> (brand label, entity uids that map to it). BTreeMap
    // keeps the pair iteration deterministic regardless of entity order.
    let mut domains: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in entities {
        if e.kind != EntityKind::Domain || is_generated_permutation(e) {
            continue;
        }
        if let Some(reg) = registrable_domain(e.value.trim()) {
            domains.entry(reg).or_default().push(e.uid.clone());
        }
    }
    if domains.len() < 2 {
        return Vec::new();
    }

    // Deterministic pairwise scan. Bounded work: a scan's distinct-domain count
    // is a small fraction of the entity cap, so the O(n^2) pass is cheap; guard
    // an extreme set anyway so a pathological scan can't stall the pass.
    const MAX_DOMAINS: usize = 400;
    let keys: Vec<&String> = domains.keys().take(MAX_DOMAINS).collect();
    let label = |reg: &str| reg.split('.').next().unwrap_or(reg).to_string();

    let mut out = Vec::new();
    for i in 0..keys.len() {
        let li = label(keys[i]);
        for kj in keys.iter().skip(i + 1) {
            let lj = label(kj);
            if !is_lookalike(&li, &lj) || differ_only_in_digits(&li, &lj) {
                continue;
            }
            // Union both sides' entities, in entity order for a stable render.
            let members: std::collections::HashSet<&str> = domains[keys[i]]
                .iter()
                .chain(domains[*kj].iter())
                .map(String::as_str)
                .collect();
            let uids: Vec<String> = entities
                .iter()
                .filter(|e| members.contains(e.uid.as_str()))
                .map(|e| e.uid.clone())
                .collect();

            out.push(Correlation::new(
                "AU-118",
                "Look-alike domain impersonation",
                Severity::High,
                format!(
                    "'{}' and '{}' are visual/typo look-alike domains discovered in the same \
                     scan — one is almost certainly impersonating the other (phishing / \
                     brand-abuse infrastructure standing up beside the genuine domain).",
                    keys[i], kj,
                ),
                uids,
                scan_id,
                ts,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;

    fn dom(v: &str) -> Entity {
        Entity::new(EntityKind::Domain, v, confidence::HIGH_PLUSPLUS, "s")
    }

    #[test]
    fn au118_fires_on_a_homoglyph_lookalike_pair() {
        let real = dom("paypal.com");
        let fake = dom("paypa1.com");
        let out = rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[real.clone(), fake.clone()]),
            "s",
            0,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-118");
        assert_eq!(out[0].severity, Severity::High);
        assert!(out[0].entity_uids.contains(&real.uid));
        assert!(out[0].entity_uids.contains(&fake.uid));
    }

    #[test]
    fn au118_silent_on_a_brand_tld_variant() {
        // Same brand label, different TLD — legitimate, not impersonation.
        let out = rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[dom("paypal.com"), dom("paypal.net")]),
            "s",
            0,
        );
        assert!(
            out.is_empty(),
            "TLD variants of one brand are not look-alikes"
        );
    }

    #[test]
    fn au118_silent_on_unrelated_domains() {
        let out = rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[dom("google.com"), dom("facebook.com")]),
            "s",
            0,
        );
        assert!(out.is_empty(), "unrelated domains do not impersonate");
    }

    #[test]
    fn au118_folds_subdomains_to_the_registrable_pair() {
        // Subdomains must not multiply the finding — both fold to one registrable.
        let out = rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[dom("login.paypal.com"), dom("secure.paypa1.com")]),
            "s",
            0,
        );
        assert_eq!(out.len(), 1, "one registrable pair → one finding");
    }

    /// A `typosquat`-only-sourced domain is a GENERATED permutation of the seed,
    /// not a discovery — pairing two of them manufactures a false impersonation
    /// finding. On a real `iana.org` scan this flooded 82% of all correlations.
    #[test]
    fn au118_ignores_typosquat_generated_sibling_pairs() {
        use crate::core::entity::Evidence;
        let mut a = dom("iqana.org");
        a.tag("typosquat");
        a.add_evidence(Evidence::new(
            "typosquat",
            "Registered lookalike of iana.org via insertion → resolves to 1.2.3.4",
        ));
        let mut b = dom("izana.org");
        b.tag("typosquat");
        b.add_evidence(Evidence::new(
            "typosquat",
            "Registered lookalike of iana.org via insertion → resolves to 5.6.7.8",
        ));
        let mut seed = dom("iana.org");
        seed.add_evidence(Evidence::new("rdap_domain", "seed"));
        let out =
            rule_au_118_lookalike_domain_impersonation(&RuleContext::new(&[a, b, seed]), "s", 0);
        assert!(out.is_empty(), "typosquat siblings must not pair: {out:?}");
    }

    /// The recall-bypass regression: a routine RE-SCAN of the same seed recalls
    /// each generated sibling from the local database and stamps a `"recall"`
    /// evidence record on top of its original `"typosquat"` evidence (every
    /// recalled entity gets one, regardless of kind — see
    /// `Engine::recall_prior_entities`). Before this fix, `is_generated_permutation`
    /// read the raw `evidence_sources()` set (`{"typosquat", "recall"}`), so
    /// `all(|s| *s == "typosquat")` went false and a SECOND scan of the exact same
    /// seed silently defeated the exclusion this test's sibling
    /// (`au118_ignores_typosquat_generated_sibling_pairs`) already covers for a
    /// first scan.
    #[test]
    fn au118_ignores_typosquat_generated_sibling_pairs_after_recall() {
        use crate::core::entity::Evidence;
        let mut a = dom("iqana.org");
        a.tag("typosquat");
        a.add_evidence(Evidence::new(
            "typosquat",
            "Registered lookalike via insertion",
        ));
        a.add_evidence(Evidence::new(
            "recall",
            "Recalled from the local intelligence database (prior scan)",
        ));
        let mut b = dom("izana.org");
        b.tag("typosquat");
        b.add_evidence(Evidence::new(
            "typosquat",
            "Registered lookalike via insertion",
        ));
        b.add_evidence(Evidence::new(
            "recall",
            "Recalled from the local intelligence database (prior scan)",
        ));
        let out = rule_au_118_lookalike_domain_impersonation(&RuleContext::new(&[a, b]), "s", 0);
        assert!(
            out.is_empty(),
            "a recalled typosquat sibling pair must still not pair: {out:?}"
        );
    }

    /// A permutation a SECOND, independent source also surfaced is a genuine
    /// discovery and must still fire.
    #[test]
    fn au118_still_fires_when_a_permutation_was_independently_discovered() {
        use crate::core::entity::Evidence;
        let mut real = dom("paypal.com");
        real.add_evidence(Evidence::new("crtsh", "cert"));
        let mut fake = dom("paypa1.com");
        fake.tag("typosquat");
        fake.add_evidence(Evidence::new("typosquat", "generated"));
        fake.add_evidence(Evidence::new("crtsh", "cert"));
        let out = rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[real, fake.clone()]),
            "s",
            0,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-118");
        assert!(out[0].entity_uids.contains(&fake.uid));
    }

    /// REQ-ATTR-004: two members of one operator's numbered infrastructure
    /// series differ only in a shard number, which `is_lookalike` reads as a
    /// single edit. A live `redcross.org.au` scan flagged the zone's own AWS
    /// Route 53 nameserver parents `awsdns-52.org` / `awsdns-62.net` as
    /// "phishing / brand-abuse infrastructure" at High. They are the same
    /// provider's enumerated hosts, not one impersonating the other, so AU-118
    /// must stay silent — while a digit-for-LETTER homoglyph still fires.
    #[test]
    fn au118_silent_on_a_numbered_infrastructure_series() {
        let out = rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[dom("awsdns-52.org"), dom("awsdns-62.net")]),
            "s",
            0,
        );
        assert!(
            out.is_empty(),
            "two shards of one AWS nameserver series are not impersonation: {out:?}"
        );
        // Sibling infrastructure enumerations behave the same.
        let out = rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[dom("mx1.example-mail.com"), dom("mx2.example-host.net")]),
            "s",
            0,
        );
        assert!(
            out.is_empty(),
            "mx1 / mx2 are enumerated hosts, not impersonation: {out:?}"
        );
        // A digit that REPLACES a letter is still a homoglyph impersonation: the
        // digit-stripped forms (`paypa` vs `paypal`) are unequal, so it fires.
        let out = rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[dom("paypal.com"), dom("paypa1.com")]),
            "s",
            0,
        );
        assert_eq!(
            out.len(),
            1,
            "a digit-for-letter homoglyph still fires: {out:?}"
        );
    }

    #[test]
    fn differ_only_in_digits_distinguishes_a_series_from_a_homoglyph() {
        assert!(differ_only_in_digits("awsdns-52", "awsdns-62"));
        assert!(differ_only_in_digits("ns1", "ns2"));
        assert!(differ_only_in_digits("server01", "server02"));
        // Digit-for-letter substitution is NOT a pure numeric difference.
        assert!(!differ_only_in_digits("paypa1", "paypal"));
        assert!(!differ_only_in_digits("g00gle", "google"));
        assert!(!differ_only_in_digits("arnazon", "amazon"));
    }
}
