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

/// AU-118 — Look-alike domain impersonation.
///
/// Entity-only: folds the `Domain` entities to distinct registrable domains and
/// emits one High correlation per pair whose brand labels are confusable. Each
/// finding's `entity_uids` carries the Domain entities of both sides, in entity
/// order, so the SPA can render the impersonating/impersonated pair.
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
        if e.kind != EntityKind::Domain {
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
            if !is_lookalike(&li, &lj) {
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
}
