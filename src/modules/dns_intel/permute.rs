//! Structural subdomain permutation ("alteration") enumeration — the
//! `altdns`/`gotator`/`dnsgen`-class technique: given an ALREADY-DISCOVERED
//! subdomain, generate structurally plausible siblings of its own leftmost
//! label (numeric neighbours, environment/stage prefixes and suffixes,
//! separator normalisation) and resolve them.
//!
//! This complements the static-dictionary brute force
//! ([`super::brute::brute_subdomains`], which only tries GENERIC common names
//! against the bare apex) with a target-INFORMED technique: a real
//! `api-prod.example.com` strongly implies `api-dev`/`api-staging`/`api-uat`
//! siblings exist — patterns no generic wordlist would ever guess, because
//! they depend on THIS target's own naming convention, not a common one.
//!
//! Because the engine recurses on every discovered `Domain` entity
//! (`DnsIntel::accepts()` matches `TargetKind::Domain` unconditionally, so
//! every subdomain this module — or crt.sh, or a zone transfer — discovers
//! gets re-dispatched back through this same module on a later round), this
//! pass fires automatically on every subdomain the WHOLE scan ever discovers,
//! including its own prior permutation round. That compounds into a
//! genuinely exhaustive structural sweep bounded only by the engine's own
//! depth / entity-cap / ROI-saturation safety rails — the same ones every
//! other recursive discovery in this codebase already respects. No new
//! engine wiring is needed for the recursion; only the candidate generator
//! and its wiring into `process_domain` are new.
//!
//! Only fires on a target with **≥3 labels** — a genuine subdomain, not the
//! bare registrable apex (`"example.com"` has no informative leftmost label
//! to mutate; `"api.example.com"` does).

use std::collections::BTreeSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleContext,
    scan::Target,
};

use super::resolve_batch::resolve_hosts_concurrently;
use super::{MAX_CONCURRENT_BRUTE, SRC};

/// Environment / deployment-stage words commonly used as a subdomain-label
/// prefix or suffix (`dev-api`, `api-staging`). Curated from the same class of
/// naming convention real infrastructure teams use across cloud providers.
const ENV_WORDS: &[&str] = &[
    "dev",
    "development",
    "staging",
    "stg",
    "test",
    "testing",
    "uat",
    "qa",
    "prod",
    "production",
    "int",
    "internal",
    "external",
    "ext",
    "old",
    "new",
    "beta",
    "alpha",
    "sandbox",
    "demo",
    "preprod",
    "pre",
];

/// Hard cap on generated candidates per invocation — a defence-in-depth bound
/// (the generator's own arithmetic already stays well under this) so a
/// pathological label can never balloon one round's query count. Matches the
/// same order of magnitude as the static dictionary (146 entries), keeping
/// this pass's per-target cost comparable rather than additive-explosive.
const MAX_PERMUTE_CANDIDATES: usize = 80;

/// Pure candidate generator: given the leftmost label of an already-discovered
/// subdomain and the rest of its hostname (everything after the first `.`),
/// return the full candidate hostnames to resolve. Deterministic (a
/// `BTreeSet`), excludes the original hostname, capped at
/// [`MAX_PERMUTE_CANDIDATES`]. No I/O — independently unit-tested.
pub(super) fn generate_permutations(label: &str, rest: &str) -> Vec<String> {
    let original = format!("{label}.{rest}");
    let mut labels: BTreeSet<String> = BTreeSet::new();

    // Numeric siblings: strip a trailing digit run to find the base word, then
    // try the small set of neighbouring numeric suffixes a real team uses for
    // parallel instances (api1/api2/api-01, …).
    let base: &str = label.trim_end_matches(|c: char| c.is_ascii_digit());
    if !base.is_empty() {
        for suffix in ["1", "2", "3", "01", "02"] {
            labels.insert(format!("{base}{suffix}"));
        }
    }

    // Environment / stage prefix and suffix, hyphen-joined.
    for env in ENV_WORDS {
        labels.insert(format!("{env}-{label}"));
        labels.insert(format!("{label}-{env}"));
    }

    // Separator normalisation: a label written with one separator style often
    // has a sibling written with another.
    if label.contains('-') {
        labels.insert(label.replace('-', "_"));
        labels.insert(label.replace('-', ""));
    }
    if label.contains('_') {
        labels.insert(label.replace('_', "-"));
        labels.insert(label.replace('_', ""));
    }

    labels
        .into_iter()
        .filter(|l| !l.is_empty())
        .map(|l| format!("{l}.{rest}"))
        .filter(|h| *h != original)
        .take(MAX_PERMUTE_CANDIDATES)
        .collect()
}

/// Structural permutation sweep for one target. No-op (returns empty) unless
/// `target` already has ≥3 labels — the bare registrable apex has no
/// informative leftmost label to mutate.
pub(super) async fn permute_subdomains(
    target: &Target,
    ctx: &ModuleContext,
) -> Result<Vec<Entity>> {
    let host = target.value.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() || host.contains('/') || host.contains(' ') {
        return Ok(Vec::new());
    }
    let Some((label, rest)) = host.split_once('.') else {
        return Ok(Vec::new());
    };
    // The apex itself (`example.com`, 2 labels) has nothing informative to
    // mutate — permutation needs an ALREADY-DISCOVERED subdomain label.
    if !rest.contains('.') {
        return Ok(Vec::new());
    }
    if label.is_empty() {
        return Ok(Vec::new());
    }

    let candidates = generate_permutations(label, rest);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let hits = resolve_hosts_concurrently(candidates, MAX_CONCURRENT_BRUTE, ctx).await;

    let entities: Vec<Entity> = hits
        .into_iter()
        .map(|(resolved_host, ips_joined, count)| {
            let mut e = Entity::new(EntityKind::Domain, &resolved_host, 0.75, &ctx.scan_id);
            e.tag("subdomain");
            e.tag("dns-permute");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Subdomain {resolved_host} resolves — a structural permutation of \
                         discovered sibling {host}"
                    ),
                )
                .with_attr("permuted_from", &host)
                .with_attr("method", "structural-permutation")
                .with_attr("resolved_ips", &ips_joined)
                .with_attr("ip_count", count.to_string()),
            );
            e
        })
        .collect();
    Ok(entities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_environment_prefix_and_suffix_variants() {
        let out = generate_permutations("api", "example.com");
        assert!(out.contains(&"dev-api.example.com".to_string()));
        assert!(out.contains(&"api-dev.example.com".to_string()));
        assert!(out.contains(&"staging-api.example.com".to_string()));
        assert!(out.contains(&"api-prod.example.com".to_string()));
    }

    #[test]
    fn generates_numeric_siblings() {
        let out = generate_permutations("api2", "example.com");
        // Base "api" (digit stripped) siblings, not "api22".
        assert!(out.contains(&"api1.example.com".to_string()));
        assert!(out.contains(&"api3.example.com".to_string()));
        assert!(out.contains(&"api01.example.com".to_string()));
        // The original itself must never be re-offered as its own candidate.
        assert!(!out.contains(&"api2.example.com".to_string()));
    }

    #[test]
    fn generates_separator_variants_only_when_present() {
        let out = generate_permutations("api-gateway", "example.com");
        assert!(out.contains(&"api_gateway.example.com".to_string()));
        assert!(out.contains(&"apigateway.example.com".to_string()));

        // A label with no separator generates no separator-swap noise.
        let out2 = generate_permutations("api", "example.com");
        assert!(!out2.iter().any(|h| h.contains('_')));
    }

    #[test]
    fn never_includes_the_original_hostname() {
        let out = generate_permutations("dev", "example.com");
        assert!(!out.contains(&"dev.example.com".to_string()));
    }

    #[test]
    fn is_deterministic_and_bounded() {
        let a = generate_permutations("api-gateway2", "example.com");
        let b = generate_permutations("api-gateway2", "example.com");
        assert_eq!(a, b, "identical input must yield identical output order");
        assert!(a.len() <= MAX_PERMUTE_CANDIDATES);
        assert!(!a.is_empty());
    }

    #[tokio::test]
    async fn skips_the_bare_apex_with_no_subdomain_label() {
        use crate::core::module::ModuleContext;

        let target = Target::new(crate::core::scan::TargetKind::Domain, "example.com");
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        };
        let out = permute_subdomains(&target, &ctx).await.unwrap();
        assert!(
            out.is_empty(),
            "a 2-label apex has no discovered subdomain label to permute"
        );
    }
}
