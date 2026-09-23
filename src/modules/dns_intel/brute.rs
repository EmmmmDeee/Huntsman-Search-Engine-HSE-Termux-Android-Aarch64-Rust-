use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{ModuleContext, ModuleResult},
    scan::Target,
};

use super::constants::SUBDOMAINS;
use super::resolve_batch::{reportable_hits, resolve_hosts_concurrently};
use super::wildcard::detect_wildcard;
use super::{MAX_CONCURRENT_BRUTE, SRC};

/// True when `host` canonicalises to the exact same identity as `parent` —
/// i.e. constructing it as a `Domain` entity would collapse onto the scan's
/// own apex/subject uid (`Entity::new` strips a leading "www." label, among
/// other things — see [`crate::core::entity::normalise`]) rather than
/// representing a genuinely distinct host. **Pure**, so this classification
/// is unit-testable without a live resolver.
pub(super) fn is_apex_echo(host: &str, parent: &str) -> bool {
    crate::core::entity::normalise(&EntityKind::Domain, host)
        == crate::core::entity::normalise(&EntityKind::Domain, parent)
}

/// Subdomain brute-force via the common-name dictionary. A pass a wildcard
/// swallows comes back empty and declared truncated ([`reportable_hits`]).
pub(super) async fn brute_subdomains(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let parent = target.value.trim().trim_end_matches('.').to_lowercase();
    if parent.is_empty() || parent.contains('/') || parent.contains(' ') {
        return Ok(ModuleResult::new());
    }

    let candidates: Vec<String> = SUBDOMAINS
        .iter()
        // Skip if the sub-label is already the leftmost label of the input.
        .filter(|sub| {
            !(parent.starts_with(*sub) && parent.as_bytes().get(sub.len()) == Some(&b'.'))
        })
        .map(|sub| format!("{sub}.{parent}"))
        .collect();
    let candidate_count = candidates.len();

    // A wildcard-DNS zone (`*.parent A x.x.x.x`) makes every dictionary word
    // "resolve" — reproduced live against blogspot.com, where two unrelated
    // random labels both answered with the same IP. Detect it once up front:
    // filter out any hit that is nothing more than a stable catch-all's noise,
    // and report nothing a wildcard leaves indistinguishable.
    let wildcard = detect_wildcard(&parent).await;

    let hits = resolve_hosts_concurrently(
        candidates,
        MAX_CONCURRENT_BRUTE,
        wildcard.fingerprint(),
        ctx,
    )
    .await;

    let mut result = ModuleResult::new();
    let hits = reportable_hits(&parent, &wildcard, candidate_count, hits, &mut result);
    let entities: Vec<Entity> = hits
        .into_iter()
        .filter_map(|(host, ips_joined, count)| {
            // Skip a hit that is really just the parent itself. The
            // dictionary always includes "www", which resolves for nearly
            // every real domain — a near-certain, non-adversarial hit, not
            // an edge case — and tagging it "subdomain" below would survive
            // onto the scan's own merged apex/subject entity via
            // `Entity::merge`'s tag-union, permanently mislabeling it as a
            // subdomain of itself. See [`is_apex_echo`].
            if is_apex_echo(&host, &parent) {
                return None;
            }
            let mut e = Entity::new(
                EntityKind::Domain,
                &host,
                confidence::HIGH_PLUSPLUS_PLUS,
                &ctx.scan_id,
            );
            e.tag("subdomain");
            e.tag("dns-brute");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Subdomain {host} resolves to one or more A/AAAA records"),
                )
                .with_attr("parent_domain", &parent)
                .with_attr("method", "common-name-dictionary")
                .with_attr("dictionary_size", SUBDOMAINS.len().to_string())
                .with_attr("resolved_ips", &ips_joined)
                .with_attr("ip_count", count.to_string()),
            );
            Some(e)
        })
        .collect();
    result.extend(entities);
    Ok(result)
}
