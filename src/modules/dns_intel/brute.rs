use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleContext,
    scan::Target,
};

use super::constants::SUBDOMAINS;
use super::resolve_batch::resolve_hosts_concurrently;
use super::{MAX_CONCURRENT_BRUTE, SRC};

/// Subdomain brute-force via the common-name dictionary.
pub(super) async fn brute_subdomains(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let parent = target.value.trim().trim_end_matches('.').to_lowercase();
    if parent.is_empty() || parent.contains('/') || parent.contains(' ') {
        return Ok(Vec::new());
    }

    let candidates: Vec<String> = SUBDOMAINS
        .iter()
        // Skip if the sub-label is already the leftmost label of the input.
        .filter(|sub| {
            !(parent.starts_with(*sub) && parent.as_bytes().get(sub.len()) == Some(&b'.'))
        })
        .map(|sub| format!("{sub}.{parent}"))
        .collect();

    let hits = resolve_hosts_concurrently(candidates, MAX_CONCURRENT_BRUTE, ctx).await;

    let entities: Vec<Entity> = hits
        .into_iter()
        .map(|(host, ips_joined, count)| {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
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
            e
        })
        .collect();
    Ok(entities)
}
