use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleContext,
    scan::Target,
};
use crate::util::dns::shared_resolver;

use super::constants::SUBDOMAINS;
use super::{MAX_CONCURRENT_BRUTE, SRC};

/// Subdomain brute-force via the common-name dictionary.
pub(super) async fn brute_subdomains(
    target: &Target,
    ctx: &ModuleContext,
) -> Result<Vec<Entity>> {
    let parent = target.value.trim().trim_end_matches('.').to_lowercase();
    if parent.is_empty() || parent.contains('/') || parent.contains(' ') {
        return Ok(Vec::new());
    }

    let resolver = shared_resolver();
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_BRUTE));
    let mut set = tokio::task::JoinSet::new();

    for sub in SUBDOMAINS {
        // Skip if the sub-label is already the leftmost label of the input.
        if parent.starts_with(sub) && parent.as_bytes().get(sub.len()) == Some(&b'.') {
            continue;
        }
        let mut host = String::with_capacity(sub.len() + 1 + parent.len());
        host.push_str(sub);
        host.push('.');
        host.push_str(&parent);
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            match resolver.lookup_ip(host.as_str()).await {
                Ok(lookup) => {
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    let count = ips.len();
                    let joined = ips.join(", ");
                    Some((host, joined, count))
                }
                Err(_) => None,
            }
        });
    }

    // Drain the JoinSet, then SORT hits by host before emitting entities.
    // `join_next()` yields in network-completion order — nondeterministic
    // run-to-run — so collecting first and sorting makes this module's output
    // deterministic for a given DNS state, matching the fixed-order
    // `tokio::join!` resolution path. Hosts are unique, so the order is total.
    let mut hits: Vec<(String, String, usize)> = Vec::new();
    while let Some(join_result) = set.join_next().await {
        if let Ok(Some(hit)) = join_result {
            hits.push(hit);
        }
    }
    hits.sort_unstable_by(|a, b| a.0.cmp(&b.0));

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
