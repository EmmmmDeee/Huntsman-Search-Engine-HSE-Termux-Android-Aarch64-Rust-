//! Shared concurrent-resolution primitive for `dns_intel`'s two hostname-
//! candidate enumeration passes: the static-dictionary brute force
//! ([`super::brute`]) and the structural permutation sweep ([`super::permute`]).
//! Both reduce to the same shape — "resolve a batch of candidate hostnames,
//! bounded-concurrency, keep only the ones that answer, report deterministically"
//! — so this is the ONE implementation both call (Rule 4: delegate, never
//! duplicate) rather than each hand-rolling its own `JoinSet`/`Semaphore`/sort.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::core::module::ModuleContext;
use crate::util::dns::shared_resolver;

/// A resolved hostname candidate: `(host, comma-joined resolved IPs, IP count)`.
pub(super) type ResolvedHost = (String, String, usize);

/// Resolve every `candidates` hostname concurrently (bounded to `max_concurrent`
/// in flight), keep only the ones with at least one A/AAAA record, and return
/// them sorted by hostname for deterministic output regardless of DNS
/// completion order — `join_next()` yields in network-completion order
/// (nondeterministic run-to-run), so this collects first and sorts after,
/// matching the fixed-order resolution every other dns_intel pass produces.
pub(super) async fn resolve_hosts_concurrently(
    candidates: Vec<String>,
    max_concurrent: usize,
    _ctx: &ModuleContext,
) -> Vec<ResolvedHost> {
    let resolver = shared_resolver();
    let sem = Arc::new(Semaphore::new(max_concurrent));
    let mut set = tokio::task::JoinSet::new();

    for host in candidates {
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

    let mut hits: Vec<ResolvedHost> = Vec::new();
    while let Some(join_result) = set.join_next().await {
        if let Ok(Some(hit)) = join_result {
            hits.push(hit);
        }
    }
    hits.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    hits
}
