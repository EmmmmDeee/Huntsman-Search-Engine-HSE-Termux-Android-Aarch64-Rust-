//! Shared concurrent-resolution primitive for `dns_intel`'s two hostname-
//! candidate enumeration passes: the static-dictionary brute force
//! ([`super::brute`]) and the structural permutation sweep ([`super::permute`]).
//! Both reduce to the same shape — "resolve a batch of candidate hostnames,
//! bounded-concurrency, keep only the ones that answer, report deterministically"
//! — so this is the ONE implementation both call (Rule 4: delegate, never
//! duplicate) rather than each hand-rolling its own `JoinSet`/`Semaphore`/sort.

use std::collections::BTreeSet;
use std::sync::Arc;

use tokio::sync::Semaphore;

use super::wildcard::is_wildcard_noise;
use crate::core::module::ModuleContext;
use crate::util::dns::shared_resolver;

/// A resolved hostname candidate: `(host, comma-joined resolved IPs, IP count)`.
pub(super) type ResolvedHost = (String, String, usize);

/// Resolve every `candidates` hostname concurrently (bounded to `max_concurrent`
/// in flight), keep only the ones with at least one A/AAAA record that is NOT
/// indistinguishable from `wildcard_fingerprint`'s catch-all noise (`None` when
/// the caller's zone has no detected wildcard — the common case, and the only
/// behaviour prior to wildcard detection existing), and return them sorted by
/// hostname for deterministic output regardless of DNS completion order —
/// `join_next()` yields in network-completion order (nondeterministic
/// run-to-run), so this collects first and sorts after, matching the
/// fixed-order resolution every other dns_intel pass produces.
pub(super) async fn resolve_hosts_concurrently(
    candidates: Vec<String>,
    max_concurrent: usize,
    wildcard_fingerprint: Option<Arc<BTreeSet<String>>>,
    _ctx: &ModuleContext,
) -> Vec<ResolvedHost> {
    let resolver = shared_resolver();
    // Clamp the concurrency floor to 1: `Semaphore::new(0)` hands out no permits,
    // so every spawned task would await `acquire_owned()` forever and `join_next()`
    // would never complete — a hang. Callers pass a fixed non-zero constant today,
    // but this is a shared primitive, so guard the invariant here rather than
    // trusting every present and future caller.
    let sem = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let mut set = tokio::task::JoinSet::new();

    for host in candidates {
        let sem = Arc::clone(&sem);
        let fingerprint = wildcard_fingerprint.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            match resolver.lookup_ip(host.as_str()).await {
                Ok(lookup) => {
                    let ip_set: BTreeSet<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    if ip_set.is_empty() {
                        return None;
                    }
                    if let Some(fp) = fingerprint.as_deref()
                        && is_wildcard_noise(&ip_set, fp)
                    {
                        return None;
                    }
                    let count = ip_set.len();
                    let joined = ip_set.into_iter().collect::<Vec<_>>().join(", ");
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
