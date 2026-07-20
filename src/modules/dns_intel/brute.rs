use std::collections::HashSet;
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

/// Fixed, improbable probe labels for wildcard-DNS detection. A domain with a
/// `*.domain` A/AAAA record resolves EVERY name, so these guaranteed-nonexistent
/// labels still return an IP — and any IP they return is a wildcard artifact, not
/// a real host. Fixed (not random) to keep the module deterministic run-to-run,
/// which the codebase requires; three independent labels guard against one
/// improbably being registered for real.
const WILDCARD_PROBES: &[&str] = &[
    "wildcard-probe-a1b2c3d4e5f6",
    "nonexistent-8f7e6d5c4b3a-hse",
    "zzz-no-such-host-9q8w7e6r5t",
];

/// Resolve the wildcard-probe labels under `parent` (concurrently — one DNS
/// round-trip) and return the union of every IP they answer with: the domain's
/// **wildcard IP set**, empty when the domain has no wildcard record. A
/// brute-forced subdomain whose resolved IPs are ALL in this set is a wildcard
/// artifact, dropped by [`strip_wildcard_hits`].
async fn detect_wildcard_ips(parent: &str) -> HashSet<String> {
    let resolver = shared_resolver();
    let probes = WILDCARD_PROBES.iter().map(|label| {
        let host = format!("{label}.{parent}");
        async move {
            match resolver.lookup_ip(host.as_str()).await {
                Ok(lookup) => lookup.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                Err(_) => Vec::new(),
            }
        }
    });
    futures::future::join_all(probes)
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Drop wildcard-artifact hits in place. A brute hit is a REAL host only if at
/// least one of its resolved IPs is NOT a wildcard IP; a hit resolving solely to
/// wildcard IPs is the domain answering an arbitrary name with its catch-all
/// record, not a distinct service. An empty `wildcard_ips` (no wildcard) keeps
/// every hit. **Pure** — unit-tested directly. Each hit is `(host, "ip, ip, …",
/// count)`; the IP string is the `", "`-joined list the resolver produced, so
/// splitting on `", "` recovers the exact per-hit IP set.
fn strip_wildcard_hits(hits: &mut Vec<(String, String, usize)>, wildcard_ips: &HashSet<String>) {
    if wildcard_ips.is_empty() {
        return;
    }
    hits.retain(|(_host, ips_joined, _count)| {
        ips_joined.split(", ").any(|ip| !wildcard_ips.contains(ip))
    });
}

/// Subdomain brute-force via the common-name dictionary.
pub(super) async fn brute_subdomains(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let parent = target.value.trim().trim_end_matches('.').to_lowercase();
    if parent.is_empty() || parent.contains('/') || parent.contains(' ') {
        return Ok(Vec::new());
    }

    // Wildcard-DNS guard (see `detect_wildcard_ips`): probe first so a catch-all
    // `*.parent` record can't turn every dictionary guess into a false "confirmed
    // subdomain". One concurrent round-trip up front, negligible beside the brute
    // sweep's own latency.
    let wildcard_ips = detect_wildcard_ips(&parent).await;

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

    // Drop wildcard artifacts before emitting — a hit resolving ONLY to the
    // domain's wildcard IP set is the catch-all record answering, not a real host.
    strip_wildcard_hits(&mut hits, &wildcard_ips);

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

#[cfg(test)]
mod tests {
    use super::strip_wildcard_hits;
    use std::collections::HashSet;

    fn hit(host: &str, ips: &str) -> (String, String, usize) {
        (host.to_string(), ips.to_string(), ips.split(", ").count())
    }

    fn wildcard_set(ips: &[&str]) -> HashSet<String> {
        ips.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn no_wildcard_keeps_every_hit() {
        // Empty wildcard set (domain has no catch-all) → nothing is filtered.
        let mut hits = vec![hit("admin.example.com", "1.1.1.1"), hit("vpn.example.com", "2.2.2.2")];
        strip_wildcard_hits(&mut hits, &HashSet::new());
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn hit_resolving_only_to_wildcard_ips_is_dropped() {
        // The classic false positive: `*.example.com -> 9.9.9.9`, so every guess
        // resolves to 9.9.9.9 and must NOT be emitted as a confirmed host.
        let wc = wildcard_set(&["9.9.9.9"]);
        let mut hits = vec![
            hit("admin.example.com", "9.9.9.9"),
            hit("vpn.example.com", "9.9.9.9"),
        ];
        strip_wildcard_hits(&mut hits, &wc);
        assert!(hits.is_empty(), "pure wildcard artifacts must be filtered out");
    }

    #[test]
    fn hit_with_a_distinct_ip_survives_the_wildcard() {
        // A real service behind a wildcard domain resolves to a DIFFERENT IP than
        // the catch-all — that distinct IP proves it is genuine, so it is kept.
        let wc = wildcard_set(&["9.9.9.9"]);
        let mut hits = vec![
            hit("junk.example.com", "9.9.9.9"),          // artifact → dropped
            hit("mail.example.com", "10.0.0.5"),          // distinct → kept
            hit("api.example.com", "9.9.9.9, 10.0.0.6"),  // mixed → kept (has a real IP)
        ];
        strip_wildcard_hits(&mut hits, &wc);
        let kept: Vec<&str> = hits.iter().map(|h| h.0.as_str()).collect();
        assert_eq!(kept, vec!["mail.example.com", "api.example.com"]);
    }

    #[test]
    fn multi_ip_wildcard_set_is_matched_fully() {
        // A wildcard that round-robins several IPs: a hit resolving only to those
        // (in any subset) is still an artifact.
        let wc = wildcard_set(&["9.9.9.9", "9.9.9.10"]);
        let mut hits = vec![
            hit("a.example.com", "9.9.9.10"),
            hit("b.example.com", "9.9.9.9, 9.9.9.10"),
            hit("c.example.com", "9.9.9.9, 8.8.8.8"), // has a non-wildcard IP → kept
        ];
        strip_wildcard_hits(&mut hits, &wc);
        let kept: Vec<&str> = hits.iter().map(|h| h.0.as_str()).collect();
        assert_eq!(kept, vec!["c.example.com"]);
    }
}
