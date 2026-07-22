use std::sync::OnceLock;

use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};

/// Upstream resolvers, in preference order, that back the shared resolver's
/// self-healing pool:
///
/// 1. **Cloudflare** (`1.1.1.1`) — fastest anycast, privacy-respecting.
/// 2. **Quad9** (`9.9.9.9`) — no-logging, malware-blocking, independent (Swiss).
/// 3. **Google** (`8.8.8.8`) — ubiquitous, rarely blocked.
///
/// One reputable resolver is a single point of failure: networks that block
/// `1.1.1.1` (some mobile carriers, captive portals, and censored regions do)
/// would make **every** DNS-issuing module fail — resources unreachable purely
/// for DNS reasons. A pool of independent providers removes that: if the
/// preferred resolver is blocked or dead, hickory transparently fails over to
/// the next (see [`resolver_config`]).
const PROVIDERS: [hickory_resolver::config::ServerGroup<'static>; 3] = [CLOUDFLARE, QUAD9, GOOGLE];

/// Build the shared resolver's [`ResolverConfig`]: a validated, self-healing
/// pool of the [`PROVIDERS`], mirroring the egress proxy pool's
/// prefer-healthy / route-around-dead design one layer down.
///
/// **Failover is within a single lookup**: hickory's `NameServerPool` tries the
/// servers `num_concurrent_reqs` at a time and, on error or timeout, advances
/// through the *rest* of the pool before giving up — so a blocked preferred
/// resolver falls through to Quad9 then Google in the same query, not only on a
/// later one. Across queries, the default `QueryStatistics` server-ordering
/// then reorders the pool by observed success/latency: a resolver that starts
/// failing is passively demoted and the healthy ones are preferred — validated
/// failover from real outcomes, with no extra probe traffic. This is the DNS
/// analogue of [`crate::util::egress`]'s health-ranked proxy pool.
///
/// **IPv4-only nameservers.** Each provider also publishes IPv6 resolver IPs,
/// but on a v6-less host (this container, many no-root Termux / mobile setups)
/// connecting to them just burns a per-server timeout during failover — the
/// same wedge the `Ipv4thenIpv6` lookup strategy avoids for target records. We
/// keep only the v4 resolver addresses so the pool's worst-case failover stays
/// tightly bounded (6 servers, 2 at a time ⇒ ≤3 rounds); this constrains only
/// which IP we *talk to the resolver over*, never which record types we can
/// resolve (AAAA target lookups are unaffected).
#[must_use]
fn resolver_config() -> ResolverConfig {
    let name_servers = PROVIDERS
        .iter()
        .flat_map(hickory_resolver::config::ServerGroup::udp_and_tcp)
        .filter(|ns| ns.ip.is_ipv4())
        .collect::<Vec<_>>();
    ResolverConfig::from_parts(None, vec![], name_servers)
}

/// The process-wide DNS resolver — a lazily-initialised [`TokioResolver`] backed
/// by a self-healing multi-provider pool (Cloudflare → Quad9 → Google; see
/// [`resolver_config`]) and shared by every DNS-issuing module (`dns_intel`,
/// `geo_intel`, the DNSBL checks, …) so they reuse one connection pool and cache
/// instead of each standing up its own.
///
/// Tuned for **bounded latency over completeness** (the platform's "a slow or
/// dead service degrades the scan, never freezes it" rule): a 2-second timeout
/// with a single attempt so a wedged query fails fast, and an `Ipv4thenIpv6`
/// strategy so a v6-less host doesn't pay the failover tax on every lookup — see
/// the inline notes for the observed wedge this prevents. Initialised once via
/// [`OnceLock`]; the hardcoded config is infallible by construction.
#[must_use]
pub fn shared_resolver() -> &'static TokioResolver {
    static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        use hickory_resolver::config::LookupIpStrategy;
        let mut builder =
            TokioResolver::builder_with_config(resolver_config(), TokioRuntimeProvider::default());
        // Bound DNS like every other external call (Requirement: a slow or
        // dead service degrades the scan, never freezes it). hickory's
        // defaults are 5s timeout x 2 attempts = ~10s PER lookup, and
        // dns_intel issues A/AAAA/MX/NS/SOA/TXT (+ DNSBL) lookups, so a
        // stalled resolver stacked well past the module's 15s budget — an
        // IP scan was observed wedging ~25s on a single DNSBL AAAA query
        // when IPv6 nameserver connect failed (os error 97) and the
        // resolver paid the full v6→v4 failover tax on every lookup.
        //
        // - timeout 2s, attempts 1: a wedged query fails fast and the scan
        //   moves on, staying inside dns_intel's 15s declaration even when
        //   several lookups are slow. One attempt is enough because the
        //   pool already fails over across ALL providers within a single
        //   query (see `resolver_config`) — `attempts` would only add a
        //   redundant second sweep of the same pool.
        // - Ipv4thenIpv6: try the v4 nameserver first so a v6-less host
        //   (this container, many mobile networks) doesn't stall on an
        //   unreachable AAAA nameserver, while v6 still resolves where
        //   available.
        {
            let opts = builder.options_mut();
            opts.timeout = std::time::Duration::from_secs(2);
            opts.attempts = 1;
            opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        }
        builder
            .build()
            .expect("hardcoded multi-provider resolver config must build")
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn pool_spans_all_three_providers() {
        let cfg = resolver_config();
        let ips: Vec<IpAddr> = cfg.name_servers.iter().map(|ns| ns.ip).collect();
        // One dead/blocked provider must never take DNS down: each independent
        // network is represented so failover has somewhere to go.
        assert!(
            ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            "Cloudflare"
        );
        assert!(
            ips.contains(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            "Quad9"
        );
        assert!(
            ips.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            "Google"
        );
    }

    #[test]
    fn pool_is_ipv4_only() {
        // v6 resolver IPs would burn a connect timeout per server during
        // failover on a v6-less host; the pool must carry none.
        let cfg = resolver_config();
        assert!(
            cfg.name_servers.iter().all(|ns| ns.ip.is_ipv4()),
            "no IPv6 resolver addresses in the pool"
        );
        assert!(!cfg.name_servers.is_empty(), "pool is populated");
    }

    #[test]
    fn preferred_resolver_is_cloudflare() {
        // Ordering seeds hickory's QueryStatistics pool; the fastest, most
        // privacy-respecting provider leads before real stats accrue.
        let cfg = resolver_config();
        assert_eq!(
            cfg.name_servers.first().map(|ns| ns.ip),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            "Cloudflare is tried first"
        );
    }

    #[tokio::test]
    async fn resolver_initialises() {
        // The hardcoded config must actually build a resolver (the `expect` in
        // `shared_resolver` never fires) and be process-shared (same pointer).
        // Built inside a runtime because the Tokio-backed resolver expects one.
        let a = shared_resolver();
        let b = shared_resolver();
        assert!(std::ptr::eq(a, b), "one shared resolver, not per-call");
    }
}
