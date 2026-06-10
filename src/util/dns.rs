use std::sync::OnceLock;

use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};

pub fn shared_resolver() -> &'static TokioResolver {
    static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        use hickory_resolver::config::LookupIpStrategy;
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        );
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
        //   several lookups are slow.
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
            .expect("hardcoded Cloudflare resolver config must build")
    })
}
