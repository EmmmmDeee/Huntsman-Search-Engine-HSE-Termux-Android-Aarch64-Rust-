//! Shared DNS resolver. Built once per process and reused across every
//! module that does DNS lookups — `dns_resolver`, `reverse_dns`,
//! `dns_brute` — so the resolver's thread pool, connection cache, and
//! TLS session state survive across scans. On Termux this turns the
//! per-target DNS cost from "build resolver + lookup" into just
//! "lookup", which is a noticeable wall-time win on cellular links.

use std::sync::OnceLock;

use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};

/// Process-wide DNS resolver. Hard-coded to Cloudflare 1.1.1.1 / 1.0.0.1
/// — the config never changes, so the `expect` on `.build()` is unreachable
/// in practice; a failure here means the rustls bundle is broken.
pub fn shared_resolver() -> &'static TokioResolver {
    static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .build()
        .expect("hardcoded Cloudflare resolver config must build")
    })
}
