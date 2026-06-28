//! SSRF-guarded DNS resolver and shared reqwest client builder.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Fail-fast TCP connect budget. Independent of each module's total
/// `max_timeout_ms()`. Five seconds is generous on slow mobile links
/// while still preventing a wedged peer from holding a concurrency
/// slot for the module's entire (often double-digit) total budget.
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// True if a redirect's next-hop `host` must be refused as an SSRF risk — i.e.
/// it is a private/reserved IP literal (cloud-metadata 169.254.169.254,
/// loopback, RFC1918, ULA, …). Hostnames are not judged here (they are resolved
/// at connect time); the engine's `url_host_is_private` gate already rejects
/// private-host *targets*, and this extends the guard to every redirect hop so
/// a public URL can't 3xx us onto an internal address.
///
/// `host` is `Url::host_str()`, which (`url` 2.5) returns IPv6 literals **with**
/// brackets (`[::1]`). The brackets must be stripped before the `IpAddr` parse
/// inside `is_private_ip`, or every IPv6-literal hop (loopback `[::1]`, ULA,
/// link-local, IPv4-mapped metadata `[::ffff:169.254.169.254]`) fails to parse,
/// returns `false`, and is followed — an SSRF bypass. Mirrors the bracket
/// handling in [`crate::util::preflight::url_host_is_private`].
pub(super) fn redirect_to_private_ip(host: Option<&str>) -> bool {
    host.map(crate::util::preflight::unbracket_host)
        .is_some_and(crate::util::preflight::is_private_ip)
}

/// True if a redirect hop is an unencrypted **cross-host** downgrade — i.e. the
/// next hop is plaintext `http://` and its host differs from the host that
/// issued the redirect. This is the on-path-injection risk the [`client_builder`]
/// redirect policy must refuse: a MITM on a flaky mobile link can rewrite a 3xx
/// `Location` to bounce the client onto an attacker-controlled plaintext host and
/// tamper with the (then-unauthenticated, unencrypted) response.
///
/// Deliberately **scoped to cross-host**: the two modules that legitimately speak
/// plaintext (`ip_geo` → `http://ip-api.com`, `contact_enrich`'s `http://apilayer.net`
/// fallback) reach their endpoint directly or stay on the same host across a hop,
/// so a same-host `http`→`http` redirect and any `http`→`https` upgrade are still
/// followed. Only a downgrade that *also* changes host is treated as hostile.
/// Operators who want a blanket plaintext ban set `HUNTSMAN_HTTPS_ONLY` (see
/// [`https_only_opt_in`]), which additionally rejects every plaintext hop and target.
///
/// `prev` is the URL that issued the redirect (the last entry of
/// `redirect::Attempt::previous()`); `next` is `redirect::Attempt::url()`.
pub(super) fn is_plaintext_downgrade(prev: &url::Url, next: &url::Url) -> bool {
    next.scheme() == "http" && prev.host_str() != next.host_str()
}

/// Operator opt-in for a blanket plaintext ban via `HUNTSMAN_HTTPS_ONLY`
/// (`1`/`true`/`yes`/`on`). Default **off**: two modules legitimately require
/// plaintext on their free tiers (`ip_geo` → `http://ip-api.com`,
/// `contact_enrich` → `http://apilayer.net` fallback; both upstreams gate HTTPS
/// behind a paid plan), so `https_only(true)` cannot be the unconditional default
/// without silently breaking them. When set, [`client_builder`] applies
/// `reqwest::ClientBuilder::https_only(true)`, refusing every non-TLS target and
/// redirect hop — defense-in-depth for deployments that have confirmed they don't
/// exercise the plaintext modules. The cross-host downgrade guard
/// ([`is_plaintext_downgrade`]) is always on regardless of this flag.
fn https_only_opt_in() -> bool {
    std::env::var("HUNTSMAN_HTTPS_ONLY")
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

/// Drop private/reserved IPs from a resolved address set — the SSRF DNS filter.
pub(super) fn filter_public(
    addrs: impl Iterator<Item = std::net::SocketAddr>,
) -> Vec<std::net::SocketAddr> {
    addrs
        .filter(|a| !crate::util::preflight::is_private_addr(a.ip()))
        .collect()
}

/// reqwest DNS resolver that refuses private/reserved addresses. This is the
/// TOCTOU-safe half of the SSRF defense for **hostname** targets: a discovered
/// hostname that resolves (via DNS rebinding, or an internal name like
/// `intranet`) to an RFC1918 / loopback / link-local / 169.254 metadata address
/// yields **no connectable address**, so the request fails instead of reaching
/// an internal service. reqwest connects only to the addresses returned here, so
/// there is no resolve-then-connect race. Delegates the actual lookup to the
/// system resolver (`getaddrinfo` via `tokio::net::lookup_host`) — no root,
/// Termux-ok.
///
/// IMPORTANT — scope: this resolver is invoked **only for hostnames**. An
/// IP-literal URL (`http://169.254.169.254/`, `http://127.0.0.1/`, `http://[::1]/`)
/// is connected directly by hyper-util *without* a DNS lookup, so it never
/// reaches this filter. IP-literal SSRF is therefore gated separately, before
/// dispatch, by the engine's target check (`core::engine::url_host_is_private` /
/// `util::preflight::should_skip_external_ip`) — not here. The redirect policy in
/// [`client_builder`] (`redirect_to_private_ip`) covers private-IP *redirect* hops.
struct SsrfResolver;

/// Build the rotating public-resolver set from `HUNTSMAN_DNS_RESOLVERS`
/// (`cloudflare`/`google`/`quad9`). Returns `None` when unset/empty, so the
/// resolver falls back to the system path and default behaviour is unchanged.
/// A resolver that fails to build is simply skipped — never a hard error.
fn build_rotating_resolvers() -> Option<Vec<hickory_resolver::TokioResolver>> {
    use hickory_resolver::{
        TokioResolver,
        config::{CLOUDFLARE, GOOGLE, LookupIpStrategy, QUAD9, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
    };
    let raw = std::env::var("HUNTSMAN_DNS_RESOLVERS").ok()?;
    let providers = crate::util::netrotate::parse_dns_providers(&raw);
    if providers.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for p in providers {
        let group = match p {
            "cloudflare" => &CLOUDFLARE,
            "google" => &GOOGLE,
            "quad9" => &QUAD9,
            _ => continue,
        };
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(group),
            TokioRuntimeProvider::default(),
        );
        {
            let opts = builder.options_mut();
            opts.timeout = std::time::Duration::from_secs(2);
            opts.attempts = 1;
            opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        }
        if let Ok(r) = builder.build() {
            out.push(r);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Lazily-built rotating resolvers (or `None` for the system resolver).
fn rotating_resolvers() -> Option<&'static Vec<hickory_resolver::TokioResolver>> {
    static RESOLVERS: OnceLock<Option<Vec<hickory_resolver::TokioResolver>>> = OnceLock::new();
    RESOLVERS.get_or_init(build_rotating_resolvers).as_ref()
}

impl reqwest::dns::Resolve for SsrfResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // Opt-in rotating public resolvers (HUNTSMAN_DNS_RESOLVERS): spread
            // lookups across providers, with the same private-IP SSRF filter.
            // Any resolver error degrades gracefully to the system resolver.
            if let Some(resolvers) = rotating_resolvers() {
                static IDX: AtomicUsize = AtomicUsize::new(0);
                let idx = IDX.fetch_add(1, Ordering::Relaxed) % resolvers.len();
                if let Ok(lookup) = resolvers[idx].lookup_ip(host.as_str()).await {
                    let public: Vec<SocketAddr> = lookup
                        .iter()
                        .filter(|ip| !crate::util::preflight::is_private_addr(*ip))
                        .map(|ip| SocketAddr::new(ip, 0))
                        .collect();
                    return Ok(Box::new(public.into_iter()) as reqwest::dns::Addrs);
                }
            }
            let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let public = filter_public(addrs);
            Ok(Box::new(public.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Shared reqwest configuration (SSRF-guarded DNS, redirect policy, timeouts,
/// pool, UA) used by both the plain and the trace-stamped client builders.
pub(super) fn client_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .dns_resolver(std::sync::Arc::new(SsrfResolver))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else if redirect_to_private_ip(attempt.url().host_str()) {
                // SSRF: a public URL 3xx-ing onto a private/metadata IP hop.
                attempt.stop()
            } else if attempt
                .previous()
                .last()
                .is_some_and(|prev| is_plaintext_downgrade(prev, attempt.url()))
            {
                // Defense-in-depth: refuse a cross-host plaintext (`http://`)
                // downgrade. On a flaky mobile link a MITM could rewrite the
                // `Location` to bounce us onto an attacker-controlled cleartext
                // host and tamper with the response. Same-host http→http hops and
                // http→https upgrades are still followed, so the plaintext-only
                // free-tier modules (ip_geo / contact_enrich) are unaffected.
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .connect_timeout(CONNECT_TIMEOUT)
        // Per-read inactivity backstop (NOT a total timeout — streaming bodies
        // are deliberately unbounded): a server that connects then stalls
        // mid-response can no longer hang an `await` forever. Generous (30 s) so
        // it never cuts a slow-but-progressing stream; complements the explicit
        // per-call `tokio::time::timeout`s on the budgeted fetch paths.
        .read_timeout(Duration::from_secs(30))
        // Pool sizing for the 130-module fan-out: many modules hammer a small
        // set of shared OSINT hosts (crt.sh, ip-api, hudsonrock, …), so the
        // dominant hosts benefit from keeping more warm keep-alive connections
        // rather than re-running a rustls handshake per request — handshakes cost
        // far more CPU/battery on a constrained Termux device than the few extra
        // idle sockets. 16 covers the username_search 32-way probe burst without
        // unbounded socket growth (the 90 s idle timeout reaps the rest).
        .pool_max_idle_per_host(16)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(15))
        // NOTE: HTTP/2 keep-alive / adaptive-window tuning is intentionally NOT
        // applied here. Those `ClientBuilder` methods (`http2_adaptive_window`,
        // `http2_keep_alive_interval`, `http2_keep_alive_while_idle`,
        // `http2_keep_alive_timeout`) are all `#[cfg(feature = "http2")]`-gated in
        // reqwest; the crate is built with `features = ["json", "rustls-tls",
        // "stream"]` (Cargo.toml) — no `http2` — so the methods do not exist on
        // `ClientBuilder` and calling them would be a hard compile error. Enabling
        // the feature pulls in the `h2` crate, a new transitive dependency absent
        // from the lock file. The reqwest dependency surface is deliberately
        // minimal and pinned for the Termux aarch64 target (see Cargo.toml's
        // reqwest comment block), so adding `h2` is a deliberate, on-device-
        // validated dependency decision that cannot be made from this file alone.
        // Until then, `tcp_keepalive` above plus the 30 s `read_timeout` bound a
        // stalled pooled connection.
        .user_agent(concat!(
            "huntsman-search-engine/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)"
        ));
    // Defense-in-depth opt-in: a blanket plaintext ban when the operator sets
    // `HUNTSMAN_HTTPS_ONLY`. Default off so the two free-tier plaintext modules
    // (ip_geo, contact_enrich) keep working; the always-on cross-host downgrade
    // guard in the redirect policy above already neutralises the MITM-redirect
    // case without it. Applied last so every other knob is set regardless.
    if https_only_opt_in() {
        builder.https_only(true)
    } else {
        builder
    }
}
