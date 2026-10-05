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

/// Hops the shared client will follow before giving up on a redirect chain.
pub(super) const MAX_REDIRECT_HOPS: usize = 10;

/// What the shared client's redirect policy decides for one 3xx hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RedirectVerdict {
    /// Follow the hop.
    Follow,
    /// Refuse the hop. reqwest hands the caller the 3xx response itself, so the
    /// refusal is visible rather than silently mistaken for the final answer.
    Stop,
    /// The chain is longer than [`MAX_REDIRECT_HOPS`] — surface a request error.
    TooManyHops,
}

/// True if `next` is the *same site* as `origin` — the boundary a credential
/// may be replayed across.
///
/// "Site" is the registrable domain (eTLD+1) via the codebase's own
/// [`crate::util::domains::registrable_domain`] authority, not the bare host.
/// Host equality is too strict to ship: measured against ten real sites HSE
/// fetches, five reach their content only through a cross-*host* redirect
/// (`reddit.com` → `www.reddit.com`, `wikipedia.org` → `en.wikipedia.org`,
/// and the apex → `www` hop of nytimes/bbc/amazon). Refusing those would break
/// ordinary un-credentialed fetching of much of the web to close a hole that
/// only exists for credentialed requests.
///
/// The registrable domain is the right boundary because it is the unit of
/// registration: every host under it answers to the same registrant — the party
/// that issued the key in the first place. A hop off it reaches a different
/// registrant, which is exactly the leak.
///
/// IP literals are compared exactly, never by registrable domain:
/// `registrable_domain` is a name-oriented helper, and its last-two-labels rule
/// would read the unrelated public addresses `93.184.216.34` and `8.8.216.34` as
/// the same "site" (`216.34`). Total and fail-closed: a pair that is not two
/// domains or two same-family IPs is not the same site.
fn same_site(origin: &url::Url, next: &url::Url) -> bool {
    use crate::util::domains::registrable_domain;
    match (origin.host(), next.host()) {
        (Some(url::Host::Domain(a)), Some(url::Host::Domain(b))) => {
            if a.eq_ignore_ascii_case(b) {
                return true;
            }
            match (registrable_domain(a), registrable_domain(b)) {
                (Some(x), Some(y)) => x == y,
                _ => false,
            }
        }
        (Some(url::Host::Ipv4(a)), Some(url::Host::Ipv4(b))) => a == b,
        (Some(url::Host::Ipv6(a)), Some(url::Host::Ipv6(b))) => a == b,
        _ => false,
    }
}

/// Decide a single redirect hop for the shared client.
///
/// `previous` is the chain already requested — `previous[0]` is the ORIGINAL
/// request, the one whose headers the caller chose; `next` is where this hop
/// wants to go. Extracted from the policy closure in [`client_builder`] because
/// the closure itself cannot be exercised end-to-end: every loopback test server
/// is refused by the private-IP arm below before the credential arms are ever
/// reached, so a client-level test of those arms would pass on a build that had
/// them removed. Judged here, against ordinary public URLs, the arms are real.
///
/// Three invariants. The first is the pre-existing SSRF guard; the other two are
/// about where a credential may be replayed. reqwest copies the original
/// request's headers onto every followed hop, and while it strips the four
/// headers it knows to be sensitive (`Authorization`, `Cookie`,
/// `Proxy-Authorization`, `WWW-Authenticate`) when a hop leaves the host, HSE's
/// providers authenticate with names reqwest has never heard of — `x-api-key`,
/// `hibp-api-key`, `Dehashed-Api-Key`, `X-RapidAPI-Key`, `Auth-Key`, and a dozen
/// more. Those replay verbatim, so a hop to a destination the caller did not
/// choose hands a live provider key to whoever answers:
///
/// * **No private-IP hop.** [`redirect_to_private_ip`] — a public URL must not
///   3xx us onto an internal address.
/// * **Same site.** A 3xx off the original request's registrable domain is
///   refused — see [`same_site`] for why the boundary is the site and not the
///   host. Judged against the original request rather than the immediately
///   preceding hop, so an intermediate same-site hop cannot launder a later one.
/// * **No transport downgrade.** An `https` → `http` hop is refused even within
///   the site: it would put the same key on the wire in plaintext for any
///   on-path observer. (`http` → `https` is an upgrade and is allowed.)
///
/// A module that genuinely needs a second site issues its own request, with its
/// own deliberate header scope.
pub(super) fn redirect_verdict(previous: &[url::Url], next: &url::Url) -> RedirectVerdict {
    if previous.len() >= MAX_REDIRECT_HOPS {
        return RedirectVerdict::TooManyHops;
    }
    if redirect_to_private_ip(next.host_str()) {
        return RedirectVerdict::Stop;
    }
    let Some(origin) = previous.first() else {
        // Not a redirect at all (no prior hop) — nothing to compare against.
        return RedirectVerdict::Follow;
    };
    if !same_site(origin, next) {
        return RedirectVerdict::Stop;
    }
    if origin.scheme() == "https" && next.scheme() != "https" {
        return RedirectVerdict::Stop;
    }
    RedirectVerdict::Follow
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
    // Surface misspelled/unknown provider names instead of silently dropping
    // them — a typo (`clouflare`) would otherwise leave the operator believing
    // egress DNS is pinned to a public resolver. The valid set is derived from
    // the same DNS_PROVIDER_IPS authority (never hard-coded), and the fallback
    // clause fires only when NO recognised provider remains — if some do, they
    // still rotate and no system-resolver fallback occurs.
    let unknown = crate::util::netrotate::unknown_dns_providers(&raw);
    if !unknown.is_empty() {
        let valid = crate::util::netrotate::DNS_PROVIDER_IPS
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ");
        if providers.is_empty() {
            tracing::warn!(
                unknown = ?unknown, valid = %valid,
                "HUNTSMAN_DNS_RESOLVERS names only unrecognised provider(s); none remain, so \
                 egress DNS falls back to the system resolver — check spelling"
            );
        } else {
            tracing::warn!(
                unknown = ?unknown, valid = %valid,
                "HUNTSMAN_DNS_RESOLVERS names unrecognised provider(s), which are ignored; the \
                 recognised ones still rotate — check spelling"
            );
        }
    }
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

/// Resolve `host` to its public addresses, trying the operator's rotating
/// resolver set first when configured (`HUNTSMAN_DNS_RESOLVERS`) and falling
/// back to the system resolver — on an outright rotating-resolver error, or
/// whenever no override is configured at all. Any resolver error degrades
/// gracefully to the system resolver; a rotating-resolver lookup that
/// *succeeds* but yields only private/reserved addresses is trusted as final
/// (not retried against the system resolver), matching the SSRF filter's
/// refuse-don't-retry posture.
///
/// `pub(crate)` so the curl-fallback SSRF pin (`util::curl::ssrf_resolve_pin`)
/// shares this exact resolution strategy instead of being hard-wired to the
/// system resolver alone — the same class of DNS-reachability gap the
/// paid-API [`crate::util::curl_client`] transport already self-heals (there,
/// via curl's own `--doh-url` retry on a bare "could not resolve host").
pub(crate) async fn resolve_public_ips(host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
    if let Some(resolvers) = rotating_resolvers() {
        static IDX: AtomicUsize = AtomicUsize::new(0);
        let idx = IDX.fetch_add(1, Ordering::Relaxed) % resolvers.len();
        if let Ok(lookup) = resolvers[idx].lookup_ip(host).await {
            let public: Vec<std::net::IpAddr> = lookup
                .iter()
                .filter(|ip| !crate::util::preflight::is_private_addr(*ip))
                .collect();
            return Ok(public);
        }
    }
    let addrs = tokio::net::lookup_host((host, 0)).await?;
    Ok(filter_public(addrs).into_iter().map(|a| a.ip()).collect())
}

impl reqwest::dns::Resolve for SsrfResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let public = resolve_public_ips(&host).await?;
            let addrs: Vec<SocketAddr> = public
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Shared reqwest configuration (SSRF-guarded DNS, redirect policy, timeouts,
/// pool, UA) used by both the plain and the trace-stamped client builders.
pub(super) fn client_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .dns_resolver(std::sync::Arc::new(SsrfResolver))
        // Never honor an ambient `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`: reqwest's
        // default would route through it and let the PROXY perform DNS resolution,
        // silently bypassing the `SsrfResolver` private-IP filter installed above.
        // The engine's own egress control is `HUNTSMAN_SEARCH_PROXY` via the vetted
        // curl pool, not this guarded reqwest path — so an ambient proxy env must
        // never neutralize the SSRF DNS guard here.
        .no_proxy()
        // Every arm of this decision lives in `redirect_verdict`, which is where
        // it is tested; this closure only translates the verdict into reqwest's
        // vocabulary, so there is no second copy of the policy to drift.
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            match redirect_verdict(attempt.previous(), attempt.url()) {
                RedirectVerdict::Follow => attempt.follow(),
                RedirectVerdict::Stop => attempt.stop(),
                RedirectVerdict::TooManyHops => attempt.error("too many redirects"),
            }
        }))
        .connect_timeout(CONNECT_TIMEOUT)
        // Advertise + transparently decompress gzip on every fetch. reqwest adds
        // `Accept-Encoding: gzip`, decodes the body, and strips the encoding
        // headers, so callers see identical decompressed bytes while the wire
        // transfer for a provider's JSON shrinks ~4× — a data-cost/latency win on
        // a metered Termux link across the whole free + intel-API cluster (the
        // curl paid-API transport gets the same via `--compressed`). Safe against
        // a decompression bomb: `read_json_text`/`read_text` stream the
        // DECOMPRESSED body and error past `JSON_BODY_CAP` (32 MiB), so the cap
        // bounds the EXPANDED size here — unlike curl's `--max-filesize`, which
        // is why compression is enabled unconditionally on this path but only for
        // trusted hosts on the curl path.
        .gzip(true)
        // Capture the peer's leaf certificate (DER) into each response's type-map
        // extensions so a TLS-aware module can read it back via
        // `reqwest::tls::TlsInfo`. `cert_intel`'s live-TLS probe is the sole
        // consumer; without this switch the capture is never enabled, so its
        // whole certificate-parsing leg was dead code that still minted an
        // EXPERT "TLS certificate" finding having examined no certificate at all
        // (REQ-CERTINTEL-001). Cost: the ~1–4 KB leaf DER is retained on a
        // response for its lifetime and dropped with it — negligible on this
        // tool's request volume.
        .tls_info(true)
        // Per-read inactivity backstop (NOT a total timeout — streaming bodies
        // are deliberately unbounded): a server that connects then stalls
        // mid-response can no longer hang an `await` forever. Generous (30 s) so
        // it never cuts a slow-but-progressing stream; complements the explicit
        // per-call `tokio::time::timeout`s on the budgeted fetch paths.
        .read_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(5)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(15))
        .user_agent(concat!(
            "huntsman-search-engine/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)"
        ));
    // Extra trust roots from `SSL_CERT_FILE` — additive to the built-in webpki
    // roots; empty unless the operator set it, loud if set but unusable. Lets
    // this guarded client work behind a TLS-inspecting proxy (see `super::trust`).
    super::trust::extra_root_certs()
        .iter()
        .cloned()
        .fold(builder, reqwest::ClientBuilder::add_root_certificate)
}
