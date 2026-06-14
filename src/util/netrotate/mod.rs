//! Network-egress rotation + the never-scan-infrastructure guard.
//!
//! Two operator-configured, **opt-in** rotations smooth out a deep/everything
//! scan so it neither floods a single egress path nor trips per-source rate
//! limits:
//!
//! * **Proxies** — `HUNTSMAN_SEARCH_PROXY` may be a comma-separated list
//!   (`socks5://127.0.0.1:9050, http://u:p@host:3128`); requests rotate through
//!   them round-robin (see [`select_proxy`]). A single value behaves exactly as
//!   before.
//! * **DNS resolvers** — `HUNTSMAN_DNS_RESOLVERS` is a comma list of the public
//!   providers `cloudflare`, `google`, `quad9`; lookups rotate across them (see
//!   `util::http`'s SSRF resolver), falling back to the system resolver.
//!
//! Crucially, the hosts/IPs these rotations run *through* must never become
//! scan **targets** — we route via them, we don't investigate them. The
//! never-scan guard ([`host_matches_infra`], surfaced as
//! `util::preflight::is_infrastructure_host`) rejects any target whose host/IP
//! matches a configured proxy or rotation resolver, at the same admission
//! boundary that already rejects placeholder/reserved hosts.

/// Public DNS providers eligible for resolver rotation, paired with the anycast
/// IPs they answer on. The IPs feed the never-scan guard so a configured
/// resolver can't be scanned; the provider name selects the hickory preset in
/// `util::http`.
pub const DNS_PROVIDER_IPS: &[(&str, &[&str])] = &[
    (
        "cloudflare",
        &[
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001",
        ],
    ),
    (
        "google",
        &[
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
        ],
    ),
    (
        "quad9",
        &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
    ),
];

/// Parse a comma-separated proxy list, trimming blanks. Pure.
#[must_use]
pub fn parse_proxy_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// Pick one proxy from `list` by rotating `counter` (round-robin). `None` when
/// the list is empty. Pure, so the rotation is unit-testable without globals.
#[must_use]
pub fn select_proxy(list: &[String], counter: usize) -> Option<String> {
    if list.is_empty() {
        return None;
    }
    Some(list[counter % list.len()].clone())
}

/// Parse `HUNTSMAN_DNS_RESOLVERS` into the recognised provider names, preserving
/// order and dropping unknown/blank entries. Pure.
#[must_use]
pub fn parse_dns_providers(raw: &str) -> Vec<&'static str> {
    raw.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter_map(|s| {
            DNS_PROVIDER_IPS
                .iter()
                .map(|(name, _)| *name)
                .find(|name| *name == s)
        })
        .collect()
}

/// Extract the bare host (no scheme, userinfo, or port) from a proxy spec such
/// as `socks5://user:pass@host:1080`, `http://host:3128`, or `host:1080`. Pure.
#[must_use]
pub fn proxy_host(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    // Strip scheme, then userinfo.
    let after_scheme = spec.split_once("://").map_or(spec, |(_, rest)| rest);
    let host_port = after_scheme
        .rsplit_once('@')
        .map_or(after_scheme, |(_, rest)| rest);
    // Bracketed IPv6 literal: [::1]:1080
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest.split_once(']').map(|(h, _)| h.to_ascii_lowercase());
    }
    // host:port or bare host — strip a trailing :port (a colon-only-once tail).
    let host = match host_port.rsplit_once(':') {
        // Only treat the tail as a port when the head still looks like a host
        // (avoids mangling a bare IPv6 literal, which has multiple colons).
        Some((h, _)) if !h.contains(':') => h,
        _ => host_port,
    };
    let host = host.trim_end_matches('/');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Normalise a host for comparison: lowercase, strip brackets and a trailing
/// dot. Pure.
fn norm_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Collect the hosts/IPs that are configured network infrastructure (proxies +
/// rotation DNS resolvers) and therefore must never be scanned. Reads the
/// environment, so impure — the matching itself ([`host_matches_infra`]) is
/// pure and tested.
#[must_use]
pub fn configured_infra_hosts() -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for var in ["HUNTSMAN_SEARCH_PROXY", "HUNTSMAN_PROXY"] {
        if let Ok(raw) = std::env::var(var) {
            for spec in parse_proxy_list(&raw) {
                if let Some(h) = proxy_host(&spec) {
                    hosts.push(h);
                }
            }
        }
    }
    if let Ok(raw) = std::env::var("HUNTSMAN_DNS_RESOLVERS") {
        for provider in parse_dns_providers(&raw) {
            if let Some((_, ips)) = DNS_PROVIDER_IPS.iter().find(|(n, _)| *n == provider) {
                hosts.extend(ips.iter().map(|ip| norm_host(ip)));
            }
        }
    }
    hosts
}

/// True if `host` is one of the configured infrastructure hosts/IPs. Pure over
/// its inputs (case-insensitive, bracket/dot-tolerant), so callers test it by
/// passing a fixed `infra` set rather than mutating the environment.
#[must_use]
pub fn host_matches_infra(host: &str, infra: &[String]) -> bool {
    if infra.is_empty() {
        return false;
    }
    let h = norm_host(host);
    infra.iter().any(|i| norm_host(i) == h)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
