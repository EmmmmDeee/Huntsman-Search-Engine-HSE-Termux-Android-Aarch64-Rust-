//! Minimal SPF (RFC 7208) mechanism extraction, shared by the DNS modules so
//! `dns_intel` and `doh_resolver` can't drift in what they pull out of a
//! `v=spf1` record (they had: one case-sensitive version check, one
//! case-insensitive; both silently dropping `ip6:`).

/// True if `txt` is an SPF record. Per RFC 7208 §4.5 the `v=spf1` version
/// tag is matched case-insensitively.
#[must_use]
pub fn is_spf(txt: &str) -> bool {
    let b = txt.as_bytes();
    b.len() >= 6 && b[..6].eq_ignore_ascii_case(b"v=spf1")
}

/// An authorising member of an SPF record that resolves to an entity.
#[derive(Debug, PartialEq, Eq)]
pub enum Member<'a> {
    /// An `ip4:` / `ip6:` address with any CIDR suffix stripped — never empty.
    Ip(&'a str),
    /// An `include:` domain — guaranteed non-empty and dotted.
    Include(&'a str),
    /// The `redirect=` modifier's target domain — guaranteed non-empty and
    /// dotted. Delegates the whole SPF policy to another domain (RFC 7208 §6),
    /// so for OSINT it is a related-domain pivot just like an `include:`.
    Redirect(&'a str),
    /// An `a:domain` mechanism target — whose A records authorise sending.
    /// Bare `a` (no colon) is skipped; only explicit cross-domain references
    /// are surfaced as new OSINT pivots.
    A(&'a str),
    /// An `mx:domain` mechanism target — whose MX records authorise sending.
    /// Bare `mx` (no colon) is skipped for the same reason as bare `a`.
    Mx(&'a str),
}

/// Iterate the `ip4:`/`ip6:`/`include:`/`redirect=`/`a:`/`mx:` members of an
/// SPF record. Bare/blank IP mechanisms and empty/dotless or macro-bearing
/// domain targets are skipped (they would only normalise to junk entities).
/// Bare `a` and `mx` (no explicit domain target), `ptr`, `exists`, `all`, and
/// the `exp=` modifier are not interpreted — callers tag the domain itself.
pub fn members(txt: &str) -> impl Iterator<Item = Member<'_>> {
    // A usable include/redirect/a/mx target is non-empty, dotted, and free of
    // SPF macros (`%{…}`) which don't resolve to a literal domain.
    fn usable_domain(d: &str) -> bool {
        d.contains('.') && !d.contains('%')
    }
    txt.split_whitespace().filter_map(|part| {
        // A *mechanism* (ip4/ip6/include/a/mx) may carry an optional leading
        // qualifier — `+`/`-`/`~`/`?` (RFC 7208 §4.6.1) — e.g. `-ip4:…` or
        // `?include:…`. Strip it before matching, or a qualified member is
        // silently dropped. A *modifier* (`redirect=`) takes no qualifier, so
        // it is matched on the original token.
        let mech = part.strip_prefix(['+', '-', '~', '?']).unwrap_or(part);
        if let Some(ip) = mech
            .strip_prefix("ip4:")
            .or_else(|| mech.strip_prefix("ip6:"))
        {
            let ip = ip.split('/').next().unwrap_or(ip);
            (!ip.is_empty()).then_some(Member::Ip(ip))
        } else if let Some(inc) = mech.strip_prefix("include:") {
            usable_domain(inc).then_some(Member::Include(inc))
        } else if let Some(red) = part.strip_prefix("redirect=") {
            usable_domain(red).then_some(Member::Redirect(red))
        } else if let Some(a_dom) = mech.strip_prefix("a:") {
            usable_domain(a_dom).then_some(Member::A(a_dom))
        } else if let Some(mx_dom) = mech.strip_prefix("mx:") {
            usable_domain(mx_dom).then_some(Member::Mx(mx_dom))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
