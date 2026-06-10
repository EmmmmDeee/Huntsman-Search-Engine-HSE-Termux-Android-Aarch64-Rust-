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
}

/// Iterate the `ip4:`/`ip6:`/`include:`/`redirect=` members of an SPF record.
/// Bare/blank IP mechanisms and empty/dotless or macro-bearing
/// include/redirect domains are skipped (they would only normalise to junk
/// entities). Other mechanisms (`a`, `mx`, `ptr`, `exists`, `all`, the `exp=`
/// modifier) and qualifier prefixes are not interpreted here — callers tag the
/// domain itself.
pub fn members(txt: &str) -> impl Iterator<Item = Member<'_>> {
    // A usable include/redirect target is non-empty, dotted, and free of SPF
    // macros (`%{…}`) which don't resolve to a literal domain.
    fn usable_domain(d: &str) -> bool {
        d.contains('.') && !d.contains('%')
    }
    txt.split_whitespace().filter_map(|part| {
        // A *mechanism* (ip4/ip6/include) may carry an optional leading
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
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{Member, is_spf, members};

    #[test]
    fn is_spf_is_case_insensitive_on_the_version_tag() {
        assert!(is_spf("v=spf1 -all"));
        assert!(is_spf("V=SPF1 ip4:1.2.3.4 -all")); // RFC 7208 §4.5
        assert!(!is_spf("v=dmarc1"));
        assert!(!is_spf("spf1"));
        assert!(!is_spf(""));
    }

    #[test]
    fn members_yields_ip4_ip6_and_includes_skipping_junk() {
        let got: Vec<Member> = members(
            "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.example.com \
             ip4: ip6: include: include:localhost a mx -all",
        )
        .collect();
        assert_eq!(
            got,
            vec![
                Member::Ip("198.51.100.0"),
                Member::Ip("2001:db8::"), // IPv6 colons preserved, CIDR stripped
                Member::Include("_spf.example.com"),
                // bare ip4:/ip6:/include: and dotless include:localhost dropped;
                // a/mx/-all are not IP/include members.
            ]
        );
    }

    #[test]
    fn members_strip_mechanism_qualifiers() {
        // Mechanisms can carry a qualifier (`+`/`-`/`~`/`?`, RFC 7208 §4.6.1).
        // Each qualified ip4/ip6/include must still be surfaced.
        let got: Vec<Member> = members(
            "v=spf1 +ip4:198.51.100.1 -ip6:2001:db8::1 ~include:_spf.a.test \
             ?include:_spf.b.test -all",
        )
        .collect();
        assert_eq!(
            got,
            vec![
                Member::Ip("198.51.100.1"),
                Member::Ip("2001:db8::1"),
                Member::Include("_spf.a.test"),
                Member::Include("_spf.b.test"),
            ]
        );
    }

    #[test]
    fn members_yields_redirect_target_and_skips_macros() {
        let got: Vec<Member> =
            members("v=spf1 redirect=_spf.example.net include:%{i}._spf.macro.test").collect();
        // The redirect target is surfaced; the macro-bearing include is skipped
        // (a `%{…}` member is not a literal domain).
        assert_eq!(got, vec![Member::Redirect("_spf.example.net")]);
        // A dotless / empty redirect is dropped like a dotless include.
        assert!(
            members("v=spf1 redirect= redirect=localhost")
                .next()
                .is_none()
        );
    }
}
