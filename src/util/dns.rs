use std::sync::OnceLock;

use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};

/// The process-wide DNS resolver — a lazily-initialised, Cloudflare-backed
/// [`TokioResolver`] shared by every DNS-issuing module (`dns_intel`, `geo_intel`,
/// the DNSBL checks, …) so they reuse one connection pool and cache instead of
/// each standing up its own.
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

/// Decode DNS presentation-format escapes in a label: `\DDD` (a decimal byte) or
/// `\X` (the literal char `X`, covering the common `\.` and `\\`). A trailing
/// lone `\` is dropped. Per RFC 1035 §3.3.13. **Pure**.
pub fn unescape_dns_label(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // `\DDD` decimal escape (exactly three digits, ≤ 255).
        if i + 3 < bytes.len()
            && bytes[i + 1..i + 4].iter().all(u8::is_ascii_digit)
            && let Ok(n) = std::str::from_utf8(&bytes[i + 1..i + 4])
                .unwrap_or("")
                .parse::<u16>()
            && n <= 255
        {
            out.push(n as u8);
            i += 4;
        } else if i + 1 < bytes.len() {
            out.push(bytes[i + 1]); // `\X` → literal X (e.g. `\.` → `.`)
            i += 2;
        } else {
            i += 1; // trailing lone backslash — drop it
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// SOA RNAME field is encoded as `local-part.domain` (no `@` allowed in DNS
/// labels), with any literal `.` in the local part backslash-escaped (RFC 1035
/// §8). Decode by splitting on the first *unescaped* `.` into `@`, then
/// **unescaping** the local part so `hostmaster\.ops.example.com` becomes
/// `hostmaster.ops@example.com`. A wire-format trailing dot on the domain
/// (`hostmaster.example.com.`) is stripped. Returns an empty string when the
/// input doesn't look like an email. **Pure**.
pub fn soa_rname_to_email(rname: &str) -> String {
    if rname.is_empty() || !rname.contains('.') {
        return String::new();
    }
    let bytes = rname.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'.' {
            let (local, rest) = rname.split_at(i);
            // Strip a wire-format trailing dot on the FQDN so a directly-passed
            // `hostmaster.example.com.` decodes the same as the pre-trimmed form.
            let domain = rest[1..].trim_end_matches('.');
            if local.is_empty() || domain.is_empty() {
                return String::new();
            }
            return format!("{}@{domain}", unescape_dns_label(local));
        }
        i += 1;
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::{soa_rname_to_email, unescape_dns_label};

    #[test]
    fn soa_rname_standard_and_subdomain() {
        assert_eq!(
            soa_rname_to_email("hostmaster.example.com"),
            "hostmaster@example.com"
        );
        assert_eq!(
            soa_rname_to_email("admin.sub.example.org"),
            "admin@sub.example.org"
        );
    }

    #[test]
    fn soa_rname_strips_wire_format_trailing_dot() {
        // A directly-passed FQDN with the wire-format trailing dot decodes the
        // same as the pre-trimmed form (the two callers previously disagreed).
        assert_eq!(
            soa_rname_to_email("hostmaster.example.com."),
            "hostmaster@example.com"
        );
    }

    #[test]
    fn soa_rname_unescapes_dotted_local_part() {
        assert_eq!(
            soa_rname_to_email(r"hostmaster\.ops.example.com"),
            "hostmaster.ops@example.com"
        );
        // `\DDD` decimal escape (46 = '.') decodes identically.
        assert_eq!(
            soa_rname_to_email(r"first\046last.example.org"),
            "first.last@example.org"
        );
    }

    #[test]
    fn soa_rname_rejects_non_email_input() {
        assert_eq!(soa_rname_to_email(""), "");
        assert_eq!(soa_rname_to_email("notanemail"), "");
    }

    #[test]
    fn unescape_dns_label_handles_literal_and_decimal_escapes() {
        assert_eq!(unescape_dns_label(r"a\.b"), "a.b");
        assert_eq!(unescape_dns_label(r"a\\b"), r"a\b");
        assert_eq!(unescape_dns_label(r"x\046y"), "x.y"); // \046 = '.'
        assert_eq!(unescape_dns_label("plain"), "plain");
        assert_eq!(unescape_dns_label(r"trailing\"), "trailing"); // lone backslash dropped
    }
}
