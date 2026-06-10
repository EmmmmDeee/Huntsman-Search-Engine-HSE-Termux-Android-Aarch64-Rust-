/// The bare host substring of a URL-ish string: strip a leading `http(s)://`
/// scheme (case-insensitively — `HTTPS://` is valid per RFC 3986 §3.1), then
/// everything from the first `/` (path) and `:` (port). Borrows; applies
/// **no** case-folding or validity policy on the host itself — callers layer
/// that on (see [`host_from_url`]). A plain host or `host:port` passes through
/// as its host. Returns `""` when nothing host-like remains.
///
/// A **bracketed IPv6 literal** (`[2606:4700::1]:443`) is returned intact
/// **with** its brackets (matching `Url::host_str`): the colons inside the
/// brackets are part of the address, not the `:port` separator, so the naive
/// "split on the first colon" would otherwise truncate it to `[2606`.
#[must_use]
pub fn host_only(s: &str) -> &str {
    let trimmed = s.trim();
    let after_scheme = ["https://", "http://"]
        .iter()
        .find_map(|scheme| {
            trimmed
                .get(..scheme.len())
                .filter(|p| p.eq_ignore_ascii_case(scheme))
                .map(|_| &trimmed[scheme.len()..])
        })
        .unwrap_or(trimmed);
    let authority = after_scheme.split('/').next().unwrap_or("");
    // Bracketed IPv6 literal: the host is the whole `[...]`; its inner colons
    // are not a port delimiter. Return it (brackets included) before the
    // port split below would cut it at the first colon.
    if let Some(after_open) = authority.strip_prefix('[')
        && let Some(close) = after_open.find(']')
    {
        // `close` indexes into `after_open` (one past the `[`), so the `]`
        // sits at `close + 1` in `authority`; include it.
        return &authority[..close + 2];
    }
    authority.split(':').next().unwrap_or("")
}

/// The lowercased host of a URL, or `None` unless it looks like a real domain
/// (non-empty and contains a `.`). Built on [`host_only`].
#[must_use]
pub fn host_from_url(url: &str) -> Option<String> {
    let host = host_only(url).to_lowercase();
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::{host_from_url, host_only};

    #[test]
    fn host_only_strips_scheme_path_and_port() {
        assert_eq!(host_only("https://Example.com:8443/a/b?x=1"), "Example.com");
        assert_eq!(host_only("http://host.org/"), "host.org");
        assert_eq!(host_only("  bare.host:25 "), "bare.host");
        assert_eq!(host_only("plainhost"), "plainhost");
        assert_eq!(host_only(""), "");
        // Scheme match is case-insensitive (RFC 3986 §3.1)...
        assert_eq!(host_only("HTTPS://Up.Example.com/p"), "Up.Example.com");
        assert_eq!(host_only("HtTp://x.test"), "x.test");
        // ...but the host slice itself is returned verbatim (no case-folding).
        assert_eq!(host_only("https://MixedCase.Net"), "MixedCase.Net");
    }

    #[test]
    fn host_only_keeps_bracketed_ipv6_literal_intact() {
        // The colons inside the brackets are part of the address, not a
        // `:port` delimiter — the host must not be truncated at the first.
        assert_eq!(
            host_only("https://[2606:4700:4700::1111]:443/dns-query"),
            "[2606:4700:4700::1111]"
        );
        assert_eq!(host_only("http://[::1]/admin"), "[::1]");
        assert_eq!(host_only("[fe80::1]:8080"), "[fe80::1]");
        // No port after the literal.
        assert_eq!(host_only("https://[2001:db8::1]/"), "[2001:db8::1]");
    }

    #[test]
    fn host_from_url_lowercases_and_requires_a_dot() {
        assert_eq!(
            host_from_url("https://Sub.Example.COM/p"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(host_from_url("http://localhost:8080"), None); // no dot
        assert_eq!(host_from_url(""), None);
    }
}
