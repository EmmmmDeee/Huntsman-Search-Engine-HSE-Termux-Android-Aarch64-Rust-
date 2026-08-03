
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
    fn host_only_cuts_a_query_or_fragment_with_no_path_slash() {
        // Regression: the authority component ends at the first `/`, `?` OR `#`
        // (RFC 3986 §3.2). Splitting on `/` alone only *appears* to handle a
        // query because the common shape carries a path slash first
        // (`…/a/b?x=1`, covered above). With an EMPTY path — a legal and
        // commonplace shape for a bio/profile link (`https://site.com?utm=x`,
        // `https://site.com#about`) — nothing cut the query/fragment and the
        // whole `example.com?x=1` was returned AS the host, then minted as a
        // malformed `Domain` entity by every caller that trusts this helper.
        assert_eq!(host_only("https://example.com?x=1"), "example.com");
        assert_eq!(host_only("https://example.com#frag"), "example.com");
        assert_eq!(host_only("https://example.com:8443?x=1"), "example.com");
        // A query containing a slash must still cut at the `?`, not the `/`.
        assert_eq!(host_only("https://example.com?next=/a/b"), "example.com");
        // Scheme-less forms take the same path.
        assert_eq!(host_only("example.com?x=1"), "example.com");
        // The IPv6 literal branch stays intact alongside a query.
        assert_eq!(host_only("https://[2001:db8::1]?x=1"), "[2001:db8::1]");
    }

    #[test]
    fn host_from_url_strips_a_query_or_fragment_from_the_host() {
        // The end-to-end consequence: without the cut, this yielded
        // `Some("example.com?x=1")` — a domain entity that is not a domain.
        assert_eq!(
            host_from_url("https://Example.com?utm_source=x"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_from_url("https://Example.com#section"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn host_only_path_without_scheme() {
        // No scheme: the whole string is treated as host/authority + path.
        assert_eq!(host_only("example.com/some/path"), "example.com");
        assert_eq!(host_only("example.com:8080/path"), "example.com");
    }

    #[test]
    fn host_from_url_dotted_ip_returns_some() {
        assert_eq!(
            host_from_url("http://1.2.3.4/path"),
            Some("1.2.3.4".to_string())
        );
        assert_eq!(
            host_from_url("https://192.0.2.1"),
            Some("192.0.2.1".to_string())
        );
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
