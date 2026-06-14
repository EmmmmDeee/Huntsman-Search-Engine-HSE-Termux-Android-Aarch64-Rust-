use super::*;

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
