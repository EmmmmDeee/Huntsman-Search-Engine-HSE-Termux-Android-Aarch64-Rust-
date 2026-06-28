use super::*;

    // ── is_private_ip ──────────────────────────────────────────────────────

    #[test]
    fn private_v4_rejected() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "255.255.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "100.64.0.1", // CGNAT
            "100.127.255.255",
        ] {
            assert!(is_private_ip(ip), "expected {ip} private");
        }
    }

    #[test]
    fn public_v4_accepted() {
        for ip in ["1.1.1.1", "8.8.8.8", "203.0.113.5", "13.107.42.14"] {
            assert!(!is_private_ip(ip), "expected {ip} public");
        }
    }

    #[test]
    fn class_e_v4_rejected() {
        // 240.0.0.0/4 is reserved/non-routable — an SSRF target there must be
        // blocked, while genuine public space just below stays allowed.
        for ip in ["240.0.0.1", "250.1.2.3", "255.255.255.254"] {
            assert!(is_private_ip(ip), "expected {ip} private (Class E 240/4)");
        }
        // The public space just below the multicast/Class-E block stays allowed.
        assert!(!is_private_ip("223.255.255.255"), "223.x is public");
    }

    #[test]
    fn zero_network_v4_rejected() {
        // 0.0.0.0/8 ("this network", RFC 1122) is reserved/unroutable — not just
        // the single 0.0.0.0 caught by `is_unspecified`.
        for ip in ["0.0.0.0", "0.1.2.3", "0.255.255.255"] {
            assert!(is_private_ip(ip), "expected {ip} private (0.0.0.0/8)");
        }
    }

    #[test]
    fn private_v6_rejected() {
        for ip in ["::1", "::", "ff00::1", "fc00::1", "fd12::1", "fe80::1"] {
            assert!(is_private_ip(ip), "expected {ip} private");
        }
    }

    #[test]
    fn public_v6_accepted() {
        assert!(!is_private_ip("2606:4700:4700::1111"));
        assert!(!is_private_ip("2001:4860:4860::8888"));
    }

    #[test]
    fn ipv4_mapped_private_v6_rejected() {
        // IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is connected by the OS to the
        // underlying IPv4 address, so the v4 reserved ranges must apply.
        // Without canonicalisation these parse as V6, slip past every v6
        // check, and reach internal hosts — a classic SSRF-filter bypass.
        for ip in [
            "::ffff:127.0.0.1",       // loopback
            "::ffff:10.0.0.1",        // RFC1918
            "::ffff:192.168.1.1",     // RFC1918
            "::ffff:172.16.0.1",      // RFC1918
            "::ffff:169.254.169.254", // cloud-metadata
            "::ffff:100.64.0.1",      // CGNAT
            "::ffff:a9fe:a9fe",       // hex form of 169.254.169.254
        ] {
            assert!(is_private_ip(ip), "expected IPv4-mapped {ip} private");
        }
    }

    #[test]
    fn ipv4_mapped_public_v6_accepted() {
        // A mapped *public* address must still pass — canonicalisation only
        // reclassifies, it doesn't blanket-block the mapped range.
        assert!(!is_private_ip("::ffff:8.8.8.8"));
        assert!(!is_private_ip("::ffff:1.1.1.1"));
    }

    #[test]
    fn nat64_embedded_private_v4_rejected() {
        // Android cellular networks commonly run NAT64 (64:ff9b::/96); a host
        // resolving to a NAT64 address that embeds an internal v4 must be
        // refused (it routes to the embedded v4 on-device).
        for ip in [
            "64:ff9b::7f00:1",    // 127.0.0.1
            "64:ff9b::a00:1",     // 10.0.0.1
            "64:ff9b::c0a8:101",  // 192.168.1.1
            "64:ff9b::a9fe:a9fe", // 169.254.169.254 (cloud metadata)
            "64:ff9b::6440:1",    // 100.64.0.1 (CGNAT)
        ] {
            assert!(is_private_ip(ip), "expected NAT64 {ip} private");
        }
        // NAT64 wrapping a PUBLIC v4 resolves to that public host → allowed.
        assert!(
            !is_private_ip("64:ff9b::808:808"),
            "NAT64 8.8.8.8 is public"
        );
        assert!(
            !is_private_ip("64:ff9b::101:101"),
            "NAT64 1.1.1.1 is public"
        );
    }

    #[test]
    fn deprecated_site_local_v6_rejected() {
        // fec0::/10 (RFC 3879) is withdrawn but legacy gear still routes it as
        // internal space; the link-local mask (& 0xC0 == 0x80) does not cover
        // it, so these previously classified as public.
        for ip in ["fec0::1", "fec0::a:b", "feff:ffff::1"] {
            assert!(is_private_ip(ip), "expected site-local {ip} private");
        }
        // The boundary just below the site-local block: fe80::/10 (link-local)
        // is already private; fe00::/9 outside both masks stays unclassified.
        assert!(!is_private_ip("fe00::1"), "fe00::/9 is not site/link-local");
    }

    #[test]
    fn local_use_nat64_embedded_private_v4_rejected() {
        // RFC 8215 local-use NAT64 (64:ff9b:1::/48) exists precisely for
        // private-network NAT64; RFC 6052's /48 layout puts the v4 at octets
        // 6-7 and 9-10 (around the zero `u` octet). Embedded 127.0.0.1:
        // groups = 64:ff9b:1:7f00:0:100:: (0x7f00 | u=00,0x00 | 0x01,..).
        assert!(
            is_private_ip("64:ff9b:1:7f00:0:100::"),
            "local-use NAT64 embedding 127.0.0.1 must be refused"
        );
        // Embedded 169.254.169.254 → o6,7=0xa9fe; o9,10=0xa9,0xfe.
        assert!(
            is_private_ip("64:ff9b:1:a9fe:0:a9fe::"),
            "local-use NAT64 embedding cloud metadata must be refused"
        );
        // Embedded PUBLIC 8.8.8.8 → allowed (the gate judges the v4, it does
        // not blanket-ban the prefix).
        assert!(
            !is_private_ip("64:ff9b:1:808:0:808::"),
            "local-use NAT64 embedding a public v4 stays allowed"
        );
    }

    #[test]
    fn sixtofour_and_compat_embedded_private_v4_rejected() {
        // 6to4 (2002::/16) embeds the v4 in bits 16..48.
        assert!(is_private_ip("2002:7f00:1::"), "6to4 127.0.0.1");
        assert!(is_private_ip("2002:a9fe:a9fe::"), "6to4 169.254.169.254");
        assert!(!is_private_ip("2002:808:808::"), "6to4 8.8.8.8 is public");
        // Deprecated IPv4-compatible ::a.b.c.d.
        assert!(is_private_ip("::127.0.0.1"), "compat loopback");
        assert!(is_private_ip("::169.254.169.254"), "compat metadata");
    }

    #[test]
    fn teredo_embedded_private_v4_rejected() {
        // Teredo (2001:0000::/32, RFC 4380) carries TWO embedded v4s: the
        // plaintext server in octets 4..8 and the obfuscated client (XOR 0xff)
        // in the low 32 bits. Both are embedded-v4 SSRF vectors; both rejected.

        // Private SERVER, irrelevant client → server octets 4..8 = 127.0.0.1.
        assert!(
            is_private_ip("2001:0:7f00:1::"),
            "Teredo with internal server 127.0.0.1 must be refused"
        );
        // Public server 8.8.8.8, but obfuscated CLIENT decodes to 127.0.0.1
        // (80ff:fffe = !7f00:0001), isolating the client decode path.
        assert!(
            is_private_ip("2001:0:808:808::80ff:fffe"),
            "Teredo with internal client 127.0.0.1 must be refused"
        );
        // Public server AND public client (client a9fe… → not used here): a
        // Teredo wrapping only public v4s must still pass. Server 8.8.8.8,
        // client !0808:0808 = f7f7:f7f7 = 247.247.247.247 (public).
        assert!(
            !is_private_ip("2001:0:808:808::f7f7:f7f7"),
            "Teredo wrapping only public v4s stays allowed"
        );
    }

    #[test]
    fn isatap_embedded_private_v4_rejected() {
        // ISATAP modified-EUI-64 interface IDs (…:0:5efe:a.b.c.d, RFC 5214)
        // embed the v4 in the interface ID, so it routes for ANY prefix. The
        // prefix masks only catch the link-local case; a ULA/global prefix with
        // a 5efe interface ID embedding a private v4 was previously public.

        // Global (Google) prefix + ISATAP interface ID embedding cloud metadata.
        assert!(
            is_private_ip("2607:f8b0::5efe:a9fe:a9fe"),
            "global-prefix ISATAP embedding 169.254.169.254 must be refused"
        );
        // Global prefix + ISATAP embedding 127.0.0.1.
        assert!(
            is_private_ip("2607:f8b0::5efe:7f00:1"),
            "global-prefix ISATAP embedding 127.0.0.1 must be refused"
        );
        // Same global prefix, ISATAP embedding a PUBLIC v4 (8.8.8.8) → allowed:
        // the gate judges the embedded v4, it does not blanket-ban 5efe IDs, and
        // the bare global prefix itself is public.
        assert!(
            !is_private_ip("2607:f8b0::5efe:808:808"),
            "global-prefix ISATAP embedding a public v4 stays allowed"
        );
        // The bare global prefix without a 5efe interface ID stays public —
        // confirms the ISATAP decode (not the prefix) drove the rejections.
        assert!(
            !is_private_ip("2607:f8b0::1"),
            "bare global prefix is public"
        );
    }

    #[test]
    fn non_ip_strings_return_false() {
        assert!(!is_private_ip(""));
        assert!(!is_private_ip("not-an-ip"));
        assert!(!is_private_ip("999.999.999.999"));
    }

    // ── should_skip_external_ipv4 ───────────────────────────────────────

    #[test]
    fn should_skip_combines_empty_v6_and_private_cases() {
        // Empty / whitespace
        assert!(should_skip_external_ipv4(""));
        assert!(should_skip_external_ipv4("   "));
        // IPv6 (URL-fmt would break on IPv4-only APIs)
        assert!(should_skip_external_ipv4("::1"));
        assert!(should_skip_external_ipv4("2001:db8::1"));
        // Private v4
        assert!(should_skip_external_ipv4("10.0.0.1"));
        assert!(should_skip_external_ipv4("192.168.1.1"));
        assert!(should_skip_external_ipv4("127.0.0.1"));
        assert!(should_skip_external_ipv4("100.64.0.1")); // CGNAT
    }

    #[test]
    fn should_skip_lets_public_v4_through() {
        assert!(!should_skip_external_ipv4("1.1.1.1"));
        assert!(!should_skip_external_ipv4("8.8.8.8"));
        assert!(!should_skip_external_ipv4("13.107.42.14"));
    }

    // ── should_skip_external_ip (v6-tolerant universal gate) ──────────────

    #[test]
    fn should_skip_external_ip_rejects_empty_and_private() {
        assert!(should_skip_external_ip(""));
        assert!(should_skip_external_ip("  "));
        assert!(should_skip_external_ip("10.0.0.1"));
        assert!(should_skip_external_ip("192.168.1.1"));
        assert!(should_skip_external_ip("127.0.0.1"));
        assert!(should_skip_external_ip("::1"));
        assert!(should_skip_external_ip("fc00::1"));
        assert!(should_skip_external_ip("fe80::1"));
        // NAT64 embedding metadata is refused by the universal gate too.
        assert!(should_skip_external_ip("64:ff9b::a9fe:a9fe"));
    }

    #[test]
    fn should_skip_external_ip_lets_public_v6_through() {
        // Public IPv6 must NOT be rejected by the universal gate —
        // modules like shodan/censys/RDAP support v6 lookups.
        assert!(!should_skip_external_ip("2606:4700:4700::1111"));
        assert!(!should_skip_external_ip("2001:4860:4860::8888"));
    }

    #[test]
    fn should_skip_external_ip_lets_public_v4_through() {
        assert!(!should_skip_external_ip("1.1.1.1"));
        assert!(!should_skip_external_ip("8.8.8.8"));
    }

    // ── is_local_domain ────────────────────────────────────────────────────

    #[test]
    fn local_domains_rejected() {
        for d in [
            "localhost",
            "localhost.",
            "LOCALHOST",
            "router.local",
            "host.lan",
            "intra.internal",
            "device.home",
            "anything.arpa",
            "site.test",
            "x.invalid",
            "y.example",
            "z.localhost",
        ] {
            assert!(is_local_domain(d), "expected {d} local");
        }
    }

    #[test]
    fn public_domains_accepted() {
        for d in [
            "example.com",
            "google.com",
            "sub.target-company.com.au",
            "wikipedia.org",
        ] {
            assert!(!is_local_domain(d), "expected {d} public");
        }
    }

    // ── is_placeholder_username ───────────────────────────────────────────

    #[test]
    fn known_placeholders_rejected() {
        for u in [
            "admin",
            "Admin",
            "ADMIN",
            "test",
            "testing",
            "user",
            "anonymous",
            "anon",
            "demo",
            "guest",
            "root",
            "username",
            "default",
            "example",
            "null",
            "undefined",
            "none",
            "n/a",
            "na",
            "unknown",
            "tbd",
        ] {
            assert!(is_placeholder_username(u), "expected {u} placeholder");
        }
    }

    #[test]
    fn real_usernames_accepted() {
        for u in [
            "alice",
            "jordanleighmeyers",
            "j_doe23",
            "h4ck3r",
            "BobSmith",
        ] {
            assert!(!is_placeholder_username(u), "expected {u} real");
        }
    }

    // ── url_host_is_private ─────────────────────────────────────────────────

    #[test]
    fn url_host_is_private_rejects_internal_targets() {
        for u in [
            "http://127.0.0.1/admin",
            "http://10.0.0.5:8080/",
            "https://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/", // cloud metadata
            "http://[::1]/",                            // IPv6 loopback (bracketed)
            "http://[::ffff:169.254.169.254]/",         // IPv4-mapped metadata
            "http://localhost/",
            "https://printer.local/status",
            "http://db.internal:5432/",
        ] {
            assert!(url_host_is_private(u), "expected {u} guarded");
        }
    }

    #[test]
    fn url_host_is_private_allows_public_urls() {
        for u in [
            "https://example.com/path",
            "http://8.8.8.8/",
            "https://api.twitter.com/2/users",
            "https://[2606:4700:4700::1111]/",
            "not a url",
        ] {
            assert!(!url_host_is_private(u), "expected {u} allowed");
        }
    }
