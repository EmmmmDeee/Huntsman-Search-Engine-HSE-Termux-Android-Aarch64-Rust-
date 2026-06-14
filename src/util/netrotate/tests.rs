use super::*;

    #[test]
    fn parse_proxy_list_trims_and_drops_blanks() {
        assert_eq!(
            parse_proxy_list(" socks5://a:1 , , http://b:2 "),
            vec!["socks5://a:1".to_string(), "http://b:2".to_string()]
        );
        assert!(parse_proxy_list("").is_empty());
        assert!(parse_proxy_list("  ,  ").is_empty());
    }

    #[test]
    fn select_proxy_rotates_round_robin() {
        let list = parse_proxy_list("p0,p1,p2");
        assert_eq!(select_proxy(&list, 0).as_deref(), Some("p0"));
        assert_eq!(select_proxy(&list, 1).as_deref(), Some("p1"));
        assert_eq!(select_proxy(&list, 2).as_deref(), Some("p2"));
        assert_eq!(select_proxy(&list, 3).as_deref(), Some("p0"), "wraps");
        assert_eq!(select_proxy(&[], 0), None);
        // Single entry behaves like the old single-proxy path.
        assert_eq!(
            select_proxy(&parse_proxy_list("only"), 99).as_deref(),
            Some("only")
        );
    }

    #[test]
    fn parse_dns_providers_filters_to_known() {
        assert_eq!(
            parse_dns_providers("cloudflare, GOOGLE, nope, quad9"),
            vec!["cloudflare", "google", "quad9"]
        );
        assert!(parse_dns_providers("bogus,").is_empty());
    }

    #[test]
    fn proxy_host_extracts_bare_host() {
        assert_eq!(
            proxy_host("socks5://127.0.0.1:9050").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            proxy_host("http://user:pass@proxy.example:3128").as_deref(),
            Some("proxy.example")
        );
        assert_eq!(proxy_host("host:1080").as_deref(), Some("host"));
        assert_eq!(proxy_host("barehost").as_deref(), Some("barehost"));
        assert_eq!(
            proxy_host("[2001:db8::1]:1080").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(proxy_host("   "), None);
    }

    #[test]
    fn host_matches_infra_is_case_and_dot_insensitive() {
        let infra = vec!["proxy.example".to_string(), "1.1.1.1".to_string()];
        assert!(host_matches_infra("PROXY.example.", &infra));
        assert!(host_matches_infra("1.1.1.1", &infra));
        assert!(!host_matches_infra("other.example", &infra));
        // No configured infra ⇒ never matches (default behaviour unchanged).
        assert!(!host_matches_infra("proxy.example", &[]));
    }

    #[test]
    fn dns_resolver_ips_are_flagged_as_infra() {
        // A configured rotation resolver's anycast IP must be unscannable.
        let infra: Vec<String> = DNS_PROVIDER_IPS
            .iter()
            .find(|(n, _)| *n == "cloudflare")
            .unwrap()
            .1
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(host_matches_infra("1.1.1.1", &infra));
    }
