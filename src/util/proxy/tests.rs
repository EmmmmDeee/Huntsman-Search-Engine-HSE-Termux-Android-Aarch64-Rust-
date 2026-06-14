use super::*;

    #[test]
    fn proxy_pool_round_robin() {
        let pool = ProxyPool::new();
        pool.replace(vec![
            Proxy {
                addr: "1.2.3.4:8080".into(),
                proto: "http",
                latency_ms: 100,
            },
            Proxy {
                addr: "5.6.7.8:3128".into(),
                proto: "http",
                latency_ms: 200,
            },
        ]);
        assert_eq!(pool.count(), 2);
        let a = pool.next().unwrap();
        let b = pool.next().unwrap();
        let c = pool.next().unwrap();
        assert_eq!(a.addr, "1.2.3.4:8080");
        assert_eq!(b.addr, "5.6.7.8:3128");
        assert_eq!(c.addr, "1.2.3.4:8080"); // wraps around
    }

    #[test]
    fn proxy_url_format() {
        let p = Proxy {
            addr: "1.2.3.4:8080".into(),
            proto: "http",
            latency_ms: 50,
        };
        assert_eq!(p.url(), "http://1.2.3.4:8080");
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = ProxyPool::new();
        assert!(pool.next().is_none());
    }

    #[test]
    fn is_public_proxy_filters_private_and_malformed() {
        // Public IPv4 endpoints pass.
        assert!(is_public_proxy("8.8.8.8:8080"));
        assert!(is_public_proxy("1.1.1.1:3128"));
        // Private / reserved / loopback / link-local metadata are dropped (SSRF).
        for bad in [
            "127.0.0.1:8080",
            "10.0.0.1:3128",
            "192.168.1.1:8080",
            "169.254.169.254:80",
            "[::1]:8080",
        ] {
            assert!(
                !is_public_proxy(bad),
                "{bad} must be rejected as non-public"
            );
        }
        // Malformed: no port, non-numeric port, hostname, empty.
        for bad in ["8.8.8.8", "8.8.8.8:abc", "proxy.example.com:8080", ""] {
            assert!(!is_public_proxy(bad), "{bad} must be rejected as malformed");
        }
    }
