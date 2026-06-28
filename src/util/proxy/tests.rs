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
    fn replace_resets_rotation_to_head() {
        let pool = ProxyPool::new();
        pool.replace(vec![
            Proxy {
                addr: "1.2.3.4:8080".into(),
                proto: "http",
                latency_ms: 100,
            },
            Proxy {
                addr: "5.6.7.8:3128".into(),
                proto: "socks5",
                latency_ms: 200,
            },
        ]);
        // Advance the rotation cursor, then replace: the next pick must start
        // from the new head, not wherever the old cursor pointed.
        let _ = pool.next();
        pool.replace(vec![Proxy {
            addr: "9.9.9.9:1080".into(),
            proto: "socks5",
            latency_ms: 10,
        }]);
        assert_eq!(pool.count(), 1);
        let p = pool.next().unwrap();
        assert_eq!(p.addr, "9.9.9.9:1080");
        // A socks5 entry renders its scheme through `url()` (proto is not pinned
        // to http) — guards the mixed-scheme contract the field documents.
        assert_eq!(p.url(), "socks5://9.9.9.9:1080");
    }
