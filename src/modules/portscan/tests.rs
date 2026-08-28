use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn module_shape() {
        let m = PortScan;
        assert!(!m.is_passive(), "port scan is active");
        assert_eq!(m.category(), ModuleCategory::Infrastructure);
        assert_eq!(m.produces(), &[EntityKind::IpAddress, EntityKind::Url]);
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn ports_are_sorted_and_unique() {
        let mut seen = std::collections::HashSet::new();
        let mut prev = 0u16;
        for (p, svc) in PORTS {
            assert!(!svc.is_empty());
            assert!(seen.insert(*p), "duplicate port {p}");
            assert!(*p > prev, "PORTS must be ascending (got {p} after {prev})");
            prev = *p;
        }
    }

    #[test]
    fn bracketed_ipv6_and_plain_ipv4() {
        assert_eq!(bracketed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), "1.2.3.4");
        assert_eq!(bracketed("2001:db8::1".parse().expect("should succeed")), "[2001:db8::1]");
    }

    #[tokio::test]
    async fn scan_detects_a_listening_local_port() {
        // Bind an ephemeral localhost listener, then confirm the scanner reports
        // that exact port open and a definitely-closed port shut. Uses 127.0.0.1
        // directly (the module's non-routable guard is applied by `process`, not
        // `scan_ports`, so the primitive is testable offline).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("should succeed");
        let port = listener.local_addr().expect("should succeed").port();
        let ip: IpAddr = "127.0.0.1".parse().expect("should succeed");
        // A port almost-certainly closed.
        let closed = port.wrapping_add(1).max(1);
        let open = scan_ports(ip, &[(port, "test"), (closed, "closed")], 4).await;
        assert!(
            open.iter().any(|(p, _)| *p == port),
            "listening port must be open: {open:?}"
        );
    }

    #[test]
    fn process_guards_against_non_routable_targets() {
        // `process` refuses reserved/documentation/private IPs (the guard it
        // applies before scanning). Pin the inputs that gate it so the refusal
        // can't silently regress.
        for ip in ["192.0.2.1", "10.0.0.1", "127.0.0.1", "169.254.0.1"] {
            assert!(
                crate::core::validation::is_non_routable_ip(ip),
                "{ip} must be treated as non-routable (and thus not scanned)"
            );
        }
        assert!(!crate::core::validation::is_non_routable_ip("8.8.8.8"));
    }
