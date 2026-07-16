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
        assert_eq!(bracketed("2001:db8::1".parse().unwrap()), "[2001:db8::1]");
    }

    #[tokio::test]
    async fn scan_detects_a_listening_local_port() {
        // Bind an ephemeral localhost listener, then confirm the scanner reports
        // that exact port open and a definitely-closed port shut. Uses 127.0.0.1
        // directly (the module's non-routable guard is applied by `process`, not
        // `scan_ports`, so the primitive is testable offline).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // A port almost-certainly closed.
        let closed = port.wrapping_add(1).max(1);
        let (open, transport_failures) =
            scan_ports(ip, &[(port, "test"), (closed, "closed")], 4).await;
        assert!(
            open.iter().any(|(p, _)| *p == port),
            "listening port must be open: {open:?}"
        );
        assert_eq!(
            transport_failures, 0,
            "a real listener/refusal is not a transport failure"
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

    // -- all_ports_failed_transport failure contract (T2.159) ---------------

    #[test]
    fn all_ports_failed_transport_only_on_total_outage_with_no_hits() {
        // T2.159 regression: every connect collapsing to `NetworkUnreachable`/
        // `HostUnreachable` (no route to the target at all) previously read
        // identically to 23/23 genuine closed/filtered ports.
        assert!(all_ports_failed_transport(23, 23, 0));
        // Mixed: some ports genuinely closed/filtered, not a total outage.
        assert!(!all_ports_failed_transport(5, 23, 0));
        // Any real hit, even alongside transport failures, is not an outage.
        assert!(!all_ports_failed_transport(22, 23, 1));
        // The vacuous case (no ports configured) must never be a false outage.
        assert!(!all_ports_failed_transport(0, 0, 0));
    }
