use super::*;

    #[test]
    fn normalise_pins_localhost_to_v4_loopback() {
        assert_eq!(normalise_bind("localhost:8080"), "127.0.0.1:8080");
        assert_eq!(normalise_bind("localhost:9999"), "127.0.0.1:9999");
        // Everything else passes through untouched.
        assert_eq!(normalise_bind("127.0.0.1:8080"), "127.0.0.1:8080");
        assert_eq!(normalise_bind("0.0.0.0:8080"), "0.0.0.0:8080");
        assert_eq!(normalise_bind("[::1]:8080"), "[::1]:8080");
    }

    #[test]
    fn loopback_detection_distinguishes_lan_exposure() {
        for lo in [
            "127.0.0.1:8080",
            "[::1]:8080",
            "127.0.0.1:1",
            "localhost:8080",
            // Regression: this module's former private copy split at the LAST
            // colon, leaving the host as `":"`, and called the bare v6 loopback
            // EXPOSED — disagreeing with the `routes` copy that decides whether
            // the auth gate is installed. Both questions now have one answer.
            "::1",
        ] {
            assert!(is_loopback_bind(lo), "{lo} should be loopback");
        }
        for exposed in ["0.0.0.0:8080", "192.168.1.5:8080", "10.0.0.1:8080"] {
            assert!(
                !is_loopback_bind(exposed),
                "{exposed} should be flagged exposed"
            );
        }
    }

    #[test]
    fn bind_error_adds_actionable_hints() {
        let in_use = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let Error::Other(msg) = bind_error("127.0.0.1:8080", &in_use) else {
            panic!("expected Error::Other");
        };
        assert!(msg.contains("port already in use"), "{msg}");
        assert!(msg.contains("8090"), "{msg}");

        // An unmapped kind still yields a clean message with no dangling hint.
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let Error::Other(msg) = bind_error("127.0.0.1:8080", &refused) else {
            panic!("expected Error::Other");
        };
        assert!(msg.starts_with("bind 127.0.0.1:8080:"), "{msg}");
    }

