use super::*;

    #[test]
    fn error_module_constructor() {
        let e = Error::module("dns_resolver", "connection refused");
        let s = e.to_string();
        assert!(s.contains("dns_resolver"));
        assert!(s.contains("connection refused"));
    }

    #[test]
    fn error_missing_key_display() {
        let e = Error::MissingKey("HUNTSMAN_SHODAN_KEY".into());
        assert!(e.to_string().contains("HUNTSMAN_SHODAN_KEY"));
    }

    #[test]
    fn error_from_json() {
        let bad = serde_json::from_str::<serde_json::Value>("not json");
        let e: Error = bad.unwrap_err().into();
        assert!(e.to_string().contains("json"));
    }

    #[test]
    fn error_invalid_target_display() {
        let e = Error::InvalidTarget("not-a-valid-ip".into());
        let s = e.to_string();
        assert!(s.contains("invalid target"));
        assert!(s.contains("not-a-valid-ip"));
    }

    #[test]
    fn error_other_is_passthrough_display() {
        let e = Error::Other("custom error message".into());
        assert_eq!(e.to_string(), "custom error message");
    }

    #[test]
    fn error_io_from_std() {
        use std::io;
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let e: Error = io_err.into();
        assert!(e.to_string().starts_with("io:"));
    }
