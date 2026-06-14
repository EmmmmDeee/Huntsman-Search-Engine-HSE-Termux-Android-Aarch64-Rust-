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
