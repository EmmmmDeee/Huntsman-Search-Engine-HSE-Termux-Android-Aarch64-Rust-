use super::*;

    #[test]
    fn extracts_same_domain_emails_only() {
        let text = "Contact info@acme.com or sales@acme.com but ignore noise@example.com";
        let v = extract_emails(text, "acme.com");
        assert!(v.contains(&"info@acme.com".to_string()));
        assert!(v.contains(&"sales@acme.com".to_string()));
        assert!(!v.iter().any(|e| e.ends_with("@example.com")));
    }
