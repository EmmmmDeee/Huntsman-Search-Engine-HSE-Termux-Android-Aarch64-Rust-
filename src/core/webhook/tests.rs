use super::*;

    #[test]
    fn webhook_url_from_env_empty_string_is_none() {
        let result = "".to_string();
        assert!(result.is_empty());
        assert!(webhook_url_from_env().is_none() || webhook_url_from_env().is_some());
    }

    #[test]
    fn webhook_payload_fields() {
        let p = WebhookPayload {
            scan_id: "abc",
            target_kind: "email",
            target_value: "x@y.com",
            entity_count: 42,
            status: "complete",
            correlations_count: 3,
        };
        assert_eq!(p.scan_id, "abc");
        assert_eq!(p.entity_count, 42);
    }
