use super::*;

    #[test]
    fn accepts_api_key_only() {
        let m = ApiKeyProbe;
        assert!(m.accepts(&Target::new(TargetKind::ApiKey, "test-key-12345678")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn probe_count_matches_services() {
        let p = probes();
        assert!(p.len() >= 23);
        for probe in &p {
            assert!(!probe.service.is_empty());
            assert!(!probe.env_var.is_empty());
            assert!(probe.env_var.starts_with("HUNTSMAN_"));
        }
    }

    #[test]
    fn every_probe_transmits_its_key_only_over_https() {
        // These probes send a LIVE secret API key to a validation endpoint —
        // whether in the URL query or an auth header. A plaintext `http://`
        // endpoint would leak the credential to any on-path observer, so the
        // table must be https-only (it is; this guards against a future
        // contributor adding an http endpoint), and every probe must actually
        // carry the key — via the URL or at least one header — or it would send
        // an unauthenticated request and report a valid key as invalid.
        const SENTINEL: &str = "SENTINELKEY0123456789";
        for probe in &probes() {
            let (url, headers) = (probe.url_builder)(SENTINEL);
            assert!(
                url.starts_with("https://"),
                "{}: probe URL is not https ({url}) — would leak the key in plaintext",
                probe.service
            );
            assert!(
                url.contains(SENTINEL) || !headers.is_empty(),
                "{}: probe carries the key neither in the URL nor a header — it would \
                 send an unauthenticated request",
                probe.service
            );
            assert!(
                !probe.category.is_empty(),
                "{}: empty category",
                probe.service
            );
        }
    }

    #[test]
    fn probe_services_and_env_vars_are_unique() {
        // A duplicate service or env var means one probe shadows the other:
        // wasted requests, or a key validated against the wrong endpoint.
        let p = probes();
        let mut services = std::collections::HashSet::new();
        let mut env_vars = std::collections::HashSet::new();
        for probe in &p {
            assert!(
                services.insert(probe.service),
                "duplicate probe service: {}",
                probe.service
            );
            assert!(
                env_vars.insert(probe.env_var),
                "duplicate probe env var: {}",
                probe.env_var
            );
        }
    }

    #[test]
    fn error_detection() {
        let err1: Value = serde_json::json!({"error": "Invalid API key"});
        assert!(is_error_response(&err1));

        let err2: Value = serde_json::json!({"success": false});
        assert!(is_error_response(&err2));

        let ok: Value = serde_json::json!({"plan": "free", "credits": 100});
        assert!(!is_error_response(&ok));
    }

    #[test]
    fn is_free_and_active() {
        let m = ApiKeyProbe;
        // Network-reaching: probes seeded keys against live service endpoints,
        // so it must NOT be passive (a passive_only scan has to skip it).
        assert!(!m.is_passive());
        assert_eq!(m.cost(), ModuleCost::Free);
    }
