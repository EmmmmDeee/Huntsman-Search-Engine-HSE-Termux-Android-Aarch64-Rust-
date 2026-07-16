use super::*;
    #[test]
    fn accepts_ip_and_domain() {
        let m = LeakIx;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(LeakIx.cost(), ModuleCost::KeyGated));
    }

    fn body(json: &str) -> HostResp {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a crate::core::entity::Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn summarises_counts_ports_and_window() {
        let b = body(
            r#"{
              "services":[
                {"event_type":"http","protocol":"tcp","event_source":"HttpPlugin",
                 "time":"2024-02-01T00:00:00Z","port":80},
                {"event_type":"http","protocol":"tcp","event_source":"HttpPlugin",
                 "time":"2024-05-01T00:00:00Z","port":443}
              ],
              "leaks":[
                {"event_type":"leak","event_source":"GitConfigPlugin",
                 "time":"2024-01-01T00:00:00Z"}
              ]
            }"#,
        );
        let e = build_exposure_entity(EntityKind::IpAddress, "1.2.3.4", &b, "s");
        assert_eq!(e.kind, EntityKind::IpAddress);
        assert!(e.has_tag("leakix") && e.has_tag("leak"));
        assert!(!e.has_tag("ssh-exposed"));
        assert_eq!(attr(&e, "service_count"), Some("2"));
        assert_eq!(attr(&e, "leak_count"), Some("1"));
        assert_eq!(attr(&e, "ports"), Some("80,443")); // sorted
        // top_event_types ranks by frequency: http(2) before leak(1).
        assert_eq!(attr(&e, "top_event_types"), Some("http×2, leak×1"));
        // Window spans every event, leaks included.
        assert_eq!(attr(&e, "most_recent"), Some("2024-05-01T00:00:00Z"));
        assert_eq!(attr(&e, "earliest"), Some("2024-01-01T00:00:00Z"));
        assert_eq!(attr(&e, "protocols"), Some("tcp×2"));
        assert_eq!(
            attr(&e, "event_sources"),
            Some("HttpPlugin×2, GitConfigPlugin×1")
        );
    }

    #[test]
    fn ssh_service_raises_ssh_exposed_tag_case_insensitively() {
        let b = body(r#"{"services":[{"event_type":"SSH","port":22}],"leaks":[]}"#);
        let e = build_exposure_entity(EntityKind::IpAddress, "1.2.3.4", &b, "s");
        assert!(e.has_tag("ssh-exposed"));
        // No leaks → no `leak` tag.
        assert!(!e.has_tag("leak"));
    }

    #[test]
    fn services_only_omits_leak_and_optional_attrs() {
        // Bare service with no metadata: counts present, every optional
        // aggregate omitted rather than emitted blank.
        let b = body(r#"{"services":[{"port":8080}],"leaks":[]}"#);
        let e = build_exposure_entity(EntityKind::Domain, "x.test", &b, "s");
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(!e.has_tag("leak") && !e.has_tag("ssh-exposed"));
        assert_eq!(attr(&e, "ports"), Some("8080"));
        assert_eq!(attr(&e, "top_event_types"), None);
        assert_eq!(attr(&e, "protocols"), None);
        assert_eq!(attr(&e, "event_sources"), None);
        assert_eq!(attr(&e, "most_recent"), None);
    }

    #[test]
    fn port_list_is_capped() {
        // Regression: 40 distinct open ports exceed MAX_PORTS=20, so the
        // emitted list must be capped AND the seed tagged `truncated` with
        // the true total surfaced — the operator must know 20 more ports
        // exist beyond what's printed.
        let services: String = (0..40)
            .map(|p| format!(r#"{{"port":{}}}"#, 1000 + p))
            .collect::<Vec<_>>()
            .join(",");
        let b = body(&format!(r#"{{"services":[{services}],"leaks":[]}}"#));
        let e = build_exposure_entity(EntityKind::IpAddress, "1.2.3.4", &b, "s");
        assert_eq!(attr(&e, "ports").unwrap().split(',').count(), MAX_PORTS);
        assert!(e.has_tag("truncated"), "seed must be tagged 'truncated'");
        assert_eq!(attr(&e, "total_ports"), Some("40"));
        assert_eq!(attr(&e, "ports_capped"), Some("true"));
    }

    #[test]
    fn port_list_under_cap_is_not_flagged() {
        // 3 distinct ports stays well under MAX_PORTS=20: total is still
        // surfaced, but no truncation is claimed.
        let b = body(
            r#"{"services":[{"port":80},{"port":443},{"port":8080}],"leaks":[]}"#,
        );
        let e = build_exposure_entity(EntityKind::IpAddress, "1.2.3.4", &b, "s");
        assert!(!e.has_tag("truncated"), "must not flag when under cap");
        assert_eq!(attr(&e, "total_ports"), Some("3"));
        assert_eq!(attr(&e, "ports_capped"), None);
    }
