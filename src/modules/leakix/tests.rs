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
        serde_json::from_str(json).expect("should succeed")
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
        let services: String = (0..40)
            .map(|p| format!(r#"{{"port":{}}}"#, 1000 + p))
            .collect::<Vec<_>>()
            .join(",");
        let b = body(&format!(r#"{{"services":[{services}],"leaks":[]}}"#));
        let e = build_exposure_entity(EntityKind::IpAddress, "1.2.3.4", &b, "s");
        assert_eq!(attr(&e, "ports").expect("should succeed").split(',').count(), MAX_PORTS);
    }

    // ── REQ-LEAKIX-001: the wire shape LeakIX actually sends ───────────────
    //
    // Keys and types from LeakIX's own client (`leakix` 1.1.0 `HostResult`:
    // `Services` / `Leaks`, nullable; `l9format` `L9Event.port: str`). Every
    // fixture above was author-written lowercase with numeric ports — the one
    // shape LeakIX never sends — so none of them could see the defect.

    const REAL: &str = r#"{
      "Services": [
        {"event_type":"service","event_source":"SSHOpenPlugin","protocol":"ssh",
         "port":"22","time":"2024-05-01T00:00:00Z"},
        {"event_type":"service","event_source":"HttpPlugin","protocol":"https",
         "port":"443","time":"2024-04-01T00:00:00Z"}
      ],
      "Leaks": null
    }"#;

    fn raw(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("json")
    }

    #[test]
    fn the_real_wire_shape_is_an_exposure_not_a_clean_negative() {
        // FAILS before the fix: `Services` was an unknown field, so the body
        // decoded as two empty lists and the module returned Ok(empty) —
        // "LeakIX indexed nothing on this host" — for every real response.
        let r = leakix_result(EntityKind::IpAddress, "1.2.3.4", raw(REAL), "s").expect("decodes");
        assert_eq!(r.entities.len(), 1, "a host with two indexed services");
        let e = &r.entities[0];
        assert_eq!(attr(e, "service_count"), Some("2"));
        assert_eq!(attr(e, "ports"), Some("22,443"), "string ports decode");
        assert!(e.has_tag("ssh-exposed"), "SSH is named in `protocol`");
        assert!(!e.has_tag("leak"), "`Leaks: null` is no leak");
    }

    #[test]
    fn null_or_empty_lists_are_the_real_clean_negative() {
        for body in [
            r#"{"Services":null,"Leaks":null}"#,
            r#"{"Services":[],"Leaks":[]}"#,
            r#"{"services":[],"leaks":[]}"#,
        ] {
            let r = leakix_result(EntityKind::Domain, "example.com", raw(body), "s")
                .expect("a recognised empty answer");
            assert!(r.entities.is_empty(), "{body}");
        }
    }

    #[test]
    fn a_body_with_neither_key_fails_closed() {
        // The shape that let the defect hide: an unrecognised 200 read as
        // "no exposure". It is now the module's error.
        for body in [r#"{"Error":"quota exceeded"}"#, r#"{}"#, r#"[]"#, r#""Invalid API key""#] {
            assert!(
                leakix_result(EntityKind::Domain, "example.com", raw(body), "s").is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn a_port_of_any_scalar_shape_or_none_never_fails_the_event() {
        let b = body(r#"{"Services":[{"port":"8080"},{"port":8443},{"port":"n/a"},{"port":null},{}]}"#);
        let ports: Vec<i64> = b.services().iter().filter_map(|e| e.port).collect();
        assert_eq!(ports, [8080, 8443]);
    }
