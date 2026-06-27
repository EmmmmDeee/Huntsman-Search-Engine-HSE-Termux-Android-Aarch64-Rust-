use super::*;

#[test]
fn accepts_domain_and_ip() {
        let m = UrlHaus;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn parse_clean_response() {
        let raw = r#"{"query_status":"no_results"}"#;
        let r: UrlhausResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.query_status, "no_results");
        assert!(r.urls.is_none());
    }

    #[test]
    fn parse_hit_response() {
        let raw = r#"{
            "query_status":"ok",
            "urlhaus_reference":"https://urlhaus.abuse.ch/host/example.com/",
            "url_count":"3",
            "firstseen":"2024-01-01 00:00:00 UTC",
            "lastseen":"2024-06-01 00:00:00 UTC",
            "blacklists":{"surbl":"not_listed","spamhaus_dbl":"listed"},
            "urls":[
              {"threat":"malware_download","url_status":"online"},
              {"threat":"phishing","url_status":"offline"}
            ]
        }"#;
        let r: UrlhausResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.query_status, "ok");
        assert_eq!(r.url_count.as_deref(), Some("3"));
        assert_eq!(r.urls.as_ref().unwrap().len(), 2);
    }

    fn resp(json: &str) -> UrlhausResp {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a crate::core::entity::Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn threat_entity_aggregates_counts_window_and_blocklists() {
        let body = resp(
            r#"{
              "query_status":"ok",
              "urlhaus_reference":"https://urlhaus.abuse.ch/host/evil.test/",
              "url_count":"3",
              "firstseen":"2024-01-01 00:00:00 UTC",
              "lastseen":"2024-06-01 00:00:00 UTC",
              "blacklists":{"surbl":"not_listed","spamhaus_dbl":"listed"},
              "urls":[
                {"threat":"malware_download","url_status":"online","tags":["elf","mirai"]},
                {"threat":"phishing","url_status":"offline","tags":["elf"]},
                {"threat":"malware_download","url_status":"online","tags":["elf"]}
              ]
            }"#,
        );
        let e = build_threat_entity(EntityKind::Domain, "evil.test", &body, 3, "s");
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("malicious") && e.has_tag("urlhaus"));
        assert!((e.confidence - 0.90).abs() < 1e-9);
        assert_eq!(attr(&e, "url_count"), Some("3"));
        assert_eq!(
            attr(&e, "reference"),
            Some("https://urlhaus.abuse.ch/host/evil.test/")
        );
        assert_eq!(attr(&e, "first_seen"), Some("2024-01-01 00:00:00 UTC"));
        assert_eq!(attr(&e, "surbl"), Some("not_listed"));
        assert_eq!(attr(&e, "spamhaus_dbl"), Some("listed"));
        assert_eq!(attr(&e, "urls_online"), Some("2"));
        assert_eq!(attr(&e, "urls_offline"), Some("1"));
        // Distinct threat families, lexically sorted.
        assert_eq!(attr(&e, "threats"), Some("malware_download,phishing"));
        // top_tags by frequency: elf(3) before mirai(1).
        assert_eq!(attr(&e, "top_tags"), Some("elf(3), mirai(1)"));
    }

    #[test]
    fn threats_are_deterministic_lexically_sorted_in_full() {
        // Distinct families supplied out of order — full-fidelity policy: EVERY
        // distinct family is surfaced, lexically sorted, never a capped subset.
        let urls: String = ["m", "z", "a", "c", "b", "y", "x", "d", "e", "f"]
            .iter()
            .map(|t| format!(r#"{{"threat":"{t}","url_status":"online"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let body = resp(&format!(r#"{{"query_status":"ok","urls":[{urls}]}}"#));
        let e = build_threat_entity(EntityKind::Domain, "h", &body, 10, "s");
        let threats = attr(&e, "threats").unwrap();
        assert_eq!(threats.split(',').count(), 10);
        assert_eq!(threats, "a,b,c,d,e,f,m,x,y,z");
    }

    #[test]
    fn no_urls_array_omits_url_aggregates() {
        // A host hit with a count but no per-URL array (abuse.ch can omit it).
        let e = build_threat_entity(
            EntityKind::IpAddress,
            "1.2.3.4",
            &resp(r#"{"query_status":"ok","url_count":"5"}"#),
            5,
            "s",
        );
        assert_eq!(attr(&e, "url_count"), Some("5"));
        assert_eq!(attr(&e, "urls_online"), None);
        assert_eq!(attr(&e, "threats"), None);
        assert_eq!(attr(&e, "top_tags"), None);
    }
