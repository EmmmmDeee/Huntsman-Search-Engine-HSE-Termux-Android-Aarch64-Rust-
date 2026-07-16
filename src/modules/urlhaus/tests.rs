use super::*;

#[test]
fn resolve_key_prefers_dedicated_urlhaus_key() {
    let r = resolve_key(Some("uh-key"), Some("tf-key"));
    assert_eq!(r, Some(("uh-key", "urlhaus")));
}

#[test]
fn resolve_key_falls_back_to_threatfox_key() {
    let r = resolve_key(None, Some("tf-key"));
    assert_eq!(r, Some(("tf-key", "threatfox")));
}

#[test]
fn resolve_key_treats_empty_primary_as_absent() {
    // A present-but-empty env var (e.g. `HUNTSMAN_ABUSECH_KEY=`) must not win
    // over a real fallback key, and must not itself be returned as "the key".
    let r = resolve_key(Some(""), Some("tf-key"));
    assert_eq!(r, Some(("tf-key", "threatfox")));
}

#[test]
fn resolve_key_none_when_both_absent_or_empty() {
    assert_eq!(resolve_key(None, None), None);
    assert_eq!(resolve_key(Some(""), Some("")), None);
}

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
        assert!(e.has_tag(crate::core::tags::MALICIOUS) && e.has_tag("urlhaus"));
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

    // -- parse_url_count failure contract (T2.164) --------------------------

    #[test]
    fn parse_url_count_surfaces_an_unparseable_count_as_error() {
        // T2.164 regression: `.and_then(|s| s.parse().ok()).unwrap_or(0)`
        // previously collapsed a real abuse.ch contract violation (ok, but
        // url_count unparseable) into the same Ok(empty) as a genuine clean
        // miss — silently discarding a confirmed malicious-host finding.
        let body = resp(r#"{"query_status":"ok","url_count":"not-a-number"}"#);
        let out = parse_url_count(&body);
        assert!(
            out.is_err(),
            "an unparseable url_count on query_status=ok must surface as Err"
        );
    }

    #[test]
    fn parse_url_count_treats_missing_or_zero_as_the_conservative_floor() {
        // query_status=="ok" guarantees a real positive finding even when
        // abuse.ch omits/zeroes url_count — never silently discard it.
        assert_eq!(parse_url_count(&resp(r#"{"query_status":"ok"}"#)).unwrap(), 1);
        assert_eq!(
            parse_url_count(&resp(r#"{"query_status":"ok","url_count":"0"}"#)).unwrap(),
            1
        );
    }

    #[test]
    fn parse_url_count_keeps_a_real_count() {
        assert_eq!(
            parse_url_count(&resp(r#"{"query_status":"ok","url_count":"7"}"#)).unwrap(),
            7
        );
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
