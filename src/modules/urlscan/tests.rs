use super::*;

    #[test]
    fn accepts_domain_url_and_ip() {
        let m = UrlScan;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/path")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    }

    #[test]
    fn module_metadata() {
        let m = UrlScan;
        assert_eq!(m.name(), "urlscan");
        assert_eq!(m.priority(), 15);
        assert_eq!(m.cost(), crate::core::module::ModuleCost::Free);
        assert_eq!(m.max_timeout_ms(), 8_000);
        assert!(!m.description().is_empty());
    }

    #[test]
    fn deserialize_empty_results() {
        let raw = r#"{"results":[]}"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert!(resp.results.is_empty());
    }

    #[test]
    fn deserialize_results_with_page_and_verdicts() {
        let raw = r#"{
            "results": [
                {
                    "page": {
                        "url": "https://example.com/login",
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                        "country": "US",
                        "server": "nginx"
                    },
                    "verdicts": {
                        "malicious": false
                    }
                },
                {
                    "page": {
                        "url": "https://example.com/phish",
                        "domain": "example.com",
                        "ip": "104.21.5.100",
                        "country": "DE",
                        "server": "cloudflare"
                    },
                    "verdicts": {
                        "malicious": true
                    }
                }
            ]
        }"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.results.len(), 2);

        let first = &resp.results[0];
        let page = first.page.as_ref().unwrap();
        assert_eq!(page.domain.as_deref(), Some("example.com"));
        assert_eq!(page.ip.as_deref(), Some("93.184.216.34"));
        assert_eq!(page.country.as_deref(), Some("US"));
        assert_eq!(page.server.as_deref(), Some("nginx"));
        assert_eq!(first.verdicts.as_ref().unwrap().malicious, Some(false));

        let second = &resp.results[1];
        assert_eq!(second.verdicts.as_ref().unwrap().malicious, Some(true));
    }

    #[test]
    fn deserialize_sparse_response() {
        // URLScan.io can return results with missing optional fields.
        let raw = r#"{
            "results": [
                {
                    "page": {
                        "url": "https://example.com/"
                    }
                },
                {}
            ]
        }"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.results.len(), 2);

        let first = &resp.results[0];
        let page = first.page.as_ref().unwrap();
        assert_eq!(page.url.as_deref(), Some("https://example.com/"));
        assert!(page.ip.is_none());
        assert!(page.country.is_none());
        assert!(first.verdicts.is_none());

        // Completely empty result object still deserialises.
        let second = &resp.results[1];
        assert!(second.page.is_none());
        assert!(second.verdicts.is_none());
    }

    fn results(raw: &str) -> Vec<ScanResult> {
        serde_json::from_str::<SearchResp>(raw).unwrap().results
    }

    #[test]
    fn deserialize_parses_the_true_total_when_present() {
        let raw = r#"{"results":[{}],"total":12345,"took":3,"has_more":true}"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.total, Some(12345));
    }

    #[test]
    fn deserialize_total_is_none_when_the_field_is_absent() {
        let raw = r#"{"results":[{}]}"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.total, None);
    }

    #[test]
    fn target_entity_reports_the_true_total_not_the_page_capped_shown_count() {
        // A heavily-scanned domain: URLScan.io's true match count (12,345) far
        // exceeds the page this query actually returned (3 results) — the
        // fabricated-count bug reported the LATTER as if it were the former.
        let r = results(
            r#"{"results":[
              {"page":{"url":"https://a.example.com/x","domain":"a.example.com","ip":"1.1.1.1"}},
              {"page":{"url":"https://a.example.com/y","domain":"a.example.com","ip":"1.1.1.1"}},
              {"page":{"url":"https://a.example.com/z","domain":"a.example.com","ip":"1.1.1.1"}}
            ]}"#,
        );
        let intel = summarize(&r);
        assert_eq!(intel.scan_count, 3, "the page itself has 3 results");

        let target = Target::new(TargetKind::Domain, "a.example.com");
        let entity = build_target_entity(&target, &intel, 12_345, "s");
        let ev = entity.evidence.first().expect("evidence attached");
        assert_eq!(
            ev.attributes.get("scan_count").map(String::as_str),
            Some("12345"),
            "scan_count must be the true total, not the page-capped shown count"
        );
        assert_eq!(
            ev.attributes.get("scans_shown").map(String::as_str),
            Some("3"),
            "the actual page size is still surfaced, under a distinct attribute"
        );
        assert!(ev.summary.contains("12345 scan(s) total"));
        assert!(ev.summary.contains("3 shown"));
    }

    #[test]
    fn target_entity_falls_back_to_the_shown_count_when_no_total_is_given() {
        let r = results(r#"{"results":[{"page":{"domain":"example.com"}}]}"#);
        let intel = summarize(&r);
        let target = Target::new(TargetKind::Domain, "example.com");
        // Caller passes results.len() as the fallback, matching process()'s
        // `data.total.unwrap_or(data.results.len() as u64)`.
        let entity = build_target_entity(&target, &intel, 1, "s");
        let ev = entity.evidence.first().unwrap();
        assert_eq!(ev.attributes.get("scan_count").map(String::as_str), Some("1"));
    }

    #[test]
    fn summarize_dedups_every_field() {
        let r = results(
            r#"{"results":[
              {"page":{"url":"https://a.example.com/x","domain":"a.example.com","ip":"1.1.1.1","country":"US","server":"nginx"},"verdicts":{"malicious":false}},
              {"page":{"url":"https://a.example.com/x","domain":"a.example.com","ip":"1.1.1.1","country":"US","server":"nginx"},"verdicts":{"malicious":true}},
              {"page":{"url":"https://b.example.com/y","domain":"b.example.com","ip":"2.2.2.2","country":"DE","server":"cloudflare"}}
            ]}"#,
        );
        let i = summarize(&r);
        assert_eq!(i.scan_count, 3);
        assert_eq!(i.unique_ips.len(), 2);
        assert_eq!(i.urls.len(), 2);
        assert_eq!(i.domains.len(), 2);
        assert!(i.any_malicious);
    }

    #[test]
    fn child_entities_surface_announcing_asn_and_ptr_host() {
        let r = results(
            r#"{"results":[
              {"page":{"domain":"example.com","ip":"93.184.216.34","asn":"AS15133","asnname":"EDGECAST","ptr":"93.184.216.34.example-cdn.net"}},
              {"page":{"domain":"example.com","ip":"104.21.5.100","asn":"as13335","ptr":"example.com"}}
            ]}"#,
        );
        let es = child_entities(&summarize(&r), "example.com", "s");
        let have = |k: EntityKind, v: &str| es.iter().any(|e| e.kind == k && e.value == v);

        // Announcing ASN → Asn pivot, re-emitted canonically (upper `AS` + digits)
        // regardless of the source field's casing (`AS15133`, `as13335`).
        assert!(have(EntityKind::Asn, "AS15133"));
        assert!(have(EntityKind::Asn, "AS13335"));

        // PTR host → Domain pivot (tagged `ptr`)…
        let ptr = es
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == "93.184.216.34.example-cdn.net")
            .expect("PTR host surfaces as a Domain");
        assert!(ptr.has_tag("ptr"));
        // …but a PTR equal to the seed target is suppressed (no self-echo).
        assert!(!have(EntityKind::Domain, "example.com"));
    }

    #[test]
    fn malformed_asn_is_never_a_pivot() {
        // A blank/garbage ASN field must not become an `AS`-junk entity.
        let r = results(
            r#"{"results":[
              {"page":{"domain":"x.example","ip":"1.1.1.1","asn":"AS"}},
              {"page":{"domain":"x.example","ip":"1.1.1.1","asn":"notanasn"}}
            ]}"#,
        );
        let es = child_entities(&summarize(&r), "x.example", "s");
        assert_eq!(
            es.iter().filter(|e| e.kind == EntityKind::Asn).count(),
            0,
            "neither the empty `AS` nor a non-`AS<digits>` string is a valid ASN"
        );
    }

    #[test]
    fn child_entities_surface_domains_and_urls_and_drop_seed_echo() {
        let r = results(
            r#"{"results":[
              {"page":{"url":"https://shop.example.com/login","domain":"shop.example.com","ip":"93.184.216.34","country":"US"}},
              {"page":{"url":"https://example.com/","domain":"example.com","ip":"93.184.216.34","country":"US"}}
            ]}"#,
        );
        let es = child_entities(&summarize(&r), "example.com", "s");
        let have = |k: EntityKind, v: &str| es.iter().any(|e| e.kind == k && e.value == v);
        // Subdomain surfaces as a Domain pivot…
        assert!(have(EntityKind::Domain, "shop.example.com"));
        // …but the seed domain itself is not echoed back.
        assert!(!have(EntityKind::Domain, "example.com"));
        // Scanned URLs become Url pivots (both distinct URLs; value is the
        // entity's normalised form, so assert by count + the path-bearing one).
        assert!(have(EntityKind::Url, "https://shop.example.com/login"));
        assert_eq!(es.iter().filter(|e| e.kind == EntityKind::Url).count(), 2);
        // IP + country still emitted; IP deduped.
        assert_eq!(es.iter().filter(|e| e.kind == EntityKind::IpAddress).count(), 1);
        assert!(have(EntityKind::Address, "US"));
    }

    #[test]
    fn build_query_uses_correct_field_and_max_page_size() {
        // Page size is the keyless per-page maximum (100), verified live — a 10×
        // enumeration widening over the former size=10/5 at no extra request cost.
        let d = build_query(TargetKind::Domain, "github.com").unwrap();
        assert!(d.contains("q=domain:\"github.com\"") && d.contains("size=100"));
        let u = build_query(TargetKind::Url, "https://x.com/a").unwrap();
        assert!(u.contains("q=page.url:") && u.contains("size=100"));
        let i = build_query(TargetKind::IpAddress, "1.2.3.4").unwrap();
        assert!(i.contains("q=page.ip:\"1.2.3.4\"") && i.contains("size=100"));
        // A kind URLScan can't be keyed on yields no query.
        assert!(build_query(TargetKind::Email, "a@b.com").is_none());
    }
