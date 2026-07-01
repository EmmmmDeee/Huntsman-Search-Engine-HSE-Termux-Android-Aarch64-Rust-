use super::*;
    use crate::core::module::ModuleResult;
    use reqwest::header::HeaderMap;
    use std::collections::VecDeque;

    fn empty_state() -> CrawlState {
        CrawlState {
            visited: HashSet::new(),
            queue: VecDeque::new(),
            pages_fetched: 0,
            disallow_rules: Vec::new(),
            result: ModuleResult::new(),
            external_domains: HashSet::new(),
            subdomains: HashSet::new(),
            emails: HashSet::new(),
            phones: HashSet::new(),
            tracking_ids: HashSet::new(),
            frameworks: HashSet::new(),
            page_types: HashSet::new(),
            security_headers: Vec::new(),
            internal_links: 0,
            external_links: 0,
            notable_pages: Vec::new(),
        }
    }

    #[test]
    fn extract_tracking_ids_finds_analytics_anchors() {
        let html = r#"
            <script>gtag('config','UA-123456-1');</script>
            <script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCDE12345"></script>
            <!-- GTM-XYZ12 -->
            <ins class="adsbygoogle" data-ad-client="ca-pub-1234567890123456"></ins>
            <script>fbq('init', '987654321098765');</script>
            <script>ym(12345678, "init", {});</script>
            <script>hjid:1234567,hjsv:6</script>
        "#;
        let mut ids = HashSet::new();
        extract_tracking_ids(html, &mut ids);
        let got: std::collections::BTreeSet<&str> = ids.iter().map(|(v, _)| v.as_str()).collect();
        for want in [
            "UA-123456-1",
            "G-ABCDE12345",
            "GTM-XYZ12",
            "ca-pub-1234567890123456",
            "fb-pixel:987654321098765",
            "yandex:12345678",
            "hotjar:1234567",
        ] {
            assert!(got.contains(want), "missing {want}: {got:?}");
        }
        // A page with no analytics yields nothing.
        let mut none = HashSet::new();
        extract_tracking_ids("<html><body>plain</body></html>", &mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn link_iter_extracts_only_real_hrefs() {
        let html = r##"<a href="/a">x</a> <a href='https://b.com/c'>y</a>
            <a href="#frag">z</a> <a href="mailto:e@x.com">m</a>
            <a href="javascript:void(0)">j</a> <a href="">empty</a> <a>noattr</a>"##;
        let links: Vec<&str> = LinkIter::new(html).collect();
        assert_eq!(links, vec!["/a", "https://b.com/c"]);
    }

    #[test]
    fn registrable_domain_takes_last_two_labels() {
        assert_eq!(
            extract_registrable_domain("www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            extract_registrable_domain("example.com").as_deref(),
            Some("example.com")
        );
        // Multi-label public suffixes are handled via util::domains'
        // curated table (not a full PSL): a.b.co.uk → b.co.uk, the registrable
        // domain, rather than the bare suffix co.uk.
        assert_eq!(
            extract_registrable_domain("a.b.co.uk").as_deref(),
            Some("b.co.uk")
        );
        assert_eq!(extract_registrable_domain("localhost"), None);
    }

    #[test]
    fn binary_url_detection() {
        assert!(is_binary_url("https://x.com/file.pdf"));
        assert!(is_binary_url("https://x.com/IMG.PNG")); // case-insensitive
        assert!(is_binary_url("https://x.com/a.zip?v=2")); // query stripped
        assert!(!is_binary_url("https://x.com/page"));
        assert!(!is_binary_url("https://x.com/article.html"));
    }

    #[test]
    fn disallowed_matches_path_prefix() {
        let rules = vec!["/admin".to_string(), "/private/".to_string()];
        assert!(is_disallowed("https://x.com/admin/panel", &rules));
        assert!(is_disallowed("https://x.com/private/x", &rules));
        assert!(!is_disallowed("https://x.com/public", &rules));
        // Unparseable input → empty path → no rule matches (never panics).
        assert!(!is_disallowed("not a url", &rules));
    }

    #[test]
    fn email_extraction_filters_assets_and_dedups() {
        let mut emails = HashSet::new();
        extract_emails(
            "reach John.Doe@Example.com or sales@a.co — skip logo@2x.png and x@y.z",
            &mut emails,
        );
        assert!(emails.contains("john.doe@example.com")); // lowercased
        assert!(emails.contains("sales@a.co"));
        assert!(!emails.iter().any(|e| e.ends_with(".png"))); // image excluded
        assert!(!emails.contains("x@y.z")); // domain ≤3 chars rejected

        let mut dup = HashSet::new();
        extract_emails("a@b.com a@b.com", &mut dup);
        assert_eq!(dup.len(), 1);
    }

    #[test]
    fn email_extraction_rejects_syntactically_invalid_candidates() {
        // Routed through the canonical validator, malformed runs the byte-scan
        // can grab (consecutive dots, an edge dot) are no longer surfaced, while
        // an ordinary address alongside them still is.
        let mut emails = HashSet::new();
        extract_emails(
            "bad john..doe@example.com and .lead@example.com and trail.@example.com \
             but good real.person@example.com",
            &mut emails,
        );
        assert!(emails.contains("real.person@example.com"));
        assert!(!emails.contains("john..doe@example.com")); // consecutive dots
        assert!(!emails.contains(".lead@example.com")); // leading dot
        assert!(!emails.contains("trail.@example.com")); // trailing-dot local
    }

    #[test]
    fn email_extraction_filters_modern_asset_extensions_but_not_gtlds() {
        let mut emails = HashSet::new();
        extract_emails(
            "sprites logo@2x.webp icon@3x.svg hero@2x.jpeg fav@2x.ico font@1x.woff2 \
             — but real ops@acme.com and archive lover@backups.zip stay",
            &mut emails,
        );
        // Retina/asset filenames the old 5-extension filter missed are now dropped.
        for asset in [
            "logo@2x.webp",
            "icon@3x.svg",
            "hero@2x.jpeg",
            "fav@2x.ico",
            "font@1x.woff2",
        ] {
            assert!(!emails.contains(asset), "asset leaked as email: {asset}");
        }
        // Real addresses survive — including the `.zip` gTLD, which must NOT be
        // mistaken for a file extension.
        assert!(emails.contains("ops@acme.com"));
        assert!(emails.contains("lover@backups.zip"));
    }

    #[test]
    fn phone_extraction_bounds_digit_count() {
        let mut phones = HashSet::new();
        extract_phones(
            "call +1 415 555 2671 or +44 20 7946 0958, skip +123, junk +01020103",
            &mut phones,
        );
        assert!(phones.contains("+14155552671"));
        assert!(phones.iter().any(|p| p.starts_with("+44")));
        // Practical minimum is 10 digits (no inhabited country has fewer).
        assert!(!phones.iter().any(|p| p.len() < 11)); // '+' + 10 digits = 11 chars
        // E.164 country codes never start with 0 — `+0…` is a scrape artifact.
        assert!(!phones.iter().any(|p| p.starts_with("+0")));

        // 7- and 8- and 9-digit strings are web-scrape noise — reject all.
        let mut short = HashSet::new();
        extract_phones("ring +1 234567 now", &mut short); // 7 digits
        assert!(short.is_empty(), "7-digit must be rejected: {short:?}");
        let mut also_short = HashSet::new();
        extract_phones("ring +1 2345678 now", &mut also_short); // 8 digits
        assert!(also_short.is_empty(), "8-digit must be rejected: {also_short:?}");
        let mut nine = HashSet::new();
        extract_phones("ring +1 23456789 now", &mut nine); // 9 digits
        assert!(nine.is_empty(), "9-digit must be rejected: {nine:?}");
        // 10 digits — smallest real subscriber number (Niue +683, Singapore +65, etc.)
        let mut ok = HashSet::new();
        extract_phones("ring +6569504420 now", &mut ok); // 10 digits, Singapore
        assert!(ok.contains("+6569504420"));
    }

    #[test]
    fn extractors_are_utf8_safe_on_adversarial_multibyte_html() {
        // These run on untrusted, possibly hostile page bodies. The byte-scan
        // indexes `body` directly, so the invariant is: multibyte UTF-8 around a
        // match must never split a code point (no panic), a valid ASCII match is
        // still recovered, and the non-ASCII runs themselves yield nothing.
        let mut emails = HashSet::new();
        // 2-/3-/4-byte chars (é, 日本語, 𝔘) abut and surround a real ASCII email,
        // including a multibyte char immediately before the local part.
        extract_emails(
            "日本語语alice@example.com café résumé 𝔘 contact:bob@test.co 日本語",
            &mut emails,
        );
        assert!(emails.contains("alice@example.com"), "got {emails:?}");
        assert!(emails.contains("bob@test.co"), "got {emails:?}");
        assert_eq!(
            emails.len(),
            2,
            "multibyte noise must not fabricate: {emails:?}"
        );

        // A large delimiter-free multibyte blob with no '@' must not panic and
        // must yield nothing (bounded, char-boundary-safe scan).
        let blob = "日本語".repeat(50_000);
        let mut none = HashSet::new();
        extract_emails(&blob, &mut none);
        assert!(none.is_empty());

        // Phones: a real E.164 number surrounded by multibyte text.
        let mut phones = HashSet::new();
        extract_phones("☎ 日本 +1 415 555 2671 語 résumé", &mut phones);
        assert!(phones.contains("+14155552671"), "got {phones:?}");
        let mut pnone = HashSet::new();
        extract_phones(&blob, &mut pnone); // must not panic
        assert!(pnone.is_empty());
    }

    #[test]
    fn char_class_predicates() {
        assert!(
            is_email_char(b'a')
                && is_email_char(b'.')
                && is_email_char(b'+')
                && is_email_char(b'_')
        );
        assert!(!is_email_char(b'@') && !is_email_char(b' '));
        assert!(is_domain_char(b'z') && is_domain_char(b'.') && is_domain_char(b'-'));
        assert!(!is_domain_char(b'_') && !is_domain_char(b'@'));
    }

    #[test]
    fn framework_detection_and_dedup() {
        let mut f = HashSet::new();
        detect_frameworks(
            "<link href='/wp-content/x.css'> jQuery here and /wp-includes/y",
            &mut f,
        );
        assert!(f.contains("WordPress"));
        assert!(f.contains("jQuery"));
        // Two WordPress markers collapse to one entry.
        assert_eq!(f.iter().filter(|&&n| n == "WordPress").count(), 1);

        let mut r = HashSet::new();
        detect_frameworks("import React from 'react'", &mut r);
        assert!(r.contains("React"));
    }

    #[test]
    fn page_type_detection() {
        let mut t = HashSet::new();
        detect_page_types(
            r#"<form><input type="password"><input type="file"></form><script>x</script> /admin apikey"#,
            &mut t,
        );
        for want in [
            "has_forms",
            "login_form",
            "file_upload",
            "javascript",
            "admin_panel",
            "api_reference",
        ] {
            assert!(t.contains(want), "missing page type: {want}");
        }
        let mut none = HashSet::new();
        detect_page_types("<p>plain text</p>", &mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn security_header_audit_reports_presence() {
        let mut h = HeaderMap::new();
        h.insert(
            "content-security-policy",
            "default-src 'self'".parse().unwrap(),
        );
        h.insert("x-frame-options", "DENY".parse().unwrap());
        let mut results = Vec::new();
        audit_security_headers(&h, &mut results);
        assert_eq!(results.len(), 6);
        let map: std::collections::HashMap<_, _> = results.into_iter().collect();
        assert!(map["Content-Security-Policy"]);
        assert!(map["X-Frame-Options"]);
        assert!(!map["Strict-Transport-Security"]);
        assert!(!map["Referrer-Policy"]);
    }

    #[test]
    fn extract_links_classifies_internal_external_and_subdomains() {
        let mut state = empty_state();
        let body = r#"<a href="/about">a</a><a href="https://sub.example.com/x">b</a>
            <a href="https://other.org/page">c</a><a href="/logo.png">d</a>
            <a href="ftp://example.com/f">e</a>"#;
        extract_links(
            body,
            "https://example.com/",
            "example.com",
            "example.com",
            &mut state,
        );

        // /about (apex) + sub.example.com (subdomain) are internal.
        assert_eq!(state.internal_links, 2);
        assert!(state.subdomains.contains("sub.example.com"));
        // other.org is external.
        assert_eq!(state.external_links, 1);
        assert!(state.external_domains.contains("other.org"));
        // /about is queued; binary asset and non-http scheme are not.
        assert!(
            state
                .queue
                .iter()
                .any(|(u, _)| u.as_str() == "https://example.com/about")
        );
        assert!(!state.queue.iter().any(|(u, _)| u.contains("logo.png")));
        assert!(!state.queue.iter().any(|(u, _)| u.starts_with("ftp")));
    }

    #[test]
    fn extract_links_refuses_private_ip_literal_links() {
        // Worst case for the SSRF guard: the seed host IS the cloud-metadata
        // literal, so the same-host filter would otherwise enqueue its links.
        // The explicit egress guard must keep the queue empty regardless.
        let mut state = empty_state();
        let body = r#"<a href="/latest/meta-data/iam/security-credentials/">creds</a>
            <a href="http://127.0.0.1:8080/admin">loopback</a>"#;
        extract_links(
            body,
            "http://169.254.169.254/",
            "169.254.169.254",
            "169.254.169.254",
            &mut state,
        );
        assert!(
            state.queue.is_empty(),
            "private/reserved IP-literal links must never be enqueued, got {:?}",
            state.queue
        );
    }

    #[test]
    fn extract_api_keys_from_body_gates_length_and_rejects_non_poolable() {
        // Hermetic characterization of the credential-harvester (previously
        // untested despite mutating the process-global key pool). It splits the
        // body into bare words, so it can only ever classify PREFIX keys (github,
        // aws, …) — none of which are poolable OSINT providers — and the
        // context-only OSINT keys never fire without surrounding text. So a
        // web-scraped key is correctly NEVER added to the pool here. We scope to a
        // unique domain so the assertion is isolated from any concurrent test.
        let pool = crate::util::key_pool::global_pool();
        let domain = "crawlutil-test.example";
        let scraped = || -> usize {
            pool.snapshot()
                .services
                .values()
                .flatten()
                .filter(|e| {
                    e.discovered_by
                        .as_deref()
                        .is_some_and(|d| d == format!("web_crawler:{domain}"))
                })
                .count()
        };
        assert_eq!(scraped(), 0, "precondition: a clean pool for this domain");

        // (1) Length gate: <16 or >200 chars are never classified.
        extract_api_keys_from_body("short ghp_x", domain);
        // (2) A VALID github token is classified by identify_api_key but github is
        //     not a poolable provider, so pool.add rejects it.
        extract_api_keys_from_body(
            "github_token=ghp_aBc1deFG2HiJK3lmnoPqrStUVwXyZA end",
            domain,
        );
        // (3) An obvious placeholder is rejected by identify_api_key outright.
        extract_api_keys_from_body("ghp_your_token_here_xxxxxxxxxxxx", domain);

        assert_eq!(
            scraped(),
            0,
            "web_crawler must not add length-gated / non-poolable keys to the global pool"
        );

        // Defensive cleanup: if a future detection change DID add anything for this
        // domain, remove it so the global pool stays hermetic (in-memory only).
        for (svc, entries) in pool.snapshot().services {
            for e in entries {
                if e.discovered_by.as_deref() == Some(&format!("web_crawler:{domain}")) {
                    pool.remove(&svc, &e.value);
                }
            }
        }
    }

    /// A tiny multi-connection mock HTTP server: accepts `delays_ms.len()`
    /// connections, each parsed for a `GET /page/<idx>` request line, sleeps
    /// `delays_ms[idx]` before responding `PAGE-<idx>` as `text/html`. Lets
    /// tests control exactly which "page" is slow and which is fast, to
    /// prove `fetch_batch` reassembles results by original index rather than
    /// completion order.
    async fn spawn_delay_server(
        delays_ms: Vec<u64>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for _ in 0..delays_ms.len() {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let delays = delays_ms.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let idx: usize = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|p| p.trim_start_matches("/page/").parse().ok())
                        .unwrap_or(0);
                    let delay = delays.get(idx).copied().unwrap_or(0);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    let body = format!("PAGE-{idx}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn fetch_batch_runs_concurrently_not_sequentially() {
        let delays = vec![250u64, 250, 250, 250];
        let (addr, _server) = spawn_delay_server(delays.clone()).await;
        let urls: Vec<String> = (0..delays.len())
            .map(|i| format!("http://{addr}/page/{i}"))
            .collect();
        let http = reqwest::Client::new();

        let start = std::time::Instant::now();
        let outcomes = fetch_batch(&http, &urls).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(250 * 2),
            "4 pages at 250ms each took {elapsed:?} — expected well under {}ms if genuinely \
             concurrent, not ~1000ms if still sequential",
            250 * 2
        );
        for (i, outcome) in outcomes.iter().enumerate() {
            let (body, headers) =
                outcome.as_ref().unwrap_or_else(|| panic!("page {i} should have fetched"));
            assert_eq!(body, &format!("PAGE-{i}"));
            assert!(headers.get("content-type").is_some());
        }
    }

    #[tokio::test]
    async fn fetch_batch_preserves_original_order_regardless_of_completion_order() {
        // Page 0 is the SLOWEST to respond, page 2 responds instantly —
        // outcomes must still come back indexed by original request
        // position, not completion order, or the crawl loop's page-visit
        // determinism guarantee (`docs/CONVENTIONS.md` §5) breaks.
        let delays = vec![200u64, 100, 0];
        let (addr, _server) = spawn_delay_server(delays.clone()).await;
        let urls: Vec<String> = (0..delays.len())
            .map(|i| format!("http://{addr}/page/{i}"))
            .collect();
        let http = reqwest::Client::new();

        let outcomes = fetch_batch(&http, &urls).await;

        assert_eq!(outcomes.len(), 3);
        for (i, outcome) in outcomes.iter().enumerate() {
            let (body, _) =
                outcome.as_ref().unwrap_or_else(|| panic!("page {i} should have fetched"));
            assert_eq!(
                body,
                &format!("PAGE-{i}"),
                "outcome[{i}] must be page {i}'s body regardless of which fetch completed first"
            );
        }
    }

    #[tokio::test]
    async fn fetch_batch_returns_none_for_an_unreachable_url() {
        // Nothing listens on this loopback port — connection is refused
        // immediately, giving a deterministic failure outcome.
        let http = reqwest::Client::new();
        let outcomes = fetch_batch(&http, &["http://127.0.0.1:1/".to_string()]).await;
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].is_none());
    }
