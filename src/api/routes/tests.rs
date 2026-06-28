use super::*;

    #[test]
    fn loopback_recognised() {
        assert!(is_loopback_bind("127.0.0.1:8080"));
        assert!(is_loopback_bind("127.1.2.3:9000"));
        assert!(is_loopback_bind("localhost:8080"));
        assert!(is_loopback_bind("[::1]:8080"));
        assert!(is_loopback_bind("::1"));
    }

    #[test]
    fn non_loopback_rejected() {
        assert!(!is_loopback_bind("0.0.0.0:8080"));
        assert!(!is_loopback_bind("192.168.1.10:8080"));
        assert!(!is_loopback_bind("10.0.0.5:8080"));
        assert!(!is_loopback_bind("example.com:8080"));
    }

    #[test]
    fn host_allowlist_covers_loopback_aliases_and_rejects_rebind() {
        let set = host_allowlist("127.0.0.1:8080").expect("loopback bind has an allowlist");
        // The names a user legitimately types — all accepted.
        for h in [
            "127.0.0.1:8080",
            "localhost:8080",
            "[::1]:8080",
            "localhost",
            "127.0.0.1",
        ] {
            assert!(set.contains(h), "{h} must be allowed");
        }
        // A DNS-rebind Host (the attacker's domain) is NOT in the set.
        assert!(!set.contains("evil.example.com:8080"));
        assert!(!set.contains("evil.example.com"));
    }

    #[test]
    fn host_allowlist_is_none_for_non_loopback_bind() {
        // A 0.0.0.0 bind is an explicit operator choice to expose the API; the
        // valid Host set is the box's own (unknowable) addresses, so no guard.
        assert!(host_allowlist("0.0.0.0:8080").is_none());
    }

    #[test]
    fn loopback_edge_cases() {
        assert!(is_loopback_bind("localhost"));
        assert!(!is_loopback_bind("localhostx:8080"));
        assert!(!is_loopback_bind(""));
    }

    #[test]
    fn cors_loopback_includes_localhost_alias() {
        let layer = build_cors_layer("127.0.0.1:8080");
        let _ = layer;
    }

    #[test]
    fn cors_non_loopback_excludes_localhost() {
        let layer = build_cors_layer("192.168.1.5:8080");
        let _ = layer;
    }

    #[test]
    fn cors_ipv6_loopback() {
        let layer = build_cors_layer("[::1]:8080");
        let _ = layer;
    }

    #[test]
    fn state_changing_methods_classified() {
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(is_state_changing(&m), "{m} mutates state");
        }
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!is_state_changing(&m), "{m} is read-only");
        }
    }

    #[test]
    fn token_bucket_throttles_then_refills() {
        use std::net::{IpAddr, Ipv4Addr};
        // Tiny bucket: capacity 2, 1 token/sec, so the third immediate call is
        // denied; then rewinding the bucket's clock ~1.1s restores one token.
        let rl = RateLimiter::new(2.0, 1.0);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(rl.try_acquire(ip), "1st within capacity");
        assert!(rl.try_acquire(ip), "2nd within capacity");
        assert!(!rl.try_acquire(ip), "3rd exceeds capacity → denied");
        {
            let mut b = rl.buckets.lock();
            if let Some(bucket) = b.get_mut(&ip) {
                bucket.last_refill -= std::time::Duration::from_millis(1100);
            }
        }
        assert!(rl.try_acquire(ip), "a token refilled after ~1s");
    }

    #[test]
    fn retry_after_constant_matches() {
        // The `429` header literal must equal the numeric constant (a const fn
        // can't format it), so bumping the constant can't silently leave the
        // header stale.
        assert_eq!(
            const_retry_after(),
            RATE_LIMIT_RETRY_AFTER_SECS.to_string(),
            "Retry-After literal must track RATE_LIMIT_RETRY_AFTER_SECS"
        );
    }

    #[test]
    fn if_none_match_hits_star_exact_and_list() {
        let etag = concat!("\"", env!("CARGO_PKG_VERSION"), "\"");
        assert!(if_none_match_hit("*", etag), "wildcard matches");
        assert!(if_none_match_hit(etag, etag), "exact match");
        assert!(
            if_none_match_hit(&format!("\"old\", {etag}"), etag),
            "match within a comma list"
        );
        assert!(!if_none_match_hit("\"old\"", etag), "different tag misses");
        assert!(!if_none_match_hit("", etag), "empty header misses");
    }

    // ── Airtight, offline-by-construction local console ────────────────────────
    //
    // The console is a self-contained binary that, on the project's flaky-
    // cellular phone target, must talk to nothing but itself: no CDN, no font
    // host, no analytics beacon, no exfiltration path for the sensitive findings
    // it holds. The integration tests assert the strict CSP directives are
    // PRESENT on served responses; these source-level tests assert nothing
    // external was ADDED — a gap a `contains("connect-src 'self'")` check leaves
    // open, since `connect-src 'self' https://exfil.example` contains it too.

    /// Tokens a CSP fetch/navigation directive may legitimately carry. Anything
    /// else — notably an `http(s)://` host or a `*` wildcard — would let the
    /// console reach an external origin, the one thing this policy forbids.
    const ALLOWED_CSP_TOKENS: &[&str] = &["'self'", "'unsafe-inline'", "'none'", "data:"];

    #[test]
    fn csp_names_no_external_origin() {
        for needle in ["http://", "https://", "//", "*"] {
            assert!(
                !CONTENT_SECURITY_POLICY.contains(needle),
                "CSP must name no external origin/wildcard, found {needle:?}: \
                 {CONTENT_SECURITY_POLICY}"
            );
        }
    }

    #[test]
    fn csp_directives_use_only_self_or_inline_tokens() {
        for directive in CONTENT_SECURITY_POLICY.split(';') {
            let mut parts = directive.split_whitespace();
            let Some(name) = parts.next() else { continue };
            for token in parts {
                assert!(
                    ALLOWED_CSP_TOKENS.contains(&token),
                    "CSP directive {name:?} carries a non-self token {token:?}"
                );
            }
        }
    }

    #[test]
    fn permissions_policy_denies_phone_sensors() {
        // Every powerful feature must be present with an empty `()` allowlist.
        for feature in ["camera", "microphone", "geolocation", "usb", "bluetooth"] {
            assert!(
                PERMISSIONS_POLICY.contains(&format!("{feature}=()")),
                "Permissions-Policy must deny {feature}: {PERMISSIONS_POLICY}"
            );
        }
        // A non-empty allowlist would grant the feature — none may appear.
        assert!(
            !PERMISSIONS_POLICY.contains("=(self)") && !PERMISSIONS_POLICY.contains("=*"),
            "Permissions-Policy must grant nothing: {PERMISSIONS_POLICY}"
        );
    }

    /// Any external (`http(s)://` or protocol-relative `//host`) resource the
    /// embedded SPA auto-loads via `<script src>`, `<link href>`, or `<img src>`.
    /// Navigational `<a href>` links and the SVG `xmlns` identifier are not
    /// resource loads and are intentionally not inspected.
    fn external_resource_refs(html: &str) -> Vec<String> {
        fn attr_value<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
            for q in ['"', '\''] {
                let needle = format!("{attr}={q}");
                if let Some(p) = tag.find(&needle) {
                    let rest = &tag[p + needle.len()..];
                    if let Some(e) = rest.find(q) {
                        return Some(&rest[..e]);
                    }
                }
            }
            None
        }
        let mut hits = Vec::new();
        for (tag, attr) in [("<script", "src"), ("<link", "href"), ("<img", "src")] {
            let mut idx = 0;
            while let Some(rel) = html[idx..].find(tag) {
                let start = idx + rel;
                let end = html[start..].find('>').map_or(html.len(), |e| start + e);
                if let Some(v) = attr_value(&html[start..end], attr) {
                    let v = v.trim();
                    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("//")
                    {
                        hits.push(format!("{tag} {attr}={v:?}"));
                    }
                }
                idx = end;
            }
        }
        hits
    }

    #[test]
    fn embedded_spa_auto_loads_nothing_external() {
        let hits = external_resource_refs(SPA_HTML);
        assert!(
            hits.is_empty(),
            "the embedded SPA must auto-load no external resource (CDN/font/\
             beacon); found: {hits:?}"
        );
    }

    #[test]
    fn external_resource_scanner_flags_a_cdn_but_not_a_local_or_anchor() {
        // Guard the guard: the scanner must catch a real external resource load,
        // ignore same-origin ones, and ignore navigational <a> links.
        let sample = r#"
            <link rel="stylesheet" href="https://cdn.example/x.css">
            <script src="/static/app.js"></script>
            <link rel="icon" href="data:image/svg+xml,<svg/>">
            <a href="https://github.com/example">repo</a>
            <img src="//cdn.example/pixel.gif">
        "#;
        let hits = external_resource_refs(sample);
        assert_eq!(
            hits.len(),
            2,
            "exactly the CDN css + protocol-relative img: {hits:?}"
        );
        assert!(hits.iter().any(|h| h.contains("cdn.example/x.css")));
        assert!(hits.iter().any(|h| h.contains("//cdn.example/pixel.gif")));
        assert!(
            !hits.iter().any(|h| h.contains("github.com")),
            "<a> is not a resource"
        );
        assert!(
            !hits.iter().any(|h| h.contains("/static/")),
            "same-origin is fine"
        );
    }

    #[test]
    fn spa_scan_preset_modules_are_all_registered() {
        // The New-Scan use-case presets (Footprint / Investigate / …) select their
        // module set by name from a hard-coded `pick:m=>['a','b',…].includes(m.name)`
        // list in the SPA. A renamed or removed module silently drops out of the
        // preset — the name simply stops matching — quietly shrinking coverage in
        // the web UI with no error anywhere. Pin every preset name to the live
        // registry so a module rename/removal can't rot a preset unnoticed: the
        // same no-silent-drift guard the README / MODULES.md counts already carry.
        let registered: std::collections::BTreeSet<&str> =
            crate::modules::registry().iter().map(|m| m.name()).collect();

        let mut checked = 0usize;
        let mut idx = 0;
        while let Some(rel) = SPA_HTML[idx..].find("pick:m=>[") {
            let start = idx + rel + "pick:m=>[".len();
            let end = SPA_HTML[start..]
                .find(']')
                .map_or(SPA_HTML.len(), |e| start + e);
            for raw in SPA_HTML[start..end].split(',') {
                let name = raw.trim().trim_matches(['\'', '"']);
                if name.is_empty() {
                    continue;
                }
                assert!(
                    registered.contains(name),
                    "New-Scan preset references unknown module `{name}` — update \
                     src/web/spa.html after a module rename/removal"
                );
                checked += 1;
            }
            idx = end;
        }
        // Sanity floor: the literal-list presets (Footprint + Investigate) name
        // ~20 modules between them, so a refactor that drops the `pick:m=>[…]`
        // syntax can't quietly make this guard vacuous.
        assert!(
            checked >= 20,
            "expected the SPA scan presets to name many modules, saw {checked}"
        );
    }

    // ── CORS allow-headers regression guard ────────────────────────────────────

    #[test]
    fn cors_allow_headers_never_includes_csrf() {
        // The `/scans/import` CSRF defence depends on `X-HSE-CSRF` NOT being
        // CORS-allow-listed: its absence forces a cross-origin import to preflight
        // and fail. A future maintainer who "fixes CORS" by allow-listing it would
        // silently re-open the import to a forgeable simple request. Pin it.
        for h in CORS_ALLOW_HEADERS {
            assert_ne!(
                h.as_str(),
                "x-hse-csrf",
                "X-HSE-CSRF must never be in the CORS allow-headers set — it is the \
                 import CSRF token, and allow-listing it removes the import CSRF defence"
            );
        }
        // Positive control: the SPA's same-origin requests need `Content-Type`
        // cross-checked, so the set is not vacuously empty.
        assert!(
            CORS_ALLOW_HEADERS.contains(&header::CONTENT_TYPE),
            "CONTENT_TYPE must remain in the CORS allow-headers set"
        );
    }

    // ── Rate-limiter token bucket: per-peer isolation ──────────────────────────

    #[test]
    fn rate_limiter_keys_buckets_per_peer() {
        // Two distinct peers must not share a bucket — exhausting one leaves the
        // other untouched (matters on a non-loopback bind serving many clients).
        let limiter = RateLimiter::new(1.0, 0.0);
        let a = IpAddr::from([127, 0, 0, 1]);
        let b = IpAddr::from([127, 0, 0, 2]);
        assert!(limiter.try_acquire(a));
        assert!(!limiter.try_acquire(a), "peer A exhausted");
        assert!(
            limiter.try_acquire(b),
            "peer B has its own bucket, unaffected by A"
        );
    }

    // ── Rate-limit request classifier ──────────────────────────────────────────

    #[test]
    fn rate_limit_classifier_charges_mutations_and_heavy_gets_only() {
        // Every state-changing method is charged, regardless of path.
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(
                is_rate_limited_request(&m, "/api/v1/scans"),
                "{m} must be rate-limited"
            );
        }
        // Compute-heavy analysis GETs are charged.
        for path in [
            "/api/v1/scans/abc/network",
            "/api/v1/scans/abc/benchmark",
            "/api/v1/scans/abc/communities",
            "/api/v1/scans/abc/report.json",
            "/api/v1/scans/abc/graph.gexf",
        ] {
            assert!(
                is_rate_limited_request(&Method::GET, path),
                "{path} must be rate-limited"
            );
        }
        // Cheap reads and the long-lived SSE streams are NEVER charged.
        for path in [
            "/api/v1/health",
            "/api/v1/version",
            "/api/v1/scans",
            "/api/v1/scans/abc/events",
            "/api/v1/live/abc/events",
            "/",
            "/favicon.svg",
            "/static/jquery.min.js",
        ] {
            assert!(
                !is_rate_limited_request(&Method::GET, path),
                "{path} must NOT be rate-limited"
            );
        }
    }

    // ── DNS-rebind guard: h2 :authority is enforced as HOST ─────────────────────

    #[tokio::test]
    async fn h2_authority_is_enforced_as_host() {
        // On HTTP/2 the browser sends `:authority`, not `Host`; axum/hyper map it
        // into the `HeaderMap`'s HOST entry before our middleware runs. This test
        // pins that the allowlist enforces that mapped value: a request carrying a
        // mismatched Host (the post-mapping state of a rebind `:authority`) is
        // rejected with 403, while an allow-listed one passes.
        use axum::routing::get;
        use tower::ServiceExt as _;

        let allowed = Arc::new(host_allowlist("127.0.0.1:8080").expect("loopback allowlist"));
        let app = Router::new()
            .route("/probe", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    enforce_host_allowlist(Arc::clone(&allowed), req, next)
                },
            ));

        // Allow-listed authority (mapped to HOST) passes.
        let ok = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "127.0.0.1:8080")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(ok.status(), StatusCode::OK);

        // Rebind authority (attacker domain mapped to HOST) is rejected.
        let rebind = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/probe")
                    .header(header::HOST, "evil.example.com:8080")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(rebind.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn host_less_mutation_is_rejected_but_safe_get_passes() {
        // A legitimate browser always sends Host/:authority, so a header-less
        // mutation is never a real same-origin SPA request — reject it. A
        // header-less GET (non-browser local tooling) is tolerated.
        use axum::routing::get;
        use tower::ServiceExt as _;

        let allowed = Arc::new(host_allowlist("127.0.0.1:8080").expect("loopback allowlist"));
        let app = Router::new()
            .route("/probe", get(|| async { "ok" }).post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    enforce_host_allowlist(Arc::clone(&allowed), req, next)
                },
            ));

        // Host-less GET: tolerated.
        let safe = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/probe")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(safe.status(), StatusCode::OK);

        // Host-less POST: rejected.
        let mutation = app
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::POST)
                    .uri("/probe")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(mutation.status(), StatusCode::FORBIDDEN);
    }
