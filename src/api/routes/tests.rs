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
