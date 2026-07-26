use super::*;

    #[test]
    fn auth_scheme_renders_bearer_header() {
        assert_eq!(
            AuthScheme::Bearer.header_line("abc123"),
            Some("Authorization: Bearer abc123".to_string())
        );
    }

    #[test]
    fn auth_scheme_renders_x_api_key_header() {
        assert_eq!(
            AuthScheme::XApiKey.header_line("abc123"),
            Some("x-api-key: abc123".to_string())
        );
    }

    #[test]
    fn auth_scheme_none_emits_no_header() {
        assert_eq!(AuthScheme::None.header_line("ignored"), None);
    }

    #[tokio::test]
    async fn curl_failure_reports_exit_code_not_opaque_message() {
        // Point at an unroutable host with a tiny timeout so curl exits
        // non-zero (typically 28 timeout, 6/7 resolve/connect, or 60 cert
        // mismatch on an environment that intercepts the connection). The
        // error must carry curl's exit code, not the old opaque "curl failed".
        static C: CurlClient = CurlClient::new("test_seeknow", AuthScheme::None, 1, 3_000);
        let err = C
            .get("https://10.255.255.1/definitely-not-real", "")
            .await
            .expect("should be an error")
            .to_string();
        assert!(
            err.contains("curl exited"),
            "error must surface curl's exit code, got: {err}"
        );
        // The OLD opaque message was the bare literal "curl failed" with no
        // exit code or detail at all — distinct from curl's own diagnostic
        // text (which may itself legitimately mention "curl failed to verify
        // the legitimacy of the server..." for a TLS-cert-mismatch failure, as
        // happens when a network intercepts the connection). Check the exact
        // old opaque form is gone, not a coincidental substring of real detail.
        assert_ne!(
            err, "curl failed",
            "opaque message with no exit code/detail must be gone"
        );
        // `-S`/`--show-error` must accompany `-s`: silent mode alone
        // suppresses curl's own diagnostic text too, leaving only the bare
        // "curl exited N" with no indication of WHY (DNS failure? refused
        // connection? cert mismatch?). A real diagnostic snippet — signalled
        // here by the ": " separator `exec` only appends when `stderr` was
        // non-empty — must be present.
        assert!(
            err.contains("curl exited") && err.contains(": "),
            "error must carry curl's own diagnostic text (requires -S alongside -s), got: {err}"
        );
    }

    #[test]
    fn const_constructor_admits_static_declaration() {
        // The whole point of `const fn new()` is that the caller can
        // declare a `static`. Construct one here so the test fails
        // at compile time if that ever stops being possible.
        static C: CurlClient = CurlClient::new("test_module", AuthScheme::Bearer, 12, 15_000);
        // Field accessors (via methods if added later) would be
        // exercised here. For now the test is a compile-time assertion.
        let _ = &C;
    }

    #[test]
    fn paid_api_transport_requests_compression_but_the_ssrf_fetch_path_does_not() {
        // Potentiation: every CurlClient call (SeekNow, OathNet, …) advertises
        // Accept-Encoding via `--compressed`, so a paid API's JSON transfers
        // ~4x smaller with a byte-identical decompressed body — a direct
        // mobile-data / latency win on Termux.
        assert!(
            CLIENT_BASE_ARGS.contains(&"--compressed"),
            "the trusted paid-API transport must request response compression"
        );
        // Security boundary: `--compressed` must NEVER leak onto the general
        // SSRF fetch path, whose hosts can be attacker-influenced (web crawl)
        // and whose `--max-filesize` cap bounds the COMPRESSED transfer — so a
        // decompression bomb could blow past the intended memory cap there.
        assert!(
            !crate::util::curl::FETCH_HARDENING_ARGS.contains(&"--compressed"),
            "the general (attacker-influenced) fetch path must stay uncompressed \
             so --max-filesize keeps bounding a decompression-bomb"
        );
    }

    #[test]
    fn split_status_separates_the_body_from_the_trailing_code() {
        // Normal JSON body + trailing status line.
        assert_eq!(
            split_status("{\"a\":1}\n200"),
            ("{\"a\":1}".to_string(), 200)
        );
        // A body with INTERNAL newlines is preserved (only the LAST line is the code).
        assert_eq!(
            split_status("line1\nline2\n503"),
            ("line1\nline2".to_string(), 503)
        );
        // Empty body, only the code line.
        assert_eq!(split_status("\n404"), (String::new(), 404));
        // No newline, only a bare code (empty-body edge).
        assert_eq!(split_status("500"), (String::new(), 500));
        // No code at all → status 0 (transient), body preserved verbatim.
        assert_eq!(
            split_status("just text, no code"),
            ("just text, no code".to_string(), 0)
        );
    }

    #[test]
    fn auth_scheme_equality_and_clone() {
        let a = AuthScheme::Bearer;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(AuthScheme::Bearer, AuthScheme::XApiKey);
    }

    #[test]
    fn default_doh_url_is_an_ip_literal_not_a_hostname() {
        // Regression guard for the bootstrap gap: a hostname-based default
        // (`cloudflare-dns.com`) would itself need resolving via the very
        // system resolver the DoH fallback exists to route around, so it
        // provides no self-heal at all during a TOTAL resolver failure (only
        // the narrower "this one provider domain is filtered" case). An IP
        // literal needs no lookup — curl dials it directly.
        let host = url::Url::parse(DEFAULT_DOH_URL)
            .expect("DEFAULT_DOH_URL must be a valid URL")
            .host_str()
            .expect("DEFAULT_DOH_URL must have a host")
            .to_string();
        assert!(
            host.parse::<std::net::IpAddr>().is_ok(),
            "DEFAULT_DOH_URL's host must be an IP literal so reaching it needs no DNS \
             lookup of its own — got {host:?}"
        );
    }

    #[test]
    fn doh_fallback_defaults_on_and_honours_disable_keywords() {
        // Unset → default-on (Cloudflare), so a filtering system resolver
        // self-heals without any operator action.
        assert_eq!(resolve_doh(None), Some(DEFAULT_DOH_URL.to_string()));
        // Explicit disable keywords (case-insensitive, trimmed) turn it off.
        for off in ["off", "OFF", "none", "None", "false", "0", "", "  off  "] {
            assert_eq!(resolve_doh(Some(off)), None, "'{off}' must disable DoH");
        }
        // Any other value is a custom DoH endpoint (trimmed).
        assert_eq!(
            resolve_doh(Some("  https://dns.google/dns-query  ")),
            Some("https://dns.google/dns-query".to_string())
        );
    }

    #[test]
    fn curl_args_normal_path_is_unchanged_and_omits_doh() {
        // With doh_url = None the argument vector must carry the base transport
        // flags, request compression, terminate options with `--`, and NOT
        // contain a resolver flag — i.e. byte-identical to the historical path.
        let args = curl_args("15", Some("x-api-key: k"), None, None, "https://api.example/x");
        assert!(!args.iter().any(|a| a == "--doh-url"), "no DoH on the normal path");
        assert!(args.contains(&"--compressed".to_string()));
        assert!(args.contains(&"x-api-key: k".to_string()));
        // `-w` then `--` then the URL must be the tail, in that order.
        let w = args.iter().position(|a| a == "-w").expect("-w present");
        let dd = args.iter().position(|a| a == "--").expect("-- present");
        assert!(w < dd, "-w must precede --");
        assert_eq!(args.last().expect("should succeed"), "https://api.example/x", "url is last");
    }

    #[test]
    fn curl_args_doh_path_inserts_resolver_flag_with_value() {
        let doh = "https://cloudflare-dns.com/dns-query";
        let args = curl_args("15", None, None, Some(doh), "https://api.example/x");
        let i = args
            .iter()
            .position(|a| a == "--doh-url")
            .expect("--doh-url present on the fallback path");
        assert_eq!(args.get(i + 1).map(String::as_str), Some(doh), "URL follows --doh-url");
        // The resolver flag must sit before the terminating `--` so curl parses it.
        let dd = args.iter().position(|a| a == "--").expect("-- present");
        assert!(i < dd, "--doh-url must precede --");
    }

    #[test]
    fn curl_args_post_body_adds_json_framing() {
        let args = curl_args("15", None, Some("{\"q\":1}"), None, "https://api.example/x");
        assert!(args.windows(2).any(|w| w[0] == "-X" && w[1] == "POST"));
        assert!(args.contains(&"Content-Type: application/json".to_string()));
        assert!(args.windows(2).any(|w| w[0] == "-d" && w[1] == "{\"q\":1}"));
    }

    // Note: the curl-invocation failure path (`Error::module(self.module,
    // "curl failed" | "timeout")`) is intentionally NOT unit-tested here.
    // Such a test would depend on the host's curl version and on `curl
    // not-a-url`'s exact exit code, both of which vary across CI runners
    // and developer machines (e.g. captive-portal DNS that resolves
    // arbitrary hostnames to an HTTP capture page). The failure-path
    // wiring is exercised end-to-end whenever the `see_know` or
    // `oathnet` modules attempt a real call in a network-unreachable
    // test environment.
