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
            .unwrap_err()
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
    fn auth_scheme_equality_and_clone() {
        let a = AuthScheme::Bearer;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(AuthScheme::Bearer, AuthScheme::XApiKey);
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
