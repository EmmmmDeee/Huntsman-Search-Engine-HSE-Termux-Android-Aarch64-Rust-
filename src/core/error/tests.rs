use super::*;

    #[test]
    fn error_module_constructor() {
        // Pin the EXACT `[module] message` shape, not just substrings: this is a
        // wire form — modules build it via `Error::module(..)` and the engine
        // serialises `e.to_string()` into `EventKind::ModuleError.error` (SSE +
        // persisted dossier) and feeds it to `circuit::record_error`. A reformat
        // (e.g. `{module}: {message}`) would silently change every emitted
        // module-error string; a substring check would not catch it.
        let e = Error::module("dns_resolver", "connection refused");
        assert_eq!(e.to_string(), "[dns_resolver] connection refused");
    }

    #[test]
    fn error_missing_key_display() {
        let e = Error::MissingKey("HUNTSMAN_SHODAN_KEY".into());
        assert!(e.to_string().contains("HUNTSMAN_SHODAN_KEY"));
    }

    #[test]
    fn error_from_json() {
        let bad = serde_json::from_str::<serde_json::Value>("not json");
        let e: Error = bad.expect("should be an error").into();
        assert!(e.to_string().contains("json"));
    }

    #[test]
    fn error_invalid_target_display() {
        let e = Error::InvalidTarget("not-a-valid-ip".into());
        let s = e.to_string();
        assert!(s.contains("invalid target"));
        assert!(s.contains("not-a-valid-ip"));
    }

    #[test]
    fn error_other_is_passthrough_display() {
        let e = Error::Other("custom error message".into());
        assert_eq!(e.to_string(), "custom error message");
    }

    #[test]
    fn error_io_from_std() {
        use std::io;
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let e: Error = io_err.into();
        assert!(e.to_string().starts_with("io:"));
    }

    /// DRIFT GUARD for the crate's user-facing error strings. Every variant's
    /// Display reaches an operator sink (the `ModuleError` SSE event, the
    /// persisted dossier, `/api/v1/logs`), so the format is a wire contract. The
    /// arm-less `match` (no `_`) is a compile-time tripwire: adding an `Error`
    /// variant fails to compile here until its Display is pinned, and the runtime
    /// assertions then prove HSE's own prefix/format contribution for each. The
    /// foreign-wrapped variants (Storage/Io/Json/Http) pin only the prefix HSE
    /// controls, not the inner message.
    #[test]
    fn every_variant_display_is_pinned() {
        fn assert_display(e: &Error) {
            let s = e.to_string();
            match e {
                Error::Storage(_) => assert!(s.starts_with("storage: "), "{s}"),
                Error::Io(_) => assert!(s.starts_with("io: "), "{s}"),
                Error::Json(_) => assert!(s.starts_with("json: "), "{s}"),
                Error::Http(m) => assert_eq!(s, format!("http: {m}")),
                Error::InvalidTarget(m) => assert_eq!(s, format!("invalid target: {m}")),
                Error::MissingKey(m) => assert_eq!(s, format!("missing key: {m}")),
                Error::Module { module, message } => assert_eq!(s, format!("[{module}] {message}")),
                Error::RateLimited(m) => assert_eq!(s, format!("rate limited: {m}")),
                Error::Other(m) => assert_eq!(&s, m),
            }
        }
        // One representative per variant — the constructor list must stay in
        // step with the exhaustive match above.
        assert_display(&Error::Storage(rusqlite::Error::QueryReturnedNoRows));
        assert_display(&Error::Io(std::io::Error::other("x")));
        assert_display(&Error::Json(
            serde_json::from_str::<serde_json::Value>("nope").expect("should be an error"),
        ));
        assert_display(&Error::Http("boom".into()));
        assert_display(&Error::InvalidTarget("1.2.3".into()));
        assert_display(&Error::MissingKey("HUNTSMAN_X".into()));
        assert_display(&Error::module("m", "msg"));
        assert_display(&Error::RateLimited("seek_now: throttled".into()));
        assert_display(&Error::Other("plain".into()));
    }

    /// SECURITY REGRESSION. The `From<reqwest::Error>` conversion MUST strip the
    /// request URL: it carries the upstream API key and the target's PII in its
    /// query string, and `Error::Http`'s Display flows into the verbose log / SSE
    /// event / persisted dossier. A bare `?` on a reqwest call (bypassing the
    /// `send_tagged`/`redact_credentials` helpers) must therefore still be
    /// leak-proof. The `ftp://` scheme keys the URL onto the error offline (no
    /// network), exactly as the sibling `send_tagged` test does.
    #[tokio::test]
    async fn http_conversion_strips_url_so_credentials_and_pii_dont_leak() {
        let transport = reqwest::Client::new()
            .get("ftp://example.invalid/v1/lookup?apikey=SECRETKEY123&q=target@example.com")
            .send()
            .await
            .expect("should be an error");
        // Exercise the crate's `From<reqwest::Error>` (what a bare `?` invokes).
        let e: Error = transport.into();
        let s = e.to_string();
        assert!(s.starts_with("http: "), "unexpected shape: {s}");
        assert!(!s.contains("SECRETKEY123"), "API key leaked via Error::Http: {s}");
        assert!(
            !s.contains("target@example.com"),
            "target PII leaked via Error::Http: {s}"
        );
        assert!(!s.contains("ftp://"), "request URL leaked via Error::Http: {s}");
    }
