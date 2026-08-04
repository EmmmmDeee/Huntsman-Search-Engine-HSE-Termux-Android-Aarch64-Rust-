use super::*;

    #[tokio::test]
    async fn fetch_returns_none_for_bad_url() {
        let r = fetch("https://256.256.256.256/nonexistent", 3000).await;
        assert!(r.is_none());
    }

    #[test]
    fn ua_pool_has_four_entries() {
        assert_eq!(UA_POOL.len(), 4);
    }

    #[test]
    fn curl_max_time_arg_honours_a_sub_second_budget_precisely() {
        // Regression: this used to be `(timeout_ms / 1000).max(3)`, which
        // floored ANY sub-3s budget up to a flat 3 seconds — a caller with
        // 500ms left got a curl call allowed to run 6x longer than its actual
        // remaining deadline. curl accepts fractional `--max-time` seconds, so
        // the real budget is now passed through exactly instead of rounded up.
        assert_eq!(curl_max_time_arg(500), "0.500");
        assert_eq!(curl_max_time_arg(1_500), "1.500");
        assert_eq!(curl_max_time_arg(3_000), "3.000");
    }

    #[test]
    fn curl_max_time_arg_never_emits_zero() {
        // curl treats `--max-time 0` as NO LIMIT — the opposite of what a
        // near-zero remaining budget means here. A near-empty or literally
        // zero budget must still floor to a tiny positive value, never "0".
        assert_eq!(curl_max_time_arg(0), "0.001");
        assert_ne!(curl_max_time_arg(0), "0.000");
    }

    #[test]
    fn fetch_hardening_pins_protocols_and_bounds_redirects_and_size() {
        // Locks the security-critical content of the single-sourced hardening
        // args so a careless future edit that loosens the protocol allow-list,
        // unbounds redirects, or drops the size cap fails here.
        let a = FETCH_HARDENING_ARGS;
        let has = |pair: [&str; 2]| a.windows(2).any(|w| w == pair);
        // Protocol allow-list on both the initial request and every redirect hop
        // (blocks file://, gopher://, dict:// SSRF pivots).
        assert!(
            has(["--proto", "=http,https"]),
            "missing --proto allow-list"
        );
        assert!(
            has(["--proto-redir", "=http,https"]),
            "missing --proto-redir allow-list"
        );
        // Redirects bounded (defence-in-depth against redirect loops / chains).
        assert!(has(["--max-redirs", "5"]), "redirects not bounded");
        // Download size capped via the single-sourced constant.
        assert!(
            has(["--max-filesize", CURL_MAX_DOWNLOAD_BYTES]),
            "download size not capped"
        );
        // Connect phase bounded so a dead host fails fast instead of burning the
        // whole --max-time budget.
        assert!(
            has(["--connect-timeout", "15"]),
            "TCP connect phase not bounded"
        );
    }

    // ── SSRF pin (B8: the security-critical path was untested) ─────────

    #[tokio::test]
    async fn ssrf_pin_refuses_private_and_metadata_hosts() {
        // Literal IPs resolve offline (no DNS query) → deterministic, network-
        // free. Each private/reserved host must yield no pin so the caller
        // refuses the fetch (the curl half of the SSRF defense).
        for u in [
            "http://127.0.0.1/x",
            "http://10.0.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/x",                    // IPv6 loopback (bracketed)
            "http://[fc00::1]/x",                // IPv6 ULA
            "http://[::ffff:169.254.169.254]/x", // IPv4-mapped metadata
        ] {
            assert!(
                ssrf_resolve_pin(u).await.is_none(),
                "{u} must be refused as private/reserved"
            );
        }
    }

    #[tokio::test]
    async fn ssrf_pin_allows_public_ip_literal_without_a_pointless_pin() {
        // An IP-literal target is dialled directly by curl (no DNS lookup), so
        // there is no rebinding race and `--resolve` would rewrite nothing. The
        // vetted-public literal must be accepted with an empty arg set rather
        // than a redundant `--resolve host:port:host`.
        for u in ["http://8.8.8.8/x", "http://[2606:4700:4700::1111]/x"] {
            let pin = ssrf_resolve_pin(u)
                .await
                .unwrap_or_else(|| panic!("public literal {u} must be accepted"));
            assert!(pin.is_empty(), "{u} needs no --resolve pin, got {pin:?}");
        }
    }
