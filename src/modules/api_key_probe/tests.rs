use super::*;

    #[test]
    fn accepts_api_key_only() {
        let m = ApiKeyProbe;
        assert!(m.accepts(&Target::new(TargetKind::ApiKey, "test-key-12345678")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn probe_count_matches_services() {
        let p = probes();
        assert!(p.len() >= 23);
        for probe in &p {
            assert!(!probe.service.is_empty());
            assert!(!probe.env_var.is_empty());
            assert!(probe.env_var.starts_with("HUNTSMAN_"));
        }
    }

    #[test]
    fn every_probe_transmits_its_key_only_over_https() {
        // These probes send a LIVE secret API key to a validation endpoint —
        // whether in the URL query or an auth header. A plaintext `http://`
        // endpoint would leak the credential to any on-path observer, so the
        // table must be https-only (it is; this guards against a future
        // contributor adding an http endpoint), and every probe must actually
        // carry the key — via the URL or at least one header — or it would send
        // an unauthenticated request and report a valid key as invalid.
        const SENTINEL: &str = "SENTINELKEY0123456789";
        for probe in &probes() {
            let (url, headers) = super::probes::request_for(probe.def, SENTINEL);
            assert!(
                url.starts_with("https://"),
                "{}: probe URL is not https ({url}) — would leak the key in plaintext",
                probe.service
            );
            assert!(
                url.contains(SENTINEL) || !headers.is_empty(),
                "{}: probe carries the key neither in the URL nor a header — it would \
                 send an unauthenticated request",
                probe.service
            );
            assert!(
                !probe.category.is_empty(),
                "{}: empty category",
                probe.service
            );
        }
    }

    #[test]
    fn probe_request_uses_the_single_sourced_service_def_not_a_duplicate_table() {
        // Regression: this probe table and `secrets::key_pool::validation`'s
        // key-validation probe used to be two independently-maintained
        // tables (this one in api_key_probe/probes.rs, the other in
        // secrets::service_defs) that had already drifted on 3 real endpoints —
        // securitytrails, virustotal, and greynoise each tested a DIFFERENT
        // URL in the two tables, one of them wrong. Now both read the same
        // `ServiceDef`, so a probe's derived URL is exactly `test_url` (plus
        // the key for a query-param placement) — these three assert the
        // corrected, no-longer-divergent values specifically.
        let expected: &[(&str, &str)] = &[
            ("securitytrails", "https://api.securitytrails.com/v1/ping"),
            ("virustotal", "https://www.virustotal.com/api/v3/users/me"),
            ("greynoise", "https://api.greynoise.io/v3/ip/8.8.8.8"),
        ];
        let p = probes();
        for (service, expected_url) in expected {
            let probe = p
                .iter()
                .find(|p| p.service == *service)
                .unwrap_or_else(|| panic!("{service}: expected a probe"));
            let (url, _headers) = super::probes::request_for(probe.def, "SENTINELKEY");
            assert_eq!(url, *expected_url, "{service}: probe URL");
        }
    }

    #[test]
    fn probe_services_and_env_vars_are_unique() {
        // A duplicate service or env var means one probe shadows the other:
        // wasted requests, or a key validated against the wrong endpoint.
        let p = probes();
        let mut services = std::collections::HashSet::new();
        let mut env_vars = std::collections::HashSet::new();
        for probe in &p {
            assert!(
                services.insert(probe.service),
                "duplicate probe service: {}",
                probe.service
            );
            assert!(
                env_vars.insert(probe.env_var),
                "duplicate probe env var: {}",
                probe.env_var
            );
        }
    }

    #[test]
    fn error_detection() {
        let err1: Value = serde_json::json!({"error": "Invalid API key"});
        assert!(is_error_response(&err1));

        let err2: Value = serde_json::json!({"success": false});
        assert!(is_error_response(&err2));

        let ok: Value = serde_json::json!({"plan": "free", "credits": 100});
        assert!(!is_error_response(&ok));
    }

    #[test]
    fn is_free_and_active() {
        let m = ApiKeyProbe;
        // Network-reaching: probes seeded keys against live service endpoints,
        // so it must NOT be passive (a passive_only scan has to skip it).
        assert!(!m.is_passive());
        assert_eq!(m.cost(), ModuleCost::Free);
    }

    #[tokio::test]
    async fn timed_out_process_aborts_in_flight_probe_tasks_not_just_detaches_them() {
        // Regression: `process()` used to collect probe tasks in a
        // `Vec<JoinHandle<_>>`. Dropping a `Vec` of bare `JoinHandle`s only
        // DETACHES each task — it keeps running (and its kill_on_drop curl
        // subprocess keeps the OS process alive) even after the engine's outer
        // per-module `tokio::time::timeout` declares the module "timed out" and
        // drops the `process()` future. Switching to a `JoinSet` fixes this:
        // dropping a `JoinSet` aborts every task still running in it. Proven
        // here without any network/curl: a synthetic slow "probe" sets a flag
        // only if allowed to run to completion.
        //
        // Uses REAL time (not paused): a paused-clock + `time::advance` setup
        // was tried first and produced a false pass for *both* the buggy
        // Vec<JoinHandle> pattern and the JoinSet fix — `time::advance` does
        // not drive forward a task whose JoinHandle was already dropped and
        // is no longer being polled by anyone, so it never discriminated
        // between the two. Verified directly (a throwaway harness outside
        // this crate) that with real time the buggy pattern DOES set the
        // flag (proving this test would have caught it) while the fix
        // doesn't — only the real-time version is trustworthy here.
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = completed.clone();

        let probe_future = async {
            let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            tasks.spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            while tasks.join_next().await.is_some() {}
        };

        // Mirrors `run_module_guarded`'s outer timeout wrapping `process()`,
        // here shorter than the spawned task's sleep so it fires first.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(20), probe_future).await;

        // Real-time wait past the spawned task's sleep — every opportunity
        // for it to wrongly set the flag if it were merely detached.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        assert!(
            !completed.load(std::sync::atomic::Ordering::SeqCst),
            "JoinSet must abort its in-flight task when dropped by the outer \
             timeout — a bare Vec<JoinHandle<_>> would let it run to completion"
        );
    }

    // ── T2.123: a total transport failure must not read as "no keys found" ──

    #[test]
    fn all_probes_failed_to_execute_only_when_nothing_ran_and_nothing_matched() {
        // Every probe failed to execute AND nothing was identified → error.
        assert!(all_probes_failed_to_execute(23, 23, 0));
        // At least one probe RAN (match or honest negative) → clean negative,
        // not an error, even though the rest failed to execute.
        assert!(!all_probes_failed_to_execute(22, 23, 0));
        // Something WAS identified → never an error, regardless of failures.
        assert!(!all_probes_failed_to_execute(23, 23, 1));
        // No probes at all → not an error (nothing to fail).
        assert!(!all_probes_failed_to_execute(0, 0, 0));
    }

    /// A one-shot local HTTP server that answers with a fixed JSON body — a real
    /// (not mocked) endpoint for the curl-subprocess `probe_endpoint` to hit.
    async fn serve_once_json(body: &'static str) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn probe_endpoint_reports_transport_failure_on_an_unreachable_host() {
        // T2.123 regression: previously a probe that could not execute returned
        // the same `None` a genuine non-match did. Port 1 has nothing listening,
        // so curl exits non-zero (connection refused) — a real transport failure
        // that must now be reported as such, not folded into a miss.
        let outcome = probe_endpoint("http://127.0.0.1:1/", "test-key-12345678", &[]).await;
        assert!(
            matches!(outcome, ProbeOutcome::TransportFailure),
            "an unreachable host must be a TransportFailure, not an Executed miss"
        );
    }

    #[tokio::test]
    async fn probe_endpoint_reports_executed_when_the_host_answers() {
        // The host answered with a real body — that is `Executed(Some(..))`, a
        // negative the caller can evaluate, NOT a transport failure.
        let addr = serve_once_json(r#"{"plan":"free"}"#).await;
        let outcome = probe_endpoint(&format!("http://{addr}/"), "test-key-12345678", &[]).await;
        match outcome {
            ProbeOutcome::Executed(Some(body)) => assert!(body.contains("free")),
            other @ (ProbeOutcome::Executed(None) | ProbeOutcome::TransportFailure) => {
                let _ = other;
                panic!("a host that answered with a JSON body must be Executed(Some(..))")
            }
        }
    }
