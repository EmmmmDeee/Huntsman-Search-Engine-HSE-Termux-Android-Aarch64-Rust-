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
        // Regression: this probe table and `util::key_pool::validation`'s
        // key-validation probe used to be two independently-maintained
        // tables (this one in api_key_probe/probes.rs, the other in
        // util::service_defs) that had already drifted on 3 real endpoints —
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

        let err3: Value = serde_json::json!({"valid": false});
        assert!(
            is_error_response(&err3),
            "dead/rejected keys with valid:false must be detected (numverify, etc.)"
        );

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
        use crate::util::http::test_server::{Canned, serve};
        let base = serve(vec![Canned::json(200, r#"{"plan":"free"}"#)]).await;
        let outcome = probe_endpoint(&base, "test-key-12345678", &[]).await;
        match outcome {
            ProbeOutcome::Executed(Some(reply)) => {
                assert!(reply.body.contains("free"));
                assert_eq!(reply.status, "200", "the status rides with the body");
            }
            other @ (ProbeOutcome::Executed(None) | ProbeOutcome::TransportFailure) => {
                let _ = other;
                panic!("a host that answered with a JSON body must be Executed(Some(..))")
            }
        }
    }

    // ── REQ-KEYPROBE-002: only an answer that accepts the key validates it ──
    //
    // `probe_endpoint` ran `curl -s` with no status capture, and without `-f`
    // curl exits 0 for a 401 exactly as for a 200, so every refusal reached
    // `process()` as an ordinary answer. Only the body heuristic
    // `is_error_response` then stood between it and a `validated` ApiKey at
    // VERY_HIGH_PLUSPLUS plus a service-domain pivot, and it read `error` only
    // as a string: VirusTotal's documented 401 carries an `error` OBJECT, so any
    // key at all was reported as a live VirusTotal credential. Hunter's
    // `errors` list and Netlas' auth-failure 400 passed the same way.

    /// VirusTotal's answer to a wrong key: `401 WrongCredentialsError` in its
    /// documented error envelope (`docs.virustotal.com/reference/errors`). The
    /// `message` text is illustrative; the envelope and the code are the vendor's.
    const VT_WRONG_KEY: &str =
        r#"{"error":{"code":"WrongCredentialsError","message":"Wrong API key"}}"#;

    /// An answered probe, for the pure verdict tests.
    fn answer(status: &str, body: &str) -> Answer {
        Answer {
            status: status.to_string(),
            body: body.to_string(),
        }
    }

    #[tokio::test]
    async fn a_virustotal_refusal_is_an_answer_but_never_a_validated_key() {
        use crate::util::http::test_server::{Canned, serve};
        let base = serve(vec![Canned::json(401, VT_WRONG_KEY)]).await;
        // Through the real curl subprocess: a parser test alone could agree with
        // itself while curl wrote something else.
        let ProbeOutcome::Executed(Some(refusal)) =
            probe_endpoint(&base, "not-a-virustotal-key-0123", &[]).await
        else {
            panic!("a 401 is the host answering: not a transport failure, not an empty answer");
        };
        assert_eq!(
            refusal.status, "401",
            "the status the host sent must reach the verdict"
        );
        assert!(
            accepted_body("virustotal", &refusal).is_none(),
            "a key VirusTotal refused must not be reported as a validated VirusTotal key"
        );
    }

    #[test]
    fn a_refusal_only_the_status_carries_is_still_a_refusal() {
        // Hunter's error envelope is an `errors` LIST (hunter.io/api-documentation/v2,
        // "Errors": "401 - Unauthorized: No valid API key was provided"; the id
        // and details text here are illustrative). Netlas answers a dead key with
        // a 400 whose body `util::http`'s AUTH_400_SIGNATURES records as observed
        // live. Neither body carries a field the heuristic reads.
        let refusals = [
            (
                "hunter",
                answer(
                    "401",
                    r#"{"errors":[{"id":"authentication_failed","code":401,"details":"No user found for the API key supplied"}]}"#,
                ),
            ),
            (
                "netlas",
                answer(
                    "400",
                    r#"{"detail":"Request had invalid authorization credentials: API key not found"}"#,
                ),
            ),
        ];
        for (service, refusal) in &refusals {
            let body: Value = serde_json::from_str(&refusal.body).expect("fixture is JSON");
            assert!(
                !is_error_response(&body),
                "{service}: control: the body heuristic alone cannot see this refusal"
            );
            assert!(
                accepted_body(service, refusal).is_none(),
                "{service}: a key the service refused must not be reported as validated"
            );
        }
    }

    #[test]
    fn an_answer_that_settles_nothing_about_the_key_is_not_a_validation() {
        // AbuseIPDB's documented error body, verbatim (docs.abuseipdb.com, "Error
        // Handling"). A 422 says nothing about whether the key is good, so it
        // cannot prove it good; the shared verdict reads it Indeterminate, as it
        // reads a throttle or an outage.
        let unsettled = answer(
            "422",
            r#"{"errors":[{"detail":"The max age in days must be between 1 and 365.","status":422}]}"#,
        );
        assert!(accepted_body("abuseipdb", &unsettled).is_none());
    }

    #[test]
    fn a_dead_key_reported_inside_a_200_body_is_a_refusal() {
        // Criminal IP reports a dead or exhausted key as an in-body `status` on
        // an HTTP 200 (`service_defs::body_rejects_key`, mirroring
        // `modules::criminal_ip`'s live cascade). A 2xx gate of this module's
        // own would pass it; the shared verdict does not.
        for status in [401, 402, 429] {
            let dead = answer("200", &format!(r#"{{"status":{status}}}"#));
            assert!(
                accepted_body("criminal_ip", &dead).is_none(),
                "in-body status {status} is a dead key, not a validated one"
            );
        }
    }

    #[test]
    fn a_key_the_service_accepts_is_still_reported_validated() {
        // The guard against over-correcting. VirusTotal's 200 for its own key
        // (the shape its probe parser reads), and ONYPHE's success body, which
        // carries `"error": 0` (0 = Success in ONYPHE's error-code table, see
        // `modules::onyphe`).
        let accepted = [
            (
                "virustotal",
                answer(
                    "200",
                    r#"{"data":{"attributes":{"quotas":{"api_requests_daily":{"allowed":500}}}}}"#,
                ),
            ),
            (
                "onyphe",
                answer("200", r#"{"count":1,"error":0,"status":"ok","results":[]}"#),
            ),
        ];
        for (service, acceptance) in &accepted {
            assert!(
                accepted_body(service, acceptance).is_some(),
                "{service}: an answer that accepts the key must still validate it"
            );
        }
    }

    #[test]
    fn an_error_object_is_an_error_response_but_a_scalar_error_marker_is_not() {
        // `error` was read only as a string, so VirusTotal's object envelope read
        // as no error at all. The status verdict now refuses VirusTotal's own 401
        // first; this arm keeps a 2xx body that IS an error envelope from proving
        // a key good.
        let vt: Value = serde_json::from_str(VT_WRONG_KEY).expect("fixture is JSON");
        assert!(is_error_response(&vt));
        // Over-correction guards: ONYPHE's success body carries `error: 0`, and a
        // `null` or empty `error` names no failure.
        for not_an_error in [
            serde_json::json!({"count": 1, "error": 0, "status": "ok"}),
            serde_json::json!({"data": {}, "error": null}),
            serde_json::json!({"data": {}, "error": {}}),
        ] {
            assert!(!is_error_response(&not_an_error), "{not_an_error}");
        }
    }

/// The identified-services report must be deterministic.
///
/// `identified` is filled inside the `join_next` loop, which resolves in
/// COMPLETION order — network-race order, not spawn order. That order reached
/// the operator verbatim in the evidence headline and the `services_matched`
/// attribute, so two runs against the same key and the same services could
/// print them in different orders and a diff of two reports showed a change
/// where nothing had changed.
#[test]
fn identified_services_are_reported_in_a_stable_order() {
    // One `identified` row: (service, category, parsed info pairs).
    type Row = (&'static str, &'static str, Vec<(String, String)>);

    // Two arrival orders of the SAME three services — what the race produces.
    let mut race_a: Vec<Row> = vec![
        ("virustotal", "malware", vec![]),
        ("shodan", "infra", vec![]),
        ("censys", "infra", vec![]),
    ];
    let mut race_b: Vec<Row> = vec![
        ("censys", "infra", vec![]),
        ("virustotal", "malware", vec![]),
        ("shodan", "infra", vec![]),
    ];

    super::sort_identified_for_report(&mut race_a);
    super::sort_identified_for_report(&mut race_b);

    let names_a: Vec<&str> = race_a.iter().map(|(s, _, _)| *s).collect();
    let names_b: Vec<&str> = race_b.iter().map(|(s, _, _)| *s).collect();

    assert_eq!(
        names_a, names_b,
        "two different completion orders must produce the SAME report"
    );
    assert_eq!(
        names_a,
        vec!["censys", "shodan", "virustotal"],
        "sorted by service name"
    );
}
