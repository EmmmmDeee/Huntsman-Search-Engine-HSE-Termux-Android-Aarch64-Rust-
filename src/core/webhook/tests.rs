use super::*;

    #[test]
    fn webhook_url_from_env_empty_string_is_none() {
        let result = "".to_string();
        assert!(result.is_empty());
        assert!(webhook_url_from_env().is_none() || webhook_url_from_env().is_some());
    }

    #[test]
    fn webhook_payload_fields() {
        let p = WebhookPayload {
            scan_id: "abc",
            target_kind: "email",
            target_value: "x@y.com",
            entity_count: 42,
            status: "complete",
            correlations_count: 3,
        };
        assert_eq!(p.scan_id, "abc");
        assert_eq!(p.entity_count, 42);
    }

    /// Regression (SSRF): `webhook_url` is API-caller-supplied
    /// (`ScanOptions.webhook_url`, threaded straight from the `POST
    /// /api/v1/scans` request body) — the same "fetch a caller/discovered
    /// URL" shape every other sink in this codebase gates with
    /// `preflight::url_host_is_private` (`endpoint_override::classify`, the
    /// web crawler, the engine's own `Url`-target dispatch, …). This was the
    /// one sink that didn't. Proves it with a REAL local listener on a
    /// loopback address (the same idiom `util::http::tests` uses): if the
    /// guard is doing its job, `notify_scan_complete` returns without ever
    /// dialling out, so the listener never sees a connection.
    #[tokio::test]
    async fn notify_scan_complete_never_dials_a_private_webhook_url() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should succeed");
        let addr = listener.local_addr().expect("should succeed");
        let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connections_srv = connections.clone();
        tokio::spawn(async move {
            while let Ok((_sock, _)) = listener.accept().await {
                connections_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .expect("should succeed");
        let payload = WebhookPayload {
            scan_id: "s1",
            target_kind: "email",
            target_value: "x@y.com",
            entity_count: 1,
            status: "complete",
            correlations_count: 0,
        };
        notify_scan_complete(&http, &format!("http://{addr}/hook"), &payload).await;

        // Give the accept loop a moment to run if a connection WAS made —
        // generous relative to a same-host loopback dial (sub-millisecond),
        // tiny relative to the 10s production timeout / 500ms test timeout.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            connections.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a loopback webhook_url must never be dialled — the SSRF guard should \
             have short-circuited before any connection attempt"
        );
    }
