use super::*;
    use crate::core::scan::TargetKind;
    use std::sync::Arc;

    fn scan_import_router() -> axum::Router {
        axum::Router::new()
            .route("/api/v1/scans/import", axum::routing::post(scan_import))
            .with_state(crate::api::test_state())
    }

    fn scan_create_router() -> axum::Router {
        axum::Router::new()
            .route("/api/v1/scans", axum::routing::post(super::core::scan_create))
            .route(
                "/api/v1/scans/batch",
                axum::routing::post(super::core::scan_batch),
            )
            .with_state(crate::api::test_state())
    }

    /// Regression for the web upload path silently dropping a stealer-row
    /// persistence failure: proves the happy path wires `stealer_rows_parsed`
    /// and `stealer_rows_stored` correctly (equal, matching the fixture's row
    /// count) so a future edit that breaks the tuple threading through
    /// `offload_store`'s closure fails this test rather than only showing up
    /// as a silently wrong count in production. The failure branch itself
    /// (`insert_stealer_rows_batch` returning `Err`) has no data-driven
    /// trigger — `stealer_rows`' schema carries no constraint a well-formed
    /// row can violate, only a genuine I/O fault — so it is covered by direct
    /// code review (mirrors `run_module_guarded`'s already-proven
    /// `tracing::warn!` + safe-default pattern) rather than a forced failure
    /// here.
    #[tokio::test]
    async fn scan_import_reports_stealer_row_counts_on_success() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        const STEALER: &str = "Module: Stealerlogs
Victims:
  [1]
    Log Id:
      abc123
    Credentials:
      [1]
        Username:
          alice
        Password:
          hunter2
        Pwned At:
          2026-05-20T21:00:00Z
    Domains:
      [1]
        example.com
    Credential Count:
      1
";
        let app = scan_import_router();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/scans/import?format=stealerlogs")
            .header("x-hse-csrf", "1")
            .body(Body::from(STEALER))
            .expect("should succeed");
        let resp = app.oneshot(req).await.expect("should succeed");
        assert_eq!(resp.status(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .expect("should succeed");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("should succeed");
        assert_eq!(json["stealer_rows_parsed"], 1);
        assert_eq!(json["stealer_rows_stored"], 1);
        assert_eq!(json["status"], "complete");
    }

    /// REQ-SCANSTATUS-005: the web import commits its row through the shared
    /// `ImportScanRow` lifecycle — `Complete` on success, the response reports
    /// the committed status, and the import leaves this process's in-flight
    /// registry once it has returned.
    #[tokio::test]
    async fn scan_import_commits_its_row_and_leaves_the_in_flight_registry() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;
        let state = crate::api::test_state();
        let app = axum::Router::new()
            .route("/api/v1/scans/import", axum::routing::post(scan_import))
            .with_state(Arc::clone(&state));
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/scans/import?format=stealerlogs")
            .header("x-hse-csrf", "1")
            .body(Body::from(
                "Module: Stealerlogs\nVictims:\n  [1]\n    Log Id:\n      abc123\n    Credentials:\n      [1]\n        Username:\n          alice\n        Password:\n          hunter2\n    Domains:\n      [1]\n        example.com\n    Credential Count:\n      1\n",
            ))
            .expect("should succeed");
        let resp = app.oneshot(req).await.expect("should succeed");
        assert_eq!(resp.status(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .expect("should succeed");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let sid = json["scan_id"].as_str().expect("scan id").to_string();
        let row = state.store.get_scan(&sid).unwrap().expect("row");
        assert_eq!(row.status, crate::core::scan::ScanStatus::Complete);
        assert_eq!(json["status"], row.status.as_str());
        assert!(
            !state.cancellations.lock().contains_key(&sid),
            "the import is no longer in flight once it has returned"
        );
    }

    /// REQ-SCANSTATUS-006: an import stays in flight for as long as its
    /// blocking work runs, not for as long as its HTTP request does. The
    /// registry guard and the semaphore permit lived in the handler's future,
    /// but the import runs under `spawn_blocking`, which keeps going when that
    /// future is dropped — as hyper drops it when the client goes away. The
    /// guard then left the registry mid-import: the `Running` row read as
    /// interrupted, `DELETE` passed its in-flight check (and the import's
    /// commit resurrected the deleted row), and cancel answered 404.
    #[tokio::test]
    async fn an_import_whose_client_went_away_stays_in_flight_until_it_commits() {
        use crate::core::test_support::RefusingStore;
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        let inner: Arc<dyn crate::core::StoragePort> =
            Arc::new(crate::storage::Store::open(":memory:").expect("should succeed"));
        let (gated, pause) = RefusingStore::new(Arc::clone(&inner)).pausing_entity_batch();
        let state = crate::api::test_state_with_store(Arc::new(gated));
        let permits = state.scan_semaphore.available_permits();
        let app = axum::Router::new()
            .route("/api/v1/scans/import", axum::routing::post(scan_import))
            .with_state(Arc::clone(&state));
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/scans/import")
            .header("x-hse-csrf", "1")
            .body(Body::from(
                "Entry #1:\n   \u{2022} email: ops@acme-corp.io\n   \u{2022} name: Ops Lead\n",
            ))
            .expect("should succeed");
        let request = tokio::spawn(app.oneshot(req));
        // The import has written its `Running` row and is inside its entity
        // write when the client goes away.
        let entered = pause.entered;
        let entered = tokio::task::spawn_blocking(move || {
            entered
                .recv_timeout(std::time::Duration::from_secs(30))
                .map(|()| entered)
        })
        .await
        .expect("should succeed")
        .expect("the import reached its entity write");
        request.abort();
        assert!(request.await.is_err(), "the request future was dropped");

        let sid = {
            let registry = state.cancellations.lock();
            let ids: Vec<&String> = registry.keys().collect();
            assert_eq!(ids.len(), 1, "the import is still in flight: {ids:?}");
            ids[0].clone()
        };
        let row = inner.get_scan(&sid).expect("should succeed").expect("row");
        assert_eq!(row.status, crate::core::scan::ScanStatus::Running);
        assert_eq!(
            state.scan_semaphore.available_permits(),
            permits - 1,
            "the import still holds its permit"
        );

        // Let it finish: it commits, then leaves the registry and frees the
        // permit.
        pause.release.send(()).expect("the import is waiting");
        drop(entered);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while state.cancellations.lock().contains_key(&sid) {
            assert!(std::time::Instant::now() < deadline, "the import never ended");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let row = inner.get_scan(&sid).expect("should succeed").expect("row");
        assert_eq!(row.status, crate::core::scan::ScanStatus::Complete);
        assert_eq!(state.scan_semaphore.available_permits(), permits);
    }

    /// Copilot review of #649: the web upload counted relation / correlation
    /// writes with `.is_ok()`, dropped the errors, wrote the scan `Complete`
    /// with `error: None`, and answered with a hardcoded `"status":
    /// "complete"`. A store that refuses the graph must leave the scan
    /// `Complete` (every entity was imported) with the shortfall recorded, and
    /// the response must say `partial` and name it.
    #[tokio::test]
    async fn scan_import_reports_a_refused_graph_as_partial() {
        use crate::core::test_support::{REFUSED_RELATION, RefusingStore};
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        // A URL and its host domain: `derive_all` links them.
        const DOSSIER: &str = "Entry #1:\n   \u{2022} email: ops@acme-corp.io\n   \u{2022} name: Ops Lead\n   \u{2022} domain: acme-corp.io\nhttp://acme-corp.io/login\n";
        let import = |store: Arc<dyn crate::core::StoragePort>| async move {
            let app = axum::Router::new()
                .route("/api/v1/scans/import", axum::routing::post(scan_import))
                .with_state(crate::api::test_state_with_store(store));
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/scans/import")
                .header("x-hse-csrf", "1")
                .body(Body::from(DOSSIER))
                .expect("should succeed");
            let resp = app.oneshot(req).await.expect("should succeed");
            assert_eq!(resp.status(), 200);
            let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
                .await
                .expect("should succeed");
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("should succeed")
        };
        let open = || -> Arc<dyn crate::core::StoragePort> {
            Arc::new(crate::storage::Store::open(":memory:").expect("should succeed"))
        };

        // Control: a store that keeps everything answers `complete`.
        let whole = import(open()).await;
        assert_eq!(whole["status"], "complete", "{whole}");
        assert!(whole["finalise_error"].is_null(), "{whole}");
        let edges = whole["relation_count"].as_u64().expect("relation_count");
        assert!(edges > 0, "the fixture must derive relations: {whole}");

        let inner = open();
        let json = import(Arc::new(
            RefusingStore::new(Arc::clone(&inner)).refusing_relations(),
        ))
        .await;
        assert_eq!(json["status"], "partial", "{json}");
        assert_eq!(json["relation_count"], 0, "{json}");
        let err = json["finalise_error"].as_str().expect("finalise_error named");
        assert_eq!(
            err,
            format!("{edges}/{edges} relations failed to persist: {REFUSED_RELATION}")
        );

        // The stored row — what every export classifies — says the same.
        let sid = json["scan_id"].as_str().expect("scan_id");
        let scan = inner
            .get_scan(sid)
            .expect("should succeed")
            .expect("the scan row exists");
        assert_eq!(scan.status, crate::core::scan::ScanStatus::Complete);
        assert_eq!(scan.error.as_deref(), Some(err));
    }

    /// Review of #649, second round: a correlator pass that failed outright on
    /// the web upload (a refused read of the graph it evaluates) answered
    /// `"status": "complete"` over a scan with no correlations and no error.
    #[tokio::test]
    async fn scan_import_reports_a_failed_correlation_pass_as_partial() {
        use crate::core::test_support::{REFUSED_RELATION_READ, RefusingStore};
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        const DOSSIER: &str = "Entry #1:\n   \u{2022} email: ops@acme-corp.io\n   \u{2022} name: Ops Lead\n";
        let inner: Arc<dyn crate::core::StoragePort> =
            Arc::new(crate::storage::Store::open(":memory:").expect("should succeed"));
        let app = axum::Router::new()
            .route("/api/v1/scans/import", axum::routing::post(scan_import))
            .with_state(crate::api::test_state_with_store(Arc::new(
                RefusingStore::new(Arc::clone(&inner)).refusing_relation_reads(),
            )));
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/scans/import")
            .header("x-hse-csrf", "1")
            .body(Body::from(DOSSIER))
            .expect("should succeed");
        let resp = app.oneshot(req).await.expect("should succeed");
        assert_eq!(resp.status(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
            .await
            .expect("should succeed");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("should succeed");
        assert_eq!(json["status"], "partial", "{json}");
        let expected = format!("correlation pass failed: {REFUSED_RELATION_READ}");
        assert_eq!(json["finalise_error"], expected.as_str(), "{json}");
        let sid = json["scan_id"].as_str().expect("scan_id");
        let scan = inner
            .get_scan(sid)
            .expect("should succeed")
            .expect("the scan row exists");
        assert_eq!(scan.error.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn max_upload_bytes_stays_in_sync_with_the_app_import_authority() {
        // MAX_UPLOAD_BYTES is DEFINED as `app::import::MAX_IMPORT_BYTES as
        // usize` (Pass 30), so the two can't currently diverge by
        // construction — but that derivation is itself a future edit could
        // silently undo (nothing stops reverting this back to its own
        // literal the way it used to be). Pin the relationship so such an
        // edit fails a test, not just loses the guarantee unnoticed.
        assert_eq!(
            u64::try_from(MAX_UPLOAD_BYTES).expect("16 MiB fits in u64"),
            crate::app::import::MAX_IMPORT_BYTES
        );
    }

    #[test]
    fn fold_expansion_signals_counts_exclusions_and_collects_stops() {
        use crate::core::event::{Event, EventKind};
        let evs = vec![
            Event::new(
                "s",
                EventKind::EntityExcluded {
                    kind: "username".into(),
                    value: "arizonambb".into(),
                    reason: "identity_mismatch".into(),
                },
            ),
            Event::new(
                "s",
                EventKind::EntityExcluded {
                    kind: "username".into(),
                    value: "centenario".into(),
                    reason: "identity_mismatch".into(),
                },
            ),
            Event::new(
                "s",
                EventKind::EntityExcluded {
                    kind: "credential".into(),
                    value: "x".into(),
                    reason: "non_pivotable_kind".into(),
                },
            ),
            Event::new(
                "s",
                EventKind::ExpansionStop {
                    reason: "depth exhausted".into(),
                },
            ),
            // An unrelated event must be ignored.
            Event::new(
                "s",
                EventKind::ModuleStart {
                    module: "dns".into(),
                },
            ),
        ];
        let mut sig = crate::audit::LogSignals::default();
        crate::audit::fold_events(&mut sig, &evs);
        assert_eq!(sig.excluded_reasons.get("identity_mismatch"), Some(&2));
        assert_eq!(sig.excluded_reasons.get("non_pivotable_kind"), Some(&1));
        assert_eq!(sig.expansion_stops, vec!["depth exhausted".to_string()]);
    }

    #[test]
    fn wants_candidates_parses_truthy_values_only() {
        use std::collections::HashMap;
        let mut p: HashMap<String, String> = HashMap::new();
        assert!(!wants_candidates(&p), "absent ⇒ hide candidates");
        for v in ["1", "true", "yes", "on"] {
            p.insert("include_candidates".into(), v.into());
            assert!(wants_candidates(&p), "{v} should opt in");
        }
        p.insert("include_candidates".into(), "0".into());
        assert!(!wants_candidates(&p));
    }

    #[test]
    fn build_scan_from_request_valid_is_deterministic() {
        let req = ScanRequest {
            kind: Some(TargetKind::Domain),
            value: "cloudflare.com".to_string(),
            options: Default::default(),
        };
        let (scan, target) = build_scan_from_request(req).expect("valid domain should build");
        assert_eq!(target.value, "cloudflare.com");
        assert_eq!(target.kind, TargetKind::Domain);
        // `scan_id` mixes `unix_now()` (so re-scans of one target get a fresh
        // id), so assert the id's SHAPE — not equality to a recomputed
        // `scan_id(...)`, which flakes across a one-second boundary.
        assert_eq!(scan.id.len(), 64);
        assert!(scan.id.chars().all(|c| c.is_ascii_hexdigit()));
        // The deterministic part — the resolved target — is identical across
        // two builds of the same request.
        let req2 = ScanRequest {
            kind: Some(TargetKind::Domain),
            value: "cloudflare.com".to_string(),
            options: Default::default(),
        };
        let (_, target2) = build_scan_from_request(req2).expect("should succeed");
        assert_eq!(target.kind, target2.kind);
        assert_eq!(target.value, target2.value);
    }

    #[test]
    fn build_scan_from_request_auto_detects_omitted_kind() {
        // Unified scan: no kind supplied → detected from the value, and the
        // scan id keys off the *detected* kind (here, email).
        let req = ScanRequest {
            kind: None,
            value: "alice@proton.me".to_string(),
            options: Default::default(),
        };
        let (scan, target) = build_scan_from_request(req).expect("auto-detected email builds");
        assert_eq!(target.kind, TargetKind::Email);
        assert_eq!(target.value, "alice@proton.me");
        // `scan_id` mixes a timestamp — assert id shape, not a recomputed value.
        assert_eq!(scan.id.len(), 64);
        assert!(scan.id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn build_scan_from_request_profile_overlay_preserves_client_options() {
        // The bug this guards: a full `opts = profile_opts` replace silently
        // discarded every option the client set alongside `"profile"` — here,
        // `modules` and `min_confidence` have no profile equivalent at all, so
        // a request combining a profile with an explicit module allowlist used
        // to have that allowlist vanish without any error or warning.
        let req = ScanRequest {
            kind: Some(TargetKind::Domain),
            value: "cloudflare.com".to_string(),
            options: crate::core::scan::ScanOptions {
                profile: Some("investigate".to_string()),
                modules: Some(vec!["hunter_io".to_string()]),
                min_confidence: Some(0.7),
                ..Default::default()
            },
        };
        let (scan, _) = build_scan_from_request(req).expect("valid request should build");
        assert_eq!(
            scan.options.modules,
            Some(vec!["hunter_io".to_string()]),
            "client-supplied modules must survive a profile overlay"
        );
        assert_eq!(
            scan.options.min_confidence,
            Some(0.7),
            "client-supplied min_confidence must survive a profile overlay"
        );
        // The named profile's own tuning still takes effect (depth is clamped
        // to MAX_DEPTH by `clamp_depth`, same as any other scan).
        let investigate = crate::core::profiles::resolve_profile("investigate").expect("should succeed");
        assert_eq!(scan.options.depth, crate::core::scan::MAX_DEPTH);
        assert_eq!(scan.options.max_entities, investigate.max_entities);
    }

    #[test]
    fn build_scan_from_request_rejects_invalid_target() {
        let req = ScanRequest {
            kind: Some(TargetKind::Domain),
            value: "no-dot-here".to_string(),
            options: Default::default(),
        };
        let err = build_scan_from_request(req).expect_err("should be an error");
        assert!(
            err.starts_with("invalid target: "),
            "error must carry the client-facing prefix, got: {err}"
        );
    }

    #[test]
    fn radar_scan_spec_activates_only_the_live_sensors() {
        // The radar takes no parameters: one fixed sentinel coordinate, always.
        // (`Target::new` canonicalises the coordinate pair; the sensors ignore the
        // value entirely, so the exact sentinel form is immaterial.)
        let (target, opts) = radar_scan_spec();
        assert_eq!(target.kind, TargetKind::Coordinates);
        assert!(
            target.value.starts_with('0') && target.value.contains(','),
            "default radar seed is a 0,0 sentinel coordinate, got {}",
            target.value
        );
        // The sole activation path for live sensors — without this the engine's
        // gate keeps every sensor off, even when named in `modules`.
        assert!(
            opts.allow_live_sensors,
            "radar MUST set allow_live_sensors — it is the only activation path"
        );
        // Autonomous + ambient: passive, single-round, no expansion fan-out.
        assert!(opts.passive_only);
        assert_eq!(opts.depth, 0);
        // It runs EXACTLY the live device-sensor set — nothing target-facing, so
        // it can never piggyback ordinary target scanning.
        let mods = opts.modules.expect("radar pins an explicit module set");
        let want: std::collections::HashSet<&str> =
            crate::core::engine::LOCAL_PASSIVE_MODULES.iter().copied().collect();
        let got: std::collections::HashSet<&str> = mods.iter().map(String::as_str).collect();
        assert_eq!(got, want, "radar runs exactly the live device sensors");

        // Deterministic: the radar has no inputs, so repeated activation must
        // produce byte-identical scan specs.
        let (again, _) = radar_scan_spec();
        assert_eq!(again.kind, target.kind);
        assert_eq!(again.value, target.value);
    }

    /// Every sensor gates on `Coordinates | MacAddress` and ignores the VALUE,
    /// so the removed `?seed=` knob could not change what any of them collected
    /// — it only chose which sentinel kind to label the sweep with. This pins
    /// the property that made removing it safe.
    #[test]
    fn every_live_sensor_accepts_the_radar_sentinel() {
        let (target, _) = radar_scan_spec();
        let registry = crate::modules::registry();
        for name in crate::core::engine::LOCAL_PASSIVE_MODULES {
            let m = registry
                .iter()
                .find(|m| m.name() == *name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            assert!(
                m.accepts(&target),
                "{name} must accept the radar sentinel, or the sweep dispatches nothing"
            );
        }
    }

    // ── `snapshot_still_relevant_to` (stale engine-health-cache attribution) ──

    #[test]
    fn a_snapshot_taken_shortly_after_the_scan_is_relevant() {
        // Audit run moments after the scan finished — the ordinary case.
        assert!(snapshot_still_relevant_to(1_000, 1_000));
        assert!(snapshot_still_relevant_to(1_500, 1_000));
    }

    #[test]
    fn a_snapshot_from_well_before_the_relevance_window_expires_is_relevant() {
        use crate::modules::search_engines::health::DEFAULT_REFRESH_SECS;
        let scan_ts = 1_000;
        let checked_at = scan_ts + DEFAULT_REFRESH_SECS * 2;
        assert!(
            snapshot_still_relevant_to(checked_at, scan_ts),
            "exactly at the 2x-refresh-interval boundary is still relevant"
        );
    }

    #[test]
    fn a_snapshot_from_long_after_the_scan_is_not_relevant() {
        // The exact false-positive scenario the bug named: a scan that ran with
        // full coverage, audited weeks later after engines broke — today's
        // snapshot must NOT be attributed to that old scan's report.
        use crate::modules::search_engines::health::DEFAULT_REFRESH_SECS;
        let scan_ts = 1_000;
        let two_weeks_later = scan_ts + 14 * 24 * 60 * 60;
        assert!(two_weeks_later - scan_ts > DEFAULT_REFRESH_SECS * 2);
        assert!(
            !snapshot_still_relevant_to(two_weeks_later, scan_ts),
            "a snapshot two weeks newer than the scan describes a different era"
        );
    }

    #[test]
    fn a_snapshot_older_than_the_scan_is_never_rejected_here() {
        // The cache hasn't caught up to a just-finished scan yet — that's the
        // cache being incomplete (handled separately by `health::cached()`
        // returning `None`), not a misattribution, so this helper must not
        // reject it.
        assert!(snapshot_still_relevant_to(500, 1_000));
    }

    #[test]
    fn apply_candidate_gate_hides_candidates_unless_opted_in() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::tags::CANDIDATE;
        use std::collections::HashMap;

        let subject = Entity::new(EntityKind::Email, "subject@real.example", 0.9, "s");
        let mut candidate = Entity::new(EntityKind::Email, "stranger@breach.example", 0.5, "s");
        candidate.tag(CANDIDATE);

        // Default (no query params): the quarantined candidate is dropped.
        let mut ents = vec![subject.clone(), candidate.clone()];
        apply_candidate_gate(&mut ents, &HashMap::new());
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].value, "subject@real.example");

        // Opt-in with `?include_candidates=1`: both retained.
        let mut ents = vec![subject, candidate];
        let params = HashMap::from([("include_candidates".to_string(), "1".to_string())]);
        apply_candidate_gate(&mut ents, &params);
        assert_eq!(ents.len(), 2);
    }

    #[test]
    fn confine_graph_to_visible_drops_candidate_nodes_and_their_dangling_edges() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::relation::{Relation, RelationKind};
        use crate::core::tags::CANDIDATE;
        use std::collections::HashMap;

        let subject = Entity::new(EntityKind::Email, "subject@real.example", 0.9, "s");
        let mut candidate = Entity::new(EntityKind::Email, "stranger@breach.example", 0.5, "s");
        candidate.tag(CANDIDATE);
        // Edge subject → candidate: once the candidate NODE is hidden this edge
        // would dangle and re-expose the candidate's UID, so it must go too.
        let edge = Relation::new(
            subject.uid.as_str(),
            candidate.uid.as_str(),
            RelationKind::AssociatedWith,
            0.5,
            "s",
        );

        // Default: candidate node gone AND the edge to it gone.
        let (ents, rels) = confine_graph_to_visible(
            vec![subject.clone(), candidate.clone()],
            vec![edge.clone()],
            &HashMap::new(),
        );
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].value, "subject@real.example");
        assert!(
            rels.is_empty(),
            "the edge to the hidden candidate must be dropped, not left dangling"
        );

        // Opt-in: full graph returned untouched.
        let params = HashMap::from([("include_candidates".to_string(), "on".to_string())]);
        let (ents, rels) =
            confine_graph_to_visible(vec![subject, candidate], vec![edge], &params);
        assert_eq!(ents.len(), 2);
        assert_eq!(rels.len(), 1);
    }

    // ── REQ-SCANOPTS-001: the unknown-option check, through the real route ──

    async fn post_json(router: axum::Router, path: &str, body: &str) -> (u16, String) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("should succeed"),
            )
            .await
            .expect("should succeed");
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("should succeed");
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    /// The defect as an operator meets it: a one-character slip in a scope
    /// control. Pre-fix this returned 202 Accepted and ran a FULL ACTIVE scan
    /// for an operator who asked for a passive one — indistinguishable, in the
    /// response, from the scan they requested.
    #[tokio::test]
    async fn scan_create_rejects_a_misspelled_scope_control() {
        let (status, body) = post_json(
            scan_create_router(),
            "/api/v1/scans",
            r#"{"value":"cloudflare.com","options":{"passive-only":true}}"#,
        )
        .await;
        assert_eq!(status, 400, "a misspelled scope control must not be accepted");
        assert!(
            body.contains("passive-only"),
            "the error must name the offending key, got: {body}"
        );
        assert!(
            body.contains("passive_only"),
            "the error must suggest the intended key, got: {body}"
        );
    }

    /// The control: the same request, spelled correctly, is still accepted.
    /// Without this, the test above would also pass if the seam rejected
    /// every request.
    #[tokio::test]
    async fn scan_create_still_accepts_a_correctly_spelled_option() {
        let (status, body) = post_json(
            scan_create_router(),
            "/api/v1/scans",
            r#"{"value":"cloudflare.com","options":{"passive_only":true}}"#,
        )
        .await;
        assert_eq!(status, 202, "a valid request must still be queued: {body}");
    }

    /// And the second control: an `options`-less request — the documented
    /// "bare `{\"value\": …}` is as thorough as the CLI" shape — is unaffected.
    #[tokio::test]
    async fn scan_create_still_accepts_a_request_with_no_options() {
        let (status, body) = post_json(
            scan_create_router(),
            "/api/v1/scans",
            r#"{"value":"cloudflare.com"}"#,
        )
        .await;
        assert_eq!(status, 202, "an options-less request must still be queued: {body}");
    }

    /// The batch seam is the same authority: one entry's typo is that entry's
    /// error, and does not silently run as a default — nor abort its siblings.
    #[tokio::test]
    async fn scan_batch_reports_a_misspelled_option_per_entry() {
        let (status, body) = post_json(
            scan_create_router(),
            "/api/v1/scans/batch",
            r#"[{"value":"cloudflare.com","options":{"free-only":true}},
                {"value":"mozilla.org","options":{"free_only":true}}]"#,
        )
        .await;
        assert_eq!(status, 202, "the batch itself must still be processed: {body}");
        assert!(
            body.contains("free-only"),
            "the bad entry must report its own key, got: {body}"
        );
        assert!(
            body.contains("scan_id"),
            "the good entry must still have been queued, got: {body}"
        );
    }

    /// A key that is not a transcription of any option gets the full accepted
    /// list — the only in-band documentation of the option names, since no
    /// schema route serves them. The suggestible case must NOT carry it: that
    /// branch exists to keep the common typo's error readable, so both sides
    /// are asserted rather than just the one that happens to fire.
    #[tokio::test]
    async fn an_unsuggestible_option_gets_the_catalogue_and_a_typo_does_not() {
        let (status, body) = post_json(
            scan_create_router(),
            "/api/v1/scans",
            r#"{"value":"cloudflare.com","options":{"stealth_mode":true}}"#,
        )
        .await;
        assert_eq!(status, 400);
        assert!(
            body.contains("Accepted keys for options:") && body.contains("passive_only"),
            "an unsuggestible key must be answered with the catalogue, got: {body}"
        );

        let (_, typo_body) = post_json(
            scan_create_router(),
            "/api/v1/scans",
            r#"{"value":"cloudflare.com","options":{"passive-only":true}}"#,
        )
        .await;
        assert!(
            !typo_body.contains("Accepted keys for options:"),
            "a suggestible key must NOT drag in the whole catalogue, got: {typo_body}"
        );
    }

    // ── REQ-SCANSTATUS-001: the derived `interrupted` flag, through the real routes ──

    /// A `running` row this process holds no handle for reports
    /// `interrupted: true` on both read surfaces; installing the handle — the
    /// state a genuinely in-flight scan is in — flips it to `false`. The row
    /// itself is never rewritten: the same store answers both reads.
    #[tokio::test]
    async fn a_hard_killed_scan_reads_as_interrupted_until_a_process_owns_it() {
        use axum::body::Body;
        use axum::http::Request;
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};
        use tower::ServiceExt as _;

        let state = crate::api::test_state();
        let router = || {
            axum::Router::new()
                .route("/api/v1/scans", axum::routing::get(super::core::scan_list))
                .route("/api/v1/scans/{id}", axum::routing::get(super::core::scan_get))
                .with_state(std::sync::Arc::clone(&state))
        };
        // The row a dead process leaves behind: `running`, no handle anywhere.
        let mut scan = Scan::new("orphan-1", Target::new(TargetKind::Domain, "cloudflare.com"));
        scan.status = ScanStatus::Running;
        state.store.upsert_scan(&scan).expect("should succeed");

        let get = |path: &'static str| {
            let r = router();
            async move {
                let resp = r
                    .oneshot(Request::builder().uri(path).body(Body::empty()).expect("ok"))
                    .await
                    .expect("ok");
                let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.expect("ok");
                serde_json::from_slice::<serde_json::Value>(&bytes).expect("json")
            }
        };

        let one = get("/api/v1/scans/orphan-1").await;
        assert_eq!(one["status"], "running", "the persisted status is untouched");
        assert_eq!(one["interrupted"], true, "no process owns it: {one}");
        let list = get("/api/v1/scans").await;
        assert_eq!(list["scans"][0]["interrupted"], true, "list agrees: {list}");

        // CONTROL: the moment this process owns the scan, it is in flight.
        state
            .cancellations
            .lock()
            .insert("orphan-1".to_string(), crate::core::cancel::CancelHandle::new());
        let one = get("/api/v1/scans/orphan-1").await;
        assert_eq!(one["interrupted"], false, "a held handle means in flight: {one}");
        let list = get("/api/v1/scans").await;
        assert_eq!(list["scans"][0]["interrupted"], false, "list agrees: {list}");
    }

    /// A live-driven scan is run by THIS process, so it must never read
    /// `interrupted` — and, because the one registry now holds it, it is
    /// refused deletion mid-run and cancellable by scan id exactly like a
    /// one-shot scan. The first draft of this fix derived `interrupted` from a
    /// registry only `spawn_scan` filled; on the running binary a healthy live
    /// iteration read `interrupted: true`, `DELETE` returned 200 mid-run and
    /// `cancel` 404 (ledger, REQ-SCANSTATUS-001).
    #[tokio::test]
    async fn a_live_iteration_run_by_this_process_is_in_flight_not_interrupted() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use crate::core::live::{LiveOptions, LiveStatus};
        use crate::core::module::test_support::Gated;
        use crate::core::scan::{ScanOptions, ScanStatus, Target, TargetKind};
        use tower::ServiceExt as _;

        async fn settle<T>(mut probe: impl FnMut() -> Option<T>) -> Option<T> {
            for _ in 0..500 {
                if let Some(v) = probe() {
                    return Some(v);
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            None
        }

        let (module, gate) = Gated::pair();
        let state = crate::api::test_state_with_modules(vec![module]);
        let router = || {
            axum::Router::new()
                .route("/api/v1/scans", axum::routing::get(super::core::scan_list))
                .route(
                    "/api/v1/scans/{id}",
                    axum::routing::get(super::core::scan_get).delete(super::core::scan_delete),
                )
                .route(
                    "/api/v1/scans/{id}/cancel",
                    axum::routing::post(super::core::scan_cancel),
                )
                .with_state(std::sync::Arc::clone(&state))
        };
        let call = |method: Method, path: String| {
            let r = router();
            async move {
                let resp = r
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .body(Body::empty())
                            .expect("ok"),
                    )
                    .await
                    .expect("ok");
                let code = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.expect("ok");
                let body = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap_or(serde_json::Value::Null);
                (code, body)
            }
        };

        let live_id = state.live.start(
            Target::new(TargetKind::Domain, "cloudflare.com"),
            ScanOptions::default(),
            LiveOptions {
                interval_secs: 1,
                iterations: Some(1),
                radar: false,
            },
        );
        let sid = settle(|| {
            state
                .store
                .list_scans(10)
                .ok()?
                .into_iter()
                .find(|s| s.status == ScanStatus::Running)
                .map(|s| s.id)
        })
        .await
        .expect("the iteration reaches `running` while the module is gated");

        // THE lock: a scan this process is running is in flight, whichever
        // path spawned it.
        let (code, one) = call(Method::GET, format!("/api/v1/scans/{sid}")).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(one["status"], "running");
        assert_eq!(one["interrupted"], false, "this process is running it: {one}");
        let (_, list) = call(Method::GET, "/api/v1/scans".into()).await;
        assert_eq!(list["scans"][0]["interrupted"], false, "list agrees: {list}");
        // `/stats` reads the same registry: histogrammed as running, never interrupted.
        let agg = crate::api::handlers::aggregate_scan_stats(
            &state.store.list_scans(10).expect("ok"),
            &crate::api::handlers::in_flight_scan_ids(&state.cancellations),
        );
        assert_eq!(agg.by_status.get("running"), Some(&1), "{agg:?}");
        assert_eq!(agg.by_status.get("interrupted"), None, "{agg:?}");

        // The same registry protects it: no deleting a row the engine is still writing.
        let (code, body) = call(Method::DELETE, format!("/api/v1/scans/{sid}")).await;
        assert_eq!(
            code,
            StatusCode::CONFLICT,
            "a live iteration mid-run must be refused deletion: {body}"
        );

        // …and makes it cancellable by scan id.
        let (code, body) = call(Method::POST, format!("/api/v1/scans/{sid}/cancel")).await;
        assert_eq!(
            code,
            StatusCode::OK,
            "a live iteration is cancellable by its scan id: {body}"
        );
        let ended = settle(|| {
            state
                .store
                .get_scan(&sid)
                .ok()
                .flatten()
                .filter(|s| s.status != ScanStatus::Running)
                .map(|s| s.status)
        })
        .await
        .expect("the cancelled iteration reaches a terminal status");
        assert_eq!(ended, ScanStatus::Aborted);
        settle(|| {
            state
                .live
                .get(&live_id)
                .filter(|s| s.status == LiveStatus::Completed)
                .map(|_| ())
        })
        .await
        .expect("a one-iteration session completes");
        let (_, one) = call(Method::GET, format!("/api/v1/scans/{sid}")).await;
        assert_eq!(one["status"], "aborted");
        assert_eq!(one["interrupted"], false, "a finished row is never interrupted: {one}");

        // The documented recovery — cancel, then delete — now works for a live scan.
        let (code, body) = call(Method::DELETE, format!("/api/v1/scans/{sid}")).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        drop(gate);
    }

    /// The two `/radar/signals*` routes on the shared test state — the real
    /// SQLite store behind `Arc<dyn StoragePort>`, so a reader left off the port,
    /// or a `Store` override forgotten, fails here rather than answering empty in
    /// production.
    fn radar_signals_router(state: Arc<crate::api::AppState>) -> axum::Router {
        axum::Router::new()
            .route(
                "/api/v1/radar/signals",
                axum::routing::get(super::core::radar_signals),
            )
            .route(
                "/api/v1/radar/signals/{network_id}",
                axum::routing::get(super::core::radar_signal_track),
            )
            .with_state(state)
    }

    async fn get_json(app: &axum::Router, uri: &str) -> (u16, serde_json::Value) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn radar_sighting(
        id: &str,
        radio: crate::core::rf::RadioKind,
        source: crate::core::rf::RfSource,
        name: Option<&str>,
        dbm: f64,
        epoch: i64,
    ) -> crate::core::rf::RfSighting {
        let mut s = crate::core::rf::RfSighting::new(id, radio, source);
        s.name = name.map(str::to_string);
        s.signal_dbm = Some(dbm);
        s.observed_epoch = Some(epoch);
        s.latitude = Some(-27.47);
        s.longitude = Some(153.02);
        s.accuracy_m = Some(8.0);
        s
    }

    fn radar_scan(id: &str) -> Scan {
        Scan::new(
            id.to_string(),
            Target::new(
                TargetKind::Coordinates,
                crate::core::scan::RADAR_SENTINEL_COORD_RAW,
            ),
        )
    }

    #[tokio::test]
    async fn radar_signals_defaults_to_the_latest_sweep_and_refuses_before_any_sighting() {
        use crate::core::rf::{RadioKind, RfSource};
        let state = crate::api::test_state();
        let app = radar_signals_router(Arc::clone(&state));

        // Nothing recorded: a refusal carrying the CLI's own hint — not an
        // empty 200, which would read as "nothing around you".
        let (status, body) = get_json(&app, "/api/v1/radar/signals").await;
        assert_eq!(status, 404, "{body}");
        assert_eq!(body["error"], "no RF sightings recorded yet");
        assert!(
            body["detail"]
                .as_str()
                .unwrap_or("")
                .contains("POST /api/v1/radar"),
            "{body}"
        );

        // Sweep A: a named fixed-address AP (00:… — the U/L bit clear), a
        // randomised BLE address (02:… — the bit set), a tower.
        state.store.upsert_scan(&radar_scan("radar-a")).unwrap();
        state
            .store
            .insert_rf_sightings_batch(
                "radar-a",
                &[
                    radar_sighting(
                        "00:1A:2B:3C:4D:5E",
                        RadioKind::Wifi,
                        RfSource::WifiRadar,
                        Some("LabNet"),
                        -45.0,
                        1_700_000_100,
                    ),
                    radar_sighting(
                        "02:11:22:33:44:55",
                        RadioKind::Ble,
                        RfSource::BluetoothRadar,
                        None,
                        -70.0,
                        1_700_000_100,
                    ),
                    radar_sighting(
                        "505-01-678-12345",
                        RadioKind::Cellular,
                        RfSource::CellRadar,
                        None,
                        -90.0,
                        1_700_000_100,
                    ),
                ],
            )
            .unwrap();
        // Sweep B, recorded later but stamped EARLIER: "latest" is the most
        // recently recorded, as `hse signal` resolves it, not the newest clock.
        state.store.upsert_scan(&radar_scan("radar-b")).unwrap();
        state
            .store
            .insert_rf_sightings_batch(
                "radar-b",
                &[radar_sighting(
                    "00:1A:2B:3C:4D:5E",
                    RadioKind::Wifi,
                    RfSource::WifiRadar,
                    Some("LabNet"),
                    -60.0,
                    1_700_000_000,
                )],
            )
            .unwrap();

        let (status, body) = get_json(&app, "/api/v1/radar/signals").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["scan_id"], "radar-b");
        assert_eq!(body["summary"]["sightings"], 1);
        assert_eq!(body["count"], 1);

        // An explicit sweep: the summary the CLI prints, devices strongest
        // first with the address classified, and no vendor for a randomised
        // address.
        let (status, body) = get_json(&app, "/api/v1/radar/signals?scan_id=radar-a").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["summary"]["scan_id"], "radar-a");
        let s = &body["summary"];
        assert_eq!(
            (
                s["sightings"].as_i64(),
                s["devices"].as_i64(),
                s["wifi"].as_i64(),
                s["ble"].as_i64(),
                s["cellular"].as_i64(),
                s["with_position"].as_i64(),
                s["named"].as_i64(),
            ),
            (Some(3), Some(3), Some(1), Some(1), Some(1), Some(3), Some(1)),
            "{s}"
        );
        let devices = body["devices"].as_array().expect("devices");
        let ids: Vec<&str> = devices
            .iter()
            .map(|d| d["network_id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            ["00:1a:2b:3c:4d:5e", "02:11:22:33:44:55", "505-01-678-12345"],
            "strongest first, canonical ids"
        );
        assert_eq!(devices[0]["address"], "fixed");
        assert_eq!(devices[0]["radio"], "wifi");
        assert_eq!(devices[0]["name"], "LabNet");
        assert_eq!(devices[0]["best_signal_dbm"], -45.0);
        assert_eq!(devices[1]["address"], "random");
        assert!(
            devices[1]["vendor"].is_null(),
            "a randomised address names no vendor: {}",
            devices[1]
        );
        assert_eq!(devices[2]["address"], "—");
        assert_eq!(body["total"], 3);
        assert_eq!(body["trackable_only"], false);

        // Fixed addresses only — the one AU-122 definition, through the port.
        let (status, body) =
            get_json(&app, "/api/v1/radar/signals?scan_id=radar-a&trackable=1").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["trackable_only"], true);
        assert_eq!((body["count"].as_u64(), body["total"].as_u64()), (Some(1), Some(1)));
        assert_eq!(body["devices"][0]["network_id"], "00:1a:2b:3c:4d:5e");
        assert_eq!(
            body["summary"]["devices"], 3,
            "the summary still counts the whole sweep"
        );

        // A cap never reads as completeness.
        let (_, body) = get_json(&app, "/api/v1/radar/signals?scan_id=radar-a&limit=2").await;
        assert_eq!((body["count"].as_u64(), body["total"].as_u64()), (Some(2), Some(3)));

        // An unknown sweep is the plain not-found, not the "nothing recorded" hint.
        let (status, body) = get_json(&app, "/api/v1/radar/signals?scan_id=never-ran").await;
        assert_eq!(status, 404, "{body}");
        assert_eq!(body["error"], "not found");
    }

    #[tokio::test]
    async fn radar_signal_track_lists_one_devices_sightings_oldest_first() {
        use crate::core::rf::{RadioKind, RfSource};
        let state = crate::api::test_state();
        let app = radar_signals_router(Arc::clone(&state));
        state.store.upsert_scan(&radar_scan("radar-t")).unwrap();
        // Inserted out of time order, with a second device in the way.
        state
            .store
            .insert_rf_sightings_batch(
                "radar-t",
                &[
                    radar_sighting(
                        "00:1A:2B:3C:4D:5E",
                        RadioKind::Wifi,
                        RfSource::WifiRadar,
                        Some("LabNet"),
                        -52.0,
                        30,
                    ),
                    radar_sighting(
                        "AA:BB:CC:DD:EE:01",
                        RadioKind::BtClassic,
                        RfSource::BluetoothRadar,
                        None,
                        -80.0,
                        30,
                    ),
                    radar_sighting(
                        "00:1A:2B:3C:4D:5E",
                        RadioKind::Wifi,
                        RfSource::WifiRadar,
                        Some("LabNet"),
                        -45.0,
                        10,
                    ),
                    radar_sighting(
                        "00:1A:2B:3C:4D:5E",
                        RadioKind::Wifi,
                        RfSource::WifiRadar,
                        Some("LabNet"),
                        -48.0,
                        20,
                    ),
                ],
            )
            .unwrap();

        // The id as an operator might type it; the answer is canonical.
        let (status, body) = get_json(
            &app,
            "/api/v1/radar/signals/00%3A1A%3A2B%3A3C%3A4D%3A5E?scan_id=radar-t",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["network_id"], "00:1a:2b:3c:4d:5e");
        assert_eq!(body["scan_id"], "radar-t");
        assert_eq!(body["count"], 3);
        let epochs: Vec<i64> = body["sightings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["observed_epoch"].as_i64().unwrap())
            .collect();
        assert_eq!(epochs, [10, 20, 30], "oldest first, whatever the insert order");
        assert_eq!(body["sightings"][0]["signal_dbm"], -45.0);
        assert_eq!(body["sightings"][0]["latitude"], -27.47);

        // Never heard in this sweep: an empty track, because the question was
        // answerable.
        let (status, body) =
            get_json(&app, "/api/v1/radar/signals/00:00:00:00:00:99?scan_id=radar-t").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["count"], 0);

        // No sweep named: the latest, as the list reader defaults.
        let (status, body) = get_json(&app, "/api/v1/radar/signals/aa:bb:cc:dd:ee:01").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["scan_id"], "radar-t");
        assert_eq!(body["count"], 1);

        // An unknown sweep refuses.
        let (status, _) = get_json(
            &app,
            "/api/v1/radar/signals/00:1a:2b:3c:4d:5e?scan_id=never-ran",
        )
        .await;
        assert_eq!(status, 404);
    }

    fn track_router(state: Arc<crate::api::AppState>) -> axum::Router {
        axum::Router::new()
            .route(
                "/api/v1/radar/devices/{network_id}/track",
                axum::routing::get(super::core::radar_device_track),
            )
            .route(
                "/api/v1/radar/recurring",
                axum::routing::get(super::core::radar_recurring),
            )
            .with_state(state)
    }

    #[tokio::test]
    async fn radar_device_track_spans_sweeps_oldest_first_with_the_id_canonicalised() {
        use crate::core::rf::{RadioKind, RfSource};
        let state = crate::api::test_state();
        let app = track_router(Arc::clone(&state));
        for (scan, dbm, epoch) in [("radar-1", -60.0, 100), ("radar-2", -45.0, 300), ("radar-3", -52.0, 200)] {
            state.store.upsert_scan(&radar_scan(scan)).unwrap();
            state
                .store
                .insert_rf_sightings_batch(
                    scan,
                    &[radar_sighting(
                        "00:1A:2B:3C:4D:5E",
                        RadioKind::Wifi,
                        RfSource::WifiRadar,
                        Some("LabNet"),
                        dbm,
                        epoch,
                    )],
                )
                .unwrap();
        }
        let (status, body) = get_json(&app, "/api/v1/radar/devices/00%3A1A%3A2B%3A3C%3A4D%3A5E/track").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["network_id"], "00:1a:2b:3c:4d:5e");
        assert_eq!((body["count"].as_u64(), body["sweeps"].as_u64()), (Some(3), Some(3)));
        let scans: Vec<&str> = body["points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["scan_id"].as_str().unwrap())
            .collect();
        assert_eq!(scans, ["radar-1", "radar-3", "radar-2"], "oldest first across sweeps");
        assert_eq!(body["points"][2]["signal_dbm"], -45.0);
        assert_eq!(body["points"][0]["latitude"], -27.47, "the point is the sighting, flat");

        let (_, body) = get_json(&app, "/api/v1/radar/devices/00:1a:2b:3c:4d:5e/track?limit=2").await;
        assert_eq!((body["count"].as_u64(), body["limit"].as_u64()), (Some(2), Some(2)));
        assert_eq!(body["points"][0]["scan_id"], "radar-3", "the cap keeps the newest two");

        let (status, body) = get_json(&app, "/api/v1/radar/devices/ff:ff:ff:ff:ff:ff/track").await;
        assert_eq!(status, 200);
        assert_eq!(body["count"], 0);
    }

    #[tokio::test]
    async fn radar_recurring_reads_the_sighting_table_and_discloses_legacy_sweeps() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::rf::{RadioKind, RfSource};
        let state = crate::api::test_state();
        let app = track_router(Arc::clone(&state));

        // Two sweeps with sighting rows: a fixed AP heard twice (from two
        // places 200 m apart), a randomised BLE address heard twice, and a
        // fixed classic device the phone is bonded to — the tag lives on the
        // sweep's entity, where AU-117 puts it.
        for (scan, ap_dbm, lat) in [("radar-r1", -70.0, -27.4705), ("radar-r2", -52.0, -27.4723)] {
            state.store.upsert_scan(&radar_scan(scan)).unwrap();
            let mut ap = radar_sighting("00:1A:2B:3C:4D:5E", RadioKind::Wifi, RfSource::WifiRadar, Some("LabNet"), ap_dbm, 1_700_000_000);
            ap.latitude = Some(lat);
            let rnd = radar_sighting("02:11:22:33:44:55", RadioKind::Ble, RfSource::BluetoothRadar, None, -70.0, 1_700_000_000);
            let own = radar_sighting("00:1A:2B:3C:4D:01", RadioKind::BtClassic, RfSource::BluetoothRadar, Some("Car"), -40.0, 1_700_000_000);
            state
                .store
                .insert_rf_sightings_batch(scan, &[ap, rnd, own])
                .unwrap();
            let mut car = Entity::new(EntityKind::MacAddress, "00:1A:2B:3C:4D:01", 0.9, scan);
            car.tag("bluetooth");
            car.tag("bond:bonded");
            state.store.upsert_entity(&car).unwrap();
        }
        // A sweep from before readings were kept: entities only, the same AP.
        state.store.upsert_scan(&radar_scan("radar-r0")).unwrap();
        let mut old_ap = Entity::new(EntityKind::MacAddress, "00:1A:2B:3C:4D:5E", 0.9, "radar-r0");
        old_ap.tag(crate::core::tags::WIFI_AP);
        state.store.upsert_entity(&old_ap).unwrap();

        let (status, body) = get_json(&app, "/api/v1/radar/recurring?min=2").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!((body["sweeps"].as_u64(), body["legacy_sweeps"].as_u64()), (Some(3), Some(1)), "{body}");
        let devices = body["devices"].as_array().expect("devices");
        assert_eq!(devices.len(), 1, "the randomised address and the bonded car never recur: {body}");
        let ap = &devices[0];
        assert_eq!(ap["mac"], "00:1a:2b:3c:4d:5e");
        assert_eq!(ap["name"], "LabNet");
        assert_eq!(ap["sweeps_seen"], 3, "the legacy sweep still counts for recurrence");
        assert_eq!(ap["best_signal_dbm"], -52.0, "the strongest level any sweep heard");
        assert_eq!(ap["distinct_positions"], 2, "two places 200 m apart");
        assert_eq!(body["count"], 1);
    }

    #[tokio::test]
    async fn radar_disruptions_reads_the_link_records_and_the_access_points_heard() {
        use crate::core::link::LinkState;
        use crate::core::rf::{RadioKind, RfSource};
        let state = crate::api::test_state();
        let app = axum::Router::new()
            .route(
                "/api/v1/radar/disruptions",
                axum::routing::get(super::core::radar_disruptions),
            )
            .with_state(Arc::clone(&state));

        // Sweep 1 (older, on the network), sweep 2 (newer, off it while the
        // same access point is heard at −48), and an old sweep with no link
        // record at all. `radar_scan` gives them the sentinel target the
        // history lists; `Scan::new` stamps `started_at` now, so the order is
        // fixed explicitly below.
        let mut s1 = radar_scan("radar-l1");
        s1.started_at = 1_700_000_000;
        let mut s2 = radar_scan("radar-l2");
        s2.started_at = 1_700_000_060;
        let mut s0 = radar_scan("radar-l0");
        s0.started_at = 1_699_990_000;
        for sc in [&s0, &s1, &s2] {
            state.store.upsert_scan(sc).unwrap();
        }
        let up = LinkState {
            connected: true,
            ssid: Some("LabNet".to_string()),
            bssid: Some("00:1a:2b:3c:4d:5e".to_string()),
            signal_dbm: Some(-45.0),
            ip: Some("192.168.1.20".to_string()),
            link_speed_mbps: Some(433),
            supplicant_state: Some("COMPLETED".to_string()),
            observed_epoch: Some(1_700_000_000),
        };
        state.store.insert_wifi_link("radar-l1", &up).unwrap();
        state
            .store
            .insert_wifi_link("radar-l2", &LinkState::disconnected(Some(1_700_000_060)))
            .unwrap();
        for (scan, epoch) in [("radar-l1", 1_700_000_000), ("radar-l2", 1_700_000_060)] {
            state
                .store
                .insert_rf_sightings_batch(
                    scan,
                    &[radar_sighting(
                        "00:1A:2B:3C:4D:5E",
                        RadioKind::Wifi,
                        RfSource::WifiRadar,
                        Some("LabNet"),
                        -48.0,
                        epoch,
                    )],
                )
                .unwrap();
        }

        let (status, body) = get_json(&app, "/api/v1/radar/disruptions").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            (
                body["sweeps"].as_u64(),
                body["connected_sweeps"].as_u64(),
                body["disconnected_sweeps"].as_u64(),
                body["unrecorded_sweeps"].as_u64()
            ),
            (Some(2), Some(1), Some(1), Some(1)),
            "{body}"
        );
        let kinds: Vec<&str> = body["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["forced_disconnect", "outage"], "{body}");
        let forced = &body["findings"][0];
        assert_eq!(forced["bssid"], "00:1a:2b:3c:4d:5e");
        assert_eq!(forced["ssid"], "LabNet");
        assert_eq!(forced["heard_dbm"], -48.0);
        assert_eq!(forced["scan_id"], "radar-l2");
        assert!(
            forced["advice"].as_str().unwrap_or("").contains("in range"),
            "every finding carries its advice: {forced}"
        );
        assert_eq!(body["count"], 2);
    }
