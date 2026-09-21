use super::*;
    use crate::core::scan::TargetKind;

    /// The shared in-memory `AppState` every router test builds on. Extracted
    /// so a second route's test cannot drift from the first one's state.
    fn test_state() -> std::sync::Arc<AppState> {
        let store: std::sync::Arc<dyn crate::core::StoragePort> =
            std::sync::Arc::new(crate::storage::Store::open(":memory:").expect("should succeed"));
        let (bus, _rx) = tokio::sync::broadcast::channel(16);
        let engine = std::sync::Arc::new(crate::core::engine::ScanEngine::new(
            Vec::new(),
            std::sync::Arc::clone(&store),
            bus.clone(),
        ));
        let live = crate::core::live::LiveScanner::new(
            std::sync::Arc::clone(&engine),
            bus.clone(),
            reqwest::Client::new(),
            Default::default(),
        );
        std::sync::Arc::new(AppState {
            store,
            engine,
            bus,
            live,
            http: reqwest::Client::new(),
            allow_key_write: false,
            cancellations: std::sync::Arc::new(parking_lot::Mutex::new(
                std::collections::HashMap::new(),
            )),
            scan_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::api::MAX_CONCURRENT_SCANS,
            )),
            update_info: std::sync::Arc::new(std::sync::Mutex::new(
                crate::api::UpdateInfo::default(),
            )),
            cells_import: std::sync::Arc::new(std::sync::Mutex::new(
                crate::api::CellsImportPhase::default(),
            )),
        })
    }

    fn scan_import_router() -> axum::Router {
        axum::Router::new()
            .route("/api/v1/scans/import", axum::routing::post(scan_import))
            .with_state(test_state())
    }

    fn scan_create_router() -> axum::Router {
        axum::Router::new()
            .route("/api/v1/scans", axum::routing::post(super::core::scan_create))
            .route(
                "/api/v1/scans/batch",
                axum::routing::post(super::core::scan_batch),
            )
            .with_state(test_state())
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
            body.contains("Accepted options:") && body.contains("passive_only"),
            "an unsuggestible key must be answered with the catalogue, got: {body}"
        );

        let (_, typo_body) = post_json(
            scan_create_router(),
            "/api/v1/scans",
            r#"{"value":"cloudflare.com","options":{"passive-only":true}}"#,
        )
        .await;
        assert!(
            !typo_body.contains("Accepted options:"),
            "a suggestible key must NOT drag in the whole catalogue, got: {typo_body}"
        );
    }
