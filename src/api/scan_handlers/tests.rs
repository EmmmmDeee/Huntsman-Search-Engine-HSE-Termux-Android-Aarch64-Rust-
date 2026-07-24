use super::*;
    use crate::core::scan::TargetKind;

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
        let (_, target2) = build_scan_from_request(req2).unwrap();
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
        let investigate = crate::core::profiles::resolve_profile("investigate").unwrap();
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
        let err = build_scan_from_request(req).unwrap_err();
        assert!(
            err.starts_with("invalid target: "),
            "error must carry the client-facing prefix, got: {err}"
        );
    }

    #[test]
    fn radar_scan_spec_activates_only_the_live_sensors() {
        // Default (no seed) → GPS/RF ambient survey on a sentinel coordinate.
        // (`Target::new` canonicalises the coordinate pair; the sensors ignore the
        // value entirely, so the exact sentinel form is immaterial.)
        let (target, opts) = radar_scan_spec(None);
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

        // BSSID-anchored variant → MacAddress sentinel, same sensor invariants.
        for seed in ["mac", "mac_address", "bssid"] {
            let (t, o) = radar_scan_spec(Some(seed));
            assert_eq!(t.kind, TargetKind::MacAddress, "seed={seed}");
            assert!(o.allow_live_sensors);
            assert_eq!(
                o.modules.as_deref().map(<[String]>::len),
                Some(crate::core::engine::LOCAL_PASSIVE_MODULES.len())
            );
        }

        // An unknown seed value falls back to the safe default (coordinates),
        // never an arbitrary target kind.
        assert_eq!(
            radar_scan_spec(Some("example.com")).0.kind,
            TargetKind::Coordinates
        );
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
