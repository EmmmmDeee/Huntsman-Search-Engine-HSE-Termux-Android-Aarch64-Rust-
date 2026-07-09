use super::*;
    use crate::core::scan::{ScanOptions, TargetKind};

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
    fn build_scan_from_request_sanitizes_a_non_finite_min_expand_confidence() {
        // Regression (PROBLEM_TREE T2.35): a JSON request body whose
        // `options.min_expand_confidence` overflows to a non-finite value
        // (e.g. an oversized number literal) used to reach `Scan::new(..).
        // with_options(opts)` unsanitized, get persisted by `scan_create`'s
        // own `upsert_scan` call BEFORE the engine ever runs, and then
        // permanently fail to deserialize on every future `get_scan` (a
        // plain, non-Option f64 can't round-trip JSON `null`, which is what
        // `serde_json` silently serialises a non-finite float as). Every
        // request-derived `Scan` must carry a finite value by construction.
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let req = ScanRequest {
                kind: Some(TargetKind::Domain),
                value: "cloudflare.com".to_string(),
                options: ScanOptions {
                    min_expand_confidence: bad,
                    ..Default::default()
                },
            };
            let (scan, _) = build_scan_from_request(req).expect("valid domain should build");
            assert!(
                scan.options.min_expand_confidence.is_finite(),
                "{bad} must not survive into the built Scan"
            );
        }
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
        // to MAX_DEPTH by `sanitize`, same as any other scan).
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
