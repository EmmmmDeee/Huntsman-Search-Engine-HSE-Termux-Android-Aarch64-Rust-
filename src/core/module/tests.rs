use super::*;
    use crate::core::entity::{Entity, EntityKind};

    fn make_ctx(keys: HashMap<String, String>) -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys,
            cancel: crate::core::cancel::CancelHandle::new(),
        }
    }

    // ── ModuleContext::key ───────────────────────────────────────────────

    #[test]
    fn key_returns_ok_when_present() {
        let ctx = make_ctx(HashMap::from([(
            "HUNTSMAN_FOO".to_string(),
            "bar".to_string(),
        )]));
        let val = ctx.key("HUNTSMAN_FOO").unwrap();
        assert_eq!(val, "bar");
    }

    #[test]
    fn key_returns_missing_key_error_when_absent() {
        let ctx = make_ctx(HashMap::new());
        let err = ctx.key("NO_SUCH_KEY").unwrap_err();
        assert!(
            matches!(err, Error::MissingKey(ref k) if k == "NO_SUCH_KEY"),
            "expected MissingKey, got: {err:?}",
        );
    }

    // ── ModuleContext::key_opt ───────────────────────────────────────────

    #[test]
    fn key_opt_returns_some_when_present() {
        let ctx = make_ctx(HashMap::from([(
            "HUNTSMAN_FOO".to_string(),
            "bar".to_string(),
        )]));
        assert_eq!(ctx.key_opt("HUNTSMAN_FOO"), Some("bar"));
    }

    #[test]
    fn key_opt_returns_none_when_absent() {
        let ctx = make_ctx(HashMap::new());
        assert_eq!(ctx.key_opt("NO_SUCH_KEY"), None);
    }

    // ── ModuleResult ────────────────────────────────────────────────────

    #[test]
    fn new_result_is_empty() {
        let r = ModuleResult::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn with_capacity_is_empty_but_pre_allocated() {
        let r = ModuleResult::with_capacity(16);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.entities.capacity() >= 16);
    }

    #[test]
    fn push_increments_len() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"));
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn extend_adds_multiple_entities() {
        let mut r = ModuleResult::new();
        let entities = vec![
            Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"),
            Entity::new(EntityKind::Domain, "example.com", 0.7, "s"),
            Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "s"),
        ];
        r.extend(entities);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn is_empty_and_len_track_correctly() {
        let mut r = ModuleResult::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);

        r.push(Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"));
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);

        r.push(Entity::new(EntityKind::Domain, "x.com", 0.6, "s"));
        assert_eq!(r.len(), 2);
    }

    // ── ModuleCost serde ────────────────────────────────────────────────

    #[test]
    fn module_cost_as_str_matches_serde() {
        // DRIFT GUARD. `as_str` exists so dependency.rs / the API need no second
        // ModuleCost→string mapping; the canonical identifier and the serde wire
        // form must therefore never diverge. `EVERY` is walked by an arm-less
        // `match` (no `_`), so ADDING A VARIANT fails to compile here until the
        // author lists it — the runtime loop then proves as_str == serde for the
        // whole set. Without this an added `ModuleCost` whose `as_str()` typo'd
        // (e.g. "sub" vs serde "subscription") would ship undetected.
        const EVERY: &[ModuleCost] = &[ModuleCost::Free, ModuleCost::KeyGated, ModuleCost::Paid];
        for &cost in EVERY {
            match cost {
                ModuleCost::Free | ModuleCost::KeyGated | ModuleCost::Paid => {}
            }
            let json = serde_json::to_string(&cost).unwrap();
            assert_eq!(
                json.trim_matches('"'),
                cost.as_str(),
                "{cost:?}: as_str() diverged from its serde snake_case form",
            );
        }
    }

    #[test]
    fn module_cost_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&ModuleCost::Free).unwrap(),
            "\"free\""
        );
        assert_eq!(
            serde_json::to_string(&ModuleCost::KeyGated).unwrap(),
            "\"key_gated\""
        );
        assert_eq!(
            serde_json::to_string(&ModuleCost::Paid).unwrap(),
            "\"paid\""
        );
    }

    // ── ModuleInfo via trait defaults ────────────────────────────────────

    /// Minimal module that only overrides the required methods, leaving all
    /// defaulted methods at their trait-provided values.
    struct StubModule;

    #[async_trait]
    impl Module for StubModule {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn priority(&self) -> u8 {
            42
        }
        fn accepts(&self, _target: &Target) -> bool {
            true
        }
        async fn process(&self, _target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
    }

    #[test]
    fn module_info_reflects_trait_defaults() {
        let m = StubModule;
        let info = m.info();

        assert_eq!(info.name, "stub");
        assert_eq!(info.priority, 42);
        assert_eq!(info.cost, ModuleCost::Free);
        assert!(!info.passive);
        assert_eq!(info.description, "");
        assert_eq!(info.category, ModuleCategory::Other);
        // StubModule.accepts() returns true for every kind, so the
        // probe-based default surfaces every TargetKind in `consumes`.
        assert_eq!(
            info.consumes.len(),
            crate::core::dependency::ALL_TARGET_KINDS.len()
        );
        assert!(info.produces.is_empty());
        // Category Other claims no ATT&CK Reconnaissance technique.
        assert!(info.attack_techniques.is_empty());
    }

    struct CategorisedModule;
    #[async_trait]
    impl Module for CategorisedModule {
        fn name(&self) -> &'static str {
            "categorised"
        }
        fn priority(&self) -> u8 {
            10
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(&self, _t: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn category(&self) -> ModuleCategory {
            ModuleCategory::DnsRecon
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain];
            KINDS
        }
    }

    #[test]
    fn override_category_and_produces_propagate_to_info() {
        let m = CategorisedModule;
        let info = m.info();
        assert_eq!(info.category, ModuleCategory::DnsRecon);
        assert_eq!(info.consumes, vec!["domain"]);
        assert_eq!(info.produces, vec!["ip_address", "domain"]);
        // ATT&CK techniques default from the category (DnsRecon → DNS/WHOIS/cert
        // open-technical-database recon), with every ID a real catalogue entry.
        assert_eq!(
            info.attack_techniques,
            crate::core::attack::techniques_for_category(ModuleCategory::DnsRecon)
        );
        assert!(
            info.attack_techniques
                .iter()
                .all(|id| crate::core::attack::technique(id).is_some())
        );
    }

    #[test]
    fn module_category_as_str_round_trips_serde() {
        // DRIFT GUARD (was NON-EXHAUSTIVE: only 4 of 14 variants). `as_str` is
        // the canonical machine-readable identifier and MUST equal the serde
        // wire form for EVERY variant — the API emits one and the SPA parses the
        // other. `EVERY` is walked by an arm-less `match` (no `_`), so adding a
        // `ModuleCategory` variant fails to compile here until it is listed; the
        // runtime body then proves, for the whole set: (1) as_str() == the serde
        // snake_case form, and (2) that form deserializes back to the same
        // variant. A typo'd new arm (e.g. `People => "person"` vs serde
        // "people") is now caught in CI instead of silently shipping.
        const EVERY: &[ModuleCategory] = &[
            ModuleCategory::DnsRecon,
            ModuleCategory::Breach,
            ModuleCategory::Infrastructure,
            ModuleCategory::Search,
            ModuleCategory::Geo,
            ModuleCategory::Social,
            ModuleCategory::Email,
            ModuleCategory::Phone,
            ModuleCategory::Corporate,
            ModuleCategory::Threat,
            ModuleCategory::Sensor,
            ModuleCategory::People,
            ModuleCategory::Web,
            ModuleCategory::Other,
        ];
        for &cat in EVERY {
            // Compile-time tripwire: NO `_` arm, so a new variant breaks this
            // match until the author extends EVERY above.
            match cat {
                ModuleCategory::DnsRecon
                | ModuleCategory::Breach
                | ModuleCategory::Infrastructure
                | ModuleCategory::Search
                | ModuleCategory::Geo
                | ModuleCategory::Social
                | ModuleCategory::Email
                | ModuleCategory::Phone
                | ModuleCategory::Corporate
                | ModuleCategory::Threat
                | ModuleCategory::Sensor
                | ModuleCategory::People
                | ModuleCategory::Web
                | ModuleCategory::Other => {}
            }
            let json = serde_json::to_string(&cat).unwrap();
            // serde-snake_case strips quotes
            let body = json.trim_matches('"');
            assert_eq!(
                body,
                cat.as_str(),
                "{cat:?}: as_str() diverged from its serde snake_case form",
            );
            // Full round-trip: the wire form must deserialize back to `cat`.
            let back: ModuleCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cat, "{cat:?} did not round-trip through serde");
        }
    }

    // ── ModuleResult::or_hard_failure ────────────────────────────────────

    #[test]
    fn or_hard_failure_errors_when_empty_and_a_hard_failure_occurred() {
        // The exact regression this shares across every multi-sub-fetch
        // module (T2.111 ip_reputation, T2.114 niamonx): previously this
        // situation silently returned Ok(empty) — the operator could not
        // tell a real outage from a clean negative.
        let empty = ModuleResult::new();
        let err = Error::module("test", "boom");
        let out = empty.or_hard_failure(Some(err));
        assert!(
            out.is_err(),
            "an empty result with a genuine failure must surface as Err, not a hollow Ok"
        );
    }

    #[test]
    fn or_hard_failure_stays_ok_when_empty_and_no_failure_occurred() {
        // A real clean negative (every sub-fetch ran fine, found nothing)
        // must NOT be turned into a spurious error.
        let empty = ModuleResult::new();
        let out = empty.or_hard_failure(None);
        assert!(out.is_ok(), "a clean negative must stay Ok(empty)");
        assert!(out.unwrap().is_empty());
    }

    #[test]
    fn or_hard_failure_preserves_evidence_despite_a_sibling_failure() {
        // If one sub-fetch hard-fails but ANOTHER already found real
        // evidence, that evidence must never be thrown away just because a
        // sibling sub-fetch also failed.
        let mut with_data = ModuleResult::new();
        with_data.push(Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "test-scan"));
        let err = Error::module("test", "a sibling sub-fetch failed");
        let out = with_data.or_hard_failure(Some(err));
        assert!(
            out.is_ok(),
            "real evidence from one sub-fetch must survive a sibling's failure"
        );
        assert_eq!(out.unwrap().len(), 1);
    }
