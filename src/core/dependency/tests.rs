use super::*;
    use crate::core::module::{Module, ModuleContext, ModuleResult};
    use crate::core::scan::Target;
    use async_trait::async_trait;

    struct EmailToDomain;

    #[async_trait]
    impl Module for EmailToDomain {
        fn name(&self) -> &'static str {
            "email_to_domain"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Email)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::Domain];
            KINDS
        }
    }

    struct DomainToIp;
    #[async_trait]
    impl Module for DomainToIp {
        fn name(&self) -> &'static str {
            "domain_to_ip"
        }
        fn priority(&self) -> u8 {
            40
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain | TargetKind::Url)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::IpAddress];
            KINDS
        }
    }

    fn make_registry() -> Vec<Arc<dyn Module>> {
        vec![
            Arc::new(EmailToDomain),
            Arc::new(DomainToIp),
            Arc::new(DomainToIp), // duplicate to check counts
        ]
    }

    #[test]
    fn build_dispatch_index_for_consumed_kinds() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);

        assert_eq!(g.modules_for(TargetKind::Email).len(), 1);
        assert_eq!(g.modules_for(TargetKind::Domain).len(), 2);
        assert_eq!(g.modules_for(TargetKind::Url).len(), 2);
        assert!(g.modules_for(TargetKind::Coordinates).is_empty());
    }

    #[test]
    fn consumer_count_matches_dispatch_index() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);

        for k in ALL_TARGET_KINDS {
            assert_eq!(
                g.module_count_for(*k),
                g.modules_for(*k).len(),
                "count mismatch for {k:?}"
            );
        }
    }

    #[test]
    fn richness_normalises_to_unit_interval() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);

        let richest = g.richness_for(TargetKind::Domain);
        let poorest = g.richness_for(TargetKind::Coordinates);

        // Two modules consume Domain, max count is 2 → richness = 1.0
        assert!((richest - 1.0).abs() < f64::EPSILON);
        // Zero modules consume Coordinates → richness = 0.0
        assert_eq!(poorest, 0.0);

        // All other kinds are in [0, 1].
        for k in ALL_TARGET_KINDS {
            let r = g.richness_for(*k);
            assert!((0.0..=1.0).contains(&r));
        }
    }

    #[test]
    fn richness_never_panics_on_empty_registry() {
        let modules: Vec<Arc<dyn Module>> = Vec::new();
        let g = ModuleGraph::build(&modules);
        assert_eq!(g.richness_for(TargetKind::Email), 0.0);
        assert_eq!(g.module_count_for(TargetKind::Email), 0);
        assert!(g.modules_for(TargetKind::Email).is_empty());
    }

    #[test]
    fn produced_kinds_collects_unique_entries() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);
        let pk = g.produced_kinds();
        // We register IpAddress (twice) and Domain (once); produced_kinds
        // dedupes to two entries.
        assert_eq!(pk.len(), 2);
        assert!(pk.contains(&EntityKind::Domain));
        assert!(pk.contains(&EntityKind::IpAddress));
    }

    #[test]
    fn summary_includes_every_kind_sorted_by_module_count() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);
        let s = g.to_summary(&modules);
        assert_eq!(s.kinds.len(), ALL_TARGET_KINDS.len());

        // Strictly non-increasing.
        for w in s.kinds.windows(2) {
            assert!(w[0].module_count >= w[1].module_count);
        }
        // Richest first should be Domain or Url (each 2 modules).
        assert!(matches!(s.kinds[0].kind, "domain" | "url"));
    }

    #[test]
    fn summary_edges_carry_consume_and_produce_lists() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);
        let s = g.to_summary(&modules);
        assert_eq!(s.edges.len(), modules.len());

        let etd = s
            .edges
            .iter()
            .find(|e| e.module == "email_to_domain")
            .expect("email_to_domain edge");
        assert_eq!(etd.consumes, vec!["email"]);
        assert_eq!(etd.produces, vec!["domain"]);
    }

    /// A module whose `consumes()`/`produces()` override repeats a kind must be
    /// indexed at most once per kind — otherwise a free module would be
    /// dispatched twice per target (it is exempt from the DispatchLog dedup) and
    /// its consumer_count would be inflated, skewing richness.
    struct DuplicateKindModule;
    #[async_trait]
    impl Module for DuplicateKindModule {
        fn name(&self) -> &'static str {
            "duplicate_kind"
        }
        fn priority(&self) -> u8 {
            60
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn consumes(&self) -> Vec<TargetKind> {
            // Pathological override: the same kind listed twice.
            vec![TargetKind::Domain, TargetKind::Domain]
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::IpAddress];
            KINDS
        }
    }

    #[test]
    fn build_dedups_repeated_kinds_within_a_module() {
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(DuplicateKindModule)];
        let g = ModuleGraph::build(&modules);
        // The module's index appears ONCE in the Domain bucket, not twice.
        assert_eq!(
            g.modules_for(TargetKind::Domain),
            &[0],
            "a module that lists a kind twice must be indexed once"
        );
        assert_eq!(g.module_count_for(TargetKind::Domain), 1);
        // Richness reflects the deduped count (1 of max 1 = full), not an
        // inflated 2.
        assert!((g.richness_for(TargetKind::Domain) - 1.0).abs() < f64::EPSILON);
        // Produced-kind index is likewise deduped to a single entry.
        assert_eq!(g.produced_kinds(), vec![EntityKind::IpAddress]);
    }

    #[test]
    fn consumes_via_probe_finds_kind_gates_in_accepts() {
        let m = EmailToDomain;
        let kinds = consumes_via_probe(&m);
        assert_eq!(kinds, vec![TargetKind::Email]);

        let m2 = DomainToIp;
        let kinds = consumes_via_probe(&m2);
        assert!(kinds.contains(&TargetKind::Domain));
        assert!(kinds.contains(&TargetKind::Url));
    }

    // ── Convex query-value dispatch order ────────────────────────────────────

    use crate::core::module::{ModuleCategory, ModuleCost};

    /// Cheap, keyless, identity-producing query — HIGH convex query value but a
    /// deliberately LOW static priority, so it trails under the plain order and
    /// must LEAD under the convex order.
    struct CheapIdentityModule;
    #[async_trait]
    impl Module for CheapIdentityModule {
        fn name(&self) -> &'static str {
            "cheap_identity"
        }
        fn priority(&self) -> u8 {
            10
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn category(&self) -> ModuleCategory {
            ModuleCategory::Breach
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::Email];
            KINDS
        }
    }

    /// Expensive, terminal (paid scoring) query — LOW convex query value but a
    /// deliberately HIGH static priority, so it leads under the plain order and
    /// must TRAIL under the convex order.
    struct PaidTerminalModule;
    #[async_trait]
    impl Module for PaidTerminalModule {
        fn name(&self) -> &'static str {
            "paid_terminal"
        }
        fn priority(&self) -> u8 {
            90
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn cost(&self) -> ModuleCost {
            ModuleCost::Paid
        }
        fn category(&self) -> ModuleCategory {
            ModuleCategory::Threat
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
            KINDS
        }
    }

    #[test]
    fn convex_order_has_same_membership_as_priority_order() {
        let modules: Vec<Arc<dyn Module>> =
            vec![Arc::new(PaidTerminalModule), Arc::new(CheapIdentityModule)];
        let g = ModuleGraph::build(&modules);
        let mut plain = g.modules_for(TargetKind::Domain).to_vec();
        let mut convex = g.convex_modules_for(TargetKind::Domain).to_vec();
        plain.sort_unstable();
        convex.sort_unstable();
        assert_eq!(
            plain, convex,
            "convex order must dispatch the SAME modules, only reordered"
        );
    }

    #[test]
    fn convex_order_fires_cheap_cascading_query_before_paid_terminal() {
        // Registered paid-first so the plain (priority) order leads with it.
        let modules: Vec<Arc<dyn Module>> =
            vec![Arc::new(PaidTerminalModule), Arc::new(CheapIdentityModule)];
        let g = ModuleGraph::build(&modules);
        let name = |&idx: &usize| modules[idx].name();

        // Plain order: priority 90 (paid_terminal) before priority 10 (cheap).
        let plain: Vec<&str> = g.modules_for(TargetKind::Domain).iter().map(name).collect();
        assert_eq!(plain, vec!["paid_terminal", "cheap_identity"]);

        // Convex order INVERTS it: the cheap, keyless, identity-unlocking query
        // leads despite its lower static priority — max return per unit of budget.
        let convex: Vec<&str> = g
            .convex_modules_for(TargetKind::Domain)
            .iter()
            .map(name)
            .collect();
        assert_eq!(convex, vec!["cheap_identity", "paid_terminal"]);

        // The flag-driven selector returns the matching order for each setting.
        assert_eq!(g.dispatch_order_for(TargetKind::Domain, false), g.modules_for(TargetKind::Domain));
        assert_eq!(
            g.dispatch_order_for(TargetKind::Domain, true),
            g.convex_modules_for(TargetKind::Domain)
        );
    }
