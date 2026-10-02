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

    /// A module that dispatches on `Domain` — but only for a VALUE SHAPE
    /// (`.gov.au`), not a pure `matches!` on `t.kind`, and WITHOUT overriding
    /// `consumes()`. Exactly the shape REQ-CORE-003 documents as a
    /// dispatch-index mis-report risk.
    struct ValueGatedNoOverride;
    #[async_trait]
    impl Module for ValueGatedNoOverride {
        fn name(&self) -> &'static str {
            "value_gated_no_override"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain) && t.value.ends_with(".gov.au")
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
    }

    /// The same value-shape gate, WITH the documented remedy: `consumes()`
    /// overridden to declare the true input set.
    struct ValueGatedWithOverride;
    #[async_trait]
    impl Module for ValueGatedWithOverride {
        fn name(&self) -> &'static str {
            "value_gated_with_override"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain) && t.value.ends_with(".gov.au")
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn consumes(&self) -> Vec<TargetKind> {
            vec![TargetKind::Domain]
        }
    }

    /// REQ-CORE-003 — pin the documented dispatch-index mis-report. `consumes()`
    /// defaults to probing `accepts()` with a single fixed `PROBE_VALUE`, so a
    /// module that gates on the target VALUE (not a pure kind `matches!`) is
    /// mis-read: the probe value won't satisfy its value gate, so the default
    /// `consumes()` omits a kind the module really does dispatch on. The trait
    /// doc requires such modules to override `consumes()`. Pin BOTH halves — the
    /// mis-report and the override remedy — so the contract can't drift silently
    /// (a `PROBE_VALUE` that happened to satisfy a value gate would flip the
    /// first assertion, which is exactly the signal we want).
    #[test]
    fn value_gated_accepts_misreports_consumes_unless_overridden() {
        // The module genuinely dispatches on a real `.gov.au` domain…
        let m = ValueGatedNoOverride;
        assert!(
            m.accepts(&Target::new(TargetKind::Domain, "ato.gov.au")),
            "the module really does dispatch on .gov.au domains"
        );
        // …yet the default `consumes()` — probing with `PROBE_VALUE`, which is
        // not a `.gov.au` domain — MIS-REPORTS: it finds the kind nowhere, so
        // the reported input set is empty.
        assert!(
            consumes_via_probe(&m).is_empty(),
            "the probe mis-reads a value-gated module (the documented risk)"
        );
        assert!(
            m.consumes().is_empty(),
            "the trait default `consumes()` inherits the same mis-report"
        );

        // The documented remedy: override `consumes()` to declare the true set.
        assert_eq!(
            ValueGatedWithOverride.consumes(),
            vec![TargetKind::Domain],
            "overriding consumes() restores the correct dispatch kind"
        );
    }

    /// REQ-CORE-003, prevention half: no REGISTERED module may currently fall
    /// into the mis-report above in its total form. Every module in the live
    /// registry must report a non-empty `consumes()` — a module the probe reads
    /// as consuming nothing would be invisible to the dependency graph and the
    /// dispatch index for every target kind, the symptom of a value-gated
    /// `accepts()` that forgot to override `consumes()` (as
    /// `ValueGatedNoOverride` above demonstrates). This holds today: the
    /// value-gated real modules either override `consumes()` (e.g.
    /// `asic_director`) or their gate admits the probe value; this locks it so a
    /// future value-gated module can't silently ship an empty dispatch index.
    #[test]
    fn every_registered_module_consumes_at_least_one_kind() {
        let empties: Vec<&str> = crate::modules::registry()
            .iter()
            .filter(|m| m.consumes().is_empty())
            .map(|m| m.name())
            .collect();
        assert!(
            empties.is_empty(),
            "these registered modules report an empty consumes() — a value-gated \
             accepts() that must override consumes() (REQ-CORE-003), else they \
             are absent from the dispatch index for every kind: {empties:?}"
        );
    }

    // ── Convex query-value dispatch order ────────────────────────────────────

    use crate::core::module::{ModuleCategory, ModuleCost};

    /// Produces a `Person` — the kind whose EntityKind spelling (`person`) and
    /// TargetKind spelling (`full_name`) differ, which is what broke the graph's
    /// producer→consumer join.
    struct PersonProducerModule;
    #[async_trait]
    impl Module for PersonProducerModule {
        fn name(&self) -> &'static str {
            "person_producer"
        }
        fn priority(&self) -> u8 {
            50
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
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::Person];
            KINDS
        }
    }

    /// Produces only kinds that have NO `TargetKind` — terminal by design, and
    /// therefore indistinguishable from a broken join without `terminal_kinds`.
    struct CredentialModule;
    #[async_trait]
    impl Module for CredentialModule {
        fn name(&self) -> &'static str {
            "credential_producer"
        }
        fn priority(&self) -> u8 {
            50
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
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::Credential];
            KINDS
        }
    }

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

    /// The graph's whole purpose is that a consumer can join a producer to a
    /// consumer. `consumes` speaks [`TargetKind`] and `produces` speaks
    /// [`EntityKind`]; the two agree on nearly every spelling, so a naive string
    /// join looks correct and silently drops the one term where they diverge.
    ///
    /// `EntityKind::Person` is spelled `person`, but dispatch routes it to
    /// `full_name`. 55 of 168 real modules produce `person`, so this single
    /// mismatch made the most connected pivot in the system render as a dead
    /// end. `pivots_to` exists to be joined on; this pins the exact translation.
    #[test]
    fn person_pivots_to_full_name_so_producers_are_not_orphans() {
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(PersonProducerModule)];
        let summary = ModuleGraph::build(&modules).to_summary(&modules);
        let edge = &summary.edges[0];

        // The precondition that makes the naive join wrong.
        assert!(
            edge.produces.iter().any(|p| p == "person"),
            "fixture must produce a Person entity: {:?}",
            edge.produces
        );
        assert!(
            !edge.produces.iter().any(|p| p == "full_name"),
            "the emission vocabulary must NOT already say full_name — if it \
             did, this whole translation would be unnecessary"
        );

        // The joinable field carries the translation dispatch actually performs.
        assert!(
            edge.pivots_to.contains(&"full_name"),
            "person must pivot to full_name: {:?}",
            edge.pivots_to
        );
        assert!(
            !edge.pivots_to.contains(&"person"),
            "pivots_to must speak TargetKind only: {:?}",
            edge.pivots_to
        );
    }

    /// `pivots_to` must agree with dispatch by construction, for every kind a
    /// module can emit — not just the `person` case that motivated it. If these
    /// two ever disagree, the rendered graph is describing a system that isn't
    /// the one running.
    #[test]
    fn pivots_to_matches_the_dispatch_mapping_for_every_produced_kind() {
        let modules: Vec<Arc<dyn Module>> = vec![
            Arc::new(PersonProducerModule),
            Arc::new(CheapIdentityModule),
            Arc::new(PaidTerminalModule),
            Arc::new(CredentialModule),
        ];
        let summary = ModuleGraph::build(&modules).to_summary(&modules);

        for (edge, m) in summary.edges.iter().zip(modules.iter()) {
            let expected: std::collections::BTreeSet<&str> = m
                .produces()
                .iter()
                .filter_map(TargetKind::from_entity_kind)
                .map(|t| t.canonical_str())
                .collect();
            let actual: std::collections::BTreeSet<&str> =
                edge.pivots_to.iter().copied().collect();
            assert_eq!(
                actual, expected,
                "{}: pivots_to must equal produces mapped through dispatch",
                edge.module
            );
        }
    }

    /// A kind produced by many and consumed by none is ambiguous: a deliberate
    /// terminal (a `password` is evidence, never a seed) or a real coverage gap.
    /// `terminal_kinds` names the former so an auditor can tell them apart —
    /// and is derived from the modules, so a newly-emitted terminal kind is
    /// reported without anyone maintaining a list.
    #[test]
    fn terminal_kinds_are_named_and_never_appear_as_pivots() {
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(CredentialModule)];
        let summary = ModuleGraph::build(&modules).to_summary(&modules);

        assert!(
            summary.terminal_kinds.iter().any(|k| k == "credential"),
            "a produced kind with no TargetKind must be reported terminal: {:?}",
            summary.terminal_kinds
        );
        assert!(
            summary.edges[0].pivots_to.is_empty(),
            "a terminal-only producer has no outbound edges: {:?}",
            summary.edges[0].pivots_to
        );
        // It is still truthfully reported as produced — terminal is about
        // reachability, not about whether the module emits it.
        assert!(summary.edges[0].produces.iter().any(|p| p == "credential"));
    }
