
use super::{registry, technique_module_index};
    use crate::core::dependency::{ALL_TARGET_KINDS, PROBE_VALUE};
    use crate::core::scan::Target;

    /// Every registered module's `consumes()` must cover every `TargetKind`
    /// its `accepts()` matches against the canonical probe value.
    ///
    /// Why this is load-bearing: the engine builds its O(1) dispatch index
    /// from `consumes()` (see `core::dependency::ModuleGraph`). A module that
    /// hand-rolls `consumes()` and declares FEWER kinds than `accepts()`
    /// actually matches is silently never indexed for the missing kind — so
    /// it never dispatches there, and the engine's belt-and-braces `accepts()`
    /// recheck never even runs (the module isn't in the candidate list). This
    /// test turns that class of mis-declaration into a CI failure instead of a
    /// silent loss of coverage.
    ///
    /// The default `consumes()` derives itself by probing `accepts()`, so
    /// non-overriding modules satisfy this by construction; the test guards
    /// the modules that override `consumes()` by hand. A `consumes()` that is
    /// a strict *superset* of the probed-accepts set is fine (value-shape
    /// gates legitimately declare kinds the generic probe value can't match).
    #[test]
    fn corpus_owners_are_registered_modules_and_probes_consult_them() {
        // Every owner in the table is a registered module whose name is the
        // source it lends; the lookup matches the host and its subdomains and
        // nothing that merely resembles them.
        let registry = crate::modules::registry();
        for (host, src) in super::CORPUS_OWNERS {
            assert!(
                registry.iter().any(|m| m.name() == *src),
                "corpus owner `{src}` for {host} is not a registered module"
            );
            assert_eq!(super::corpus_source(&format!("https://{host}/u"), "me"), *src);
            assert_eq!(super::corpus_source(&format!("https://www.{host}/u?x=1"), "me"), *src);
            assert_eq!(super::corpus_source(&format!("https://not{host}/u"), "me"), "me");
        }
        assert_eq!(super::corpus_source("https://example.org/u", "me"), "me");
        // The two probe engines mint hundreds of sites through one evidence
        // path each; that path must consult the table.
        for (name, src) in [
            ("username_search", include_str!("username_search/mod.rs")),
            ("social_probe", include_str!("social_probe/mod.rs")),
        ] {
            assert!(
                src.contains("corpus_source("),
                "{name} must attribute a hit on an owned corpus to its owner"
            );
        }
    }

    #[test]
    fn module_consumes_covers_probed_accepts() {
        let mut violations = Vec::new();
        for m in registry() {
            let declared = m.consumes();
            for &kind in ALL_TARGET_KINDS {
                if m.accepts(&Target::new(kind, PROBE_VALUE)) && !declared.contains(&kind) {
                    violations.push(format!(
                        "  {}: accepts() matches {:?} (probe) but consumes() omits it \
                         → dispatch index would never serve it for that kind",
                        m.name(),
                        kind
                    ));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "consumes()/accepts() divergence detected:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn technique_module_index_is_a_clean_reverse_map() {
        let index = technique_module_index();
        assert!(!index.is_empty(), "registry maps to ATT&CK techniques");
        for (id, mods) in index {
            // Only catalogued technique IDs are keyed.
            assert!(
                crate::core::attack::technique(id).is_some(),
                "{id} must be a catalogued technique"
            );
            // Module lists are deduplicated and sorted.
            let mut sorted = mods.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(&sorted, mods, "module list for {id} must be sorted+deduped");
            assert!(!mods.is_empty(), "a keyed technique has at least one module");
        }
    }

    #[test]
    fn technique_module_index_inverts_the_forward_map() {
        // Every (module, technique) edge in the forward map appears in the
        // reverse index, and vice versa — the two are consistent.
        let index = technique_module_index();
        for m in registry() {
            for &id in m.attack_techniques() {
                if crate::core::attack::technique(id).is_some() {
                    assert!(
                        index.get(id).is_some_and(|mods| mods.contains(&m.name())),
                        "module {} maps to {id} but the reverse index omits it",
                        m.name()
                    );
                }
            }
        }
    }

    #[test]
    fn technique_module_index_reflects_real_reach() {
        // HSE has many modules → the reverse index spans most of the curated
        // catalogue (every keyed technique is implemented by ≥1 module). This
        // pins that the per-module ATT&CK mapping is substantive, not vacuous.
        let index = technique_module_index();
        assert!(
            index.len() >= 20,
            "registry maps to {} techniques",
            index.len()
        );
        // Every keyed technique is catalogued and has at least one module.
        for (id, mods) in index {
            assert!(
                crate::core::attack::technique(id).is_some(),
                "{id} must be catalogued"
            );
            assert!(!mods.is_empty(), "a keyed technique has ≥1 module");
        }
    }

    #[test]
    fn is_known_toggle_key_accepts_exactly_the_three_real_key_families() {
        // The one validator behind both `PUT /api/v1/settings/toggles` and
        // `hse config <key> on|off`.
        let modules = registry();
        let (feature, _) = crate::util::settings::FEATURE_TOGGLES[0];
        assert!(super::is_known_toggle_key(feature, &modules));
        assert!(!super::is_known_toggle_key("feature.no_such_feature", &modules));

        let some_module = modules[0].name();
        assert!(super::is_known_toggle_key(&format!("module.{some_module}"), &modules));
        assert!(
            !super::is_known_toggle_key("module.no_such_module_xyz", &modules),
            "a typo must not validate"
        );
        assert!(!super::is_known_toggle_key("module.", &modules));
        // The registry view is the caller's: an empty view knows no module.
        assert!(!super::is_known_toggle_key(&format!("module.{some_module}"), &[]));

        let (engine, _) = super::search_engines::engine_toggles()
            .into_iter()
            .next()
            .expect("at least one search engine");
        assert!(super::is_known_toggle_key(&engine, &modules));
        assert!(!super::is_known_toggle_key("engine.no_such_engine", &modules));

        // Anything outside the three families is unknown, whatever it names.
        assert!(!super::is_known_toggle_key("shodan", &modules));
        assert!(!super::is_known_toggle_key("", &modules));
    }

    #[test]
    fn reconnaissance_coverage_is_substantive_and_honest() {
        use crate::core::attack;
        let cov = super::reconnaissance_coverage();

        // Scoped to the one tactic HSE honestly performs collection for.
        assert_eq!(cov.tactic_id, attack::TACTIC_ID);

        // Substantive: the registry covers a real slice of TA0043, not zero and
        // not a fabricated 100% — the fraction is derived from real modules.
        assert!(
            !cov.covered.is_empty(),
            "the registry must cover at least one Reconnaissance technique"
        );
        assert!(
            cov.coverage_fraction > 0.0 && cov.coverage_fraction <= 1.0,
            "coverage fraction {} out of range",
            cov.coverage_fraction
        );

        // Honest partition: covered ∩ gaps = ∅, and covered ∪ gaps == the full
        // Reconnaissance slice. A technique is covered or a gap — never both,
        // never neither (MISSING DATA ≠ NEGATIVE FINDING has a definite home).
        let covered_ids: std::collections::BTreeSet<&str> =
            cov.covered.iter().map(|c| c.technique.id).collect();
        for u in &cov.uncovered {
            assert!(
                !covered_ids.contains(u.id),
                "{} is reported both covered and a gap",
                u.id
            );
            assert!(
                attack::technique(u.id).is_some(),
                "gap {} is not a catalogued technique",
                u.id
            );
        }
        assert_eq!(
            cov.covered.len() + cov.uncovered.len(),
            attack::reconnaissance().len(),
            "covered + gaps must equal the whole Reconnaissance slice"
        );
    }
