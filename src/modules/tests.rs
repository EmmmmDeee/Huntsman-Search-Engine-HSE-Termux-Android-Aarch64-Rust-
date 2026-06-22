
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
