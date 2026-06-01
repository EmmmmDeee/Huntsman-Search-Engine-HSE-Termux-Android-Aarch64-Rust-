//! Shared on-device sweep / pivot decision logic.
//!
//! `radar` (continuous) and `device-scan` (one-shot) both run the local
//! passive sensor module set and then pivot newly-discovered signals through
//! the full module graph. The *decisions* that govern that — which modules
//! constitute a sensor sweep, which pivots must shed paid modules to protect
//! API quota, and what depth/confidence a pivot uses — are factored here so
//! the two entry points cannot drift. The engine orchestration (building the
//! `ModuleContext`, calling `engine.run`, streaming results) stays in each
//! command; only the pure, testable decisions live here.

use crate::core::entity::Entity;
use crate::core::engine::LOCAL_PASSIVE_MODULES;
use crate::core::scan::{ScanOptions, TargetKind};

/// `ScanOptions` for a single on-device sensor sweep: the local passive
/// sensor modules only, no recursion, modest concurrency. Identical for radar
/// and device-scan so a sweep means the same thing in both.
pub(super) fn sensor_sweep_options() -> ScanOptions {
    ScanOptions {
        modules: Some(LOCAL_PASSIVE_MODULES.iter().map(|s| (*s).to_string()).collect()),
        passive_only: true,
        depth: 0,
        max_concurrent: 4,
        ..Default::default()
    }
}

/// Modules a pivot on an infrastructure/sensor-derived entity must exclude.
///
/// Sensor-discovered infra (IPs, domains, coordinates, MACs, ASNs) almost
/// never yields breach/identity results from the paid identity APIs, so we
/// don't burn quota on them — they're spent on identity-type seeds reached by
/// other paths. Identity kinds (email/username/phone/name/…) exclude nothing.
///
/// The classifier is a *total, exhaustive* match over `TargetKind` with no
/// wildcard arm: adding a new kind is a compile error here until it is
/// explicitly classified, so "an unclassified kind" is unrepresentable.
pub(super) fn infra_excludes(tk: TargetKind) -> Vec<String> {
    use TargetKind as K;
    let is_infra = match tk {
        K::IpAddress | K::Domain | K::Coordinates | K::MacAddress | K::Asn => true,
        K::Email
        | K::Username
        | K::Phone
        | K::FullName
        | K::Url
        | K::Address
        | K::Organisation
        | K::AbnAcn
        | K::ApiKey => false,
    };
    if is_infra {
        vec!["oathnet_pro".to_string(), "see_know".to_string()]
    } else {
        Vec::new()
    }
}

/// `ScanOptions` for pivoting one discovered signal through the full module
/// graph at `depth`, shedding paid modules for infra kinds and (optionally)
/// for every kind via `free_only`. `min_expand_confidence` keeps recursion on
/// solid (Probable+) data.
pub(super) fn pivot_options(depth: u32, free_only: bool, tk: TargetKind) -> ScanOptions {
    ScanOptions {
        depth,
        free_only,
        exclude_modules: infra_excludes(tk),
        max_concurrent: 4,
        min_expand_confidence: 0.50,
        ..Default::default()
    }
}

/// Distinct, scan-targetable pivot seeds from a swept entity set, in discovery
/// order. Entities whose kind has no natural scan target (credentials, device
/// IDs, …) are skipped; duplicate `(kind, value)` pairs collapse to one.
pub(super) fn pivot_targets(entities: &[Entity]) -> Vec<(TargetKind, String)> {
    let mut seen: std::collections::HashSet<(&'static str, String)> =
        std::collections::HashSet::new();
    let mut out = Vec::new();
    for e in entities {
        if let Some(tk) = TargetKind::from_entity_kind(&e.kind)
            && seen.insert((tk.canonical_str(), e.value.clone()))
        {
            out.push((tk, e.value.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    /// Every `TargetKind` the project defines. Kept in sync with the enum by
    /// the exhaustive match in [`infra_excludes`] (a new variant fails to
    /// compile there until classified) and asserted complete below.
    const ALL_KINDS: &[TargetKind] = &[
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::FullName,
        TargetKind::IpAddress,
        TargetKind::Domain,
        TargetKind::Url,
        TargetKind::Asn,
        TargetKind::Coordinates,
        TargetKind::Address,
        TargetKind::Organisation,
        TargetKind::AbnAcn,
        TargetKind::MacAddress,
        TargetKind::ApiKey,
    ];

    #[test]
    fn sensor_sweep_options_is_passive_no_recursion_sensor_modules() {
        let o = sensor_sweep_options();
        assert!(o.passive_only, "a sensor sweep must be passive");
        assert_eq!(o.depth, 0, "a sweep does not recurse");
        let mods = o.modules.expect("sweep pins the sensor module allowlist");
        assert!(!mods.is_empty());
        // The allowlist is exactly the engine's local passive set.
        for m in LOCAL_PASSIVE_MODULES {
            assert!(mods.iter().any(|x| x == m), "sweep must include {m}");
        }
        assert_eq!(mods.len(), LOCAL_PASSIVE_MODULES.len());
    }

    #[test]
    fn infra_excludes_classifies_every_target_kind_exhaustively() {
        // Exhaustive enumeration over the finite TargetKind domain: every kind
        // is either infra (sheds the two paid identity modules) or not (sheds
        // nothing). No kind may yield a partial/other exclude set.
        for &tk in ALL_KINDS {
            let ex = infra_excludes(tk);
            assert!(
                ex.is_empty() || ex == ["oathnet_pro".to_string(), "see_know".to_string()],
                "{tk:?} produced an unexpected exclude set: {ex:?}"
            );
        }
        // The five infra kinds shed the paid modules…
        for tk in [
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::Coordinates,
            TargetKind::MacAddress,
            TargetKind::Asn,
        ] {
            assert_eq!(
                infra_excludes(tk),
                vec!["oathnet_pro".to_string(), "see_know".to_string()],
                "{tk:?} is infra and must shed paid identity modules"
            );
        }
        // …every identity/other kind sheds nothing.
        for tk in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::FullName,
            TargetKind::Url,
            TargetKind::Address,
            TargetKind::Organisation,
            TargetKind::AbnAcn,
            TargetKind::ApiKey,
        ] {
            assert!(
                infra_excludes(tk).is_empty(),
                "{tk:?} is not infra and must not shed modules"
            );
        }
    }

    #[test]
    fn pivot_options_propagates_depth_free_only_and_infra_exclude() {
        let infra = pivot_options(3, true, TargetKind::IpAddress);
        assert_eq!(infra.depth, 3);
        assert!(infra.free_only);
        assert_eq!(
            infra.exclude_modules,
            vec!["oathnet_pro".to_string(), "see_know".to_string()]
        );
        assert!((infra.min_expand_confidence - 0.50).abs() < 1e-9);

        let ident = pivot_options(1, false, TargetKind::Email);
        assert_eq!(ident.depth, 1);
        assert!(!ident.free_only);
        assert!(ident.exclude_modules.is_empty());
    }

    #[test]
    fn pivot_targets_skips_unconvertible_and_dedups() {
        let mk = |k, v: &str| Entity::new(k, v, 0.9, "s");
        let entities = vec![
            mk(EntityKind::Domain, "example.com"),
            mk(EntityKind::Domain, "example.com"), // dup → collapses
            mk(EntityKind::Email, "a@b.com"),
            mk(EntityKind::Credential, "hunter2"), // no scan target → skipped
        ];
        let targets = pivot_targets(&entities);
        assert_eq!(targets.len(), 2, "dup domain collapses, credential dropped");
        assert!(targets.iter().any(|(k, v)| *k == TargetKind::Domain && v == "example.com"));
        assert!(targets.iter().any(|(k, v)| *k == TargetKind::Email && v == "a@b.com"));
    }

    #[test]
    fn pivot_targets_empty_input_is_empty() {
        assert!(pivot_targets(&[]).is_empty());
    }
}
