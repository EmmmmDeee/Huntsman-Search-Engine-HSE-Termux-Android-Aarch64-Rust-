//! ATT&CK-informed operational priorities for the existing live OSINT recursion.
//!
//! This module changes which admissible lookup executes first; it never claims that
//! an ATT&CK adversary technique was executed. No transport, storage, keys, or
//! runtime AI are introduced. Every score is deterministic and locally testable.
//! The existing scan selectors, confidence gates, quotas, and evidence remain authoritative.

use crate::attack;
use crate::scan_route::ScanKind;

/// Strategic ATT&CK Reconnaissance analogues for existing Huntsman lookup routes.
/// These are planning hints, NOT post-hoc evidence or ATT&CK conformance claims.
#[must_use]
pub const fn route_techniques(kind: ScanKind) -> &'static [&'static str] {
    match kind {
        ScanKind::People => &["T1589.003"],
        ScanKind::Email => &["T1589.002"],
        ScanKind::Exposure => &["T1589.001", "T1589.002"],
        ScanKind::Username => &["T1593.001"],
        ScanKind::Phone => &["T1589"],
        ScanKind::Domain => &["T1590.001", "T1596.003"],
        ScanKind::Ip => &["T1590.005"],
        ScanKind::Netblock | ScanKind::Asn => &["T1590.004"],
        ScanKind::Network => &["T1592"],
        ScanKind::CryptoAddress => &["T1596"],
        // For people and places this is an operational analogy: T1591.001
        // literally describes organisational physical locations.
        ScanKind::Place => &["T1591.001"],
    }
}

/// Score a *new admissible route* against the original target's investigative
/// objective. Scores guide dispatch ordering only, not identity attribution,
/// source trust, evidence confidence, authorization, or technique coverage.
#[must_use]
pub fn priority(focus: ScanKind, candidate: ScanKind) -> u16 {
    // Never use an unknown/non-Recon ATT&CK identifier to drive an action.
    if !route_techniques(candidate).iter().any(|id| {
        attack::technique(id)
            .is_some_and(|technique| technique.tactics.contains(&"reconnaissance"))
    }) {
        return 0;
    }
    match focus {
        ScanKind::People | ScanKind::Email | ScanKind::Username
        | ScanKind::Phone | ScanKind::Exposure => match candidate {
            ScanKind::Email => 110,
            ScanKind::Username => 105,
            ScanKind::Phone => 100,
            ScanKind::People => 95,
            ScanKind::Place => 90,
            ScanKind::Exposure => 85,
            ScanKind::Domain => 75,
            ScanKind::Network => 65,
            ScanKind::Ip => 60,
            ScanKind::Asn => 50,
            ScanKind::Netblock => 45,
            ScanKind::CryptoAddress => 40,
        },
        ScanKind::Place | ScanKind::Network => match candidate {
            ScanKind::Place => 110,
            ScanKind::Network => 105,
            ScanKind::Ip => 90,
            ScanKind::Domain => 85,
            ScanKind::Email => 80,
            ScanKind::Username => 75,
            ScanKind::Phone => 70,
            ScanKind::People => 65,
            ScanKind::Asn => 60,
            ScanKind::Netblock => 55,
            ScanKind::Exposure => 50,
            ScanKind::CryptoAddress => 40,
        },
        ScanKind::Domain | ScanKind::Ip | ScanKind::Netblock
        | ScanKind::Asn | ScanKind::CryptoAddress => match candidate {
            ScanKind::Domain => 110,
            ScanKind::Ip => 105,
            ScanKind::Asn => 100,
            ScanKind::Netblock => 95,
            ScanKind::Email => 85,
            ScanKind::Username => 80,
            ScanKind::Place => 75,
            ScanKind::Network => 70,
            ScanKind::Phone => 65,
            ScanKind::People => 60,
            ScanKind::Exposure => 50,
            ScanKind::CryptoAddress => 45,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_operational_mappings_resolve_to_reconnaissance_techniques() {
        for kind in ScanKind::ALL {
            assert!(!route_techniques(kind).is_empty());
            for id in route_techniques(kind) {
                let technique = attack::technique(id).expect("mapped ATT&CK identifier exists");
                assert!(technique.tactics.contains(&"reconnaissance"), "{id}");
                assert!(priority(kind, kind) > 0, "{id}");
            }
        }
    }

    #[test]
    fn the_same_pivots_rank_by_investigative_objective() {
        assert!(priority(ScanKind::People, ScanKind::Email)
            > priority(ScanKind::People, ScanKind::Ip));
        assert!(priority(ScanKind::Place, ScanKind::Place)
            > priority(ScanKind::Place, ScanKind::Domain));
        assert!(priority(ScanKind::Domain, ScanKind::Domain)
            > priority(ScanKind::Domain, ScanKind::Username));
    }
}
