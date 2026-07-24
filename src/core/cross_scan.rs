//! Cross-scan entity category: browse the history bridges as one search facet.
//!
//! The finalise passes in [`crate::core::engine`] tag entities that recur across
//! investigations (`cross-scan`, `cross-scan-cooccurrence`, `cross-scan-relation`,
//! `cross-scan-alias`). Those tags are the detection half; this module is the
//! presentation half, assembling them into a single ranked category an operator
//! can open and expand scan by scan.
//!
//! It also owns the kind-compatibility table used by the cross-kind alias probe,
//! so the notion of "these two kinds can denote one identifier" has one definition.

use crate::core::entity::{Entity, EntityKind};
use crate::core::error::Result;
use crate::core::port::StoragePort;

/// Tag marking an entity bridged to history by value under a *different* kind.
pub const ALIAS_TAG: &str = "cross-scan-alias";

/// How strongly an entity is bridged to earlier investigations.
///
/// Ordered weakest to strongest; mirrors the ladder `core::leads::history_boost`
/// scores, so the category ranks the way lead recommendation already does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BridgeTier {
    /// Same value under a compatible but different kind — heuristic.
    KindAlias,
    /// The identical identifier was recorded in an earlier scan.
    Recurrence,
    /// The identifier shared an earlier scan with a partner seen here too.
    Cooccurrence,
    /// An earlier scan recorded a typed relation between this and a current peer.
    Relation,
}

impl BridgeTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KindAlias => "kind_alias",
            Self::Recurrence => "recurrence",
            Self::Cooccurrence => "cooccurrence",
            Self::Relation => "relation",
        }
    }

    /// Strongest tier the entity's tags evidence, if any.
    pub fn strongest(entity: &Entity) -> Option<Self> {
        if entity.has_tag("cross-scan-relation") {
            Some(Self::Relation)
        } else if entity.has_tag("cross-scan-cooccurrence") {
            Some(Self::Cooccurrence)
        } else if entity.has_tag("cross-scan") {
            Some(Self::Recurrence)
        } else if entity.has_tag(ALIAS_TAG) {
            Some(Self::KindAlias)
        } else {
            None
        }
    }
}

/// One bridged entity, with the earlier scans it can be expanded into.
#[derive(Debug, Clone)]
pub struct BridgedEntity {
    pub uid: String,
    pub value: String,
    pub kind: EntityKind,
    pub confidence: f64,
    pub tier: BridgeTier,
    /// True when the entity bridges three or more distinct investigations.
    pub hub: bool,
    /// Earlier scans that also recorded this entity, ascending. Empty when the
    /// store could not answer — never a claim that no earlier scan exists.
    pub prior_scan_ids: Vec<String>,
}

/// The cross-scan category for one scan: every history bridge, ranked.
#[derive(Debug, Clone)]
pub struct CrossScanCategory {
    pub scan_id: String,
    pub entities: Vec<BridgedEntity>,
    /// Bridged entities whose prior-scan lookup failed, so `prior_scan_ids` is
    /// empty for a reason other than "no history". Surfaced, never hidden.
    pub lookups_failed: usize,
}

impl CrossScanCategory {
    /// Bridges at or above `tier`, preserving rank order.
    pub fn at_least(&self, tier: BridgeTier) -> Vec<&BridgedEntity> {
        self.entities.iter().filter(|e| e.tier >= tier).collect()
    }

    /// Distinct earlier scans reachable from this scan's bridges.
    pub fn prior_scans(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .entities
            .iter()
            .flat_map(|e| e.prior_scan_ids.iter().cloned())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

/// Assemble the cross-scan category for `scan_id`.
///
/// Ranked strongest tier first, then by confidence, then by uid so the ordering is
/// total and stable. Per-entity prior-scan lookups are indexed point queries; the
/// set they run over is already bounded by the finalise passes that write the tags.
pub fn category_for_scan(store: &dyn StoragePort, scan_id: &str) -> Result<CrossScanCategory> {
    let entities = store.entities_for_scan(scan_id)?;
    Ok(category_from_entities(store, scan_id, &entities))
}

/// Assemble the category from entities the caller has already loaded.
///
/// Split out from [`category_for_scan`] so a caller that must filter the entity
/// set first — the API, which applies the candidate quarantine before anything
/// reads the entities — controls the load. A quarantined entity gated out here is
/// then absent from the category, rather than being loaded past the gate.
#[must_use]
pub fn category_from_entities(
    store: &dyn StoragePort,
    scan_id: &str,
    entities: &[Entity],
) -> CrossScanCategory {
    let mut category = CrossScanCategory {
        scan_id: scan_id.to_string(),
        entities: Vec::new(),
        lookups_failed: 0,
    };

    for entity in entities {
        let Some(tier) = BridgeTier::strongest(entity) else {
            continue;
        };

        let prior_scan_ids = match store.scan_ids_for_entity(&entity.uid) {
            Ok(ids) => {
                let mut ids: Vec<String> = ids.into_iter().filter(|id| id != scan_id).collect();
                ids.sort_unstable();
                ids
            }
            Err(_) => {
                category.lookups_failed += 1;
                Vec::new()
            }
        };

        category.entities.push(BridgedEntity {
            uid: entity.uid.clone(),
            value: entity.value.clone(),
            kind: entity.kind.clone(),
            confidence: entity.confidence,
            hub: entity.has_tag("hub-entity") || entity.has_tag("hub-cooccurrence"),
            tier,
            prior_scan_ids,
        });
    }

    category.entities.sort_by(|a, b| {
        b.tier
            .cmp(&a.tier)
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then_with(|| a.uid.cmp(&b.uid))
    });

    category
}

/// Handle values a cross-kind history probe should look for, given an entity.
///
/// Only Email → Username. Normalisation is kind-specific, so no two kinds ever
/// share a normalised value by accident — an Email value always contains `@` and
/// so can never equal a Username value. The one real bridge is an address's
/// local-part, which is routinely the handle the same person registers elsewhere;
/// AU-076 already makes that link *within* a scan, and this is its history-facing
/// counterpart.
///
/// Returns the raw local-part first, then its separator-stripped canonical form
/// when that differs — stored usernames keep their punctuation, so both spellings
/// must be probed to recall `j.doe` from a scan that saw `jdoe`.
#[must_use]
pub fn alias_handles(entity: &Entity) -> Vec<String> {
    if entity.kind != EntityKind::Email {
        return Vec::new();
    }
    // Local-part minus any Gmail-style `+tag` suffix, matching AU-076.
    let local = entity.value.split('@').next().unwrap_or_default();
    let base = local.split('+').next().unwrap_or_default();
    if !crate::core::correlator::is_anchorable_handle(base) {
        return Vec::new();
    }

    let canonical = crate::core::correlator::canonical_handle(base);
    if canonical == base {
        vec![base.to_string()]
    } else {
        vec![base.to_string(), canonical]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;

    fn entity(kind: EntityKind, value: &str, tags: &[&str]) -> Entity {
        let mut e = Entity::new(kind, value, confidence::HIGH, "scan-1");
        for t in tags {
            e.tag(*t);
        }
        e
    }

    #[test]
    fn alias_handles_uses_the_email_local_part() {
        let e = entity(EntityKind::Email, "jordanmeyers@example.com", &[]);
        assert_eq!(alias_handles(&e), vec!["jordanmeyers".to_string()]);
    }

    #[test]
    fn alias_handles_probes_both_spellings_when_punctuated() {
        let e = entity(EntityKind::Email, "jordan.meyers@example.com", &[]);
        assert_eq!(
            alias_handles(&e),
            vec!["jordan.meyers".to_string(), "jordanmeyers".to_string()]
        );
    }

    #[test]
    fn alias_handles_strips_plus_tag() {
        let e = entity(EntityKind::Email, "jordanmeyers+shopping@example.com", &[]);
        assert_eq!(alias_handles(&e), vec!["jordanmeyers".to_string()]);
    }

    #[test]
    fn alias_handles_rejects_role_and_short_local_parts() {
        for value in ["admin@example.com", "jd@example.com", "info@example.com"] {
            assert!(
                alias_handles(&entity(EntityKind::Email, value, &[])).is_empty(),
                "{value} should not be an identity anchor"
            );
        }
    }

    #[test]
    fn only_emails_have_cross_kind_aliases() {
        // Kind-specific normalisation means no other kind can share a value.
        assert!(alias_handles(&entity(EntityKind::Username, "jdoe", &[])).is_empty());
        assert!(alias_handles(&entity(EntityKind::Person, "Jordan Meyers", &[])).is_empty());
    }

    #[test]
    fn strongest_tier_wins_over_weaker_tags() {
        let e = entity(
            EntityKind::Email,
            "a@example.com",
            &["cross-scan", ALIAS_TAG, "cross-scan-relation"],
        );
        assert_eq!(BridgeTier::strongest(&e), Some(BridgeTier::Relation));
    }

    #[test]
    fn untagged_entity_is_not_in_the_category() {
        let e = entity(EntityKind::Email, "a@example.com", &[]);
        assert_eq!(BridgeTier::strongest(&e), None);
    }

    #[test]
    fn alias_is_the_weakest_tier() {
        assert!(BridgeTier::KindAlias < BridgeTier::Recurrence);
        assert!(BridgeTier::Recurrence < BridgeTier::Cooccurrence);
        assert!(BridgeTier::Cooccurrence < BridgeTier::Relation);
    }

    #[test]
    fn category_ranks_by_tier_and_excludes_unbridged() {
        let store = crate::core::test_support::InMemoryStore::new();
        let alias = entity(EntityKind::Username, "jdoe", &[ALIAS_TAG]);
        let relation = entity(EntityKind::Email, "j@example.com", &["cross-scan-relation"]);
        let plain = entity(EntityKind::Email, "nobody@example.com", &[]);
        for e in [&alias, &relation, &plain] {
            store.upsert_entity(e).unwrap();
        }

        let category = category_for_scan(&store, "scan-1").expect("category");

        assert_eq!(category.entities.len(), 2);
        assert_eq!(category.entities[0].tier, BridgeTier::Relation);
        assert_eq!(category.entities[1].tier, BridgeTier::KindAlias);
        assert_eq!(category.at_least(BridgeTier::Cooccurrence).len(), 1);
    }
}
