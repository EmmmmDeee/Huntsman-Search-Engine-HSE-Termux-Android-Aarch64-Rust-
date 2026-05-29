//! `core::geo` — region-prior geolocation re-weighting.
//!
//! When the operator already knows the target's region ("Jordan Leigh Meyer
//! **from Australia**"), that prior is the single most powerful geolocation
//! signal available — and the engine was ignoring it. A common-name breach
//! query floods the corpus with out-of-region addresses (US financial-sector
//! dumps, in live testing) that drown the genuine in-region location.
//!
//! This pass exploits the prior: every geo-bearing entity (anything carrying a
//! `country:ISO` tag — Address, Coordinates, and country-tagged IP/Domain) is
//! re-weighted by **agreement with the prior**. In-region entities are boosted
//! (and tagged `geo-prior-match`); out-of-region entities are penalised (and
//! tagged `geo-prior-conflict`). Net effect: the target's true region rises to
//! the top of the geo ranking and the downstream convergence rules
//! (AU-014/017/030) lock onto it instead of the noise.
//!
//! # Architecture invariants
//! - Pure: depends only on `core::entity`. No I/O, deterministic.
//! - Confidence stays clamped to `[0, 1]`; only base `confidence` is touched,
//!   so `c_effective()` and classification follow automatically.

use crate::core::entity::Entity;

/// Additive confidence boost for an entity whose country matches the prior.
pub const PRIOR_MATCH_BOOST: f64 = 0.12;

/// Multiplicative penalty for an entity whose country conflicts with the
/// prior. Chosen so a `0.65` breach-dump address (the common case) drops to
/// ~`0.36` — below the `0.40` Probable floor and the `0.50` expansion gate,
/// so it neither classifies as a real lead nor seeds expansion.
pub const PRIOR_CONFLICT_FACTOR: f64 = 0.55;

/// Outcome of a region-prior pass, for logging / reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoPriorReport {
    pub prior_iso: &'static str,
    pub matched: usize,
    pub conflicted: usize,
}

/// Normalise a free-form region string to an ISO-3166-alpha-2 code.
///
/// Accepts ISO2 directly, common alpha-3, and country names/aliases for the
/// regions HSE most often anchors on. Returns `None` for anything unrecognised
/// so a typo'd prior is ignored rather than silently mis-weighting the corpus.
pub fn normalize_region(s: &str) -> Option<&'static str> {
    let k = s.trim().to_ascii_uppercase();
    Some(match k.as_str() {
        "AU" | "AUS" | "AUSTRALIA" => "AU",
        "US" | "USA" | "UNITED STATES" | "UNITED STATES OF AMERICA" | "AMERICA" => "US",
        "GB" | "UK" | "GBR" | "UNITED KINGDOM" | "BRITAIN" | "GREAT BRITAIN" => "GB",
        "NZ" | "NZL" | "NEW ZEALAND" => "NZ",
        "CA" | "CAN" | "CANADA" => "CA",
        "IE" | "IRL" | "IRELAND" => "IE",
        "IN" | "IND" | "INDIA" => "IN",
        "DE" | "DEU" | "GERMANY" => "DE",
        "FR" | "FRA" | "FRANCE" => "FR",
        "SG" | "SGP" | "SINGAPORE" => "SG",
        _ => return None,
    })
}

/// The ISO country an entity is geo-tagged with, if any. Reads the
/// `country:XX` tag the engine's geospatial enrichment attaches.
pub fn entity_country_iso(e: &Entity) -> Option<String> {
    e.tags
        .iter()
        .find_map(|t| t.strip_prefix("country:").map(|c| c.to_ascii_uppercase()))
}

/// True if the entity carries any geolocation signal worth re-weighting.
fn is_geo_bearing(e: &Entity) -> bool {
    entity_country_iso(e).is_some()
}

/// Re-weight geo-bearing entities against a known region prior, in place.
///
/// `prior` is any string `normalize_region` accepts. Returns `None` (no-op)
/// when the prior is unrecognised. Idempotent in effect: re-running with the
/// same prior re-tags but the boost/penalty are not re-stacked because the
/// tag set already contains the marker (we skip already-marked entities).
pub fn apply_region_prior(entities: &mut [Entity], prior: &str) -> Option<GeoPriorReport> {
    let prior_iso = normalize_region(prior)?;
    let mut matched = 0;
    let mut conflicted = 0;

    for e in entities.iter_mut() {
        if !is_geo_bearing(e) {
            continue;
        }
        // Don't double-apply if a previous pass already marked this entity.
        if e.has_tag("geo-prior-match") || e.has_tag("geo-prior-conflict") {
            continue;
        }
        let Some(iso) = entity_country_iso(e) else {
            continue;
        };
        if iso == prior_iso {
            e.confidence = (e.confidence + PRIOR_MATCH_BOOST).clamp(0.0, 1.0);
            e.tag("geo-prior-match");
            matched += 1;
        } else {
            e.confidence = (e.confidence * PRIOR_CONFLICT_FACTOR).clamp(0.0, 1.0);
            e.tag("geo-prior-conflict");
            conflicted += 1;
        }
    }

    Some(GeoPriorReport {
        prior_iso,
        matched,
        conflicted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    fn geo(kind: EntityKind, value: &str, conf: f64, country: &str) -> Entity {
        let mut e = Entity::new(kind, value, conf, "s");
        e.tag(format!("country:{country}"));
        e
    }

    // ── normalize_region ────────────────────────────────────────────────

    #[test]
    fn normalises_aliases_to_iso2() {
        for s in ["AU", "au", "aus", "Australia", "AUSTRALIA"] {
            assert_eq!(normalize_region(s), Some("AU"), "{s}");
        }
        assert_eq!(normalize_region("United States"), Some("US"));
        assert_eq!(normalize_region("uk"), Some("GB"));
        assert_eq!(normalize_region("New Zealand"), Some("NZ"));
        assert_eq!(normalize_region("Narnia"), None);
    }

    #[test]
    fn entity_country_iso_reads_tag() {
        let e = geo(EntityKind::Address, "Brisbane, QLD", 0.8, "AU");
        assert_eq!(entity_country_iso(&e).as_deref(), Some("AU"));
        let plain = Entity::new(EntityKind::Email, "a@b.com", 0.8, "s");
        assert_eq!(entity_country_iso(&plain), None);
    }

    // ── apply_region_prior ──────────────────────────────────────────────

    #[test]
    fn boosts_in_region_and_penalises_out_of_region() {
        let mut ents = vec![
            geo(EntityKind::Address, "Brisbane, QLD", 0.70, "AU"),
            geo(EntityKind::Address, "Helena, MT", 0.65, "US"),
            geo(EntityKind::Coordinates, "-27.47,153.02", 0.60, "AU"),
        ];
        let rep = apply_region_prior(&mut ents, "Australia").unwrap();
        assert_eq!(rep.prior_iso, "AU");
        assert_eq!(rep.matched, 2);
        assert_eq!(rep.conflicted, 1);

        // AU address boosted above its starting point, tagged.
        assert!((ents[0].confidence - 0.82).abs() < 1e-9);
        assert!(ents[0].has_tag("geo-prior-match"));
        // US address penalised below the Probable floor (0.40) and tagged.
        assert!(ents[1].confidence < 0.40, "got {}", ents[1].confidence);
        assert!(ents[1].has_tag("geo-prior-conflict"));
    }

    #[test]
    fn ignores_non_geo_entities() {
        let mut ents = vec![Entity::new(EntityKind::Email, "a@b.com", 0.9, "s")];
        let rep = apply_region_prior(&mut ents, "AU").unwrap();
        assert_eq!(rep.matched, 0);
        assert_eq!(rep.conflicted, 0);
        assert!((ents[0].confidence - 0.9).abs() < 1e-9); // untouched
    }

    #[test]
    fn unrecognised_prior_is_noop() {
        let mut ents = vec![geo(EntityKind::Address, "x", 0.7, "AU")];
        assert!(apply_region_prior(&mut ents, "Atlantis").is_none());
        assert!((ents[0].confidence - 0.7).abs() < 1e-9);
        assert!(!ents[0].has_tag("geo-prior-match"));
    }

    #[test]
    fn does_not_double_apply() {
        let mut ents = vec![geo(EntityKind::Address, "Helena, MT", 0.65, "US")];
        apply_region_prior(&mut ents, "AU").unwrap();
        let after_first = ents[0].confidence;
        // Second pass must not re-penalise the already-marked entity.
        apply_region_prior(&mut ents, "AU").unwrap();
        assert!((ents[0].confidence - after_first).abs() < 1e-9);
    }

    #[test]
    fn boost_and_penalty_stay_clamped() {
        let mut ents = vec![
            geo(EntityKind::Address, "hi", 0.97, "AU"), // boost would exceed 1.0
            geo(EntityKind::Address, "lo", 0.02, "US"),
        ];
        apply_region_prior(&mut ents, "AU").unwrap();
        assert!(ents[0].confidence <= 1.0);
        assert!(ents[1].confidence >= 0.0);
    }
}
