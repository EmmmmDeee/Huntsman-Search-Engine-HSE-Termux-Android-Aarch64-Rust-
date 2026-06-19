//! `core::geo_family` — offline geo-corroboration of family-candidates against
//! the subject's own confirmed location.
//!
//! A name scan surfaces `family-candidate` people/addresses (shared surname,
//! from the AU registers and residential directories) at postcode grain, while
//! `signal_radar`/geo give the SUBJECT a confirmed coordinate fix. When a
//! family-candidate's postcode resolves into the subject's area, "shared surname"
//! and "same area as the subject" — two INDEPENDENT free signals — agree, which
//! is what makes the relative reliable rather than a lone register hit.
//!
//! This is the one, pure, offline definition of that detection
//! ([`crate::util::city_coords`] + great-circle distance), shared by both
//! consumers so the threshold and postcode parsing can't drift: the correlator
//! (AU-061 surfaces the *finding*) and the engine's finalize pass (promotes the
//! confirmed relatives so every scan's geo-corroborated family reads as reliable,
//! not a 0.3 candidate).

use crate::core::entity::{Entity, EntityKind};

/// Distance within which a family-candidate's locality counts as the subject's
/// area. Region/postcode grain, so it answers "same part of the state as the
/// subject" — a strong independent signal for a shared-surname person, while
/// still excluding interstate / far-region namesakes.
pub const FAMILY_GEO_KM: f64 = 150.0;

/// Minimum confidence for a `Coordinates` entity to anchor the subject's
/// location — a confirmed fix (e.g. a GPS sensor reading), not a coarse guess.
const SUBJECT_FIX_MIN: f64 = 0.60;

/// The AU postcode (4 digits, 0800–7999) a family-candidate names — a standalone
/// token in its value (`"QLD 4518, Australia"`) or a `postcode` evidence
/// attribute (the `qld_unclaimed` owner Persons carry it). `None` when no
/// plausible AU postcode is present.
#[must_use]
pub fn family_postcode(e: &Entity) -> Option<String> {
    let valid = |t: &str| -> Option<String> {
        let t = t.trim();
        (t.len() == 4 && t.bytes().all(|b| b.is_ascii_digit()))
            .then(|| t.parse::<u32>().ok())
            .flatten()
            .filter(|n| (800..=7999).contains(n))
            .map(|_| t.to_string())
    };
    for tok in e.value.split(|c: char| !c.is_ascii_digit()) {
        if let Some(pc) = valid(tok) {
            return Some(pc);
        }
    }
    e.evidence
        .iter()
        .find_map(|ev| ev.attributes.get("postcode").and_then(|v| valid(v)))
}

/// The subject's confirmed location(s): high-confidence `Coordinates`, parsed to
/// `(lat, lon)`. The anchor every family-candidate's distance is measured
/// against. Empty when the scan has no confirmed fix (then nothing corroborates).
#[must_use]
pub fn subject_locations(entities: &[Entity]) -> Vec<(f64, f64)> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates && e.confidence >= SUBJECT_FIX_MIN)
        .filter_map(|e| crate::util::geohash::parse_coords(&e.value))
        .collect()
}

/// Great-circle distance (km) from a family-candidate's resolved locality to the
/// NEAREST subject location, or `None` if its postcode doesn't resolve offline.
/// Free + offline ([`crate::util::city_coords`]).
#[must_use]
pub fn distance_to_subject(e: &Entity, subject: &[(f64, f64)]) -> Option<f64> {
    let pc = family_postcode(e)?;
    let (la, lo) = crate::util::city_coords::city_coords(&pc)?;
    subject
        .iter()
        .map(|&(sla, slo)| crate::util::geohash::haversine_km(la, lo, sla, slo))
        .fold(None, |acc: Option<f64>, km| {
            Some(acc.map_or(km, |a| a.min(km)))
        })
}

/// True if `e` is a `family-candidate` whose locality is within [`FAMILY_GEO_KM`]
/// of the subject — i.e. shared surname AND same area independently agree.
#[must_use]
pub fn is_geo_corroborated_family(e: &Entity, subject: &[(f64, f64)]) -> bool {
    e.has_tag("family-candidate")
        && distance_to_subject(e, subject).is_some_and(|km| km <= FAMILY_GEO_KM)
}

#[cfg(test)]
mod tests;
