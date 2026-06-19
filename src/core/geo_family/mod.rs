//! `core::geo_family` — offline geo-corroboration of family-candidates against
//! the subject's own confirmed location.
//!
//! A name scan surfaces `family-candidate` people/addresses (shared surname,
//! from the AU registers and residential directories) at postcode grain, while
//! the SUBJECT has a confirmed location of their own. When a family-candidate's
//! postcode resolves into the subject's area, "shared surname" and "same area as
//! the subject" — two INDEPENDENT free signals — agree, which is what makes the
//! relative reliable rather than a lone register hit; when it resolves a whole
//! region away, the shared surname is more likely a coincidental namesake.
//!
//! The subject anchor ([`subject_fixes`]) is itself free and offline, from two
//! sources so the angle fires on the COMMON scan and not just sensor ones: a
//! confirmed `Coordinates` fix (GPS/`signal_radar`), OR the subject's OWN address
//! locality — a register/directory hit whose owner name exactly matched the
//! subject (`exact-name-match`). The latter is what lets a no-GPS name scan still
//! corroborate kin, since the subject's suburb is almost always known.
//!
//! This is the one, pure, offline definition of that detection
//! ([`crate::util::city_coords`] + great-circle distance), shared by every
//! consumer so the threshold, anchor and postcode parsing can't drift: the
//! correlator (AU-061 surfaces the *finding*) and the engine's finalize passes
//! (promote the confirmed relatives, flag the discordant namesakes — so every
//! scan's family reads as reliable local kin vs interstate look-alikes, not a
//! flat pile of 0.3 candidates).

use crate::core::entity::{Entity, EntityKind};

/// Distance within which a family-candidate's locality counts as the subject's
/// area. Region/postcode grain, so it answers "same part of the state as the
/// subject" — a strong independent signal for a shared-surname person, while
/// still excluding interstate / far-region namesakes.
pub const FAMILY_GEO_KM: f64 = 150.0;

/// Distance BEYOND which a shared-surname family-candidate is more likely a
/// coincidental NAMESAKE than a household relative — a different capital-city
/// catchment from the subject's confirmed area (Brisbane→Melbourne/Adelaide/Perth/
/// Tasmania all exceed this; Brisbane→Sydney does not). Deliberately generous:
/// families do spread interstate, so this only flags the clearly-distant, and the
/// resulting signal de-prioritises / annotates a lead — it never deletes one.
/// The neutral middle band ([`FAMILY_GEO_KM`]..=`NAMESAKE_GEO_KM`) is left untouched.
pub const NAMESAKE_GEO_KM: f64 = 800.0;

/// Minimum confidence for a `Coordinates` entity to anchor the subject's
/// location — a confirmed fix (e.g. a GPS sensor reading), not a coarse guess.
const SUBJECT_FIX_MIN: f64 = 0.60;

/// The AU postcode (4 digits, 0800–7999) an entity names — a standalone token in
/// its value (`"QLD 4518, Australia"`) or a `postcode` evidence attribute (the
/// `qld_unclaimed` owner Persons carry it). Used for both ends of the match: a
/// family-candidate's locality and the subject's own address. `None` when no
/// plausible AU postcode is present.
#[must_use]
pub fn au_postcode(e: &Entity) -> Option<String> {
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

/// A confirmed subject location with the entity it was derived from — the richer
/// anchor form for the correlator, which needs the source UID to wire the
/// correlation graph edge.
#[derive(Debug, Clone)]
pub struct SubjectFix {
    /// UID of the anchoring entity (a confirmed coordinate, or the subject's own
    /// name-matched address).
    pub uid: String,
    /// Parsed `(lat, lon)`.
    pub coord: (f64, f64),
}

/// The subject's confirmed location(s), with provenance — the anchor every
/// family-candidate's distance is measured against. Two free, offline sources:
///
/// 1. a confirmed `Coordinates` fix — high confidence (≥ [`SUBJECT_FIX_MIN`], a
///    GPS/sensor reading) OR one the scan name-matched to the subject
///    (`exact-name-match`); and
/// 2. the subject's OWN address locality — an `Address` tagged `exact-name-match`
///    (a register/directory record whose owner name exactly matched the subject),
///    resolved offline to its postcode-region centroid.
///
/// Source 2 is what lets the geo angle fire on the COMMON scan — no GPS, but the
/// subject's suburb is known from a name-matched register hit — rather than only
/// on sensor scans. A family-candidate's own address never anchors (it carries
/// `family-candidate`, not `exact-name-match`), so there is no circularity. Empty
/// when the scan has no confirmed subject location (then nothing corroborates).
#[must_use]
pub fn subject_fixes(entities: &[Entity]) -> Vec<SubjectFix> {
    let mut out = Vec::new();
    for e in entities {
        let coord = match e.kind {
            EntityKind::Coordinates
                if e.confidence >= SUBJECT_FIX_MIN || e.has_tag("exact-name-match") =>
            {
                crate::util::geohash::parse_coords(&e.value)
            }
            EntityKind::Address if e.has_tag("exact-name-match") => {
                au_postcode(e).and_then(|pc| crate::util::city_coords::city_coords(&pc))
            }
            _ => None,
        };
        if let Some(coord) = coord {
            out.push(SubjectFix {
                uid: e.uid.clone(),
                coord,
            });
        }
    }
    out
}

/// The subject's confirmed coordinates (provenance dropped) — the form the engine
/// passes need, since they only measure distances. See [`subject_fixes`].
#[must_use]
pub fn subject_locations(entities: &[Entity]) -> Vec<(f64, f64)> {
    subject_fixes(entities)
        .into_iter()
        .map(|f| f.coord)
        .collect()
}

/// Great-circle distance (km) from a family-candidate's resolved locality to the
/// NEAREST subject location, or `None` if its postcode doesn't resolve offline.
/// Free + offline ([`crate::util::city_coords`]).
#[must_use]
pub fn distance_to_subject(e: &Entity, subject: &[(f64, f64)]) -> Option<f64> {
    let pc = au_postcode(e)?;
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

/// True if `e` is a `family-candidate` whose locality resolves but lies BEYOND
/// [`NAMESAKE_GEO_KM`] from every subject location — shared surname, but a
/// different region, so more likely a coincidental namesake than a household
/// relative. The negative complement of [`is_geo_corroborated_family`]: both need a
/// confirmed subject fix, and a candidate can never be both (corroborated within
/// [`FAMILY_GEO_KM`], discordant beyond the far larger [`NAMESAKE_GEO_KM`]). A
/// candidate whose postcode doesn't resolve offline is neither (unknown, not far).
#[must_use]
pub fn is_geo_discordant_namesake(e: &Entity, subject: &[(f64, f64)]) -> bool {
    e.has_tag("family-candidate")
        && distance_to_subject(e, subject).is_some_and(|km| km > NAMESAKE_GEO_KM)
}

#[cfg(test)]
mod tests;
