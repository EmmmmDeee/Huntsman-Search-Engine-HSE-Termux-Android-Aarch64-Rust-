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

/// Distance BEYOND which a shared-surname family-candidate *may* be a coincidental
/// NAMESAKE rather than a household relative — a different capital-city catchment
/// from the subject's confirmed area (Brisbane→Melbourne/Adelaide/Perth/Tasmania
/// all exceed this; Brisbane→Sydney does not). Deliberately generous: families do
/// spread interstate, so this only flags the clearly-distant, and even then only
/// when the shared surname is COMMON (see [`is_namesake`]) — a distinctive surname
/// carries kinship across any distance. The resulting signal de-prioritises /
/// annotates a lead, never deletes one; the neutral middle band
/// ([`FAMILY_GEO_KM`]..=`NAMESAKE_GEO_KM`) is left untouched.
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
    // Only an Address carries a postcode IN ITS VALUE. Scanning any other kind's
    // value for a trailing 4-digit run misreads an arbitrary number — an email
    // local-part digit, a username suffix, a URL id, a person-record number — as an
    // AU postcode and geolocates it (a confident FALSE location that drags a
    // non-address entity into the subject's geo footprint). Every other kind may
    // still contribute a postcode, but only via a STRUCTURED `postcode` evidence
    // attribute (reliable — the `qld_unclaimed` owner Persons carry it), handled
    // below.
    //
    // An AU address names its postcode LAST, so only the FINAL run of digits is a
    // candidate — this stops a LEADING 4-digit street number (from a foreign
    // address whose real postcode is a 5-digit ZIP) being read as an AU postcode,
    // e.g. "1019 Winston Dr, Jefferson City, MO, 65101" → not "1019".
    if e.kind == EntityKind::Address
        && let Some(last) = e
            .value
            .split(|c: char| !c.is_ascii_digit())
            .rfind(|t| !t.is_empty())
        && let Some(pc) = valid(last)
    {
        return Some(pc);
    }
    e.evidence
        .iter()
        .find_map(|ev| ev.attributes.get("postcode").and_then(|v| valid(v)))
}

/// [`au_postcode`], but refusing a postcode that an **IP geolocation** supplied.
///
/// `au_postcode`'s evidence-attribute path accepts a `postcode` attribute on any
/// entity kind, and the IP-geo providers stamp exactly that from the IP block's
/// `zip`: `ipquery` folds its `geo_ev()` — carrying both `postcode` and `ip` —
/// onto a **city-grain** `Address` it composes from city/state/country
/// (`ipquery/mod.rs:267,292`), and `ip2location` (`mod.rs:178,189`) and `ip_geo`
/// (`mod.rs:148`) do the same.
///
/// That is not the subject's postcode. It is a geolocation database's guess for
/// an address BLOCK — frequently the ISP's registered location — and the
/// codebase already knows it: the headline-estimate's login-IP rung down-weights
/// and caps this exact class at ≤ 0.50 confidence and a 25–50 km radius, with
/// the comment "so a coarse IP city never rivals a suburb-grain postcode in any
/// downstream read". Letting the same IP reach the postcode rung through its
/// `postcode` attribute walks around that cap and reports an 8 km "postcode /
/// suburb grain" residence at full confidence — and labels its provenance
/// "breach/register postcode", which it is not.
///
/// The discriminator is the `ip` attribute that every IP-geo provider records
/// beside the postcode — the same attribute `person_login_ip_coords` already
/// keys off to recognise a login-IP fix, so this adds no new convention. An
/// entity whose evidence is *entirely* IP-derived is refused outright; otherwise
/// only the IP-derived records are skipped, so an entity that also carries a
/// real postal record still yields its postcode.
///
/// Also refuses an entity tagged `family-candidate`. Both this function's
/// callers (`best_au_location_estimate`'s postcode rung, and
/// `au_location_corroboration`) use it to establish the SUBJECT's OWN
/// location — but a `family-candidate` names a possible RELATIVE, not the
/// subject (e.g. `au_unclaimed`'s QLD register mints a non-exact co-owner
/// Person at confidence 0.35 carrying exactly this tag plus a structured
/// `postcode` attribute). [`subject_fixes`] already refuses this same source
/// for the identical reason ("a family-candidate's own address never
/// anchors... so there is no circularity"); this closes the same gap for the
/// `au_postcode_person_grain` path, which `subject_fixes` does not cover.
/// Without it, a scan with no exact-name-matched address for the subject but
/// an au_unclaimed relative hit could report that relative's suburb as the
/// subject's own 8 km "postcode grain" headline residence.
pub fn au_postcode_person_grain(e: &Entity) -> Option<String> {
    if e.has_tag("family-candidate") {
        return None;
    }
    let ip_derived = |ev: &crate::core::entity::Evidence| ev.attributes.contains_key("ip");
    if !e.evidence.is_empty() && e.evidence.iter().all(ip_derived) {
        return None;
    }
    let stripped = Entity {
        evidence: e
            .evidence
            .iter()
            .filter(|ev| !ip_derived(ev))
            .cloned()
            .collect(),
        ..e.clone()
    };
    au_postcode(&stripped)
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
            // `hse radar` seeds every sweep with a sentinel Coordinates entity
            // (0,0) minted at confidence 0.90 with an `exact-name-match`-adjacent
            // `seed`/`subject` shape — it would otherwise sail past both the
            // confidence floor and the name-match escape hatch below and anchor
            // every family-candidate distance check on null island instead of
            // the subject's real location.
            EntityKind::Coordinates
                if crate::core::scan::is_radar_sentinel(
                    crate::core::scan::TargetKind::Coordinates,
                    &e.value,
                ) =>
            {
                None
            }
            EntityKind::Coordinates
                if (e.confidence >= SUBJECT_FIX_MIN || e.has_tag("exact-name-match"))
                    && !crate::core::correlator::is_infrastructure_geo(e) =>
            {
                // Infrastructure geo (a datacentre/hosting/CDN point, or any bare
                // IP/WHOIS coordinate with no anchoring source) must NOT anchor the
                // subject: a 0.60 ip_geo/hosting fix would otherwise widen the
                // subject's "confirmed area" to the host's metro, so a same-surname
                // candidate near the DATACENTRE reads as kin. Genuine person fixes
                // (signal_radar/device_sensors/exif_geo/geocode/…) are anchoring and
                // pass. Mirrors the correlator geo rules (AU-017/030/052/…).
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

/// The subject's surname, if a named subject Person is present — the family surname
/// every `family-candidate` is presumed to share. Picks a seed-anchored /
/// name-matched Person (tagged `subject`, `seed`, or `exact-name-match`); `None`
/// when the scan has no named subject. The single source shared by the engine's
/// namesake pass and the AU-061 correlator, so "whose surname?" can't drift.
#[must_use]
pub fn subject_surname(entities: &[Entity]) -> Option<String> {
    entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Person
                && (e.has_tag("subject") || e.has_tag("seed") || e.has_tag("exact-name-match"))
        })
        .find_map(|e| crate::util::surnames::surname_of(&e.value))
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
/// different region. The geometric half of the namesake call: necessary, but on
/// its own NOT sufficient (see [`is_namesake`]). The negative complement of
/// [`is_geo_corroborated_family`]: both need a confirmed subject fix, and a
/// candidate can never be both (corroborated within [`FAMILY_GEO_KM`], discordant
/// beyond the far larger [`NAMESAKE_GEO_KM`]). A candidate whose postcode doesn't
/// resolve offline is neither (unknown, not far).
#[must_use]
pub fn is_geo_discordant_namesake(e: &Entity, subject: &[(f64, f64)]) -> bool {
    e.has_tag("family-candidate")
        && distance_to_subject(e, subject).is_some_and(|km| km > NAMESAKE_GEO_KM)
}

/// Whether a far family-candidate is a likely NAMESAKE rather than distant kin.
///
/// Geometry alone ([`is_geo_discordant_namesake`]) is necessary but not sufficient:
/// a shared DISTINCTIVE surname carries kinship across any distance — a far
/// "Bamford" is far more likely a relative who moved than a coincidental stranger —
/// so a far candidate is a probable namesake only when the shared surname is ALSO
/// COMMON. The caller supplies `surname_common` ([`crate::util::surnames`]), since
/// it knows the subject whose surname every family-candidate shares; this composes
/// the geographic and onomastic signals into the one namesake decision, so a
/// rare-surname subject's interstate kin are never mislabelled.
#[must_use]
pub fn is_namesake(e: &Entity, subject: &[(f64, f64)], surname_common: bool) -> bool {
    surname_common && is_geo_discordant_namesake(e, subject)
}

#[cfg(test)]
mod tests;
