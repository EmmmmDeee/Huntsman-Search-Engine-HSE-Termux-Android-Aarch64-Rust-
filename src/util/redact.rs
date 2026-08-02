//! Subject-PII redaction for **shareable** scan exports.
//!
//! The default `json`/`csv`/`gexf` exports already drop quarantined `candidate`
//! rows (see `cli::export::renderers::confirmed_entities`), but they still carry
//! the subject's confirmed footprint verbatim — including credential-class
//! values (breach passwords, leaked credentials, harvested third-party API keys)
//! and street-precise GPS coordinates. Handing such a file to a third party, or
//! committing it somewhere world-readable, discloses exactly the data most
//! capable of causing direct harm: credentials enable account takeover, precise
//! coordinates a person's home.
//!
//! [`redact_entities`] is an opt-in pass (`hse export --redact`, and the HTTP
//! `?redact=1` query) that transforms an entity list *before* it is serialised
//! so the shareable artifact keeps its analytic shape — every kind, confidence,
//! corroboration count, source, and non-sensitive attribute — while the
//! sensitive **content** is masked:
//!   * credential-class values ([`is_credential_kind`]) → [`REDACTED`], and their
//!     evidence summaries/attributes scrubbed so the plaintext cannot re-leak via
//!     a raw breach record echoed into the evidence trail;
//!   * `coordinates` values → coarsened to ~11 km ([`coarsen_coordinates`]),
//!     enough to place a city/region for analysis but not a dwelling, with the
//!     precise lat/lon attributes on their evidence coarsened to match.
//!
//! The entity *count*, kinds, and confidences are deliberately preserved — the
//! redacted export still says "this subject had 8 breach passwords across 3
//! sources", it just no longer says what they were. This is NOT applied to the
//! `full`/`debug` dossiers, whose documented contract is total, unredacted
//! transparency for an authorised local interpreter.

use crate::core::entity::{Entity, EntityKind};

/// The placeholder substituted for a redacted credential-class value. Fixed and
/// content-free (no length hint, no prefix) so the mask leaks nothing about the
/// secret it replaces.
pub const REDACTED: &str = "[redacted]";

/// Evidence-attribute keys whose values are coarsened when a `Coordinates`
/// entity is redacted — the precise fix could otherwise survive in the evidence
/// trail after the top-level `value` was coarsened.
const COORD_ATTR_KEYS: &[&str] = &[
    "lat",
    "lon",
    "latitude",
    "longitude",
    "coordinates",
    "coord",
];

/// True for the credential-class kinds whose *value* is itself the secret:
/// [`EntityKind::Password`], [`EntityKind::Credential`], and
/// [`EntityKind::ApiKey`] (a harvested third-party key). These are masked
/// wholesale — unlike an email or username, no part of the value is safe to
/// disclose.
#[must_use]
pub fn is_credential_kind(kind: &EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Password | EntityKind::Credential | EntityKind::ApiKey
    )
}

/// Coarsen a `"lat,lon"` pair to one decimal place (~11 km at the equator) —
/// enough to place a city or region for analysis, not a dwelling. Returns
/// `None` (caller keeps the mask decision explicit) when `value` is not a
/// parseable coordinate pair, so a malformed value is never emitted as a
/// misleading `0.0,0.0`.
#[must_use]
pub fn coarsen_coordinates(value: &str) -> Option<String> {
    let (lat_s, lon_s) = value.split_once(',')?;
    let lat: f64 = lat_s.trim().parse().ok()?;
    let lon: f64 = lon_s.trim().parse().ok()?;
    if !lat.is_finite() || !lon.is_finite() {
        return None;
    }
    Some(format!("{},{}", round1(lat), round1(lon)))
}

/// Coarsen a lone decimal degree (a single `lat` or `lon` evidence attribute,
/// which carries no comma) to one decimal place. `None` if not a finite number,
/// so a non-coordinate attribute value is left untouched.
#[must_use]
pub fn coarsen_scalar(value: &str) -> Option<String> {
    let x: f64 = value.trim().parse().ok()?;
    x.is_finite().then(|| round1(x))
}

/// Round to 1 dp (~11 km), folding `-0.0` → `0.0` so the rendered output is
/// byte-stable regardless of the input's sign of zero.
fn round1(x: f64) -> String {
    let v = (x * 10.0).round() / 10.0;
    let v = if v == 0.0 { 0.0 } else { v };
    format!("{v:.1}")
}

/// Redact subject-PII in place across `entities`, for a shareable export. Masks
/// credential-class values and coarsens precise coordinates (see the module
/// doc). Idempotent — re-redacting an already-redacted list is a no-op, since a
/// masked value is not itself a credential secret or a fine coordinate. Pure
/// aside from the in-place mutation; preserves length, kinds, confidences, and
/// every non-sensitive field.
pub fn redact_entities(entities: &mut [Entity]) {
    for e in entities.iter_mut() {
        if is_credential_kind(&e.kind) {
            redact_credential(e);
        } else if e.kind == EntityKind::Coordinates {
            redact_coordinates(e);
        }
    }
}

/// Mask a credential entity's value and scrub its evidence so the plaintext
/// cannot survive in the summary or a raw-record attribute. The evidence
/// *entries* are kept (so `source_count`/corroboration stay truthful) — only
/// their content is replaced.
fn redact_credential(e: &mut Entity) {
    if e.value != REDACTED {
        e.value = REDACTED.to_string();
    }
    e.raw_value = REDACTED.to_string();
    for ev in &mut e.evidence {
        ev.summary = format!("[redacted {} evidence]", e.kind);
        ev.attributes.clear();
    }
}

/// Coarsen a coordinate entity's value and any precise lat/lon on its evidence.
/// A value that does not parse is left as-is (it is not a precise fix that can
/// harm) rather than blanked, keeping the export faithful.
fn redact_coordinates(e: &mut Entity) {
    if let Some(coarse) = coarsen_coordinates(&e.value) {
        e.value = coarse.clone();
        // raw_value mirrors value for coordinates; coarsen it too if it parses.
        if let Some(raw_coarse) = coarsen_coordinates(&e.raw_value) {
            e.raw_value = raw_coarse;
        } else {
            e.raw_value = coarse;
        }
    }
    for ev in &mut e.evidence {
        for k in COORD_ATTR_KEYS {
            if let Some(v) = ev.attributes.get_mut(*k) {
                // A `coordinates`/`coord` attribute is a `lat,lon` pair; `lat` /
                // `lon` / `latitude` / `longitude` are lone scalars with no comma.
                // Try the pair form first, then the scalar form, so both shapes
                // are coarsened and a non-numeric value is left untouched.
                if let Some(coarse) = coarsen_coordinates(v).or_else(|| coarsen_scalar(v)) {
                    *v = coarse;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;
    use crate::core::entity::{Entity, Evidence};

    #[test]
    fn credential_kinds_are_recognised() {
        assert!(is_credential_kind(&EntityKind::Password));
        assert!(is_credential_kind(&EntityKind::Credential));
        assert!(is_credential_kind(&EntityKind::ApiKey));
        assert!(!is_credential_kind(&EntityKind::Email));
        assert!(!is_credential_kind(&EntityKind::Coordinates));
    }

    #[test]
    fn coarsen_rounds_to_one_dp_and_rejects_garbage() {
        assert_eq!(
            coarsen_coordinates("-27.5047,152.9794").as_deref(),
            Some("-27.5,153.0")
        );
        assert_eq!(
            coarsen_coordinates("0.04, -0.04").as_deref(),
            Some("0.0,0.0")
        );
        assert_eq!(coarsen_coordinates("not a coord"), None);
        assert_eq!(coarsen_coordinates("12.3"), None, "needs both components");
        assert_eq!(coarsen_coordinates("nan,1.0"), None, "non-finite rejected");
    }

    #[test]
    fn coarsen_scalar_rounds_a_lone_degree() {
        assert_eq!(coarsen_scalar("-27.5047").as_deref(), Some("-27.5"));
        assert_eq!(coarsen_scalar("152.9794").as_deref(), Some("153.0"));
        assert_eq!(
            coarsen_scalar("-0.02").as_deref(),
            Some("0.0"),
            "-0.0 folded"
        );
        assert_eq!(coarsen_scalar("Chelmer"), None, "non-numeric left alone");
    }

    #[test]
    fn password_value_and_evidence_are_masked() {
        let mut e = Entity::new(
            EntityKind::Password,
            "hunter2",
            confidence::VERY_LOW,
            "comb_search",
        );
        e.add_evidence(
            Evidence::new("comb_search", "password hunter2 seen in dump")
                .with_attr("plaintext", "hunter2")
                .with_attr("source_db", "combolist-2024"),
        );
        let mut v = vec![e];
        redact_entities(&mut v);
        let e = &v[0];
        assert_eq!(e.value, REDACTED);
        assert_eq!(e.raw_value, REDACTED);
        // The plaintext must not survive anywhere in the serialised evidence.
        let ev = &e.evidence[0];
        assert!(
            !ev.summary.contains("hunter2"),
            "summary leaked: {}",
            ev.summary
        );
        assert!(ev.attributes.is_empty(), "attributes must be scrubbed");
        // The evidence entry itself is kept so source_count stays truthful.
        assert_eq!(e.evidence.len(), 1);
        assert_eq!(ev.source, "comb_search");
    }

    #[test]
    fn coordinates_value_and_precise_attrs_are_coarsened() {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            "-27.5047,152.9794",
            0.9,
            "au_unclaimed",
        );
        e.add_evidence(
            Evidence::new("au_unclaimed", "address fix")
                .with_attr("lat", "-27.5047")
                .with_attr("lon", "152.9794")
                .with_attr("locality", "Chelmer"),
        );
        let mut v = vec![e];
        redact_entities(&mut v);
        let e = &v[0];
        assert_eq!(e.value, "-27.5,153.0");
        let ev = &e.evidence[0];
        assert_eq!(ev.attributes.get("lat").map(String::as_str), Some("-27.5"));
        assert_eq!(ev.attributes.get("lon").map(String::as_str), Some("153.0"));
        // Non-coordinate attributes are untouched.
        assert_eq!(
            ev.attributes.get("locality").map(String::as_str),
            Some("Chelmer")
        );
    }

    #[test]
    fn non_sensitive_kinds_pass_through_unchanged() {
        let mut e = Entity::new(EntityKind::Email, "a@b.com", confidence::MEDIUM_PLUS, "src");
        e.tag("keep");
        let mut v = vec![e.clone()];
        redact_entities(&mut v);
        assert_eq!(v[0].value, "a@b.com");
        assert_eq!(v[0].tags, e.tags);
    }

    #[test]
    fn redaction_is_idempotent() {
        let mut e = Entity::new(EntityKind::Password, "hunter2", confidence::VERY_LOW, "src");
        e.add_evidence(Evidence::new("src", "hunter2").with_attr("plaintext", "hunter2"));
        let mut v = vec![e];
        redact_entities(&mut v);
        let once = v.clone();
        redact_entities(&mut v);
        assert_eq!(v[0].value, once[0].value);
        assert_eq!(v[0].evidence[0].summary, once[0].evidence[0].summary);
    }
}
