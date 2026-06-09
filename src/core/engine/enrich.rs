//! Per-entity post-processing applied during a scan round, before persistence:
//! deterministic geospatial enrichment of Coordinates/Address entities, and
//! opportunistic API-key harvesting from any entity's value/evidence. Both are
//! pure free functions over a single entity (no engine state), split out of the
//! engine module so the round loop reads as orchestration, not enrichment detail.

/// Attach deterministic geospatial enrichment to a Coordinates or Address entity:
/// geohash (multiple precisions for proximity matching), timezone, hemisphere and
/// reverse-geocoded country for Coordinates; a parsed street/city/state/postal/
/// country breakdown for Address. No network — all from `util::geohash`. Other
/// kinds are untouched.
pub(super) fn enrich_geospatial(entity: &mut crate::core::entity::Entity) {
    use crate::core::entity::{EntityKind, Evidence};
    use crate::util::geohash;
    match entity.kind {
        EntityKind::Coordinates => {
            if let Some((lat, lon)) = geohash::parse_coords(&entity.value) {
                let h = geohash::geohash(lat, lon, 7);
                let tz = geohash::timezone_for(lat, lon);
                let iso = geohash::reverse_country_iso(lat, lon);
                let mut ev = Evidence::new("geo_normalize", "Geospatial enrichment");
                if !h.is_empty() {
                    ev = ev.with_attr("geohash", &h);
                    // Multiple precision-tagged hashes for proximity matching
                    // at different scales (region/city/suburb/street).
                    ev = ev
                        .with_attr("geohash_4", &h[..h.len().min(4)])
                        .with_attr("geohash_5", &h[..h.len().min(5)])
                        .with_attr("geohash_6", &h[..h.len().min(6)]);
                    if let Ok(h9) = std::panic::catch_unwind(|| geohash::geohash(lat, lon, 9)) {
                        ev = ev.with_attr("geohash_9", &h9);
                    }
                }
                ev = ev.with_attr("timezone", tz);
                ev = ev.with_attr("lat", format!("{lat:.6}"));
                ev = ev.with_attr("lon", format!("{lon:.6}"));
                let hemisphere = if lat >= 0.0 { "northern" } else { "southern" };
                ev = ev.with_attr("hemisphere", hemisphere);
                if let Some(iso) = iso {
                    ev = ev.with_attr("country_iso", iso);
                    if let Some(name) = geohash::country_name_for_iso(iso) {
                        ev = ev.with_attr("country_name", name);
                    }
                    entity.tag(format!("country:{iso}"));
                }
                entity.add_evidence(ev);
                entity.tag(format!("geohash:{}", &h[..h.len().min(5)]));
                entity.tag(format!("tz:{tz}"));
            }
        }
        EntityKind::Address => {
            let parsed = geohash::parse_address(&entity.value);
            let mut ev = Evidence::new("geo_normalize", "Address parse + normalization");
            let mut any = false;
            if let Some(s) = &parsed.street {
                ev = ev.with_attr("addr_street", s);
                any = true;
            }
            if let Some(c) = &parsed.city {
                ev = ev.with_attr("addr_city", c);
                any = true;
            }
            if let Some(s) = &parsed.state {
                ev = ev.with_attr("addr_state", s);
                any = true;
            }
            if let Some(p) = &parsed.postal_code {
                ev = ev.with_attr("addr_postal", p);
                any = true;
            }
            if let Some(c) = &parsed.country {
                ev = ev.with_attr("addr_country", c);
                any = true;
            }
            if let Some(iso) = &parsed.iso_country {
                ev = ev.with_attr("addr_iso", iso);
                entity.tag(format!("country:{iso}"));
                any = true;
            }
            if any {
                entity.add_evidence(ev);
            }
        }
        _ => {}
    }
}

/// Build the **subject anchor** for a scan seed: the queried identifier itself,
/// persisted as a root entity so the result graph always has a node for the thing
/// the operator searched for — the hub every derived relation and correlation
/// hangs off (the "individualised, subject-as-hub result" the engine is for).
///
/// Without this, the subject is a graph node only if some module happens to
/// re-emit the seed value; a `Coordinates`, `MacAddress`, `Organisation`, … seed
/// could finish a scan with no node for itself. Pre-inserting the anchor into the
/// seed round's entity map fixes that uniformly — and because merge is by uid
/// (GREATEST semantics), a module that re-emits the seed simply accumulates its
/// evidence onto this anchor rather than creating a duplicate.
///
/// `FullName` is intentionally **not** anchored here: `name_intel` already emits
/// the Person anchor for a name seed at its own deliberately Probable-tier
/// confidence (a name is inherently ambiguous — many people share one), and the
/// engine (core) must not reach into a module's calibration. Every other seed
/// kind is an exact, operator-asserted identifier, so it anchors at high
/// confidence. Returns `None` for the delegated/!pivotable kinds.
pub(super) fn seed_anchor_entity(
    target: &crate::core::scan::Target,
    scan_id: &str,
) -> Option<crate::core::entity::Entity> {
    use crate::core::entity::{Entity, Evidence};
    use crate::core::scan::TargetKind;

    // name_intel owns the Person anchor for name seeds (see doc comment).
    if target.kind == TargetKind::FullName {
        return None;
    }

    let kind = target.kind.to_entity_kind();
    // An operator-provided seed is a strong assertion that this identifier is the
    // subject — ranked above a verified single-source finding (holehe 0.85) but
    // below certainty, so a seed that later proves a dead end still ranks but
    // never claims absolute truth.
    let mut e = Entity::new(kind, &target.value, 0.90, scan_id);
    // Empty-after-normalisation guard: a blank/placeholder seed must not anchor a
    // valueless node (Entity::new keeps the raw value, but a normalised-empty
    // identifier is not a real subject).
    if e.value.trim().is_empty() {
        return None;
    }
    e.tag("seed");
    e.tag("subject");
    e.add_evidence(Evidence::new(
        "seed",
        "Scan seed — operator-provided target (subject anchor)",
    ));
    Some(e)
}

/// Harvest any API keys embedded in an entity's value or evidence attributes into
/// the global key pool (the force-multiplier loop: a key found in breach/leak data
/// unlocks more modules). Best-effort and side-effecting only on the pool; the
/// entity is read-only. Runs outside `catch_unwind`, so it uses panic-free slicing.
pub(super) fn scan_entity_for_keys(entity: &crate::core::entity::Entity) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
    use crate::util::key_pool::{KeyEntry, KeyStatus, global_pool};

    let pool = global_pool();
    let now = crate::core::entity::unix_now();
    // Short uid prefix for the harvest note. uids are 64-hex SHA-256 in practice,
    // but use the panic-free `.get(..8)` form (matching entity.rs) so a future
    // short/non-ASCII uid can never panic this out-of-`catch_unwind` scan path.
    let entity_ref = format!(
        "{}:{}",
        entity.kind,
        entity.uid.get(..8).unwrap_or(&entity.uid)
    );

    let harvest = |text: &str, source: &str, notes: Option<String>| {
        if let Some((service, key_val)) = identify_api_key(text) {
            let mut entry = KeyEntry::new(key_val);
            entry.status = KeyStatus::Untested;
            entry.discovered_at = Some(now);
            entry.discovered_by = Some(source.to_string());
            entry.discovered_in_scan = Some(entity.scan_id.clone());
            entry.source_entity = Some(entity_ref.clone());
            entry.notes = notes;
            pool.add(service, entry);
        }
    };

    harvest(&entity.value, "entity_value", None);

    for ev in &entity.evidence {
        for val in ev.attributes.values() {
            if (16..=200).contains(&val.len()) {
                harvest(
                    val,
                    &ev.source,
                    Some(format!("Evidence attr from {}", ev.source)),
                );
            }
        }
    }
}
