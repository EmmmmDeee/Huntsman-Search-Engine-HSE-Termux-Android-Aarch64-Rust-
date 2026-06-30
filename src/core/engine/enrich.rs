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

/// Convert confirmed Address entities to Coordinates via offline city lookup,
/// then return the new entities so the caller can merge them into the entity map.
///
/// This is the architectural bridge that lets AU-052/AU-053 consume location
/// signals from every module that emits an Address (social_location,
/// email_header_geo, abn_lookup, search_engines, qld_unclaimed, …), not just the
/// dedicated geocoding modules.
///
/// Gate: confidence ≥ 0.45 (all PROBABLE + postcode-qualified CANDIDATE addresses)
/// and at least one corroborating source from outside the Address itself, so a
/// bare, unsupported address string doesn't assert a footprint. The derived
/// Coordinates entity inherits the Address's sources and confidence (capped at
/// 0.72 — city-centroid precision is inherently coarser than a GPS fix), and is
/// tagged `addr-derived` so it is distinguishable from a direct geocode. An
/// existing Coordinates uid (same `lat,lon` value) is detected by the caller via
/// the normal merge path; we never re-emit duplicates within the same pass.
pub(super) fn address_to_coords_pass(
    entities: &std::collections::HashMap<String, crate::core::entity::Entity>,
    scan_id: &str,
) -> Vec<crate::core::entity::Entity> {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let mut out: Vec<Entity> = Vec::new();
    // Track coord values emitted in this pass to avoid creating two identical
    // Coordinates from two Address entities that both name the same city.
    let mut seen_coords: std::collections::HashSet<String> = std::collections::HashSet::new();

    for addr_entity in entities.values() {
        if addr_entity.kind != EntityKind::Address {
            continue;
        }
        // Registry/validated sources (ABR, company registries, social profiles
        // with explicit geoint tag) have externally-verified addresses; lower
        // their gate from 0.45 to 0.40 so even conservative confidence estimates
        // feed the footprint. All others keep the 0.45 floor.
        let validated = addr_entity.has_tag("abr") || addr_entity.has_tag("validated") || {
            addr_entity.has_tag("geoint")
                && (addr_entity.has_tag("professional-address")
                    || addr_entity.has_tag("social-profile"))
        };
        let gate = if validated { 0.40 } else { 0.45 };
        if addr_entity.confidence < gate {
            continue;
        }
        // Skip if no corroborating sources recorded — a bare assertion with
        // confidence raised purely by the seeding pass would otherwise assert a
        // location from nothing. Seed-tagged addresses are operator-provided and
        // pre-verified, so they bypass this check.
        if addr_entity.corroborating_sources().is_empty() && !addr_entity.has_tag("seed") {
            continue;
        }
        let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr_entity.value) else {
            continue;
        };
        let coord_val = format!("{lat:.4},{lon:.4}");
        if !seen_coords.insert(coord_val.clone()) {
            continue;
        }
        // Already have a Coordinates entity for this point?
        let candidate_uid = Entity::new(EntityKind::Coordinates, &coord_val, 0.0, scan_id).uid;
        if entities.contains_key(&candidate_uid) {
            continue;
        }
        // Confidence: inherit address confidence but cap at 0.72 (city centroid
        // is less precise than a GPS fix; AU-052's person-anchor gate still needs
        // ≥0.50, so we floor there too).
        let conf = addr_entity.confidence.clamp(0.50, 0.72);
        let mut c = Entity::new(EntityKind::Coordinates, &coord_val, conf, scan_id);
        c.tag("addr-derived");
        c.tag("geoint");
        // Propagate au-state from the address so AU-056 jurisdiction check works.
        for tag in &addr_entity.tags {
            if tag.starts_with("au-state:") || tag.starts_with("country:") {
                c.tag(tag.clone());
            }
        }
        // Carry originating sources: the correlator's ANCHORING_GEO_SOURCES check
        // looks at corroborating_sources(), which reads Evidence source fields.
        for src in addr_entity.corroborating_sources() {
            c.add_evidence(
                Evidence::new(
                    src,
                    format!(
                        "Inline geocode of address '{}' → {coord_val}",
                        addr_entity.value
                    ),
                )
                .with_attr("addr_entity_uid", &addr_entity.uid)
                .with_attr("addr_value", &addr_entity.value),
            );
        }
        out.push(c);
    }
    out
}

/// Tag a breach-derived entity with the **sector** of the source it leaked from
/// (`sector:real-estate`, `sector:finance`, `sector:gaming`, …), classified from
/// the breach source DB carried on its evidence.
///
/// This is the universal wiring for sector intelligence: a SINGLE admission-time
/// pass connects EVERY breach pool to [`crate::util::breach_sector`], so a hit
/// can be filtered by the sector of the breach regardless of which module
/// surfaced it (the answer to "show me only the breached real-estate data" is
/// the tag `sector:real-estate`, applied identically everywhere). Three source
/// conventions are read: the fixed per-pool keys (`oathnet_pro` `dbname`,
/// `see_know` `source`, HIBP `breach_name`/`breach_domain`, `dehashed`
/// `database`), `osintcat`'s dynamic `breach_<name>` keys, and `xposed_or_not`'s
/// comma-joined `breaches` list. EVERY distinct sector found is tagged (an
/// account in breaches across several industries earns one `sector:` tag per
/// industry), so a single-sector filter never misses a hit behind another
/// sector. Idempotent (`Entity::tag` de-duplicates), and a no-op for non-breach
/// entities and unclassifiable sources — never a guess.
pub(super) fn tag_breach_sector(entity: &mut crate::core::entity::Entity) {
    use crate::util::breach_sector::source_sector;
    if !entity.has_tag(crate::core::tags::BREACH) {
        return;
    }
    // Fixed per-pool keys whose VALUE is a clean source/DB name: oathnet
    // `dbname`, see_know `source` (the canonical DB token) + `source_db` (its
    // demoted secondary), HIBP `breach_name`/`breach_domain`, dehashed
    // `database`/`database_name`.
    const SOURCE_KEYS: &[&str] = &[
        "dbname",
        "source",
        "breach_name",
        "breach_domain",
        "database",
        "database_name",
        "source_db",
    ];
    // Collect EVERY distinct sector across all breach-source signals: an account
    // that surfaced in breaches from several industries earns a `sector:` tag for
    // each, so a single-sector filter ("breached real-estate only") can never
    // miss it behind another sector that merely classified first.
    let mut sectors: Vec<&'static str> = Vec::new();
    let note = |src: &str, sectors: &mut Vec<&'static str>| {
        if let Some(sector) = source_sector(src)
            && !sectors.contains(&sector)
        {
            sectors.push(sector);
        }
    };
    for ev in &entity.evidence {
        for (key, val) in &ev.attributes {
            if SOURCE_KEYS.contains(&key.as_str()) {
                note(val, &mut sectors);
            }
            // osintcat records each breach under a dynamic `breach_<name>` key
            // (e.g. `breach_Zynga`); the leak name is the suffix. The fixed
            // `breach_count`/`breach_date`/… suffixes simply never resolve, so no
            // exclusion list is needed.
            if let Some(name) = key.strip_prefix("breach_") {
                note(name, &mut sectors);
            }
            // xposed_or_not joins every breach name into one `breaches` attr.
            if key == "breaches" {
                for name in val.split(", ") {
                    note(name, &mut sectors);
                }
            }
        }
    }
    for sector in sectors {
        entity.tag(format!("sector:{sector}"));
    }
}

/// Stamp `platform-infra` on shared / third-party infrastructure so the default
/// report can suppress it (restorable via `--include-infra` / `--output full`)
/// and the location rules keep it out of the subject's physical footprint. The
/// three product-defined infrastructure classes:
///   * a **cloud-storage** bucket (`cloud-storage` tag),
///   * a **datacenter/CDN hosting** endpoint ([`crate::core::tags::HOSTING`]),
///   * a third-party **analytics / tag id** ([`crate::core::entity::EntityKind::TrackingId`]).
///
/// Never matches a subject-owned identity (Person/Email/Username/Phone/Address/…),
/// so it can only ever demote infrastructure, never a real finding. Idempotent;
/// the underlying entities are still stored and correlated — only the default
/// *view* hides them. One chokepoint so every producer of these classes is
/// categorised identically (the same wiring pattern as [`tag_breach_sector`]).
pub(super) fn tag_platform_infra(entity: &mut crate::core::entity::Entity) {
    use crate::core::{entity::EntityKind, tags};
    if entity.has_tag(tags::PLATFORM_INFRA) {
        return;
    }
    let is_infra = entity.has_tag("cloud-storage")
        || entity.has_tag(tags::HOSTING)
        || entity.kind == EntityKind::TrackingId;
    if is_infra {
        entity.tag(tags::PLATFORM_INFRA);
    }
}

/// Harvest any API keys embedded in an entity's value or evidence attributes into
/// the global key pool (the force-multiplier loop: a key found in breach/leak data
/// unlocks more modules). Best-effort and side-effecting only on the pool; the
/// entity is read-only. Runs outside `catch_unwind`, so it uses panic-free slicing.
pub(super) fn scan_entity_for_keys(entity: &crate::core::entity::Entity) {
    use crate::core::hooks::identify_api_key;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::scan::{Target, TargetKind};

    // ── tag_breach_sector (universal pool wiring) ─────────────────────────────

    fn breach_entity(source_key: &str, source_val: &str) -> Entity {
        let mut e = Entity::new(EntityKind::Email, "x@example.com", 0.7, "s");
        e.tag(crate::core::tags::BREACH);
        e.add_evidence(Evidence::new("pool", "breach row").with_attr(source_key, source_val));
        e
    }

    #[test]
    fn tag_breach_sector_wires_every_pool_via_its_own_source_key() {
        // oathnet `dbname`, see_know `source`, HIBP `breach_domain` — one pass
        // resolves the sector whichever key the pool used.
        for (key, val) in [
            ("dbname", "0123_HARCOURTS_AU_2M_REALESTATE_032021"),
            ("source", "realestate.com.au"),
            ("breach_domain", "ljhooker.com.au"),
            ("database_name", "PropertyTree"),
        ] {
            let mut e = breach_entity(key, val);
            tag_breach_sector(&mut e);
            assert!(
                e.has_tag("sector:real-estate"),
                "{key}={val} should resolve real-estate; tags: {:?}",
                e.tags
            );
        }
        // The real GAMING source from the dump → sector:gaming.
        let mut g = breach_entity("source", "0645_ZYNGA_COM_202M_GAMING_092019");
        tag_breach_sector(&mut g);
        assert!(g.has_tag("sector:gaming"));
    }

    #[test]
    fn wires_the_bare_name_pools_osintcat_and_xposed() {
        // osintcat records each breach under a dynamic `breach_<name>` key — the
        // real `Zynga`/`Neopets` brands from the live graph now resolve.
        let mut oc = Entity::new(EntityKind::Email, "x@example.com", 0.7, "s");
        oc.tag(crate::core::tags::BREACH);
        oc.add_evidence(
            Evidence::new("osintcat", "breaches")
                .with_attr("breach_count", "2")
                .with_attr("breach_Neopets", "Breach: Neopets (2013-01-01)")
                .with_attr("breach_SomeUnknownLeak", "Breach: SomeUnknownLeak (2020)"),
        );
        tag_breach_sector(&mut oc);
        assert!(oc.has_tag("sector:gaming"), "tags: {:?}", oc.tags);

        // xposed_or_not joins all breach names into one `breaches` attr; a single
        // pass picks up EVERY distinct sector among them (multi-sector).
        let mut xon = Entity::new(EntityKind::Email, "y@example.com", 0.7, "s");
        xon.tag(crate::core::tags::BREACH);
        xon.add_evidence(
            Evidence::new("xposed_or_not", "breaches")
                .with_attr("breaches", "Zynga, Tumblr, MyFitnessPal, Collection1"),
        );
        tag_breach_sector(&mut xon);
        assert!(xon.has_tag("sector:gaming"));
        assert!(xon.has_tag("sector:social"));
        assert!(xon.has_tag("sector:health"));
        // Collection1 is an unclassifiable combo list → no spurious tag for it.
        assert_eq!(
            xon.tags.iter().filter(|t| t.starts_with("sector:")).count(),
            3
        );
    }

    #[test]
    fn tag_breach_sector_is_a_no_op_off_the_breach_path() {
        // A non-breach entity is untouched even with a property-looking source.
        let mut not_breach = Entity::new(EntityKind::Email, "x@example.com", 0.7, "s");
        not_breach
            .add_evidence(Evidence::new("search", "x").with_attr("source", "realestate.com.au"));
        tag_breach_sector(&mut not_breach);
        assert!(!not_breach.tags.iter().any(|t| t.starts_with("sector:")));

        // A breach entity from an unclassifiable source (the real pureincubation
        // broker) gets no sector tag — never a guess.
        let mut unknown = breach_entity("dbname", "pureincubation.com");
        tag_breach_sector(&mut unknown);
        assert!(!unknown.tags.iter().any(|t| t.starts_with("sector:")));

        // Idempotent: re-running doesn't duplicate the tag.
        let mut re = breach_entity("dbname", "realestate.com.au");
        tag_breach_sector(&mut re);
        tag_breach_sector(&mut re);
        assert_eq!(
            re.tags.iter().filter(|t| t.starts_with("sector:")).count(),
            1
        );
    }

    // ── enrich_geospatial ─────────────────────────────────────────────────────

    fn geo_attr(e: &Entity, key: &str) -> Option<String> {
        e.evidence
            .iter()
            .find(|ev| ev.source == "geo_normalize")
            .and_then(|ev| ev.attributes.get(key).cloned())
    }

    #[test]
    fn enrich_geospatial_tags_coordinates_with_geohash_and_hemisphere() {
        // Southern-hemisphere coordinate (Brisbane).
        let mut e = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s");
        enrich_geospatial(&mut e);
        assert!(e.tags.iter().any(|t| t.starts_with("geohash:")));
        assert!(e.tags.iter().any(|t| t.starts_with("tz:")));
        assert_eq!(geo_attr(&e, "hemisphere").as_deref(), Some("southern"));

        // Northern-hemisphere coordinate (London).
        let mut n = Entity::new(EntityKind::Coordinates, "51.5074,-0.1278", 0.6, "s");
        enrich_geospatial(&mut n);
        assert_eq!(geo_attr(&n, "hemisphere").as_deref(), Some("northern"));
    }

    #[test]
    fn enrich_geospatial_leaves_other_kinds_untouched() {
        let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.6, "s");
        enrich_geospatial(&mut e);
        assert!(
            e.evidence.iter().all(|ev| ev.source != "geo_normalize"),
            "a non-geo entity must not gain geo_normalize evidence"
        );
    }

    // ── seed_anchor_entity ────────────────────────────────────────────────────

    #[test]
    fn seed_anchor_entity_builds_subject_hub_for_ordinary_seed() {
        let t = Target::new(TargetKind::Email, "subject@corp.io");
        let e = seed_anchor_entity(&t, "s").expect("email seed anchors");
        assert_eq!(e.kind, EntityKind::Email);
        assert!((e.confidence - 0.90).abs() < 1e-9);
        assert!(e.has_tag("seed") && e.has_tag("subject"));
        assert!(e.has_evidence_from("seed"));
    }

    #[test]
    fn seed_anchor_entity_skips_fullname_seed() {
        // name_intel owns the Person anchor for a name seed.
        let t = Target::new(TargetKind::FullName, "Haigen Bamford");
        assert!(seed_anchor_entity(&t, "s").is_none());
    }

    #[test]
    fn seed_anchor_entity_skips_blank_value() {
        let t = Target::new(TargetKind::Username, "   ");
        assert!(seed_anchor_entity(&t, "s").is_none());
    }

    // ── tag_platform_infra ────────────────────────────────────────────────────

    #[test]
    fn tag_platform_infra_marks_the_three_infrastructure_classes() {
        use crate::core::tags::PLATFORM_INFRA;
        // 1. cloud-storage bucket.
        let mut bucket = Entity::new(EntityKind::Url, "https://x.s3.amazonaws.com/", 0.6, "s");
        bucket.tag("cloud-storage");
        tag_platform_infra(&mut bucket);
        assert!(
            bucket.has_tag(PLATFORM_INFRA),
            "cloud bucket → platform-infra"
        );

        // 2. datacenter/CDN hosting endpoint.
        let mut host = Entity::new(EntityKind::IpAddress, "104.16.0.1", 0.6, "s");
        host.tag(crate::core::tags::HOSTING);
        tag_platform_infra(&mut host);
        assert!(host.has_tag(PLATFORM_INFRA), "hosting IP → platform-infra");

        // 3. third-party analytics / tag id.
        let mut tid = Entity::new(EntityKind::TrackingId, "UA-12345-1", 0.6, "s");
        tag_platform_infra(&mut tid);
        assert!(tid.has_tag(PLATFORM_INFRA), "TrackingId → platform-infra");
    }

    #[test]
    fn tag_platform_infra_never_marks_a_subject_owned_identity() {
        use crate::core::tags::PLATFORM_INFRA;
        for kind in [
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Address,
            EntityKind::Domain,
        ] {
            let mut e = Entity::new(kind.clone(), "subject-value", 0.7, "s");
            tag_platform_infra(&mut e);
            assert!(
                !e.has_tag(PLATFORM_INFRA),
                "a subject-owned {kind:?} must never be demoted to infrastructure"
            );
        }
    }

    #[test]
    fn tag_platform_infra_is_idempotent() {
        use crate::core::tags::PLATFORM_INFRA;
        let mut e = Entity::new(EntityKind::IpAddress, "104.16.0.1", 0.6, "s");
        e.tag(crate::core::tags::HOSTING);
        tag_platform_infra(&mut e);
        tag_platform_infra(&mut e);
        assert_eq!(
            e.tags.iter().filter(|t| *t == PLATFORM_INFRA).count(),
            1,
            "the tag must not be duplicated on a second pass"
        );
    }
}
