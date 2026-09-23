//! Per-entity post-processing applied during a scan round, before persistence:
//! deterministic geospatial enrichment of Coordinates/Address entities, and
//! opportunistic API-key harvesting from any entity's value/evidence. Both are
//! pure free functions over a single entity (no engine state), split out of the
//! engine module so the round loop reads as orchestration, not enrichment detail.

use crate::core::confidence;

/// The source name of the engine's own geospatial enrichment records.
const GEO_NORMALIZE_SOURCE: &str = "geo_normalize";
/// The summary of the Coordinates enrichment record — how a re-run finds (and
/// replaces) the record an earlier run wrote.
const COORD_ENRICHMENT_SUMMARY: &str = "Geospatial enrichment";

/// The country and timezone a PROVIDER already reported for this coordinate,
/// read from its evidence (`country_code` / `timezone` attributes of any source
/// but the engine's own `geo_normalize`), or — for the country — from a
/// `country:XX` tag that disagrees with the offline box (`box_iso`), which only
/// a provider can have set.
///
/// Deterministic whatever order the entity's records were merged in: each is
/// the first value by `(source, value)` order, not by evidence position.
fn provider_geo(
    entity: &crate::core::entity::Entity,
    box_iso: Option<&str>,
) -> (Option<String>, Option<String>) {
    let first_attr = |key: &str| -> Option<String> {
        entity
            .evidence
            .iter()
            .filter(|ev| ev.source != GEO_NORMALIZE_SOURCE)
            .filter_map(|ev| {
                ev.attributes
                    .get(key)
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty())
                    .map(|v| (ev.source.as_str(), v))
            })
            .min()
            .map(|(_, v)| v.to_string())
    };
    let cc = first_attr("country_code")
        .map(|c| c.to_ascii_uppercase())
        .or_else(|| {
            entity
                .tags
                .iter()
                .filter_map(|t| t.strip_prefix("country:"))
                .filter(|c| Some(*c) != box_iso)
                .min()
                .map(str::to_string)
        });
    (cc, first_attr("timezone"))
}

/// Attach deterministic geospatial enrichment to a Coordinates or Address entity:
/// geohash (multiple precisions for proximity matching), timezone, hemisphere and
/// reverse-geocoded country for Coordinates; a parsed street/city/state/postal/
/// country breakdown for Address. No network — all from `util::geohash`. Other
/// kinds are untouched.
///
/// # A provider's answer outranks the offline box
///
/// `reverse_country_iso` is a first-match bounding-box table (a hint, by its
/// own doc) and `timezone_for` a coarse zone map. When a provider already
/// reported the point's country or timezone (photon / geocode / open_meteo
/// `country_code`, open_meteo `timezone`), the box never contradicts it: the
/// provider's country is the `country:` tag, just as the provider's timezone
/// is the `tz:` tag (a disagreeing box answer is kept only as the evidence
/// attribute `country_iso_box`), and when the box's country disagrees with the
/// provider's no box timezone is emitted at all — it rests on the same wrong
/// region. Fredericton,
/// New Brunswick got `country:CA` from photon and `country:US` +
/// `tz:America/New_York` from the box (the US box is declared before CA and
/// covers southern New Brunswick), and a Queensland point got
/// `tz:Australia/Sydney` beside open_meteo's `Australia/Brisbane`
/// (REQ-GEO-013).
///
/// The provider's country is TAGGED, not merely left alone: `geocode`'s
/// forward results and `open_meteo_geo` carry `country_code` only as an
/// evidence attribute and never tag `country:XX` themselves, so leaving the
/// tag to the provider stripped every forward-geocoded point of its country
/// (no `country:AU`, no `country:US` for the "Bill Thorpe, Florida" geocodes)
/// in exports, CSV filters and the GEXF. It is recorded as `country_provider`,
/// which a re-run never retracts — it rests on the provider's own evidence,
/// which persists — so the retraction below cannot leave a point without the
/// provider's tag even when the tag string is one an earlier run also wrote
/// (REQ-GEO-015).
///
/// # Idempotent
///
/// Tags are unioned by `Entity::merge`, so a provider's answer can arrive in a
/// later emission than the box's. The engine therefore re-runs this on a
/// merged Coordinates entity, and each run first retracts what an earlier run
/// wrote — its `geo_normalize` record, and the box `country:` / `tz:` tags that
/// record says it added — before deciding afresh. Re-running never duplicates
/// the record. The event-log recovery (`Store::entities_from_events`) merges
/// the same emissions and re-runs this on each merged point too, so a scan
/// rebuilt from its events reaches the same one answer as the finalised scan
/// (REQ-GEO-016).
pub(crate) fn enrich_geospatial(entity: &mut crate::core::entity::Entity) {
    use crate::core::entity::{EntityKind, Evidence};
    use crate::util::geohash;
    match entity.kind {
        EntityKind::Coordinates => {
            if let Some((lat, lon)) = geohash::parse_coords(&entity.value) {
                // Retract an earlier run's record and the tags it recorded.
                let is_own = |ev: &Evidence| {
                    ev.source == GEO_NORMALIZE_SOURCE && ev.summary == COORD_ENRICHMENT_SUMMARY
                };
                let mut stale_tags: Vec<String> = Vec::new();
                for ev in entity.evidence.iter().filter(|ev| is_own(ev)) {
                    if let Some(c) = ev.attributes.get("country_iso") {
                        stale_tags.push(format!("country:{c}"));
                    }
                    if let Some(t) = ev.attributes.get("timezone") {
                        stale_tags.push(format!("tz:{t}"));
                    }
                }
                entity.evidence.retain(|ev| !is_own(ev));
                entity.tags.retain(|t| !stale_tags.contains(t));

                // An area standing in for a place is COARSE whichever module
                // minted it, and carries the grain it was admitted at. The
                // grain authority (`core::place::grain::assess`) decides from
                // positive evidence only — a gazetteer centroid (the one
                // authority on those values, so the ~30 modules that mint one
                // need not each remember the tag), a city lookup, an Address's
                // centroid, a geocoder's declared area grain or GeoNames feature
                // class, a forward geocode capped by an input that names no
                // street — never the unknown-provenance default, so an
                // unclassified precise emitter keeps its pivots. Before the
                // pivot gate reads the tag, and before the emit, so the event
                // log and recovery carry it too. `coarse` is never retracted
                // (the value and the evidence that decided it persist); the
                // `fix-grain:` stamp is re-decided each run from the same
                // evidence, reading the earlier stamp as a floor, so it only
                // ever coarsens and a merged point carries ONE grain
                // (REQ-GEO-017, REQ-GEOLABEL-005).
                let precision = crate::core::place::assess(entity);
                entity
                    .tags
                    .retain(|t| !t.starts_with(crate::core::place::grain::FIX_GRAIN_TAG_PREFIX));
                if precision.is_area() {
                    entity.tag(crate::core::tags::COARSE);
                    entity.tag(precision.grain.tag());
                }

                let h = geohash::geohash(lat, lon, 7);
                let box_iso = geohash::reverse_country_iso(lat, lon);
                let (provider_cc, provider_tz) = provider_geo(entity, box_iso);
                let box_disagrees = matches!(
                    (box_iso, provider_cc.as_deref()),
                    (Some(b), Some(p)) if b != p
                );
                let tz: Option<String> = provider_tz.or_else(|| {
                    (!box_disagrees).then(|| geohash::timezone_for(lat, lon).to_string())
                });
                let mut ev = Evidence::new(GEO_NORMALIZE_SOURCE, COORD_ENRICHMENT_SUMMARY);
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
                if let Some(tz) = &tz {
                    ev = ev.with_attr("timezone", tz);
                }
                ev = ev.with_attr("lat", format!("{lat:.6}"));
                ev = ev.with_attr("lon", format!("{lon:.6}"));
                let hemisphere = if lat >= 0.0 { "northern" } else { "southern" };
                ev = ev.with_attr("hemisphere", hemisphere);
                match (box_iso, provider_cc.as_deref()) {
                    // No provider answer: the box is the best available hint.
                    (Some(iso), None) => {
                        ev = ev.with_attr("country_iso", iso);
                        if let Some(name) = geohash::country_name_for_iso(iso) {
                            ev = ev.with_attr("country_name", name);
                        }
                        entity.tag(format!("country:{iso}"));
                    }
                    // A provider answered: its answer is the tag, whether the
                    // box agrees, disagrees or has none. A disagreeing box
                    // answer is recorded as the approximation it is, never as
                    // a tag.
                    (box_answer, Some(provider)) => {
                        if box_disagrees && let Some(iso) = box_answer {
                            ev = ev.with_attr("country_iso_box", iso);
                        }
                        ev = ev.with_attr("country_provider", provider);
                        if let Some(name) = geohash::country_name_for_iso(provider) {
                            ev = ev.with_attr("country_name", name);
                        }
                        entity.tag(format!("country:{provider}"));
                    }
                    (None, None) => {}
                }
                entity.add_evidence(ev);
                entity.tag(format!("geohash:{}", &h[..h.len().min(5)]));
                if let Some(tz) = tz {
                    entity.tag(format!("tz:{tz}"));
                }
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
    let mut e = Entity::new(kind, &target.value, confidence::VERY_HIGH_PLUS, scan_id);
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
/// tagged `addr-derived` so it is distinguishable from a direct geocode, and
/// [`COARSE`](crate::core::tags::COARSE) because `city_coords` has no street-level
/// result: even a full street address (`390, Simpsons Road, Bardon …`) resolves
/// to the Brisbane CBD centroid, which the next round then pivoted into reverse
/// geocoders and a cadastre lookup that returned a stranger's land parcel
/// (REQ-GEO-007). An
/// existing Coordinates uid (same `lat,lon` value) is detected by the caller via
/// the normal merge path; we never re-emit duplicates within the same pass.
/// The evidence attribute [`address_to_coords_pass`] stamps with the source
/// Address's uid — written by that pass alone, so [`is_coarse_geo`] reads it as
/// the pass's signature on a centroid recalled without its tag.
///
/// `core::geo_family` reads it too: a record carrying it is the Address's
/// source copied onto a centroid, never an observation of the subject.
pub(crate) const ADDR_ENTITY_UID_ATTR: &str = "addr_entity_uid";

/// Whether a geo entity is an area standing in for a place — the one predicate
/// behind the engine's `coarse_geo_not_pivoted` gate and the autonomous-seed
/// gate (`ranking::is_autonomous_seed_candidate`), so the two can't disagree.
///
/// A [`COARSE`](crate::core::tags::COARSE) tag decides it — and
/// [`enrich_geospatial`] stamps it on every `Coordinates` the grain authority
/// grades an area before the gate reads it. A `Coordinates` recalled from a
/// scan that predates that stamp is re-hydrated with its stored tag set and has
/// no `coarse`, so it is graded here directly by the same authority,
/// `core::place::grain::assess`
/// ([`FixPrecision::is_area`](crate::core::place::FixPrecision::is_area)),
/// which recognises the gazetteer value itself and the signature of each path
/// that minted a centroid before the table it came from could have changed:
/// `search_engines`' known-city lookup
/// ([`SEARCH_GEOCODED`](crate::core::tags::SEARCH_GEOCODED)),
/// [`address_to_coords_pass`] (its `addr_entity_uid` evidence), and
/// `search_engines`' recycled-snippet leg (the
/// [`RECYCLED`](crate::core::tags::RECYCLED) +
/// [`ADDR_DERIVED`](crate::core::tags::ADDR_DERIVED) pair, which no other path
/// mints on a `Coordinates`).
///
/// Unrecognised, such a centroid went on being pivoted into reverse geocoders
/// and cadastre lookups as a precise point (REQ-GEO-007, REQ-GEO-017).
pub(super) fn is_coarse_geo(e: &crate::core::entity::Entity) -> bool {
    use crate::core::entity::EntityKind;
    e.has_tag(crate::core::tags::COARSE)
        || (e.kind == EntityKind::Coordinates && crate::core::place::assess(e).is_area())
}

pub(super) fn address_to_coords_pass(
    entities: &std::collections::HashMap<String, crate::core::entity::Entity>,
    scan_id: &str,
) -> Vec<crate::core::entity::Entity> {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let mut out: Vec<Entity> = Vec::new();
    // Track coord values emitted in this pass to avoid creating two identical
    // Coordinates from two Address entities that both name the same city.
    let mut seen_coords: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Deterministic winner on a shared centroid: HashMap iteration is randomised,
    // and the `seen_coords` first-wins dedup below means WHICH address supplies a
    // shared city's Coordinates — its confidence and evidence — must not depend on
    // that order. Sort by confidence desc (the best address wins the slot) then
    // value asc (a total, stable tiebreak), so the persisted result is reproducible.
    let mut addrs: Vec<&Entity> = entities
        .values()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    addrs.sort_by(|a, b| {
        b.confidence
            .total_cmp(&a.confidence)
            .then_with(|| a.value.cmp(&b.value))
    });
    for addr_entity in addrs {
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
        // A reverse-geocoded Address was itself derived FROM a Coordinates
        // entity already in the map (`geocode` / `photon` reverse lookups tag
        // it so). Re-deriving it can only add a coarser copy of a point the map
        // has: scan 7258fc07 turned "390, Simpsons Road, Bardon …" back into
        // the Brisbane CBD centroid, filed under `geocode` (REQ-GEO-011).
        if addr_entity.has_tag("reverse-geocoded") {
            continue;
        }
        let Some(((lat, lon), grain)) =
            crate::util::city_coords::city_coords_with_grain(&addr_entity.value)
        else {
            continue;
        };
        let coord_val = format!("{lat:.4},{lon:.4}");
        if !seen_coords.insert(coord_val.clone()) {
            continue;
        }
        // Already have a Coordinates entity for this point?
        let candidate_uid = Entity::new(
            EntityKind::Coordinates,
            &coord_val,
            confidence::ZERO,
            scan_id,
        )
        .uid;
        if entities.contains_key(&candidate_uid) {
            continue;
        }
        // Confidence: inherit address confidence but cap at 0.72 (city centroid
        // is less precise than a GPS fix; AU-052's person-anchor gate still needs
        // ≥0.50, so we floor there too).
        let conf = addr_entity.confidence.clamp(0.50, 0.72);
        let mut c = Entity::new(EntityKind::Coordinates, &coord_val, conf, scan_id);
        c.tag(crate::core::tags::ADDR_DERIVED);
        c.tag(crate::core::tags::COARSE);
        c.tag("geoint");
        // Propagate au-state from the address so AU-056 jurisdiction check works.
        for tag in &addr_entity.tags {
            if tag.starts_with("au-state:") || tag.starts_with("country:") {
                c.tag(tag.clone());
            }
        }
        // Carry originating sources: the correlator's ANCHORING_GEO_SOURCES check
        // looks at corroborating_sources(), which reads Evidence source fields
        // (REQ-CORRELATOR-005 — no new source is invented). Each carried record
        // declares the centroid's GRAIN as `place_type`: the correlator weighs a
        // `geocode`/`photon` leg at 40 m unless a `place_type` says otherwise,
        // so a city centroid carried under `geocode` was a 40 m rooftop fix in
        // the fusion (REQ-GEO-011). The grain only ever coarsens a leg.
        let mut srcs: Vec<&str> = addr_entity.corroborating_sources().into_iter().collect();
        srcs.sort_unstable();
        for src in srcs {
            c.add_evidence(
                Evidence::new(
                    src,
                    format!(
                        "Inline geocode of address '{}' → {coord_val}",
                        addr_entity.value
                    ),
                )
                .with_attr(ADDR_ENTITY_UID_ATTR, &addr_entity.uid)
                .with_attr("addr_value", &addr_entity.value)
                .with_attr("place_type", grain)
                // Calculated from an address string, not observed here: the
                // `Evidence::is_inferred` flag's own definition, shown as
                // "(inferred)" wherever the record is rendered.
                .with_inferred(true),
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
pub(super) fn scan_entity_for_keys(
    entity: &crate::core::entity::Entity,
    module_runtime: &dyn crate::core::module_runtime::ModuleRuntime,
) {
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
        if let Some((service, key_val)) = module_runtime.identify_api_key(text) {
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
        let mut e = Entity::new(
            EntityKind::Email,
            "x@example.com",
            confidence::HIGH_PLUS,
            "s",
        );
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
        let mut oc = Entity::new(
            EntityKind::Email,
            "x@example.com",
            confidence::HIGH_PLUS,
            "s",
        );
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
        let mut xon = Entity::new(
            EntityKind::Email,
            "y@example.com",
            confidence::HIGH_PLUS,
            "s",
        );
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
        let mut not_breach = Entity::new(
            EntityKind::Email,
            "x@example.com",
            confidence::HIGH_PLUS,
            "s",
        );
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
        let mut e = Entity::new(
            EntityKind::Coordinates,
            "-27.4705,153.0260",
            confidence::MEDIUM_PLUS,
            "s",
        );
        enrich_geospatial(&mut e);
        assert!(e.tags.iter().any(|t| t.starts_with("geohash:")));
        assert!(e.tags.iter().any(|t| t.starts_with("tz:")));
        assert_eq!(geo_attr(&e, "hemisphere").as_deref(), Some("southern"));

        // Northern-hemisphere coordinate (London).
        let mut n = Entity::new(
            EntityKind::Coordinates,
            "51.5074,-0.1278",
            confidence::MEDIUM_PLUS,
            "s",
        );
        enrich_geospatial(&mut n);
        assert_eq!(geo_attr(&n, "hemisphere").as_deref(), Some("northern"));
    }

    /// REQ-GEO-013: a provider's country and timezone outrank the offline
    /// box. Scan 7258fc07: Fredericton, New Brunswick carried photon's
    /// `country:CA` AND the box's `country:US` + `tz:America/New_York`; a
    /// Queensland point got `tz:Australia/Sydney` beside open_meteo's
    /// `Australia/Brisbane`.
    #[test]
    fn enrich_geospatial_defers_to_provider_country_and_timezone() {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            "45.956872,-66.630394",
            confidence::MEDIUM_PLUS,
            "s",
        );
        e.add_evidence(Evidence::new("photon", "reverse").with_attr("country_code", "CA"));
        e.tag("country:CA");
        enrich_geospatial(&mut e);
        let cs: Vec<&String> = e
            .tags
            .iter()
            .filter(|t| t.starts_with("country:"))
            .collect();
        assert_eq!(cs, vec!["country:CA"]);
        assert!(
            !e.tags.iter().any(|t| t.starts_with("tz:")),
            "the box timezone rests on the box's wrong country: {:?}",
            e.tags
        );
        assert_eq!(geo_attr(&e, "country_iso_box").as_deref(), Some("US"));
        assert_eq!(geo_attr(&e, "country_iso"), None);

        let mut q = Entity::new(
            EntityKind::Coordinates,
            "-21.414720,148.579440",
            confidence::MEDIUM_PLUS,
            "s",
        );
        q.add_evidence(
            Evidence::new("open_meteo_geo", "geo")
                .with_attr("timezone", "Australia/Brisbane")
                .with_attr("country_code", "AU"),
        );
        enrich_geospatial(&mut q);
        assert!(q.has_tag("tz:Australia/Brisbane"));
        assert!(!q.has_tag("tz:Australia/Sydney"));
    }

    /// REQ-GEO-013: the merge unions tags, so a provider answer that arrives
    /// after the box answer must still win once the merged entity is
    /// re-enriched — and re-running replaces the engine's own record rather
    /// than adding another.
    #[test]
    fn enrich_geospatial_reconciles_a_later_provider_answer_idempotently() {
        let mut e = Entity::new(
            EntityKind::Coordinates,
            "45.956872,-66.630394",
            confidence::MEDIUM_PLUS,
            "s",
        );
        enrich_geospatial(&mut e);
        assert!(
            e.has_tag("country:US"),
            "no provider yet: the box hint stands"
        );

        let mut photon = Entity::new(
            EntityKind::Coordinates,
            "45.956872,-66.630394",
            confidence::MEDIUM_PLUS,
            "s",
        );
        photon.add_evidence(Evidence::new("photon", "reverse").with_attr("country_code", "CA"));
        photon.tag("country:CA");
        e.merge(photon);
        enrich_geospatial(&mut e);
        enrich_geospatial(&mut e);
        let cs: Vec<&String> = e
            .tags
            .iter()
            .filter(|t| t.starts_with("country:"))
            .collect();
        assert_eq!(cs, vec!["country:CA"]);
        assert!(!e.has_tag("tz:America/New_York"));
        assert_eq!(
            e.evidence
                .iter()
                .filter(|ev| ev.source == "geo_normalize")
                .count(),
            1,
            "a re-run replaces its own record"
        );
    }

    /// REQ-GEO-015: a provider's country is the tag even when the box agrees.
    /// `geocode`'s forward results and `open_meteo_geo` put `country_code` on
    /// their evidence and tag no country, so deferring to the provider without
    /// tagging left every forward-geocoded point with none.
    #[test]
    fn a_provider_country_the_box_agrees_with_is_still_tagged() {
        let mut fwd = Entity::new(
            EntityKind::Coordinates,
            "-33.868800,151.209300",
            confidence::MEDIUM_PLUS,
            "s",
        );
        fwd.add_evidence(
            Evidence::new("geocode", "Geocoded \"Sydney, NSW\"")
                .with_attr("country_code", "AU")
                .with_attr("input_address", "Sydney, NSW"),
        );
        enrich_geospatial(&mut fwd);
        enrich_geospatial(&mut fwd);
        let cs: Vec<&String> = fwd
            .tags
            .iter()
            .filter(|t| t.starts_with("country:"))
            .collect();
        assert_eq!(cs, vec!["country:AU"]);

        // A US point off the AU box table, from a provider with no tag of its own.
        let mut florida = Entity::new(
            EntityKind::Coordinates,
            "27.994402,-81.760254",
            confidence::MEDIUM_PLUS,
            "s",
        );
        florida.add_evidence(Evidence::new("geocode", "Geocoded").with_attr("country_code", "us"));
        enrich_geospatial(&mut florida);
        assert!(florida.has_tag("country:US"), "{:?}", florida.tags);

        // A recalled point from before this fix: photon's own `country:AU`
        // tag, and an old engine record that says the engine wrote the same
        // string. Retracting that record's tag must not strip photon's.
        let mut recalled = Entity::new(
            EntityKind::Coordinates,
            "-27.470500,153.026000",
            confidence::MEDIUM_PLUS,
            "s",
        );
        recalled.add_evidence(Evidence::new("photon", "reverse").with_attr("country_code", "AU"));
        recalled.tag("country:AU");
        recalled.add_evidence(
            Evidence::new(GEO_NORMALIZE_SOURCE, COORD_ENRICHMENT_SUMMARY)
                .with_attr("country_iso", "AU"),
        );
        enrich_geospatial(&mut recalled);
        assert!(recalled.has_tag("country:AU"), "{:?}", recalled.tags);
    }

    #[test]
    fn enrich_geospatial_leaves_other_kinds_untouched() {
        let mut e = Entity::new(EntityKind::Email, "a@b.com", confidence::MEDIUM_PLUS, "s");
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
        let mut bucket = Entity::new(
            EntityKind::Url,
            "https://x.s3.amazonaws.com/",
            confidence::MEDIUM_PLUS,
            "s",
        );
        bucket.tag("cloud-storage");
        tag_platform_infra(&mut bucket);
        assert!(
            bucket.has_tag(PLATFORM_INFRA),
            "cloud bucket → platform-infra"
        );

        // 2. datacenter/CDN hosting endpoint.
        let mut host = Entity::new(
            EntityKind::IpAddress,
            "104.16.0.1",
            confidence::MEDIUM_PLUS,
            "s",
        );
        host.tag(crate::core::tags::HOSTING);
        tag_platform_infra(&mut host);
        assert!(host.has_tag(PLATFORM_INFRA), "hosting IP → platform-infra");

        // 3. third-party analytics / tag id.
        let mut tid = Entity::new(
            EntityKind::TrackingId,
            "UA-12345-1",
            confidence::MEDIUM_PLUS,
            "s",
        );
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
        let mut e = Entity::new(
            EntityKind::IpAddress,
            "104.16.0.1",
            confidence::MEDIUM_PLUS,
            "s",
        );
        e.tag(crate::core::tags::HOSTING);
        tag_platform_infra(&mut e);
        tag_platform_infra(&mut e);
        assert_eq!(
            e.tags.iter().filter(|t| *t == PLATFORM_INFRA).count(),
            1,
            "the tag must not be duplicated on a second pass"
        );
    }

    #[test]
    fn address_to_coords_pass_winner_on_shared_centroid_is_deterministic() {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        // Two distinct Brisbane addresses resolve to the same city centroid, so the
        // seen_coords first-wins dedup emits ONE Coordinates. WHICH address supplies
        // it — hence the Coordinates' confidence — must be the higher-confidence
        // address every time, not whichever the randomised HashMap iterated first.
        // Confidence caps at 0.72, so the 0.80 address yields 0.72 and the 0.55
        // address yields 0.55 — a clean, order-independent discriminator.
        let mk = || {
            let mut hi = Entity::new(
                EntityKind::Address,
                "10 Queen St, Brisbane QLD 4000",
                0.80,
                "s1",
            );
            hi.tag("seed");
            hi.add_evidence(Evidence::new("abr", "hi addr"));
            let mut lo = Entity::new(
                EntityKind::Address,
                "99 King St, Brisbane QLD 4000",
                0.55,
                "s1",
            );
            lo.tag("seed");
            lo.add_evidence(Evidence::new("abr", "lo addr"));
            let mut m = std::collections::HashMap::new();
            m.insert(hi.uid.clone(), hi);
            m.insert(lo.uid.clone(), lo);
            m
        };
        for _ in 0..16 {
            let out = address_to_coords_pass(&mk(), "s1");
            let coords: Vec<_> = out
                .iter()
                .filter(|e| e.kind == EntityKind::Coordinates)
                .collect();
            assert_eq!(coords.len(), 1, "one centroid for the shared city");
            assert!(
                (coords[0].confidence - 0.72).abs() < 1e-9,
                "the higher-confidence 0.80 (→cap 0.72) address must win, got {}",
                coords[0].confidence
            );
        }
    }

    /// REQ-GEO-007: `city_coords` has no street-level result, so even a full
    /// street address becomes a city centroid — tagged COARSE so the engine
    /// never pivots it as a precise point.
    #[test]
    fn an_offline_address_centroid_is_coarse() {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let mut a = Entity::new(
            EntityKind::Address,
            "390, Simpsons Road, Bardon West, Bardon, Brisbane, Queensland, 4065, Australia",
            0.78,
            "s1",
        );
        a.add_evidence(Evidence::new("geocode", "forward geocode"));
        let mut m = std::collections::HashMap::new();
        m.insert(a.uid.clone(), a);
        let out = address_to_coords_pass(&m, "s1");
        assert_eq!(out.len(), 1, "sanity: the address resolves: {out:?}");
        let c = &out[0];
        assert!(c.has_tag(crate::core::tags::ADDR_DERIVED));
        assert!(c.has_tag(crate::core::tags::COARSE), "{c:?}");
        assert!(is_coarse_geo(c));
    }

    /// REQ-GEO-011: a reverse-geocoded Address came FROM a coordinate already
    /// in the map; re-deriving it only adds a coarser copy of that point, filed
    /// under `geocode`. Scan 7258fc07 turned a Bardon street address back into
    /// the Brisbane CBD centroid this way.
    #[test]
    fn a_reverse_geocoded_address_is_not_re_derived_to_a_centroid() {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let mut a = Entity::new(
            EntityKind::Address,
            "390, Simpsons Road, Bardon West, Bardon, Brisbane, Queensland, 4065, Australia",
            0.80,
            "s1",
        );
        a.tag("geoint");
        a.tag("reverse-geocoded");
        a.tag("country:AU");
        a.add_evidence(Evidence::new(
            "geocode",
            "Reverse geocode for -27.4459,152.9422",
        ));
        let mut m = std::collections::HashMap::new();
        m.insert(a.uid.clone(), a);
        assert!(address_to_coords_pass(&m, "s1").is_empty());
    }

    /// REQ-GEO-011: every record the pass carries onto a centroid declares the
    /// centroid's grain as `place_type`, keeping the Address's own source
    /// (REQ-CORRELATOR-005 unchanged). Without it a `geocode` leg on a city
    /// centroid was weighed as a 40 m rooftop fix — end to end, the AU-059
    /// radius floored at 0.04 km for two city-grain sightings.
    #[test]
    fn a_derived_centroid_declares_its_grain() {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let mut a = Entity::new(
            EntityKind::Address,
            "12 Example St, Toowong, Queensland",
            0.70,
            "s1",
        );
        a.add_evidence(Evidence::new("geocode", "forward geocode"));
        let mut m = std::collections::HashMap::new();
        m.insert(a.uid.clone(), a);
        let out = address_to_coords_pass(&m, "s1");
        assert_eq!(out.len(), 1, "sanity: Toowong resolves: {out:?}");
        let c = &out[0];
        assert!(!c.evidence.is_empty());
        for ev in &c.evidence {
            assert_eq!(ev.source, "geocode", "the Address's own source is kept");
            assert!(
                matches!(
                    ev.attributes.get("place_type").map(String::as_str),
                    Some("city" | "suburb" | "postcode" | "region")
                ),
                "{ev:?}"
            );
        }

        // End to end: beside a self-reported social location (5 km grain) on
        // the same point, the fused radius is never the 40 m of a rooftop.
        let mut social = Entity::new(EntityKind::Coordinates, &c.value, 0.70, "s1");
        social.add_evidence(Evidence::new("social_location", "profile location"));
        let fix = crate::core::correlator::au059_synergy_fix(&[c.clone(), social])
            .expect("two classes on one point fuse");
        assert!(
            fix.radius_km >= 1.5,
            "a gazetteer centroid is not a rooftop: radius {} km",
            fix.radius_km
        );
    }

    /// REQ-GEO-007: a centroid recalled from a scan that predates the COARSE
    /// tag is still recognised by the signature of the path that minted it.
    #[test]
    fn is_coarse_geo_recognises_an_untagged_legacy_centroid() {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let mut search = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.6, "s1");
        search.tag("search-geocoded");
        search.add_evidence(
            Evidence::new("search_engines", "Geocoded from search address: Sydney")
                .with_attr("method", "known-city-lookup"),
        );
        assert!(is_coarse_geo(&search));

        let mut pass = Entity::new(EntityKind::Coordinates, "-27.4698,153.0251", 0.6, "s1");
        pass.add_evidence(
            Evidence::new("geocode", "Inline geocode").with_attr("addr_entity_uid", "x"),
        );
        assert!(is_coarse_geo(&pass));

        // A precise fix from a geocoder is not coarse.
        let mut fix = Entity::new(EntityKind::Coordinates, "-27.4766,153.0166", 0.8, "s1");
        fix.tag("addr-derived");
        fix.add_evidence(Evidence::new("geocode", "forward geocode"));
        assert!(!is_coarse_geo(&fix));
    }

    /// REQ-GEO-017: the recycled-snippet leg's centroid, recalled from a scan
    /// that predates its `coarse` tag, is recognised by that leg's own
    /// signature — the `recycled` + `addr-derived` pair — even at a value the
    /// gazetteer no longer tabulates; and any untagged point whose value IS a
    /// gazetteer centroid is recognised by the value alone.
    #[test]
    fn is_coarse_geo_recognises_a_legacy_recycled_centroid_and_any_gazetteer_value() {
        // Off every table (Toowong's street grid), so only the signature can
        // decide it.
        let mut recycled = Entity::new(EntityKind::Coordinates, "-27.4801,152.9912", 0.5, "s1");
        for t in ["addr-derived", "geoint", "search-discovered", "recycled"] {
            recycled.tag(t);
        }
        recycled.add_evidence(
            Evidence::new("search_engines", "[bing] Coordinates from recycled search")
                .with_attr("recycle_query", "\"x\""),
        );
        assert!(
            !crate::util::city_coords::is_gazetteer_centroid(-27.4801, 152.9912),
            "fixture must be off the tables, or this proves nothing"
        );
        assert!(is_coarse_geo(&recycled));
        // `recycled` alone (a snippet's literal `geo:` coordinate) is a point.
        let mut literal = Entity::new(EntityKind::Coordinates, "-27.4801,152.9912", 0.5, "s1");
        literal.tag("recycled");
        literal.tag("snippet-coord");
        assert!(!is_coarse_geo(&literal));

        // An untagged Sydney centroid minted by any module (asic_persons tags
        // only `addr-derived`/`geoint`) is the gazetteer's value.
        let mut asic = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.6, "s1");
        asic.tag("addr-derived");
        asic.tag("geoint");
        asic.add_evidence(Evidence::new("asic_persons", "registered office"));
        assert!(is_coarse_geo(&asic));
    }

    /// REQ-GEO-017: the engine's enrichment tags every gazetteer centroid and
    /// every geocoder-declared area centroid `coarse`, whichever module minted
    /// it — so `tags::COARSE`'s "every centroid carries it" holds by one
    /// authority rather than by each of ~30 call sites remembering.
    #[test]
    fn enrichment_tags_every_gazetteer_and_declared_area_centroid_coarse() {
        let mut asic = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.6, "s1");
        asic.tag("addr-derived");
        asic.add_evidence(Evidence::new("asic_persons", "registered office"));
        enrich_geospatial(&mut asic);
        assert!(asic.has_tag(crate::core::tags::COARSE), "{:?}", asic.tags);

        // A region centroid (leading-digit table, 2-decimal row) too.
        let (lat, lon) = crate::util::city_coords::au_postcode_region("4999").unwrap();
        let mut region = Entity::new(
            EntityKind::Coordinates,
            format!("{lat:.4},{lon:.4}"),
            0.5,
            "s1",
        );
        enrich_geospatial(&mut region);
        assert!(region.has_tag(crate::core::tags::COARSE));

        // Nominatim declared its hit a city: the centroid of a city-only
        // Address, one hop from the same reverse-geocode defect.
        let mut city = Entity::new(EntityKind::Coordinates, "-33.869844,151.208285", 0.8, "s1");
        city.tag("geocoded");
        city.add_evidence(
            Evidence::new("geocode", "Geocoded \"Sydney NSW\"").with_attr("place_type", "city"),
        );
        enrich_geospatial(&mut city);
        assert!(city.has_tag(crate::core::tags::COARSE));

        // Over-correction controls: a house-grain geocode and an off-table
        // point stay points.
        let mut house = Entity::new(EntityKind::Coordinates, "-27.480123,152.991234", 0.8, "s1");
        house.add_evidence(
            Evidence::new("geocode", "Geocoded \"12 Foo St\"").with_attr("place_type", "house"),
        );
        enrich_geospatial(&mut house);
        assert!(!house.has_tag(crate::core::tags::COARSE));
        let mut gps = Entity::new(EntityKind::Coordinates, "-27.4801,152.9912", 0.8, "s1");
        gps.add_evidence(Evidence::new("exif", "photo GPS"));
        enrich_geospatial(&mut gps);
        assert!(!gps.has_tag(crate::core::tags::COARSE));
    }

    /// REQ-GEOLABEL-005 (R1): admission stamps `coarse` and the grain the point
    /// was admitted at on every emission the grain authority grades an area —
    /// including the shapes the value-and-`place_type` test missed: a
    /// known-city lookup off the tables, a forward geocode capped by an input
    /// that names only a state, a GeoNames headland — and on nothing else.
    #[test]
    fn admission_stamps_coarse_and_the_fix_grain_on_positive_evidence_only() {
        let fix_grains = |e: &Entity| -> Vec<String> {
            e.tags
                .iter()
                .filter(|t| t.starts_with(crate::core::place::grain::FIX_GRAIN_TAG_PREFIX))
                .cloned()
                .collect()
        };
        // Off every gazetteer table, so the value alone decides nothing.
        let off_table = "-27.4801,152.9912";

        let mut lookup = Entity::new(EntityKind::Coordinates, off_table, 0.6, "s1");
        lookup.add_evidence(
            Evidence::new("search_engines", "Geocoded from search address: Toowong")
                .with_attr("method", "known-city-lookup"),
        );
        enrich_geospatial(&mut lookup);
        assert!(
            lookup.has_tag(crate::core::tags::COARSE),
            "{:?}",
            lookup.tags
        );
        assert_eq!(fix_grains(&lookup), vec!["fix-grain:locality".to_string()]);

        let mut nc = Entity::new(EntityKind::Coordinates, "35.102800,-77.102600", 0.55, "s1");
        nc.add_evidence(
            Evidence::new("photon", "Photon geocoded \"Ian Thorpe, North Carolina\"")
                .with_attr("input_address", "Ian Thorpe, North Carolina")
                .with_attr("place_name", "Thorpe-Abbotts Lane")
                .with_attr("place_type", "street")
                .with_attr("ambiguity_detected", "true"),
        );
        enrich_geospatial(&mut nc);
        assert!(nc.has_tag(crate::core::tags::COARSE), "{:?}", nc.tags);
        assert_eq!(fix_grains(&nc), vec!["fix-grain:region".to_string()]);

        let mut headland = Entity::new(EntityKind::Coordinates, "-21.950000,148.680000", 0.4, "s1");
        headland.add_evidence(
            Evidence::new("open_meteo_geo", "Geocoded \"Sydney, Australia\"")
                .with_attr("feature_code", "MT"),
        );
        enrich_geospatial(&mut headland);
        assert!(headland.has_tag(crate::core::tags::COARSE));

        let mut a = Entity::new(
            EntityKind::Address,
            "12 Example St, Toowong, Queensland",
            0.7,
            "s1",
        );
        a.add_evidence(Evidence::new("geocode", "forward geocode"));
        let mut m = std::collections::HashMap::new();
        m.insert(a.uid.clone(), a);
        let mut derived = address_to_coords_pass(&m, "s1").remove(0);
        enrich_geospatial(&mut derived);
        assert_eq!(fix_grains(&derived), vec!["fix-grain:locality".to_string()]);

        // Controls: a measured device fix and an unclassified emitter are
        // never stamped — the unknown default is not positive evidence.
        let mut gps = Entity::new(
            EntityKind::Coordinates,
            "-27.4801234,152.9912345",
            0.9,
            "s1",
        );
        gps.tag("accuracy:10m");
        gps.add_evidence(Evidence::new("signal_radar", "GNSS fix"));
        enrich_geospatial(&mut gps);
        assert!(!gps.has_tag(crate::core::tags::COARSE));
        assert!(fix_grains(&gps).is_empty());
        let mut unknown = Entity::new(EntityKind::Coordinates, off_table, 0.6, "s1");
        unknown.add_evidence(Evidence::new("some_new_module", "a point"));
        enrich_geospatial(&mut unknown);
        assert!(!unknown.has_tag(crate::core::tags::COARSE));
        assert!(fix_grains(&unknown).is_empty());

        // A merged point carries ONE grain, re-decided coarser-only: a later
        // state-grain answer on the stamped locality re-stamps it a region.
        lookup.add_evidence(
            Evidence::new("geocode", "Geocoded \"Queensland\"").with_attr("place_type", "state"),
        );
        enrich_geospatial(&mut lookup);
        assert_eq!(fix_grains(&lookup), vec!["fix-grain:region".to_string()]);
        enrich_geospatial(&mut lookup);
        assert_eq!(
            fix_grains(&lookup),
            vec!["fix-grain:region".to_string()],
            "idempotent"
        );
    }

    /// REQ-GEOLABEL-005: a coordinate `address_to_coords_pass` calculates from
    /// an address is inferred, not observed — every record it carries says so.
    #[test]
    fn a_derived_centroid_records_are_inferred() {
        let mut a = Entity::new(
            EntityKind::Address,
            "12 Example St, Toowong, Queensland",
            0.7,
            "s1",
        );
        a.add_evidence(Evidence::new("geocode", "forward geocode"));
        a.add_evidence(Evidence::new("abn_lookup", "registered address"));
        let mut m = std::collections::HashMap::new();
        m.insert(a.uid.clone(), a);
        let out = address_to_coords_pass(&m, "s1");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].evidence.len(), 2);
        assert!(
            out[0].evidence.iter().all(|ev| ev.is_inferred),
            "{:?}",
            out[0].evidence
        );
    }

    /// REQ-GEOLABEL-005: the pivot gate reads the grain authority, so an
    /// untagged point recalled from an older scan is judged by its evidence —
    /// a geocode of a city-only input is that city — and a MEASURED fix that
    /// happens to sit on a tabulated centroid is not demoted to one.
    #[test]
    fn is_coarse_geo_reads_the_grain_authority() {
        let mut city_only =
            Entity::new(EntityKind::Coordinates, "-27.482111,152.998765", 0.6, "s1");
        city_only.add_evidence(
            Evidence::new("geocode", "Geocoded \"Toowong\"")
                .with_attr("input_address", "Toowong")
                .with_attr("place_type", "house"),
        );
        assert!(is_coarse_geo(&city_only));

        let mut gps = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.9, "s1");
        gps.add_evidence(Evidence::new("exif_geo", "EXIF GPS").with_attr("gps_accuracy_m", "6"));
        assert!(!is_coarse_geo(&gps));
    }
}
