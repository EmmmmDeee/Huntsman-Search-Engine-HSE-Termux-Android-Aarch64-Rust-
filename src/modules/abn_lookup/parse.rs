//! Response parsers for ABR JSON payloads.

use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

use super::SRC;

/// Expand a single ABR `AbnDetails`/`AcnDetails` record into entities.
///
/// Fans one registry hit out into the full graph the correlators expect: the
/// `Organisation` (confidence trimmed if the ABN is cancelled), the `AbnAcn`
/// identifier, the registered `Address`, an inline `Coordinates` anchor
/// (postcode → suburb centroid, falling back to state) for the AU geo rules
/// AU-052/053, the registered trading `BusinessName`s (up to
/// [`MAX_TRADING_NAMES`](super::MAX_TRADING_NAMES)), and — when the entity type
/// is an individual/sole-trader — a `Person`. A non-empty `Message` field (the
/// ABR's "no match"/error marker) or a missing `EntityName` is a no-op, so a
/// miss adds nothing. Every emitted entity is tagged `abr`/`country:AU`,
/// consistent with the platform's AU focus.
pub(super) fn parse_abn_result(data: &Value, scan_id: &str, result: &mut ModuleResult) {
    if data
        .get("Message")
        .and_then(|m| m.as_str())
        .is_some_and(|m| !m.is_empty())
    {
        return;
    }

    let abn = str_field(data, "Abn").unwrap_or_default();
    let entity_name = str_field(data, "EntityName").unwrap_or_default();
    let entity_type = str_field(data, "EntityTypeCode")
        .or_else(|| str_field(data, "EntityTypeName"))
        .unwrap_or_default();
    let status = str_field(data, "AbnStatus").unwrap_or_default();
    let state = str_field(data, "AddressState").unwrap_or_default();
    let postcode = str_field(data, "AddressPostcode").unwrap_or_default();
    let gst = str_field(data, "Gst").unwrap_or_default();

    if entity_name.is_empty() {
        return;
    }

    let mut org = Entity::new(EntityKind::Organisation, &entity_name, 0.90, scan_id);
    org.tag("abr");
    org.tag("australian");
    if status.to_lowercase().contains("active") {
        org.tag("active");
    } else if !status.is_empty() {
        org.tag("inactive");
        org.confidence = (org.confidence - 0.10).max(0.10);
    }

    let mut ev = Evidence::new(SRC, format!("ABR: {entity_name} (ABN {abn})"))
        .with_attr("abn", &abn)
        .with_attr("entity_type", &entity_type)
        .with_attr("status", &status);

    if !state.is_empty() {
        ev = ev.with_attr("state", &state);
    }
    if !postcode.is_empty() {
        ev = ev.with_attr("postcode", &postcode);
    }
    if !gst.is_empty() {
        ev = ev.with_attr("gst_registered", &gst);
    }

    org.add_evidence(ev);
    result.push(org);

    if !abn.is_empty() {
        let mut abn_entity = Entity::new(EntityKind::AbnAcn, &abn, 0.95, scan_id);
        abn_entity.tag("abr");
        abn_entity.add_evidence(Evidence::new(SRC, format!("ABN {abn} → {entity_name}")));
        result.push(abn_entity);
    }

    if !state.is_empty() {
        let addr = if postcode.is_empty() {
            format!("{state}, Australia")
        } else {
            format!("{postcode}, {state}, Australia")
        };
        let mut addr_entity = Entity::new(EntityKind::Address, &addr, 0.75, scan_id);
        addr_entity.tag("abr");
        addr_entity.tag("country:AU");
        if let Some(sc) = crate::util::address_au::state_code(&addr) {
            addr_entity.tag(format!("au-state:{sc}"));
        }
        addr_entity.add_evidence(Evidence::new(
            SRC,
            format!("Business address for {entity_name}"),
        ));
        result.push(addr_entity);

        // Emit inline Coordinates for city-level geo correlation.
        // Prefer postcode → suburb centroid, fall back to city_coords on the
        // full address string. ABR addresses are registry-validated, so these
        // coordinates are strong anchors for AU-052/053.
        let coord_source = if !postcode.is_empty() {
            crate::util::city_coords::city_coords(&addr)
                .or_else(|| crate::util::city_coords::city_coords(&state))
        } else {
            crate::util::city_coords::city_coords(&state)
        };
        if let Some((lat, lon)) = coord_source {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.65, scan_id);
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("country:AU");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                c.tag(format!("au-state:{sc}"));
            }
            c.add_evidence(Evidence::new(
                SRC,
                format!("Inline geocode of ABR address '{addr}' → {coord_val}"),
            ));
            result.push(c);
        }
    }

    if let Some(names) = data.get("BusinessName").and_then(|v| v.as_array()) {
        for bn in names.iter().take(super::MAX_TRADING_NAMES) {
            if let Some(name) = bn
                .as_str()
                .or_else(|| bn.get("Value").and_then(|v| v.as_str()))
                && !name.is_empty()
                && name != entity_name
            {
                let mut bn_entity = Entity::new(EntityKind::Organisation, name, 0.80, scan_id);
                bn_entity.tag("abr");
                bn_entity.tag("business-name");
                bn_entity.add_evidence(Evidence::new(SRC, format!("Trading name for ABN {abn}")));
                result.push(bn_entity);
            }
        }
    }

    if entity_type.contains("IND") || entity_type.contains("Individual") {
        let mut person = Entity::new(EntityKind::Person, &entity_name, 0.80, scan_id);
        person.tag("abr");
        person.tag("sole-trader");
        person.add_evidence(Evidence::new(
            SRC,
            format!("Individual/sole trader: ABN {abn}"),
        ));
        result.push(person);
    }
}

/// Expand the ranked `MatchingNames` candidate list into entities.
///
/// Walks up to [`MAX_NAME_HITS`](super::MAX_NAME_HITS) `Names` entries, mapping each ABR match `Score`
/// (0-100) onto an entity confidence band, and emits the `Organisation`,
/// `AbnAcn`, registered `Address`, and an inline `Coordinates` anchor per
/// candidate — the multi-result analogue of [`parse_abn_result`], scored a
/// touch lower since a name match is fuzzier than an exact ABN lookup. Entries
/// missing a name or ABN are skipped; an empty/absent `Names` array is a no-op.
/// `query` is the original search term, recorded in evidence for provenance.
pub(super) fn parse_name_results(
    data: &Value,
    query: &str,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    let names = match data.get("Names").and_then(|v| v.as_array()) {
        Some(n) if !n.is_empty() => n,
        _ => return,
    };

    for entry in names.iter().take(super::MAX_NAME_HITS) {
        let abn = str_field(entry, "Abn").unwrap_or_default();
        let name = str_field(entry, "Name").unwrap_or_default();
        let name_type = str_field(entry, "NameType").unwrap_or_default();
        let state = str_field(entry, "State").unwrap_or_default();
        let postcode = str_field(entry, "Postcode").unwrap_or_default();
        let score = entry
            .get("Score")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        if name.is_empty() || abn.is_empty() {
            continue;
        }

        let conf = match score {
            90..=100 => 0.90,
            70..=89 => 0.80,
            50..=69 => 0.70,
            _ => 0.60,
        };

        let mut org = Entity::new(EntityKind::Organisation, &name, conf, scan_id);
        org.tag("abr");
        org.tag("australian");

        let mut ev = Evidence::new(
            SRC,
            format!("ABR name match for '{query}': {name} (ABN {abn})"),
        )
        .with_attr("abn", &abn)
        .with_attr("match_score", score.to_string())
        .with_attr("name_type", &name_type);
        if !state.is_empty() {
            ev = ev.with_attr("state", &state);
        }
        if !postcode.is_empty() {
            ev = ev.with_attr("postcode", &postcode);
        }
        org.add_evidence(ev);
        result.push(org);

        let mut abn_entity = Entity::new(EntityKind::AbnAcn, &abn, conf, scan_id);
        abn_entity.tag("abr");
        abn_entity.add_evidence(Evidence::new(SRC, format!("{name} (score {score})")));
        result.push(abn_entity);

        if !state.is_empty() {
            let addr = if postcode.is_empty() {
                format!("{state}, Australia")
            } else {
                format!("{postcode}, {state}, Australia")
            };
            let mut addr_entity = Entity::new(EntityKind::Address, &addr, 0.65, scan_id);
            addr_entity.tag("abr");
            addr_entity.tag("country:AU");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                addr_entity.tag(format!("au-state:{sc}"));
            }
            addr_entity.add_evidence(Evidence::new(SRC, format!("Location for {name}")));
            result.push(addr_entity);

            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&state)
                .or_else(|| crate::util::city_coords::city_coords(&addr))
            {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.58, scan_id);
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("country:AU");
                if let Some(sc) = crate::util::address_au::state_code(&addr) {
                    c.tag(format!("au-state:{sc}"));
                }
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Inline geocode of ABR address '{addr}' → {coord_val}"),
                ));
                result.push(c);
            }
        }
    }
}

/// Read `key` from a JSON object as an owned `String`, treating an empty
/// string the same as a missing key (`None`). Centralises the "present and
/// non-blank" check so every field extraction in this module shares one
/// definition of "has a usable value".
pub(super) fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
}
