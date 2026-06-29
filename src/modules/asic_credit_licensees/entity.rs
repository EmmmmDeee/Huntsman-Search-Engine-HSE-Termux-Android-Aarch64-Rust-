//! Pure-data helpers: datastore-resource selection, whole-word /
//! exact-ABN matching, and the `records_to_entities` transform that turns raw
//! ASIC credit-licensee CKAN rows into an anchor `Organisation` plus its ABN/ACN,
//! address and exact-coordinate pivots.

use serde_json::{Map, Value};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::ckan::{Resource, field_str};

use super::{ABN_CONF, ADDR_CONF, COORD_CONF, MAX_RECORDS, ORG_CANDIDATE, ORG_EXACT, SRC};

/// Select the resource id to query: the datastore-active resource whose name
/// contains "Current" (case-insensitive); failing that, the first
/// datastore-active resource. Returns `None` if nothing is datastore-active.
pub(super) fn pick_resource(resources: &[Resource]) -> Option<String> {
    let active: Vec<&Resource> = resources
        .iter()
        .filter(|r| r.datastore_active == Some(true))
        .collect();
    let current = active.iter().find_map(|r| {
        let name = r.name.as_deref()?;
        if name.to_ascii_lowercase().contains("current") {
            r.id.clone()
        } else {
            None
        }
    });
    current.or_else(|| active.iter().find_map(|r| r.id.clone()))
}

/// Keep only the ASCII digits of a value (ABN/ACN comparison is digit-only:
/// `"51 824 753 556"` and `"51824753556"` are the same identifier).
fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// True if the row's recorded ABN/ACN equals the seed's digits exactly (only
/// meaningful when the seed is an `AbnAcn`). A digit-only equality so spacing
/// never defeats the match.
pub(super) fn abn_matches_query(rec: &Map<String, Value>, query: &str) -> bool {
    let seed = digits(query);
    if seed.len() < 9 {
        return false;
    }
    field_str(rec, "CRED_LIC_ABN_ACN").is_some_and(|v| digits(&v) == seed)
}

/// Decide whether a row exactly identifies the seed: an `AbnAcn` seed matches
/// `CRED_LIC_ABN_ACN` digit-for-digit; any seed also matches when the licensee
/// name contains every seed token as a whole word.
pub(super) fn record_is_exact(rec: &Map<String, Value>, query: &str, abn_query: bool) -> bool {
    if abn_query && abn_matches_query(rec, query) {
        return true;
    }
    field_str(rec, "CRED_LIC_NAME")
        .is_some_and(|n| crate::util::target_match::name_all_tokens_match(&n, query))
}

/// Build the geocodable locality string from the recorded address parts
/// ("Sydney, NSW 2000, Australia"). Returns `None` when nothing locates.
pub(super) fn licensee_locality(rec: &Map<String, Value>) -> Option<String> {
    let local = field_str(rec, "CRED_LIC_LOCALITY");
    let state = field_str(rec, "CRED_LIC_STATE");
    let pcode = field_str(rec, "CRED_LIC_PCODE");
    if local.is_none() && state.is_none() && pcode.is_none() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    if let Some(l) = local.as_deref() {
        parts.push(l.to_string());
    }
    match (state.as_deref(), pcode.as_deref()) {
        (Some(s), Some(p)) => parts.push(format!("{s} {p}")),
        (Some(s), None) => parts.push(s.to_string()),
        (None, Some(p)) => parts.push(p.to_string()),
        (None, None) => {}
    }
    parts.push("Australia".to_string());
    Some(parts.join(", "))
}

/// Parse the exact `CRED_LIC_LAT` / `CRED_LIC_LNG` ASIC supplies into a
/// `(lat, lng)` pair, but only when both parse to plausible WGS-84 degrees (lat
/// in [-90, 90], lng in [-180, 180]) — a sentinel `0,0` or out-of-range value is
/// rejected rather than emitted as a (false) location.
pub(super) fn licensee_coords(rec: &Map<String, Value>) -> Option<(f64, f64)> {
    let lat: f64 = field_str(rec, "CRED_LIC_LAT")?.parse().ok()?;
    let lng: f64 = field_str(rec, "CRED_LIC_LNG")?.parse().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lng) {
        return None;
    }
    if lat == 0.0 && lng == 0.0 {
        return None;
    }
    Some((lat, lng))
}

/// Attach every present register field to a licensee's evidence so nothing the
/// API returned is dropped — true for exact hits and candidates alike.
pub(super) fn licensee_evidence(rec: &Map<String, Value>, name: &str, total: u64) -> Evidence {
    let ev = Evidence::new(SRC, format!("ASIC credit licensee: {name}"))
        .with_attr("register", "ASIC Credit Licensee")
        .with_attr("licensee_name", name)
        .with_attr("total_matches", total.to_string());
    [
        ("REGISTER_NAME", "register_name"),
        ("CRED_LIC_NUM", "credit_licence_number"),
        ("CRED_LIC_ABN_ACN", "abn_acn"),
        ("CRED_LIC_AFSL_NUM", "afs_licence_number"),
        ("CRED_LIC_START_DT", "licence_start"),
        ("CRED_LIC_END_DT", "licence_end"),
        ("CRED_LIC_STATUS", "status"),
        ("CRED_LIC_STATUS_HISTORY", "status_history"),
        ("CRED_LIC_LOCALITY", "address_locality"),
        ("CRED_LIC_STATE", "address_state"),
        ("CRED_LIC_PCODE", "address_postcode"),
        ("CRED_LIC_LAT", "latitude"),
        ("CRED_LIC_LNG", "longitude"),
        ("CRED_LIC_EDRS", "edrs"),
        ("CRED_LIC_BN", "business_names"),
        ("CRED_LIC_AUTHORISATIONS", "authorisations"),
    ]
    .into_iter()
    .filter_map(|(col, attr)| field_str(rec, col).map(|v| (attr, v)))
    .fold(ev, |ev, (attr, v)| ev.with_attr(attr, v))
}

/// Pure transform: CKAN ASIC credit-licensee rows → entities. Every row yields a
/// primary `Organisation` (the licensee) carrying the full record in evidence
/// (no omission). A row whose licensee name contains every seed token as a whole
/// word — or whose ABN/ACN equals an `AbnAcn` seed exactly — is a high-confidence
/// finding (tagged `credit-licensee` / `financial-services`) that fans out into
/// its `AbnAcn`, `Address` and exact-`Coordinates` pivots; loose full-text hits
/// stay a single sub-floor `name-candidate` Organisation.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    query: &str,
    abn_query: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let Some(raw_name) = field_str(rec, "CRED_LIC_NAME") else {
            continue;
        };
        let name = raw_name.replace('\u{a0}', " ");
        let exact = record_is_exact(rec, query, abn_query);
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };

        let mut org = Entity::new(EntityKind::Organisation, &name, conf, scan_id);
        org.tag(SRC);
        org.tag("asic");
        org.tag("country:AU");
        if exact {
            org.tag("credit-licensee");
            org.tag("financial-services");
            org.tag("regulated-entity");
            org.tag("exact-name-match");
        } else {
            org.tag("name-candidate");
        }
        org.add_evidence(licensee_evidence(rec, &name, total));
        out.push(org);

        // Cross-correlation pivots — exact hits only.
        if !exact {
            continue;
        }

        // Recorded ABN/ACN → pivots into au_business_id / abn_lookup / asic stack.
        if let Some(abn) = field_str(rec, "CRED_LIC_ABN_ACN") {
            let abn = digits(&abn);
            if abn.len() >= 9 {
                let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
                e.tag(SRC);
                e.tag("asic");
                e.tag("country:AU");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Credit licensee ABN/ACN {abn} → {name}"),
                ));
                out.push(e);
            }
        }

        // Recorded business locality → Address pivot.
        if let Some(addr) = licensee_locality(rec) {
            let mut e = Entity::new(EntityKind::Address, &addr, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("asic");
            e.tag("country:AU");
            e.tag("geoint");
            if let Some(sc) = crate::util::address_au::state_code(&addr) {
                e.tag(format!("au-state:{sc}"));
            }
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Recorded business address of credit licensee {name}"),
                )
                .with_attr("licensee", &name),
            );
            out.push(e);
        }

        // EXACT supplied coordinates → Coordinates pivot (ASIC publishes the
        // precise lat/lng; emit it verbatim, no geocoding guess).
        if let Some((lat, lng)) = licensee_coords(rec) {
            let coord_val = format!("{lat:.6},{lng:.6}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, COORD_CONF, scan_id);
            c.tag(SRC);
            c.tag("asic");
            c.tag("country:AU");
            c.tag("geoint");
            c.tag("asic-supplied");
            c.add_evidence(
                Evidence::new(
                    SRC,
                    format!("ASIC-supplied coordinates for credit licensee {name} → {coord_val}"),
                )
                .with_attr("licensee", &name),
            );
            out.push(c);
        }
    }
    out
}
