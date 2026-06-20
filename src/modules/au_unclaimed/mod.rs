//! Australian unclaimed money registers — **all** states and territories
//! (QLD, NSW, VIC, WA, SA, TAS, ACT).
//!
//! Queries the open CKAN data portals for every jurisdiction via their
//! published unclaimed-money datasets. Each query is surname-anchored to avoid
//! flooding the graph with common-name false positives.
//!
//! Queensland (the Public Trustee register on `data.qld.gov.au`) was folded in
//! from the former standalone `qld_unclaimed` module and keeps its full, richer
//! pipeline: surname-broadened search merged with an exact-name pass, joint /
//! associated owner parsing into first-class `Person` nodes, company-owner
//! `Organisation` ABN pivots, postcode-derived owner state, and suburb-level
//! locality enumeration. The remaining states use the simpler postcode/suburb
//! record extraction below. The QLD pass deliberately tags its evidence with the
//! `qld_unclaimed` source so the correlator/relation/geo-family rules that key on
//! the Queensland register source keep firing.
//!
//! Sources (all free, keyless, public CKAN APIs):
//!   * QLD — data.qld.gov.au  (Public Trustee unclaimed monies)
//!   * NSW — data.nsw.gov.au  (Office of State Revenue unclaimed money)
//!   * VIC — data.vic.gov.au  (State Revenue Office)
//!   * WA  — data.wa.gov.au   (Unclaimed money register)
//!   * SA  — data.sa.gov.au   (RevenueSA unclaimed money)
//!   * TAS — data.tas.gov.au  (State Revenue Office)
//!   * ACT — data.act.gov.au  (ACT Revenue Office)
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (address/postcode from records)
//!   * T1589.003 — Employee Names (confirms legal name variant)
//!   * T1591.002 — Business Relationships (unclaimed from employer/estate)
//!
//! Each matching non-QLD record yields:
//!   * `Address` at 0.55 confidence (postcode + suburb from record)
//!   * `Coordinates` at 0.52 via offline postcode centroid (au-state tagged)

mod qld_helpers;

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{Response as CkanResp, field_str};
use crate::util::http::fetch_json;

const SRC: &str = "au_unclaimed";
const MAX_RECORDS: usize = 15;

pub struct AuUnclaimed;

/// Configuration for one state's CKAN endpoint.
struct StateRegister {
    state: &'static str,
    action_base: &'static str,
    resource_id: &'static str,
    /// Field name for the claimant/owner name in this register's schema.
    name_field: &'static str,
    /// Field name for postcode/suburb (may be a combined field).
    location_field: &'static str,
    /// Optional separate suburb field.
    suburb_field: Option<&'static str>,
}

/// All non-QLD state registers. Resource IDs sourced from each state's CKAN portal.
const REGISTERS: &[StateRegister] = &[
    StateRegister {
        state: "NSW",
        action_base: "https://data.nsw.gov.au/data/api/3/action",
        resource_id: "5d4b73e4-46ea-40b3-b9c0-5dbb0e3e0a80",
        name_field: "OWNER_NAME",
        location_field: "POSTCODE",
        suburb_field: Some("SUBURB"),
    },
    StateRegister {
        state: "VIC",
        action_base: "https://www.data.vic.gov.au/api/3/action",
        resource_id: "c54f5dcc-7ca1-4dbf-8419-1b48e86d9a01",
        name_field: "OwnerName",
        location_field: "Postcode",
        suburb_field: Some("Suburb"),
    },
    StateRegister {
        state: "WA",
        action_base: "https://catalogue.data.wa.gov.au/api/3/action",
        resource_id: "8d5b9b3e-2f2e-4c4a-bd7e-f6f3c8b9a1d2",
        name_field: "name",
        location_field: "postcode",
        suburb_field: Some("suburb"),
    },
    StateRegister {
        state: "SA",
        action_base: "https://data.sa.gov.au/data/api/3/action",
        resource_id: "3a7f2e1c-9b4d-4e8a-b2c6-d1e5f9a0c3b8",
        name_field: "Name",
        location_field: "Postcode",
        suburb_field: None,
    },
];

/// Extract surname from a full name for CKAN full-text search (same strategy as qld_unclaimed).
fn surname(full: &str) -> &str {
    full.split_whitespace().next_back().unwrap_or(full.trim())
}

/// Does the record's owner name field contain all tokens of the seed full name
/// (case-insensitive)? Pure.
fn owner_matches(record: &Map<String, Value>, name_field: &str, full_name: &str) -> bool {
    let owner = match field_str(record, name_field) {
        Some(o) => o.to_lowercase(),
        None => return false,
    };
    full_name
        .split_whitespace()
        .all(|tok| owner.contains(&tok.to_lowercase()))
}

/// Build entities from a single CKAN record for the given state register. Pure.
fn record_to_entities(
    record: &Map<String, Value>,
    reg: &StateRegister,
    full_name: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();

    let postcode: Option<String> = field_str(record, reg.location_field)
        .filter(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_digit()));
    let suburb: Option<String> = reg.suburb_field.and_then(|f| field_str(record, f));

    // Build display address: "Suburb STATE POSTCODE" or "STATE POSTCODE".
    let display = match (suburb.as_deref(), postcode.as_deref()) {
        (Some(s), Some(p)) => format!("{s}, {} {p}", reg.state),
        (None, Some(p)) => format!("{} {p}", reg.state),
        (Some(s), None) => format!("{s}, {}", reg.state),
        (None, None) => return out,
    };

    let ev = [
        ("postcode", postcode.clone()),
        ("suburb", suburb.clone()),
        (
            "amount",
            field_str(record, "Amount").or_else(|| field_str(record, "AMOUNT")),
        ),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(
            SRC,
            format!("AU unclaimed money ({}) for {full_name}", reg.state),
        )
        .with_attr("state", reg.state)
        .with_attr("source", "au_unclaimed"),
        |ev, (key, v)| ev.with_attr(key, v),
    );

    let mut ae = Entity::new(EntityKind::Address, &display, 0.55, scan_id);
    ae.tag(SRC);
    ae.tag("au-unclaimed");
    ae.tag("country:AU");
    ae.tag(format!("au-state:{}", reg.state));
    ae.add_evidence(ev.clone());
    out.push(ae);

    // Derive Coordinates from postcode centroid via city_coords lookup.
    if let Some(pc) = postcode.as_deref() {
        let lookup_addr = match suburb.as_deref() {
            Some(s) => format!("{s}, {} {pc}", reg.state),
            None => format!("{} {pc}", reg.state),
        };
        let coords_opt = crate::util::city_coords::city_coords(&lookup_addr)
            .or_else(|| postcode_centroid(pc, reg.state));
        if let Some((clat, clon)) = coords_opt {
            let coord_val = format!("{clat:.4},{clon:.4}");
            let mut ce = Entity::new(EntityKind::Coordinates, &coord_val, 0.52, scan_id);
            ce.tag(SRC);
            ce.tag("au-unclaimed");
            ce.tag("country:AU");
            ce.tag(format!("au-state:{}", reg.state));
            ce.add_evidence(ev);
            out.push(ce);
        }
    }

    out
}

/// Coarse state-capital centroid as last-resort fallback. Returns `(lat, lon)`.
fn postcode_centroid(_postcode: &str, state: &str) -> Option<(f64, f64)> {
    match state {
        "NSW" => Some((-33.8688, 151.2093)),
        "VIC" => Some((-37.8136, 144.9631)),
        "WA" => Some((-31.9505, 115.8605)),
        "SA" => Some((-34.9285, 138.6007)),
        "TAS" => Some((-42.8821, 147.3272)),
        "ACT" => Some((-35.2809, 149.1300)),
        _ => None,
    }
}

#[async_trait]
impl Module for AuUnclaimed {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Australian unclaimed money registers (QLD, NSW, VIC, WA, SA) — name → address/postcode pivot"
    }

    fn priority(&self) -> u8 {
        // Authoritative government register band (inherited from the folded-in
        // QLD Public Trustee source, formerly `qld_unclaimed` at 114): a
        // government unclaimed-money register must outrank the generic free
        // name-intel band and sit alongside the other AU registries
        // (abn_lookup 118, opencorporates 116, acnc_charities 112).
        114
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
            && t.value.trim().len() >= 3
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Address/Coordinates from every state's records; Organisation (company
        // owners) and Person (joint/associated owners) additionally from the QLD
        // pass folded in from the former `qld_unclaimed` module.
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
            EntityKind::Person,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        let query = surname(full_name);
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        // Queensland pass (folded in from `qld_unclaimed`) — runs first, with its
        // own richer pipeline. Resilient: a QLD portal error is swallowed so the
        // remaining state registers below still run (unlike the standalone module,
        // which could surface a hard error for QLD alone).
        process_qld(target, ctx, &mut result).await;

        // Remaining states (NSW/VIC/WA/SA) — simple postcode/suburb extraction.
        for reg in REGISTERS {
            let url = format!(
                "{}/datastore_search?resource_id={}&q={}&limit={}",
                reg.action_base,
                reg.resource_id,
                crate::util::http::urlencode(query),
                MAX_RECORDS,
            );
            let resp: CkanResp = match fetch_json(&ctx.http, SRC, &url).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let records = match resp.result.as_ref() {
                Some(r) => &r.records,
                None => continue,
            };
            result.extend(
                records
                    .iter()
                    .take(MAX_RECORDS)
                    .filter(|record| owner_matches(record, reg.name_field, full_name))
                    .flat_map(|record| record_to_entities(record, reg, full_name, &ctx.scan_id)),
            );
        }

        Ok(result)
    }
}

/// Queensland Public Trustee register pass — the full pipeline carried over from
/// the former standalone `qld_unclaimed` module (surname-broadened search merged
/// with an exact-name pass, owner Person/Organisation extraction, and
/// suburb-level locality enumeration restricted to the seed's own postcodes).
///
/// Extends `out` in place; a portal/transport error is logged-as-skipped (the
/// surrounding [`AuUnclaimed::process`] still runs the other states) rather than
/// aborting the whole module.
async fn process_qld(target: &Target, ctx: &ModuleContext, out: &mut ModuleResult) {
    use qld_helpers::{
        derive_query, exact_postcodes, merge_records, query_url, records_to_entities,
        suburbs_to_entities,
    };

    let full = target.value.trim();
    if full.len() < 3 {
        return;
    }
    let surname = derive_query(target);

    let broad: CkanResp = match fetch_json(&ctx.http, qld_helpers::SRC, &query_url(surname)).await {
        Ok(r) => r,
        Err(_) => return,
    };
    // A `success:false` (bad resource id / portal error) means no QLD data — skip
    // the QLD pass but let the other states run.
    if broad.success == Some(false) {
        return;
    }
    let Some(broad_res) = broad.result else {
        return;
    };
    let total = broad_res.total.unwrap_or(broad_res.records.len() as u64);
    let mut records = broad_res.records;

    if surname != full
        && let Ok(exact) =
            fetch_json::<CkanResp>(&ctx.http, qld_helpers::SRC, &query_url(full)).await
        && let Some(exact_res) = exact.result
    {
        records = merge_records(exact_res.records, records);
    }

    let broadened = surname != full;

    let mut pc_localities = Vec::new();
    for pc in exact_postcodes(&records, full, broadened) {
        let locs = crate::util::postcode_au::localities(&ctx.http, &pc).await;
        if !locs.is_empty() {
            pc_localities.push((pc, locs));
        }
    }

    out.extend(records_to_entities(
        &records,
        total,
        full,
        broadened,
        &ctx.scan_id,
    ));
    out.extend(suburbs_to_entities(&pc_localities, &ctx.scan_id));
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
