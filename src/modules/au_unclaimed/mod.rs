//! Australian multi-state unclaimed money registers (NSW, VIC, WA, SA, TAS, ACT).
//!
//! Complements [`crate::modules::qld_unclaimed`] which covers Queensland only. This module
//! queries the open CKAN data portals for the remaining six states/territories
//! via their published unclaimed-money datasets. Each query is surname-anchored
//! (same precision strategy as qld_unclaimed) to avoid flooding the graph with
//! common-name false positives.
//!
//! Sources (all free, keyless, public CKAN APIs):
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
//! Each matching record yields:
//!   * `Address` at 0.55 confidence (postcode + suburb from record)
//!   * `Coordinates` at 0.52 via offline postcode centroid (au-state tagged)

use async_trait::async_trait;
use futures::future::join_all;
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
        "Australian multi-state unclaimed money registers (NSW, VIC, WA, SA) — name → address/postcode pivot"
    }

    fn priority(&self) -> u8 {
        86
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
        const KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Coordinates];
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

        let encoded = crate::util::http::urlencode(query);
        let futures = REGISTERS.iter().map(|reg| {
            let url = format!(
                "{}/datastore_search?resource_id={}&q={}&limit={}",
                reg.action_base, reg.resource_id, encoded, MAX_RECORDS,
            );
            let http = ctx.http.clone();
            async move { (reg, fetch_json::<CkanResp>(&http, SRC, &url).await) }
        });
        let responses = join_all(futures).await;
        for (reg, resp) in responses {
            let Ok(resp) = resp else { continue };
            let Some(r) = resp.result.as_ref() else { continue };
            result.extend(
                r.records
                    .iter()
                    .take(MAX_RECORDS)
                    .filter(|record| owner_matches(record, reg.name_field, full_name))
                    .flat_map(|record| record_to_entities(record, reg, full_name, &ctx.scan_id)),
            );
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
