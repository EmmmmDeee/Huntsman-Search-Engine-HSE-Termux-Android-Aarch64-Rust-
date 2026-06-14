//! Cell tower survey and geolocation — single call to `termux-telephony-cellinfo`.
//!
//! Merges the former `cell_survey` and `cell_locate` modules so the Termux
//! command is invoked **once** instead of twice.  For every visible cell tower
//! the module produces:
//!
//!   1. A `DeviceId` entity (tower ID, signal info, radio type)
//!   2. A `Coordinates` entity via OpenCelliD or MCC centroid fallback
//!
//! API priority for geolocation:
//!   1. OpenCelliD / UnwiredLabs (free tier: 100 req/day, env key)
//!   2. Built-in MCC -> country centroid fallback (offline, coarse)
//!
//! Off-device -> no-op via the termux_cmd helper.

mod helpers;
mod types;

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use async_trait::async_trait;
use futures::future::join_all;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::termux::termux_cmd;

use helpers::{accuracy_to_confidence, build_tower_device, mcc_to_centroid, query_opencellid};
use types::TowerKey;

/// Owned data for one geolocatable tower — survives `async move` closures.
struct TowerGeo {
    mcc: String,
    mnc: String,
    lac: i64,
    cid: i64,
    radio: &'static str,
    tower_id: String,
    dbm: Option<i64>,
    registered: Option<bool>,
    ctype_lower: String,
}

const OPENCELLID_KEY_ENV: &str = "HUNTSMAN_OPENCELLID_KEY";

pub(super) const SRC: &str = "cell_intel";

pub struct CellIntel;

#[async_trait]
impl Module for CellIntel {
    fn name(&self) -> &'static str {
        "cell_intel"
    }

    fn description(&self) -> &'static str {
        "Cell tower survey and geolocation via Termux + OpenCelliD"
    }

    fn priority(&self) -> u8 {
        64
    }

    fn is_passive(&self) -> bool {
        // Classed passive as a local sensor: the primary action is reading
        // on-device cell-tower info via termux-telephony-cellinfo, and
        // off-Termux the module no-ops before any network use. CAVEAT: when
        // run on-device with tower data, geolocatable towers are enriched
        // via the OpenCellID API — so under --passive-only this module CAN
        // still egress. This is intentional (it lives in
        // engine::LOCAL_PASSIVE_MODULES as a seed-round sensor); a strict
        // no-egress guarantee would require gating the OpenCellID step on a
        // passive flag. Documented in docs/MODULES.md.
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        // Surveys the cell towers around the OPERATOR's device, not a remote
        // subject — engage only on a deliberately-local seed (coordinates / MAC)
        // so the operator's location isn't attributed to a name/email/domain/IP
        // subject (fault-tree cut set MCS-A). Expansion is already gated for
        // LOCAL_PASSIVE_MODULES, so this governs the seed round.
        matches!(t.kind, TargetKind::Coordinates | TargetKind::MacAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Sensor
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1592"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Single invocation — the key performance win over two separate modules.
        let Some(stdout) = termux_cmd("termux-telephony-cellinfo", &[], 5000).await else {
            return Ok(ModuleResult::new());
        };

        let cells: Vec<types::Cell> = match serde_json::from_slice(&stdout) {
            Ok(v) => v,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let api_key = ctx.key_opt(OPENCELLID_KEY_ENV);
        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();

        // Pass 1: DeviceId entities (no HTTP) + collect unique geolocatable towers.
        // TowerKey<'a> borrows from Cell, so we clone fields into owned TowerGeo
        // before moving into async closures.
        let mut geo_work: Vec<TowerGeo> = Vec::new();
        for cell in &cells {
            let Some(key) = TowerKey::from_cell(cell) else {
                continue;
            };
            result.push(build_tower_device(cell, &key, &ctx.scan_id));
            if !key.is_geolocatable() || !seen.insert(key.tower_id.clone()) {
                continue;
            }
            geo_work.push(TowerGeo {
                mcc: key.mcc.as_ref().to_owned(),
                mnc: key.mnc.as_ref().to_owned(),
                lac: key.lac,
                cid: key.cid,
                radio: key.radio_code(),
                tower_id: key.tower_id.clone(),
                dbm: cell.dbm,
                registered: cell.registered,
                ctype_lower: key.ctype.to_lowercase(),
            });
        }

        if geo_work.is_empty() {
            return Ok(result);
        }

        // Pass 2: fire all OpenCelliD queries concurrently (or skip when no key).
        let scan_id = &ctx.scan_id;
        let geo_futures = geo_work.iter().map(|tg| {
            let http = ctx.http.clone();
            let api_key = api_key.map(str::to_owned);
            async move {
                if let Some(api) = api_key.as_deref() {
                    // Build a temporary TowerKey with owned Cow for the query helper.
                    let tmp_key = TowerKey {
                        mcc: std::borrow::Cow::Borrowed(tg.mcc.as_str()),
                        mnc: std::borrow::Cow::Borrowed(tg.mnc.as_str()),
                        lac: tg.lac,
                        cid: tg.cid,
                        ctype: tg.ctype_lower.as_str(),
                        tower_id: tg.tower_id.clone(),
                    };
                    query_opencellid(&http, api, &tmp_key, tg.radio).await
                } else {
                    None
                }
            }
        });
        let geo_results: Vec<Option<(f64, f64, u64)>> = join_all(geo_futures).await;

        for (tg, geo) in geo_work.iter().zip(geo_results) {
            if let Some((lat, lon, range)) = geo {
                let coords = format!("{lat:.6},{lon:.6}");
                let confidence = accuracy_to_confidence(range);
                let mut e = Entity::new(EntityKind::Coordinates, &coords, confidence, scan_id);
                e.tag("geoint");
                e.tag("cell-tower");
                e.tag(["radio:", tg.ctype_lower.as_str()].concat());
                if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
                    e.tag(format!("au-state:{state}"));
                    e.tag("country:AU");
                }
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Cell tower {} {} -> {coords}", tg.radio, tg.tower_id),
                    )
                    .with_attr("tower_id", &tg.tower_id)
                    .with_attr("radio", tg.radio)
                    .with_attr("mcc", &tg.mcc)
                    .with_attr("mnc", &tg.mnc)
                    .with_attr("range_m", range.to_string())
                    .with_attr("source", "OpenCelliD")
                    .with_attr("dbm", tg.dbm.unwrap_or(0).to_string())
                    .with_attr("registered", tg.registered.unwrap_or(false).to_string()),
                );
                result.push(e);
            } else if let Some((lat, lon, country)) = mcc_to_centroid(&tg.mcc) {
                let coords = format!("{lat:.4},{lon:.4}");
                let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.25, scan_id);
                e.tag("geoint");
                e.tag("cell-tower");
                e.tag("coarse");
                e.tag(format!("country:{country}"));
                if country == "AU"
                    && let Some(state) = crate::util::geo::au_state_for_coords(lat, lon)
                {
                    e.tag(format!("au-state:{state}"));
                }
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Cell tower MCC {} -> {country} (country centroid)", tg.mcc),
                    )
                    .with_attr("tower_id", &tg.tower_id)
                    .with_attr("mcc", &tg.mcc)
                    .with_attr("country", country)
                    .with_attr("source", "mcc-centroid")
                    .with_attr("accuracy", "country-level"),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}
