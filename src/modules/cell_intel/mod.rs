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

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::modules::termux_sensor;
use crate::util::termux::termux_cmd;

use helpers::{accuracy_to_confidence, build_tower_device, mcc_to_centroid, query_opencellid};
use types::TowerKey;

const OPENCELLID_KEY_ENV: &str = "HUNTSMAN_OPENCELLID_KEY";

pub(super) const SRC: &str = "cell_intel";

pub struct CellIntel;

#[async_trait]
impl Module for CellIntel {
    fn name(&self) -> &'static str {
        "cell_intel"
    }

    fn description(&self) -> &'static str {
        "Cell-tower survey & geolocation — sweeps nearby towers via Termux and geolocates them against OpenCelliD"
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
        // passive flag. Surfaced to the operator by `hse modules`.
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
        const KINDS: &[EntityKind] = &[EntityKind::DeviceId, EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Single invocation — the key performance win over two separate modules.
        let Some(stdout) = termux_cmd("termux-telephony-cellinfo", &[], 5000).await else {
            return Ok(ModuleResult::new());
        };

        // Blank output means the tool exited 0 with nothing to report — an
        // honest empty answer. Non-blank output that will not parse means the
        // tool answered with something broken, which is a malfunction and must
        // surface as a real error: reporting it as zero cells would be
        // indistinguishable from "no towers in range". Mirrors
        // `signal_radar::cell::parse_cells`, which shares this tool.
        if termux_sensor::is_blank(&stdout) {
            return Ok(ModuleResult::new());
        }
        let cells: Vec<types::Cell> = serde_json::from_slice(&stdout)
            .map_err(|e| termux_sensor::unparseable(SRC, "telephony-cellinfo", &e))?;

        let api_key = ctx.key_opt(OPENCELLID_KEY_ENV);
        let mut result = ModuleResult::new();
        let mut seen = HashSet::new();

        for cell in &cells {
            // Parse + survey-skip policy in one place (TowerKey::from_cell):
            // None when the cell lacks the minimum keys (no MCC / no CID).
            let Some(key) = TowerKey::from_cell(cell) else {
                continue;
            };

            // ---- 1. DeviceId entity (from former cell_survey) ----
            result.push(build_tower_device(cell, &key, &ctx.scan_id));

            // ---- 2. Coordinates entity (from former cell_locate) ----
            // Needs MNC + non-zero LAC/TAC; skip duplicate geolocation per tower.
            if !key.is_geolocatable() || !seen.insert(key.tower_id.clone()) {
                continue;
            }

            let radio = key.radio_code();

            if let Some(api) = api_key
                && let Some((lat, lon, range)) = query_opencellid(ctx, api, &key, radio).await
            {
                let coords = format!("{lat:.6},{lon:.6}");
                let confidence = accuracy_to_confidence(range);
                let mut e = Entity::new(EntityKind::Coordinates, &coords, confidence, &ctx.scan_id);
                e.tag("geoint");
                e.tag(crate::core::tags::CELL_TOWER);
                e.tag(format!("radio:{}", key.ctype.to_lowercase()));
                crate::util::geo::tag_au_state(&mut e, lat, lon);
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Cell tower {radio} {} -> {coords}", key.tower_id),
                    )
                    .with_attr("tower_id", &key.tower_id)
                    .with_attr("radio", radio)
                    .with_attr("mcc", key.mcc.as_ref())
                    .with_attr("mnc", key.mnc.as_ref())
                    .with_attr("range_m", range.to_string())
                    .with_attr("source", "OpenCelliD")
                    .with_attr("dbm", cell.dbm.unwrap_or(0).to_string())
                    .with_attr("registered", cell.registered.unwrap_or(false).to_string()),
                );
                result.push(e);
                continue;
            }

            // Fallback: MCC -> country centroid (coarse but free, offline)
            if let Some((lat, lon, country)) = mcc_to_centroid(&key.mcc) {
                let coords = format!("{lat:.4},{lon:.4}");
                let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.25, &ctx.scan_id);
                e.tag("geoint");
                e.tag(crate::core::tags::CELL_TOWER);
                e.tag(crate::core::tags::COARSE);
                e.tag(format!("country:{country}"));
                if country == "AU"
                    && let Some(state) = crate::util::geo::au_state_for_coords(lat, lon)
                {
                    e.tag(format!("au-state:{state}"));
                }
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Cell tower MCC {} -> {country} (country centroid)", key.mcc),
                    )
                    .with_attr("tower_id", &key.tower_id)
                    .with_attr("mcc", key.mcc.as_ref())
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
