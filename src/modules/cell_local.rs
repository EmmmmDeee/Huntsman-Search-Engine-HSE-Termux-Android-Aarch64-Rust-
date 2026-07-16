//! Local OpenCelliD database query module.
//!
//! Given a `Coordinates` target, opens `~/.huntsman/cell_towers.db` (populated
//! by `hse cells import`) and returns cell towers within a ~556 m bounding box.
//! Emits a `DeviceId` and a `Coordinates` entity for each tower found.
//!
//! No API calls — completely offline once the database is populated.
//! Silent no-op when the database has not been imported yet.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "cell_local";

/// Bounding-box half-width in degrees (~556 m at mid-latitudes),
/// matching the `opencellid` module's search radius.
const DELTA: f64 = 0.005;

pub struct CellLocal;

#[async_trait]
impl Module for CellLocal {
    fn name(&self) -> &'static str {
        "cell_local"
    }

    fn description(&self) -> &'static str {
        "Local OpenCelliD database: query imported cell towers near a coordinate \
         (no API calls; run hse cells import first)"
    }

    fn priority(&self) -> u8 {
        66
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::DeviceId, EntityKind::Coordinates];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        5_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let cells = tokio::task::spawn_blocking(move || {
            let conn = match crate::util::cell_db::open_ro() {
                // DB not yet populated — silent no-op until `hse cells import` is run.
                Err(_) => return Ok(vec![]),
                Ok(c) => c,
            };
            crate::util::cell_db::query_bbox(
                &conn,
                lat - DELTA,
                lon - DELTA,
                lat + DELTA,
                lon + DELTA,
                200,
            )
            .map_err(|e| crate::core::error::Error::Other(e.to_string()))
        })
        .await
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))??;

        if cells.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        for cell in &cells {
            let tower_id = crate::util::cell::tower_id(cell.mcc, cell.mnc, cell.lac, cell.cid);

            // ── DeviceId entity ──────────────────────────────────────────────
            let mut device = Entity::new(EntityKind::DeviceId, &tower_id, 0.78, &ctx.scan_id);
            device.tag(crate::core::tags::CELL_TOWER);
            device.tag("cell-local");
            device.tag(format!("radio:{}", cell.radio.to_lowercase()));
            device.add_evidence(
                Evidence::new(SRC, format!("Local DB tower {tower_id} ({})", cell.radio))
                    .with_attr("tower_id", &tower_id)
                    .with_attr("radio", &cell.radio)
                    .with_attr("mcc", cell.mcc.to_string())
                    .with_attr("mnc", cell.mnc.to_string())
                    .with_attr("lac", cell.lac.to_string())
                    .with_attr("cid", cell.cid.to_string())
                    .with_attr("range_m", cell.range_m.to_string())
                    .with_attr("samples", cell.samples.to_string())
                    .with_attr("source", "cell_local_db"),
            );
            result.push(device);

            // ── Coordinates entity ────────────────────────────────────────────
            if crate::util::geo::is_valid_coords(cell.lat, cell.lon) {
                let coords = format!("{:.6},{:.6}", cell.lat, cell.lon);
                let conf = crate::util::geo::cell_range_to_confidence(cell.range_m as u64);
                let mut geo = Entity::new(EntityKind::Coordinates, &coords, conf, &ctx.scan_id);
                geo.tag("geoint");
                geo.tag(crate::core::tags::CELL_TOWER);
                geo.tag("cell-local");
                geo.add_evidence(
                    Evidence::new(SRC, format!("Local DB tower {tower_id} at {coords}"))
                        .with_attr("tower_id", &tower_id)
                        .with_attr("range_m", cell.range_m.to_string())
                        .with_attr("source", "cell_local_db"),
                );
                result.push(geo);
            }
        }

        Ok(result)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn module_metadata() {
        assert_eq!(CellLocal.name(), "cell_local");
        assert_eq!(CellLocal.priority(), 66);
        assert!(matches!(CellLocal.cost(), ModuleCost::Free));
        assert!(matches!(CellLocal.category(), ModuleCategory::Geo));
        assert!(!CellLocal.description().is_empty());
    }

    #[test]
    fn accepts_coordinates_only() {
        assert!(CellLocal.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
        assert!(!CellLocal.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
        assert!(!CellLocal.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!CellLocal.accepts(&Target::new(TargetKind::Email, "x@example.com")));
    }

    #[test]
    fn produces_device_id_and_coordinates() {
        let kinds = CellLocal.produces();
        assert!(kinds.contains(&EntityKind::DeviceId));
        assert!(kinds.contains(&EntityKind::Coordinates));
    }

    #[test]
    fn max_timeout_is_5s() {
        assert_eq!(CellLocal.max_timeout_ms(), 5_000);
    }

    // The tower-range → confidence tiers are single-sourced in `util::geo`
    // (`cell_range_to_confidence`) and tested there (T2.126).
}
