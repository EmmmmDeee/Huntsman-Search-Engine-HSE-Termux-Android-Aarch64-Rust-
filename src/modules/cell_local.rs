//! Local OpenCelliD database query module.
//!
//! Given a `Coordinates` target, opens `~/.huntsman/cell_towers.db` (populated
//! by `hse cells import`) and returns cell towers within a ~556 m bounding box.
//! Emits a `DeviceId` and a `Coordinates` entity for each tower found.
//!
//! No API calls — completely offline once the database is populated. When the
//! database has never been imported the module says so as a typed
//! `Unavailable` skip (an actionable coverage gap: run `hse cells import`),
//! never as an empty result — which dispatch would record as "no cell towers
//! within ~556 m of this coordinate" for a database that does not exist.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
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
        "Local OpenCelliD recon — queries imported cell towers near a coordinate offline (no API calls; run hse cells import first)"
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
                Ok(c) => c,
                // DB not yet populated: nothing was searched, and the module says
                // so in-band (`database_not_imported`) instead of returning an
                // empty result that reads as "no cell towers within ~556 m of
                // this coordinate". `open_ro` also returns `Err` when the file IS
                // there but will not open (wrong permissions, a truncated import,
                // a corrupt header) — that stays a hard error below, since
                // folding it into a skip would hide a broken import.
                Err(_) if !crate::util::cell_db::cell_db_path().exists() => {
                    return Err(database_not_imported());
                }
                Err(e) => {
                    return Err(Error::module(
                        SRC,
                        format!("cell tower database exists but could not be opened: {e}"),
                    ));
                }
            };
            crate::util::cell_db::query_bbox(
                &conn,
                lat - DELTA,
                lon - DELTA,
                lat + DELTA,
                lon + DELTA,
                200,
            )
            .map_err(|e| Error::module(SRC, e.to_string()))
        })
        .await
        .map_err(|e| Error::module(SRC, e.to_string()))??;

        if cells.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        for cell in &cells {
            // Single-sourced DeviceId tower-id key (see `util::cell`).
            let tower_id = crate::util::cell::tower_id(cell.mcc, cell.mnc, cell.lac, cell.cid);

            // ── DeviceId entity ──────────────────────────────────────────────
            let mut device = Entity::new(
                EntityKind::DeviceId,
                &tower_id,
                confidence::STRONG,
                &ctx.scan_id,
            );
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
                let conf = accuracy_to_confidence(cell.range_m as u64);
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

// ── Helpers ──────────────────────────────────────────────────────────────────

use crate::util::cell_db::accuracy_to_confidence;

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The typed outcome for a lookup against a database that was never imported:
/// an `Unavailable` skip — the provider (the local cell-tower database) could
/// not be used from this host, a coverage gap the operator closes with
/// `hse cells import`. Never `Ok(empty)`: the module doc used to call that a
/// "silent no-op", and dispatch recorded it as `ModuleDone { found: 0 }`,
/// which `core::coverage` reads as a clean negative about the coordinate.
pub(super) fn database_not_imported() -> Error {
    Error::skipped(
        crate::core::event::SkipClass::Unavailable,
        "local cell-tower database not imported (~/.huntsman/cell_towers.db) — run \
         `hse cells import`; no towers were looked up for this coordinate",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    /// An unimported database is the typed `Unavailable` skip, never an empty
    /// result; and the real `process` path takes it whenever the per-process
    /// test database does not exist (which is the state of a fresh test
    /// process — under `cfg(test)` the data directory is a pid-scoped temp
    /// directory that nothing here imports into).
    #[tokio::test]
    async fn an_unimported_database_is_a_typed_unavailable_skip_never_no_towers() {
        use crate::core::error::Error;
        use crate::core::event::SkipClass;
        match database_not_imported() {
            Error::Skipped { class, reason } => {
                assert_eq!(class, SkipClass::Unavailable);
                assert!(reason.contains("hse cells import"), "{reason}");
            }
            other => panic!("expected an Unavailable skip, got {other}"),
        }
        if crate::util::cell_db::cell_db_path().exists() {
            // Another test in this process imported a database: the skip path
            // is not reachable here, and the pure check above is the lock.
            return;
        }
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        let ctx = ModuleContext {
            scan_id: "t".into(),
            bus,
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        };
        let err = CellLocal
            .process(
                &Target::new(TargetKind::Coordinates, "-27.4698,153.0251"),
                &ctx,
            )
            .await
            .expect_err("no database means nothing was searched — never a clean negative");
        assert!(
            matches!(
                err,
                Error::Skipped {
                    class: SkipClass::Unavailable,
                    ..
                }
            ),
            "{err}"
        );
    }

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

    #[test]
    fn accuracy_to_confidence_tiers() {
        // accuracy_to_confidence delegates to the canonical util::geo ladder
        // (see its doc comment) — pin the delegation itself, at every tier
        // boundary, rather than a second hardcoded copy of the thresholds, so
        // this test can't silently drift from the one canonical scale.
        for m in [0, 50, 200, 201, 1000, 1001, 5000, 5001, 50_000] {
            assert_eq!(
                accuracy_to_confidence(m),
                crate::util::geo::confidence_for_accuracy_m(Some(m as f64)),
                "accuracy_to_confidence({m}) must match the canonical geo ladder"
            );
        }
    }
}
