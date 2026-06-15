//! Local RF signal radar — nearby Wi-Fi APs, Bluetooth devices, and cell
//! towers from the AU corpus (no API calls).
//!
//! Queries two SQLite tables that are populated by the harvest pipeline:
//! - `wigle_au`      — Wi-Fi APs and Bluetooth beacons from WiGLE exports
//! - `opencellid_au` — Cell towers from the OpenCelliD AU dataset
//!
//! The module accepts a `Coordinates` target (`"lat,lon"`), applies a
//! bounding-box approximation of ±0.009° lat / ±0.011° lon (~1 km at AU
//! latitudes), and returns up to 500 Wi-Fi/BT rows and 200 cell-tower rows.
//! If either table does not exist (first run before any harvest), the module
//! returns an empty result silently.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use rusqlite::{Connection, params};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::is_valid_coords;

const SRC: &str = "signal_radar_au";

/// Bounding-box half-widths for ~1 km at Australian latitudes.
const DLAT: f64 = 0.009;
const DLON: f64 = 0.011;

pub struct SignalRadarAu;

#[async_trait]
impl Module for SignalRadarAu {
    fn name(&self) -> &'static str {
        "signal_radar_au"
    }

    fn description(&self) -> &'static str {
        "Local RF signal radar — nearby Wi-Fi, BT, and cell towers from AU corpus"
    }

    fn priority(&self) -> u8 {
        72
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::Coordinates
    }

    fn max_timeout_ms(&self) -> u64 {
        5_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1592"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::MacAddress,
            EntityKind::DeviceId,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Parse target value as "lat,lon".
        let (lat, lon) = match parse_coords(&target.value) {
            Some(v) => v,
            None => return Ok(ModuleResult::new()),
        };

        if !is_valid_coords(lat, lon) {
            return Ok(ModuleResult::new());
        }

        let db_path = crate::default_db_path();
        let conn = match Connection::open(&db_path) {
            Ok(c) => c,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();

        query_wigle_au(&conn, lat, lon, &ctx.scan_id, &mut result);
        query_opencellid_au(&conn, lat, lon, &ctx.scan_id, &mut result);

        Ok(result)
    }
}

/// Parse `"lat,lon"` into `(f64, f64)`. Returns `None` on any parse error.
fn parse_coords(value: &str) -> Option<(f64, f64)> {
    let mut parts = value.splitn(2, ',');
    let lat: f64 = parts.next()?.trim().parse().ok()?;
    let lon: f64 = parts.next()?.trim().parse().ok()?;
    Some((lat, lon))
}

/// Query `wigle_au` for Wi-Fi APs and Bluetooth devices near the coordinate.
/// Silently returns nothing if the table does not exist.
fn query_wigle_au(conn: &Connection, lat: f64, lon: f64, scan_id: &str, result: &mut ModuleResult) {
    let sql = "SELECT netid, kind, ssid, lat, lon, accuracy, last_seen, encryption, channel \
               FROM wigle_au \
               WHERE lat BETWEEN ?1 AND ?2 \
                 AND lon BETWEEN ?3 AND ?4 \
               LIMIT 500";

    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        // Table doesn't exist yet — first run before any harvest.
        Err(_) => return,
    };

    let rows = stmt.query_map(
        params![lat - DLAT, lat + DLAT, lon - DLON, lon + DLON],
        |row| {
            Ok(WigleRow {
                netid: row.get(0)?,
                kind: row.get(1)?,
                ssid: row.get(2)?,
                lat: row.get(3)?,
                lon: row.get(4)?,
                accuracy: row.get(5)?,
                last_seen: row.get(6)?,
                encryption: row.get(7)?,
                channel: row.get(8)?,
            })
        },
    );

    let rows = match rows {
        Ok(r) => r,
        Err(_) => return,
    };

    for row in rows.flatten() {
        let kind = row.kind.to_lowercase();
        let is_wifi = kind == "wifi";
        let is_bt = kind == "bluetooth";

        if !is_wifi && !is_bt {
            continue;
        }

        let entity_kind = EntityKind::MacAddress;
        let summary = if is_wifi {
            format!("Wi-Fi AP near {:.4},{:.4}", row.lat, row.lon)
        } else {
            format!("BT device near {:.4},{:.4}", row.lat, row.lon)
        };

        let mut ev = Evidence::new(SRC, summary)
            .with_attr("bssid", &row.netid)
            .with_attr("lat", row.lat.to_string())
            .with_attr("lon", row.lon.to_string());

        if is_wifi {
            if let Some(ref ssid) = row.ssid {
                ev = ev.with_attr("ssid", ssid.as_str());
            }
        }
        if let Some(ref acc) = row.accuracy {
            ev = ev.with_attr("accuracy", acc.as_str());
        }
        if let Some(ref ls) = row.last_seen {
            ev = ev.with_attr("last_seen", ls.as_str());
        }
        if let Some(ref enc) = row.encryption {
            ev = ev.with_attr("encryption", enc.as_str());
        }
        if let Some(ref ch) = row.channel {
            ev = ev.with_attr("channel", ch.as_str());
        }

        let mut e = Entity::new(entity_kind, &row.netid, 0.85, scan_id);
        if is_wifi {
            e.tag("wifi-ap");
        } else {
            e.tag("bluetooth");
        }
        e.tag("corpus-hit");
        e.tag("au-corpus");
        e.add_evidence(ev);
        result.push(e);
    }
}

/// Query `opencellid_au` for cell towers near the coordinate.
/// Silently returns nothing if the table does not exist.
fn query_opencellid_au(
    conn: &Connection,
    lat: f64,
    lon: f64,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    let sql = "SELECT radio, mcc, mnc, lac, cid, lat, lon, range_m \
               FROM opencellid_au \
               WHERE lat BETWEEN ?1 AND ?2 \
                 AND lon BETWEEN ?3 AND ?4 \
               LIMIT 200";

    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return,
    };

    let rows = stmt.query_map(
        params![lat - DLAT, lat + DLAT, lon - DLON, lon + DLON],
        |row| {
            Ok(CellRow {
                radio: row.get(0)?,
                mcc: row.get(1)?,
                mnc: row.get(2)?,
                lac: row.get(3)?,
                cid: row.get(4)?,
                lat: row.get(5)?,
                lon: row.get(6)?,
                range_m: row.get(7)?,
            })
        },
    );

    let rows = match rows {
        Ok(r) => r,
        Err(_) => return,
    };

    for row in rows.flatten() {
        let cell_id = format!("{}-{}-{}-{}", row.mcc, row.mnc, row.lac, row.cid);
        let summary = format!("Cell tower near {:.4},{:.4}", row.lat, row.lon);

        let mut ev = Evidence::new(SRC, summary)
            .with_attr("mcc", row.mcc.to_string())
            .with_attr("mnc", row.mnc.to_string())
            .with_attr("lac", row.lac.to_string())
            .with_attr("cid", row.cid.to_string())
            .with_attr("lat", row.lat.to_string())
            .with_attr("lon", row.lon.to_string())
            .with_attr("radio", &row.radio);

        if let Some(range) = row.range_m {
            ev = ev.with_attr("range_m", range.to_string());
        }

        let mut e = Entity::new(EntityKind::DeviceId, &cell_id, 0.80, scan_id);
        e.tag("cell-tower");
        e.tag("opencellid");
        e.tag("au-corpus");
        e.tag(format!("radio:{}", row.radio.to_lowercase()));
        e.add_evidence(ev);
        result.push(e);
    }
}

// ── Row types ─────────────────────────────────────────────────────────────

struct WigleRow {
    netid: String,
    kind: String,
    ssid: Option<String>,
    lat: f64,
    lon: f64,
    accuracy: Option<String>,
    last_seen: Option<String>,
    encryption: Option<String>,
    channel: Option<String>,
}

struct CellRow {
    radio: String,
    mcc: i64,
    mnc: i64,
    lac: i64,
    cid: i64,
    lat: f64,
    lon: f64,
    range_m: Option<i64>,
}
