//! Local RF signal radar — nearby Wi-Fi, Bluetooth, and cell towers from the
//! AU corpus (wigle_au + opencellid_au).
//!
//! Accepts `Coordinates` targets and returns all known RF emitters within
//! approximately 1 km, sourced entirely from the local SQLite corpus.
//! Zero network calls; zero API quota. Sub-millisecond for indexed hits.
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations
//!   * T1592 — Gather Victim Host Information

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::is_valid_coords;

const SRC: &str = "signal_radar_au";
/// Approximate bounding-box half-width at AU latitudes (~1 km radius).
const LAT_DELTA: f64 = 0.009;
const LON_DELTA: f64 = 0.011;

pub struct SignalRadarAu;

#[async_trait]
impl Module for SignalRadarAu {
    fn name(&self) -> &'static str {
        "signal_radar_au"
    }

    fn description(&self) -> &'static str {
        "Local RF corpus radar — Wi-Fi, BT, and cell towers near a coordinate (wigle_au + opencellid_au)"
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
        const KINDS: &[EntityKind] = &[EntityKind::MacAddress, EntityKind::DeviceId];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = match parse_coords(&target.value) {
            Some(c) => c,
            None => return Ok(ModuleResult::new()),
        };

        if !is_valid_coords(lat, lon) {
            return Ok(ModuleResult::new());
        }

        let db_path = crate::default_db_path();
        let conn = match rusqlite::Connection::open(&db_path) {
            Ok(c) => c,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();

        let lat_min = lat - LAT_DELTA;
        let lat_max = lat + LAT_DELTA;
        let lon_min = lon - LON_DELTA;
        let lon_max = lon + LON_DELTA;

        // ── Query wigle_au ────────────────────────────────────────────────
        let wigle_ok = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='wigle_au'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if wigle_ok {
            let mut stmt = conn
                .prepare(
                    "SELECT netid, kind, ssid, lat, lon, accuracy, last_seen, encryption, channel \
                     FROM wigle_au \
                     WHERE lat BETWEEN ?1 AND ?2 \
                       AND lon BETWEEN ?3 AND ?4 \
                     LIMIT 500",
                )
                .ok();

            if let Some(ref mut stmt) = stmt {
                let rows = stmt.query_map(
                    rusqlite::params![lat_min, lat_max, lon_min, lon_max],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,         // netid
                            row.get::<_, String>(1)?,         // kind
                            row.get::<_, Option<String>>(2)?, // ssid
                            row.get::<_, f64>(3)?,            // lat
                            row.get::<_, f64>(4)?,            // lon
                            row.get::<_, Option<i64>>(5)?,    // accuracy
                            row.get::<_, Option<String>>(6)?, // last_seen
                            row.get::<_, Option<String>>(7)?, // encryption
                            row.get::<_, Option<i64>>(8)?,    // channel
                        ))
                    },
                );

                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        let (
                            netid,
                            kind,
                            ssid,
                            rlat,
                            rlon,
                            accuracy,
                            last_seen,
                            encryption,
                            channel,
                        ) = row;
                        let (entity_kind, tag, ev_summary) = match kind.as_str() {
                            "bluetooth" => (
                                EntityKind::MacAddress,
                                "bluetooth",
                                format!("BT device near {lat:.4},{lon:.4}"),
                            ),
                            _ => (
                                EntityKind::MacAddress,
                                "wifi-ap",
                                format!("Wi-Fi AP near {lat:.4},{lon:.4}"),
                            ),
                        };

                        let mut e = Entity::new(entity_kind, &netid, 0.85, &ctx.scan_id);
                        e.tag(tag);
                        e.tag("corpus-hit");
                        e.tag("au-corpus");

                        let mut ev = Evidence::new(SRC, ev_summary)
                            .with_attr("bssid", &netid)
                            .with_attr("latitude", rlat.to_string())
                            .with_attr("longitude", rlon.to_string())
                            .with_attr("source", "wigle_au");
                        if let Some(s) = ssid.as_deref() {
                            ev = ev.with_attr("ssid", s);
                        }
                        if let Some(a) = accuracy {
                            ev = ev.with_attr("accuracy_m", a.to_string());
                        }
                        if let Some(ls) = last_seen.as_deref() {
                            ev = ev.with_attr("last_seen", ls);
                        }
                        if let Some(enc) = encryption.as_deref() {
                            ev = ev.with_attr("encryption", enc);
                        }
                        if let Some(ch) = channel {
                            ev = ev.with_attr("channel", ch.to_string());
                        }

                        e.add_evidence(ev);
                        result.push(e);
                    }
                }
            }
        }

        // ── Query opencellid_au ───────────────────────────────────────────
        let oci_ok = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='opencellid_au'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if oci_ok {
            let mut stmt = conn
                .prepare(
                    "SELECT radio, mcc, mnc, lac, cid, lat, lon, range_m \
                     FROM opencellid_au \
                     WHERE lat BETWEEN ?1 AND ?2 \
                       AND lon BETWEEN ?3 AND ?4 \
                     LIMIT 200",
                )
                .ok();

            if let Some(ref mut stmt) = stmt {
                let rows = stmt.query_map(
                    rusqlite::params![lat_min, lat_max, lon_min, lon_max],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,      // radio
                            row.get::<_, i64>(1)?,         // mcc
                            row.get::<_, i64>(2)?,         // mnc
                            row.get::<_, i64>(3)?,         // lac
                            row.get::<_, i64>(4)?,         // cid
                            row.get::<_, f64>(5)?,         // lat
                            row.get::<_, f64>(6)?,         // lon
                            row.get::<_, Option<i64>>(7)?, // range_m
                        ))
                    },
                );

                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        let (radio, mcc, mnc, lac, cid, rlat, rlon, range_m) = row;
                        let tower_id = format!("{mcc}-{mnc}-{lac}-{cid}");
                        let mut e =
                            Entity::new(EntityKind::DeviceId, &tower_id, 0.80, &ctx.scan_id);
                        e.tag("cell-tower");
                        e.tag("opencellid");
                        e.tag("au-corpus");
                        e.tag(format!("radio:{}", radio.to_lowercase()));

                        let mut ev =
                            Evidence::new(SRC, format!("Cell tower near {lat:.4},{lon:.4}"))
                                .with_attr("tower_id", &tower_id)
                                .with_attr("radio", &radio)
                                .with_attr("mcc", mcc.to_string())
                                .with_attr("mnc", mnc.to_string())
                                .with_attr("lac", lac.to_string())
                                .with_attr("cid", cid.to_string())
                                .with_attr("latitude", rlat.to_string())
                                .with_attr("longitude", rlon.to_string())
                                .with_attr("source", "opencellid_au");
                        if let Some(r) = range_m {
                            ev = ev.with_attr("range_m", r.to_string());
                        }

                        e.add_evidence(ev);
                        result.push(e);
                    }
                }
            }
        }

        Ok(result)
    }
}

fn parse_coords(value: &str) -> Option<(f64, f64)> {
    let mut parts = value.splitn(2, ',');
    let lat = parts.next()?.trim().parse::<f64>().ok()?;
    let lon = parts.next()?.trim().parse::<f64>().ok()?;
    Some((lat, lon))
}
