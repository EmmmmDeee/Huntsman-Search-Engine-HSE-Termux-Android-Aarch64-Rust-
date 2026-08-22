//! Persistence for [`crate::core::rf::RfSighting`] — the per-sighting RF record
//! a wardriving capture or a radar sweep produces. Kept in its own table
//! (`rf_sightings`), separate from the generic `entities` graph: see the
//! `CREATE TABLE` comment in `storage::mod` for why.

use rusqlite::params;

use crate::core::error::Result;
use crate::core::rf::{RadioKind, RfSighting, RfSource};

/// One device as rolled up from its sightings within a scan — the `rf_devices`
/// view's row. Every field is derived, so this is a read model with no
/// independent lifetime: it cannot drift from the facts because it is not
/// stored.
#[derive(Debug, Clone, PartialEq)]
pub struct RfDeviceRow {
    pub network_id: String,
    pub radio: RadioKind,
    /// `None` when the id is not a hardware address (a cellular identifier).
    pub locally_administered: Option<bool>,
    pub oui: Option<String>,
    pub device_class: Option<String>,
    pub name: Option<String>,
    pub sightings: i64,
    /// Distinct rounded positions this device was heard from. Greater than one
    /// means the sightings genuinely constrain a location rather than giving a
    /// single bearing.
    pub distinct_fixes: i64,
    pub first_epoch: Option<i64>,
    pub last_epoch: Option<i64>,
    pub best_signal_dbm: Option<f64>,
    pub worst_signal_dbm: Option<f64>,
    pub best_accuracy_m: Option<f64>,
    pub best_latitude: Option<f64>,
    pub best_longitude: Option<f64>,
}

/// Scan-level totals, computed in SQL so a summary never walks every row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RfSummary {
    pub sightings: i64,
    pub devices: i64,
    pub wifi: i64,
    pub ble: i64,
    pub bt: i64,
    pub cellular: i64,
    pub fixed_address: i64,
    pub randomised_address: i64,
    pub named: i64,
    pub with_position: i64,
    pub first_epoch: Option<i64>,
    pub last_epoch: Option<i64>,
}

impl super::Store {
    /// Persist a batch of sightings for one scan under one transaction —
    /// mirrors `insert_stealer_rows_batch`'s all-or-nothing batch-commit shape.
    /// A no-op (not an error) on an empty slice, so an importer can call it
    /// unconditionally.
    ///
    /// `locally_admin` and `oui` are derived here, once, rather than at every
    /// read: they are pure functions of the address, so computing them on write
    /// keeps every reader consistent and lets the index on `oui` do its job.
    pub fn insert_rf_sightings_batch(&self, scan_id: &str, rows: &[RfSighting]) -> Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO rf_sightings(scan_id, network_id, radio, source, locally_admin,
                                          oui, device_class, name, encryption, observed_at,
                                          observed_epoch, signal_dbm, accuracy_m,
                                          latitude, longitude, raw_type)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            )?;
            for r in rows {
                let la = match r.address_kind() {
                    crate::core::rf::AddressKind::Randomised => Some(1_i64),
                    crate::core::rf::AddressKind::Fixed => Some(0_i64),
                    crate::core::rf::AddressKind::NotAnAddress => None,
                };
                // A position that failed validation is stored as absent rather
                // than as the null island, so `with_position` counts fixes the
                // receiver actually had.
                let (lat, lon) = if r.has_usable_position() {
                    (r.latitude, r.longitude)
                } else {
                    (None, None)
                };
                stmt.execute(params![
                    scan_id,
                    r.network_id,
                    r.radio.as_db_str(),
                    r.source.as_db_str(),
                    la,
                    r.oui(),
                    r.device_class,
                    r.name,
                    r.encryption,
                    r.observed_at,
                    r.observed_epoch,
                    r.signal_dbm,
                    r.accuracy_m,
                    lat,
                    lon,
                    r.raw_type,
                ])?;
            }
        }
        tx.commit()?;
        Ok(rows.len())
    }

    /// Every device in a scan, strongest first.
    ///
    /// Deterministic: signal descending with NULLs last, then `network_id`, so
    /// devices the receiver never got a level for still have a stable place
    /// rather than floating to the top.
    pub fn rf_devices_for_scan(&self, scan_id: &str) -> Result<Vec<RfDeviceRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT network_id, radio, locally_admin, oui, device_class, name,
                    sightings, distinct_fixes, first_epoch, last_epoch,
                    best_signal_dbm, worst_signal_dbm, best_accuracy_m,
                    best_latitude, best_longitude
               FROM rf_devices
              WHERE scan_id = ?1
              ORDER BY best_signal_dbm IS NULL, best_signal_dbm DESC, network_id ASC",
        )?;
        let mapped = stmt.query_map(params![scan_id], |r| {
            Ok(RfDeviceRow {
                network_id: r.get(0)?,
                radio: RadioKind::from_db_str(&r.get::<_, String>(1)?),
                locally_administered: r.get::<_, Option<i64>>(2)?.map(|v| v == 1),
                oui: r.get(3)?,
                device_class: r.get(4)?,
                name: r.get(5)?,
                sightings: r.get(6)?,
                distinct_fixes: r.get(7)?,
                first_epoch: r.get(8)?,
                last_epoch: r.get(9)?,
                best_signal_dbm: r.get(10)?,
                worst_signal_dbm: r.get(11)?,
                best_accuracy_m: r.get(12)?,
                best_latitude: r.get(13)?,
                best_longitude: r.get(14)?,
            })
        })?;
        Ok(mapped.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Every sighting of one device, oldest first. This is the movement track:
    /// the same address heard repeatedly, with where and how loudly each time.
    pub fn rf_sightings_for_device(
        &self,
        scan_id: &str,
        network_id: &str,
    ) -> Result<Vec<RfSighting>> {
        let canonical = crate::core::rf::canonical_network_id(network_id);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT network_id, radio, source, device_class, name, encryption,
                    observed_at, observed_epoch, signal_dbm, accuracy_m,
                    latitude, longitude, raw_type
               FROM rf_sightings
              WHERE scan_id = ?1 AND network_id = ?2
              ORDER BY observed_epoch IS NULL, observed_epoch ASC, id ASC",
        )?;
        let mapped = stmt.query_map(params![scan_id, canonical], |r| {
            Ok(RfSighting {
                network_id: r.get(0)?,
                radio: RadioKind::from_db_str(&r.get::<_, String>(1)?),
                source: RfSource::from_db_str(&r.get::<_, String>(2)?),
                device_class: r.get(3)?,
                name: r.get(4)?,
                encryption: r.get(5)?,
                observed_at: r.get(6)?,
                observed_epoch: r.get(7)?,
                signal_dbm: r.get(8)?,
                accuracy_m: r.get(9)?,
                latitude: r.get(10)?,
                longitude: r.get(11)?,
                raw_type: r.get(12)?,
            })
        })?;
        Ok(mapped.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Names carried by more than one radio, largest installation first.
    pub fn rf_shared_names(&self, scan_id: &str) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT name, radios FROM rf_shared_names
              WHERE scan_id = ?1 ORDER BY radios DESC, name ASC",
        )?;
        let mapped = stmt.query_map(params![scan_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(mapped.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Devices with a fixed hardware address — the only ones whose recurrence
    /// across sightings means anything (AU-122).
    pub fn rf_trackable_devices(&self, scan_id: &str) -> Result<Vec<RfDeviceRow>> {
        Ok(self
            .rf_devices_for_scan(scan_id)?
            .into_iter()
            .filter(|d| d.locally_administered == Some(false))
            .collect())
    }

    /// The scan of the most recent sighting, or `None` when nothing has been
    /// recorded. Lets the CLI default to "the survey you just ran" instead of
    /// making the operator paste an id they never saw.
    ///
    /// Ordered by sighting id, not by timestamp: a capture can carry an older
    /// wall clock than a sweep imported after it, and "most recently recorded"
    /// is the question being asked.
    pub fn rf_latest_scan_id(&self) -> Result<Option<String>> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT scan_id FROM rf_sightings ORDER BY id DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        Ok(match rows.next()? {
            Some(r) => Some(r.get(0)?),
            None => None,
        })
    }

    /// Scan-level totals in one query.
    pub fn rf_summary(&self, scan_id: &str) -> Result<RfSummary> {
        let conn = self.conn.lock();
        // Device-level counts come from the rollup view and sighting-level ones
        // from the table, because a device is counted once however often it was
        // heard — mixing the two grains is the classic way this summary lies.
        let mut stmt = conn.prepare_cached(
            "SELECT
               (SELECT COUNT(*) FROM rf_sightings WHERE scan_id = ?1),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1 AND radio = 'wifi'),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1 AND radio = 'ble'),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1 AND radio = 'bt'),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1 AND radio = 'cell'),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1 AND locally_admin = 0),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1 AND locally_admin = 1),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1 AND name IS NOT NULL),
               (SELECT COUNT(*) FROM rf_devices   WHERE scan_id = ?1 AND best_latitude IS NOT NULL),
               (SELECT MIN(observed_epoch) FROM rf_sightings WHERE scan_id = ?1),
               (SELECT MAX(observed_epoch) FROM rf_sightings WHERE scan_id = ?1)",
        )?;
        let s = stmt.query_row(params![scan_id], |r| {
            Ok(RfSummary {
                sightings: r.get(0)?,
                devices: r.get(1)?,
                wifi: r.get(2)?,
                ble: r.get(3)?,
                bt: r.get(4)?,
                cellular: r.get(5)?,
                fixed_address: r.get(6)?,
                randomised_address: r.get(7)?,
                named: r.get(8)?,
                with_position: r.get(9)?,
                first_epoch: r.get(10)?,
                last_epoch: r.get(11)?,
            })
        })?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    include!("signal_tests.rs");
}
