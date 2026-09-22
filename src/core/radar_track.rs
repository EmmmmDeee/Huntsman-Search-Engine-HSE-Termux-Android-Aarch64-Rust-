//! Cross-sweep RF device persistence — the counter-surveillance signal a
//! per-scan correlator structurally cannot see.
//!
//! A single radar sweep is one snapshot: it can say "this hardware device is
//! near me now" (AU-122) or "this is my own paired kit" (AU-117), but it cannot
//! answer the question that actually matters for personal safety — *"is the SAME
//! device following me across time and place?"*. That needs the history of every
//! sweep, which the storage layer keeps (`radar_history`), not the single scan
//! the correlator runs over.
//!
//! This module is the pure analysis: given a series of sweeps, it finds the
//! devices that recur across ≥N of them. It counts ONLY:
//!   * **universally-administered** MACs — a randomized privacy address (AU-122's
//!     "randomized" class) rotates every ~15 min, so "the same randomized MAC in
//!     two sweeps" is impossible and its absence proves nothing; only a real,
//!     persistent hardware address can meaningfully recur, and
//!   * devices the operator's phone is **not bonded to** — the operator's own
//!     car / earbuds / watch (AU-117) recur trivially and are not a threat.
//!
//! What survives both filters is an UNKNOWN persistent hardware device seen
//! across multiple sweeps — a fixed installation the operator keeps passing, or,
//! if it tracks the operator's movement, a potential tail. The output is a
//! review list, ranked by how many sweeps each device appears in.
//!
//! Pure and offline (the only dependency is the same [`crate::util::oui`] U/L-bit
//! classifier AU-122/AU-117 use), so it runs identically on-device and in CI.

use serde::Serialize;

use crate::util::oui;

/// One RF observation within a sweep.
pub struct SweepObservation {
    /// The device MAC as observed.
    pub mac: String,
    /// A human name if the scan surfaced one (Bluetooth device name / SSID).
    pub name: Option<String>,
    /// True if the operator's phone is bonded (paired) to this device — i.e. it
    /// is the operator's OWN hardware and must not count as a foreign tail.
    pub bonded: bool,
    /// The strongest level the sweep heard it at, where the source measured one.
    pub signal_dbm: Option<f64>,
    /// Where the sweep heard it from, where the sweep had a fix.
    pub position: Option<(f64, f64)>,
}

/// Read one RF sighting off a scan entity, or `None` when the entity is not an
/// RF device observation at all.
///
/// The *mapping* is single-sourced here — which evidence attribute carries the
/// device name (`name` for Bluetooth, `ssid` for a Wi-Fi AP) and which tag means
/// "the operator is bonded to this" — because that is the drift-prone part and
/// two consumers read it: the API's cross-sweep persistence review and the CLI's
/// live radar. The *filter* deliberately stays at the call site, since the two
/// genuinely differ (the review folds in Wi-Fi APs; the Bluetooth radar does
/// not).
#[must_use]
pub fn observation_from_entity(e: &crate::core::entity::Entity) -> Option<SweepObservation> {
    if e.kind != crate::core::entity::EntityKind::MacAddress {
        return None;
    }
    let name = e
        .evidence
        .iter()
        .find_map(|ev| {
            ev.attributes
                .get("name")
                .or_else(|| ev.attributes.get("ssid"))
        })
        .map(String::to_string);
    Some(SweepObservation {
        mac: e.value.clone(),
        name,
        bonded: e.has_tag("bond:bonded"),
        // The entity graph dissolves the reading: no level, no position. Only
        // a sweep from before the sighting writer existed is read this way.
        signal_dbm: None,
        position: None,
    })
}

/// Read one RF sighting off a sighting-table device row — the reading the
/// entity graph dissolves, with its level and position. `bonded` is the
/// entity's AU-117 tag, which the sighting row does not carry; the caller
/// looks it up on the same sweep's entities.
#[must_use]
pub fn observation_from_device(d: &crate::core::rf::RfDeviceRow, bonded: bool) -> SweepObservation {
    SweepObservation {
        mac: d.network_id.clone(),
        name: d.name.clone(),
        bonded,
        signal_dbm: d.best_signal_dbm,
        position: match (d.best_latitude, d.best_longitude) {
            (Some(lat), Some(lon)) => Some((lat, lon)),
            _ => None,
        },
    }
}

/// One radar sweep: every RF device it observed, with when it ran.
pub struct Sweep {
    pub scan_id: String,
    pub ts: u64,
    pub devices: Vec<SweepObservation>,
}

/// A device that recurred across multiple sweeps — a persistent presence to
/// review.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RecurringDevice {
    pub mac: String,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub device_class: Option<String>,
    /// Distinct sweeps this device appeared in.
    pub sweeps_seen: usize,
    /// Timestamp of the earliest and latest sweep it appeared in.
    pub first_ts: u64,
    pub last_ts: u64,
    /// The strongest level any sweep heard it at — `None` when no sweep that
    /// saw it carried a reading (an entity-only sweep, or a radio with no
    /// level, such as classic Bluetooth discovery).
    pub best_signal_dbm: Option<f64>,
    /// Distinct places (to ~10 m) it was heard from across the sweeps. One
    /// means a single bearing; more means the sightings constrain a location —
    /// or that the device moved with the operator.
    pub distinct_positions: usize,
}

/// Find the trackable, non-owned devices that appear in at least `min_sweeps`
/// distinct sweeps. `min_sweeps` is floored to 2 (a device in one sweep has not
/// "recurred"). Deterministic: ranked by sweep count desc, then most-recent
/// sighting desc, then MAC.
#[must_use]
pub fn recurring_devices(sweeps: &[Sweep], min_sweeps: usize) -> Vec<RecurringDevice> {
    use std::collections::HashMap;

    let min_sweeps = min_sweeps.max(2);

    struct Acc {
        name: Option<String>,
        bonded_anywhere: bool,
        sweep_ids: std::collections::HashSet<String>,
        first_ts: u64,
        last_ts: u64,
        best_signal_dbm: Option<f64>,
        /// Positions rounded to 1e-4° (~11 m), so a fix jittering by metres is
        /// one place, not many.
        positions: std::collections::HashSet<(i64, i64)>,
    }
    let mut by_mac: HashMap<String, Acc> = HashMap::new();

    for sweep in sweeps {
        for dev in &sweep.devices {
            let key = dev.mac.trim().to_lowercase();
            if key.is_empty() {
                continue;
            }
            let acc = by_mac.entry(key).or_insert_with(|| Acc {
                name: None,
                bonded_anywhere: false,
                sweep_ids: std::collections::HashSet::new(),
                first_ts: u64::MAX,
                last_ts: 0,
                best_signal_dbm: None,
                positions: std::collections::HashSet::new(),
            });
            acc.bonded_anywhere |= dev.bonded;
            if acc.name.is_none()
                && let Some(n) = dev.name.as_deref().map(str::trim)
                && !n.is_empty()
                && n != "<unknown>"
            {
                acc.name = Some(n.to_string());
            }
            acc.sweep_ids.insert(sweep.scan_id.clone());
            acc.first_ts = acc.first_ts.min(sweep.ts);
            acc.last_ts = acc.last_ts.max(sweep.ts);
            if let Some(level) = dev.signal_dbm {
                acc.best_signal_dbm = Some(acc.best_signal_dbm.map_or(level, |b| b.max(level)));
            }
            if let Some((lat, lon)) = dev.position {
                // `as` after `round()`: the value is within ±1.8e6, far inside i64.
                #[allow(clippy::cast_possible_truncation)]
                acc.positions
                    .insert(((lat * 1e4).round() as i64, (lon * 1e4).round() as i64));
            }
        }
    }

    let mut out: Vec<RecurringDevice> = by_mac
        .into_iter()
        .filter_map(|(mac, acc)| {
            // Owned (bonded) devices recur trivially — not a foreign tail.
            if acc.bonded_anywhere {
                return None;
            }
            // Only a persistent hardware (universally-administered) MAC can
            // meaningfully recur; a randomized privacy address rotates.
            if oui::is_locally_administered(&mac) != Some(false) {
                return None;
            }
            if acc.sweep_ids.len() < min_sweeps {
                return None;
            }
            let (vendor, device_class) = match oui::classify_mac(&mac) {
                Some(info)
                    if !matches!(
                        info.class,
                        oui::DeviceClass::Unregistered
                            | oui::DeviceClass::Unknown
                            | oui::DeviceClass::Randomized
                    ) =>
                {
                    (
                        Some(info.vendor.to_string()),
                        Some(info.class.as_str().to_string()),
                    )
                }
                _ => (None, None),
            };
            Some(RecurringDevice {
                mac,
                name: acc.name,
                vendor,
                device_class,
                sweeps_seen: acc.sweep_ids.len(),
                first_ts: acc.first_ts,
                last_ts: acc.last_ts,
                best_signal_dbm: acc.best_signal_dbm,
                distinct_positions: acc.positions.len(),
            })
        })
        .collect();

    out.sort_by(|a, b| {
        b.sweeps_seen
            .cmp(&a.sweeps_seen)
            .then(b.last_ts.cmp(&a.last_ts))
            .then(a.mac.cmp(&b.mac))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(mac: &str) -> SweepObservation {
        SweepObservation {
            mac: mac.to_string(),
            name: None,
            bonded: false,
            signal_dbm: None,
            position: None,
        }
    }
    fn heard(mac: &str, dbm: f64, at: (f64, f64)) -> SweepObservation {
        SweepObservation {
            signal_dbm: Some(dbm),
            position: Some(at),
            ..obs(mac)
        }
    }
    fn sweep(id: &str, ts: u64, macs: &[SweepObservation]) -> Sweep {
        Sweep {
            scan_id: id.to_string(),
            ts,
            devices: macs
                .iter()
                .map(|o| SweepObservation {
                    mac: o.mac.clone(),
                    name: o.name.clone(),
                    bonded: o.bonded,
                    signal_dbm: o.signal_dbm,
                    position: o.position,
                })
                .collect(),
        }
    }

    // Universally-administered (0x3C, U/L bit clear) — a real trackable device.
    const HW1: &str = "3C:5A:B4:11:22:33";
    const HW2: &str = "3C:5A:B4:44:55:66";
    // Locally-administered (0x36, U/L bit set) — a rotating privacy address.
    const RND: &str = "36:32:62:36:31:33";

    #[test]
    fn flags_a_hardware_device_seen_across_two_sweeps() {
        let sweeps = [
            sweep("s1", 100, &[obs(HW1), obs(HW2)]),
            sweep("s2", 200, &[obs(HW1)]), // HW1 recurs, HW2 does not
        ];
        let out = recurring_devices(&sweeps, 2);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mac, HW1.to_lowercase());
        assert_eq!(out[0].sweeps_seen, 2);
        assert_eq!(out[0].first_ts, 100);
        assert_eq!(out[0].last_ts, 200);
    }

    #[test]
    fn ignores_a_recurring_randomized_address() {
        // The same randomized MAC in two sweeps is meaningless (they rotate) —
        // never surfaced as a persistent device.
        let sweeps = [sweep("s1", 100, &[obs(RND)]), sweep("s2", 200, &[obs(RND)])];
        assert!(recurring_devices(&sweeps, 2).is_empty());
    }

    #[test]
    fn ignores_the_operators_own_bonded_device() {
        let mut owned = obs(HW1);
        owned.bonded = true;
        let sweeps = [
            sweep("s1", 100, &[owned]),
            sweep(
                "s2",
                200,
                &[SweepObservation {
                    mac: HW1.to_string(),
                    name: None,
                    bonded: false,
                    signal_dbm: None,
                    position: None,
                }],
            ),
        ];
        assert!(
            recurring_devices(&sweeps, 2).is_empty(),
            "a device bonded in any sweep is the operator's own kit"
        );
    }

    #[test]
    fn recurrence_carries_the_best_level_and_the_distinct_places() {
        // Three sweeps: two from one spot (a fix jittering by a few metres is
        // one place), one from 200 m away; the level is the strongest heard.
        let sweeps = [
            sweep("s1", 100, &[heard(HW1, -70.0, (-27.4705, 153.0260))]),
            sweep("s2", 200, &[heard(HW1, -52.0, (-27.47052, 153.02603))]),
            sweep("s3", 300, &[heard(HW1, -80.0, (-27.4723, 153.0260))]),
        ];
        let out = recurring_devices(&sweeps, 2);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sweeps_seen, 3);
        assert_eq!(out[0].best_signal_dbm, Some(-52.0));
        assert_eq!(out[0].distinct_positions, 2);

        // An entity-only sweep contributes recurrence and nothing else.
        let sweeps = [sweep("s1", 100, &[obs(HW1)]), sweep("s2", 200, &[obs(HW1)])];
        let out = recurring_devices(&sweeps, 2);
        assert_eq!(out[0].best_signal_dbm, None);
        assert_eq!(out[0].distinct_positions, 0);
    }

    #[test]
    fn a_device_row_becomes_an_observation_with_its_level_and_place() {
        let row = crate::core::rf::RfDeviceRow {
            network_id: "3c:5a:b4:11:22:33".to_string(),
            radio: crate::core::rf::RadioKind::Wifi,
            locally_administered: Some(false),
            oui: Some("3C5AB4".to_string()),
            vendor: None,
            device_class: None,
            name: Some("LabNet".to_string()),
            sightings: 2,
            distinct_fixes: 1,
            first_epoch: Some(1),
            last_epoch: Some(2),
            best_signal_dbm: Some(-45.0),
            worst_signal_dbm: Some(-60.0),
            best_accuracy_m: Some(8.0),
            best_latitude: Some(-27.4705),
            best_longitude: Some(153.026),
        };
        let o = observation_from_device(&row, true);
        assert_eq!(o.mac, "3c:5a:b4:11:22:33");
        assert_eq!(o.name.as_deref(), Some("LabNet"));
        assert!(
            o.bonded,
            "the bonded flag is the caller's, from the entity tag"
        );
        assert_eq!(o.signal_dbm, Some(-45.0));
        assert_eq!(o.position, Some((-27.4705, 153.026)));
        // No fix on the row: no position, never (0, 0).
        let unfixed = crate::core::rf::RfDeviceRow {
            best_latitude: None,
            ..row
        };
        assert_eq!(observation_from_device(&unfixed, false).position, None);
    }

    #[test]
    fn same_device_in_one_sweep_does_not_recur() {
        let sweeps = [sweep("s1", 100, &[obs(HW1), obs(HW1)])];
        assert!(
            recurring_devices(&sweeps, 2).is_empty(),
            "one sweep is not recurrence, even if listed twice"
        );
    }
}
