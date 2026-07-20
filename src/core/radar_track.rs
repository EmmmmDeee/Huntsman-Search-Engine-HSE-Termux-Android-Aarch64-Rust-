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
}

/// One radar sweep: every RF device it observed, with when it ran.
pub struct Sweep {
    pub scan_id: String,
    pub ts: u64,
    pub devices: Vec<SweepObservation>,
}

/// A device that recurred across multiple sweeps — a persistent presence to
/// review.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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
                }],
            ),
        ];
        assert!(
            recurring_devices(&sweeps, 2).is_empty(),
            "a device bonded in any sweep is the operator's own kit"
        );
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
