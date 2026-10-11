//! Cross-sweep and live-radar tracking rebuilt from `core::radar_track` and
//! `core::radar_live`.

use std::collections::{HashMap, HashSet, VecDeque};

use super::oui;

const DEPART_AFTER_MISSED_READS: u32 = 2;
const DEFAULT_TRACK_CAPACITY: usize = 4_096;

/// Whether a MAC can be held to one physical device over time: a
/// globally-registered address (not randomized or locally-administered) on a
/// device the operator has not bonded (so, not the operator's own kit). A
/// randomized address rotates and must not be tracked across sweeps or
/// locations, both because it cannot be and because treating it as one device
/// would manufacture false links. This is the single home for that rule;
/// `recurring_devices`, `follower_candidates`, and the live radar all use it.
#[must_use]
fn stable_identity(mac: &str, bonded: bool) -> bool {
    !bonded && oui::is_locally_administered(mac) == Some(false)
}

pub struct SweepObservation {
    pub mac: String,
    pub name: Option<String>,
    pub bonded: bool,
}

pub struct Sweep {
    pub scan_id: String,
    pub ts: u64,
    pub devices: Vec<SweepObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecurringDevice {
    pub mac: String,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub device_class: Option<String>,
    pub sweeps_seen: usize,
    pub first_ts: u64,
    pub last_ts: u64,
}

#[must_use]
pub fn recurring_devices(sweeps: &[Sweep], min_sweeps: usize) -> Vec<RecurringDevice> {
    struct Acc {
        name: Option<String>,
        bonded_anywhere: bool,
        sweep_ids: HashSet<String>,
        first_ts: u64,
        last_ts: u64,
    }

    let min_sweeps = min_sweeps.max(2);
    let mut by_mac: HashMap<String, Acc> = HashMap::new();
    for sweep in sweeps {
        for device in &sweep.devices {
            let key = device.mac.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            let entry = by_mac.entry(key).or_insert_with(|| Acc {
                name: None,
                bonded_anywhere: false,
                sweep_ids: HashSet::new(),
                first_ts: u64::MAX,
                last_ts: 0,
            });
            entry.bonded_anywhere |= device.bonded;
            if entry.name.is_none() {
                if let Some(name) = device.name.as_deref().map(str::trim) {
                    if !name.is_empty() && name != "<unknown>" {
                        entry.name = Some(name.to_string());
                    }
                }
            }
            entry.sweep_ids.insert(sweep.scan_id.clone());
            entry.first_ts = entry.first_ts.min(sweep.ts);
            entry.last_ts = entry.last_ts.max(sweep.ts);
        }
    }

    let mut out: Vec<RecurringDevice> = by_mac
        .into_iter()
        .filter_map(|(mac, acc)| {
            if !stable_identity(&mac, acc.bonded_anywhere) {
                return None;
            }
            if acc.sweep_ids.len() < min_sweeps {
                return None;
            }
            let (vendor, device_class) = match oui::classify_mac(&mac) {
                Some(info)
                    if !matches!(
                        info.class,
                        oui::DeviceClass::Randomized
                            | oui::DeviceClass::Unknown
                            | oui::DeviceClass::Unregistered
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
    out.sort_by(|left, right| {
        right
            .sweeps_seen
            .cmp(&left.sweeps_seen)
            .then(right.last_ts.cmp(&left.last_ts))
            .then(left.mac.cmp(&right.mac))
    });
    out
}

/// One observation of a device together with the coarse location the operator
/// was at when it was seen. `cell` is an opaque location bucket the caller
/// supplies (e.g. a low-precision geohash), so this analysis stays independent
/// of any coordinate system. This mirrors the BLE-radar schema's
/// `device_to_location` joined to the operator's own `location` track.
pub struct FollowerSighting {
    pub mac: String,
    pub bonded: bool,
    pub ts: u64,
    pub cell: String,
}

/// A device that co-travelled with the operator: seen across several distinct
/// locations over time, which a stationary fixture (a neighbour's TV, a shop
/// beacon) is not. This is a personal-safety signal about the operator —
/// "something moved with you" — not a profile of the device's owner.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FollowerCandidate {
    pub mac: String,
    pub vendor: Option<String>,
    pub device_class: Option<String>,
    pub distinct_cells: usize,
    pub sightings: usize,
    /// Fraction of the operator's own distinct locations (over this window)
    /// where the device co-occurred, in `0.0..=1.0`. A device present almost
    /// everywhere the operator went (near 1.0) is the strong tail; a few shared
    /// cells out of many (near 0.0) is likely coincidence. This separates a
    /// real follower from overlap that raw cell counts alone cannot.
    pub coverage: f64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub span_secs: u64,
}

/// Flag devices that followed the operator across distinct locations.
///
/// A candidate must appear in at least `min_distinct_cells` distinct operator
/// locations (clamped to a floor of 2 — one location is stationary, not
/// following) and persist for at least `min_span_secs` (so one dense crowd in a
/// single moment is not mistaken for a tail). The operator's own paired kit
/// (`bonded`) and non-resolvable randomized / locally-administered addresses are
/// excluded: a rotating address cannot be followed across locations, and
/// treating it as one device would manufacture false alarms.
#[must_use]
pub fn follower_candidates(
    sightings: &[FollowerSighting],
    min_distinct_cells: usize,
    min_span_secs: u64,
) -> Vec<FollowerCandidate> {
    struct Acc {
        cells: HashSet<String>,
        sightings: usize,
        first_ts: u64,
        last_ts: u64,
    }

    let min_distinct_cells = min_distinct_cells.max(2);
    let mut by_mac: HashMap<String, Acc> = HashMap::new();
    // Every cell with any observation is a place the operator was, so this is
    // the denominator for coverage — including cells where only the operator's
    // own kit or a randomized address was seen.
    let mut operator_cells: HashSet<&str> = HashSet::new();
    for sighting in sightings {
        let cell = sighting.cell.trim();
        if cell.is_empty() {
            continue;
        }
        operator_cells.insert(cell);
        let mac = sighting.mac.trim().to_ascii_lowercase();
        if mac.is_empty() {
            continue;
        }
        // A device that cannot be re-identified across locations cannot be
        // shown to be following, and its owner is deliberately unidentifiable.
        if !stable_identity(&mac, sighting.bonded) {
            continue;
        }
        let entry = by_mac.entry(mac).or_insert_with(|| Acc {
            cells: HashSet::new(),
            sightings: 0,
            first_ts: u64::MAX,
            last_ts: 0,
        });
        entry.cells.insert(cell.to_string());
        entry.sightings += 1;
        entry.first_ts = entry.first_ts.min(sighting.ts);
        entry.last_ts = entry.last_ts.max(sighting.ts);
    }
    let operator_cell_total = operator_cells.len().max(1);

    let mut out: Vec<FollowerCandidate> = by_mac
        .into_iter()
        .filter_map(|(mac, acc)| {
            if acc.cells.len() < min_distinct_cells {
                return None;
            }
            let span = acc.last_ts.saturating_sub(acc.first_ts);
            if span < min_span_secs {
                return None;
            }
            let (vendor, device_class) = classify(&mac);
            let covered = u32::try_from(acc.cells.len()).unwrap_or(u32::MAX);
            let total = u32::try_from(operator_cell_total).unwrap_or(u32::MAX);
            let coverage = f64::from(covered) / f64::from(total);
            Some(FollowerCandidate {
                mac,
                vendor,
                device_class,
                distinct_cells: acc.cells.len(),
                sightings: acc.sightings,
                coverage,
                first_ts: acc.first_ts,
                last_ts: acc.last_ts,
                span_secs: span,
            })
        })
        .collect();
    out.sort_by(|left, right| {
        // coverage is collinear with distinct_cells within one call (shared
        // denominator), so distinct_cells is the primary order; coverage is the
        // reported strength signal, not a re-ranker.
        right
            .distinct_cells
            .cmp(&left.distinct_cells)
            .then(right.sightings.cmp(&left.sightings))
            .then(right.span_secs.cmp(&left.span_secs))
            .then(left.mac.cmp(&right.mac))
    });
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    New,
    Present,
    Missing(u32),
    Departed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtTrack {
    pub mac: String,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub device_class: Option<String>,
    pub first_seen_tick: u64,
    pub last_seen_tick: u64,
    pub sweeps_seen: u32,
    pub presence: Presence,
    missed_reads: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtReadOutcome {
    Read,
    NotRead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickDelta {
    pub read: BtReadOutcome,
    pub new: Vec<String>,
    pub present: Vec<String>,
    pub missing: Vec<String>,
    pub departed: Vec<String>,
    pub evicted: Vec<String>,
    pub randomized_seen: usize,
    pub bonded_seen: usize,
}

impl TickDelta {
    fn not_read() -> Self {
        Self {
            read: BtReadOutcome::NotRead,
            new: Vec::new(),
            present: Vec::new(),
            missing: Vec::new(),
            departed: Vec::new(),
            evicted: Vec::new(),
            randomized_seen: 0,
            bonded_seen: 0,
        }
    }
}

pub struct BtRadarState {
    tracks: HashMap<String, BtTrack>,
    order: VecDeque<String>,
    capacity: usize,
    tick: u64,
}

impl Default for BtRadarState {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_TRACK_CAPACITY)
    }
}

impl BtRadarState {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity >= 1, "a zero-capacity radar remembers no devices");
        Self {
            tracks: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            tick: 0,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tracks.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tracks.is_empty()
    }

    #[must_use]
    pub fn presence_of(&self, mac: &str) -> Option<Presence> {
        self.tracks
            .get(&mac.trim().to_ascii_lowercase())
            .map(|track| track.presence)
    }

    fn is_trackable(mac: &str, bonded: bool) -> bool {
        stable_identity(mac, bonded)
    }

    pub fn apply_tick(&mut self, sightings: &[SweepObservation], read: BtReadOutcome) -> TickDelta {
        if read == BtReadOutcome::NotRead {
            return TickDelta::not_read();
        }
        self.tick += 1;
        let now = self.tick;
        let mut delta = TickDelta {
            read: BtReadOutcome::Read,
            new: Vec::new(),
            present: Vec::new(),
            missing: Vec::new(),
            departed: Vec::new(),
            evicted: Vec::new(),
            randomized_seen: 0,
            bonded_seen: 0,
        };
        let mut seen_this_tick = HashSet::new();

        for device in sightings {
            let mac = device.mac.trim().to_ascii_lowercase();
            if mac.is_empty() {
                continue;
            }
            if !Self::is_trackable(&mac, device.bonded) {
                if device.bonded {
                    delta.bonded_seen += 1;
                } else {
                    delta.randomized_seen += 1;
                }
                continue;
            }

            seen_this_tick.insert(mac.clone());
            let name = clean_name(device.name.as_deref());
            if self.tracks.contains_key(&mac) {
                let track = self
                    .tracks
                    .get_mut(&mac)
                    .expect("contains_key confirmed entry");
                track.last_seen_tick = now;
                track.sweeps_seen += 1;
                track.missed_reads = 0;
                track.presence = Presence::Present;
                if track.name.is_none() {
                    track.name = name;
                }
                delta.present.push(mac);
            } else {
                let (vendor, device_class) = classify(&mac);
                if let Some(evicted) = self.insert_track(BtTrack {
                    mac: mac.clone(),
                    name,
                    vendor,
                    device_class,
                    first_seen_tick: now,
                    last_seen_tick: now,
                    sweeps_seen: 1,
                    presence: Presence::New,
                    missed_reads: 0,
                }) {
                    delta.evicted.push(evicted);
                }
                delta.new.push(mac);
            }
        }

        let mut to_remove = Vec::new();
        for (mac, track) in &mut self.tracks {
            if seen_this_tick.contains(mac) {
                continue;
            }
            track.missed_reads += 1;
            if track.missed_reads >= DEPART_AFTER_MISSED_READS {
                track.presence = Presence::Departed;
                delta.departed.push(mac.clone());
                to_remove.push(mac.clone());
            } else {
                track.presence = Presence::Missing(track.missed_reads);
                delta.missing.push(mac.clone());
            }
        }
        for mac in to_remove {
            self.tracks.remove(&mac);
            self.order.retain(|entry| entry != &mac);
        }

        if !delta.evicted.is_empty() {
            let evicted: HashSet<&String> = delta.evicted.iter().collect();
            delta.new.retain(|mac| !evicted.contains(mac));
            delta.present.retain(|mac| !evicted.contains(mac));
            delta.missing.retain(|mac| !evicted.contains(mac));
        }

        delta.new.sort();
        delta.present.sort();
        delta.missing.sort();
        delta.departed.sort();
        delta.evicted.sort();
        delta
    }

    #[must_use]
    pub fn tracks_ranked(&self) -> Vec<&BtTrack> {
        let mut out: Vec<&BtTrack> = self.tracks.values().collect();
        out.sort_by(|left, right| {
            right
                .sweeps_seen
                .cmp(&left.sweeps_seen)
                .then(right.last_seen_tick.cmp(&left.last_seen_tick))
                .then(left.mac.cmp(&right.mac))
        });
        out
    }

    fn insert_track(&mut self, track: BtTrack) -> Option<String> {
        let mut evicted = None;
        if self.tracks.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.tracks.remove(&oldest);
                evicted = Some(oldest);
            }
        }
        self.order.push_back(track.mac.clone());
        self.tracks.insert(track.mac.clone(), track);
        evicted
    }
}

fn clean_name(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|name| !name.is_empty() && *name != "<unknown>")
        .map(str::to_string)
}

fn classify(mac: &str) -> (Option<String>, Option<String>) {
    match oui::classify_mac(mac) {
        Some(info)
            if !matches!(
                info.class,
                oui::DeviceClass::Randomized
                    | oui::DeviceClass::Unknown
                    | oui::DeviceClass::Unregistered
            ) =>
        {
            (
                Some(info.vendor.to_string()),
                Some(info.class.as_str().to_string()),
            )
        }
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HW1: &str = "3C:5A:B4:11:22:33";
    const HW2: &str = "3C:5A:B4:44:55:66";
    const RND: &str = "36:32:62:36:31:33";

    fn obs(mac: &str) -> SweepObservation {
        SweepObservation {
            mac: mac.to_string(),
            name: None,
            bonded: false,
        }
    }

    fn named(mac: &str, name: &str) -> SweepObservation {
        SweepObservation {
            mac: mac.to_string(),
            name: Some(name.to_string()),
            bonded: false,
        }
    }

    fn bonded(mac: &str) -> SweepObservation {
        SweepObservation {
            mac: mac.to_string(),
            name: None,
            bonded: true,
        }
    }

    fn sweep(id: &str, ts: u64, devices: &[SweepObservation]) -> Sweep {
        Sweep {
            scan_id: id.to_string(),
            ts,
            devices: devices
                .iter()
                .map(|device| SweepObservation {
                    mac: device.mac.clone(),
                    name: device.name.clone(),
                    bonded: device.bonded,
                })
                .collect(),
        }
    }

    fn lc(mac: &str) -> String {
        mac.to_ascii_lowercase()
    }

    #[test]
    fn recurring_devices_filters_randomised_and_owned_kit() {
        let sweeps = [
            sweep("s1", 100, &[obs(HW1), obs(HW2)]),
            sweep("s2", 200, &[obs(HW1)]),
        ];
        let out = recurring_devices(&sweeps, 2);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mac, lc(HW1));
        assert_eq!(out[0].sweeps_seen, 2);
        assert_eq!(out[0].first_ts, 100);
        assert_eq!(out[0].last_ts, 200);

        let randomised = [sweep("s1", 100, &[obs(RND)]), sweep("s2", 200, &[obs(RND)])];
        let recurring = recurring_devices(&randomised, 2);
        assert!(recurring.is_empty(), "{recurring:?}");

        let owned = [
            sweep("s1", 100, &[bonded(HW1)]),
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
        let recurring = recurring_devices(&owned, 2);
        assert!(recurring.is_empty(), "{recurring:?}");
    }

    fn sighting(mac: &str, bonded: bool, ts: u64, cell: &str) -> FollowerSighting {
        FollowerSighting {
            mac: mac.to_string(),
            bonded,
            ts,
            cell: cell.to_string(),
        }
    }

    #[test]
    fn follower_detection_separates_a_tail_from_a_fixture() {
        // HW1 moves with the operator across three cells over an hour -> a tail.
        // HW2 is seen just as often but always in one cell -> a fixture, not a
        // follower. A randomized MAC across cells, and the operator's own bonded
        // kit, are both excluded.
        let sightings = [
            sighting(HW1, false, 0, "cellA"),
            sighting(HW1, false, 1800, "cellB"),
            sighting(HW1, false, 3600, "cellC"),
            sighting(HW2, false, 0, "cellA"),
            sighting(HW2, false, 1800, "cellA"),
            sighting(HW2, false, 3600, "cellA"),
            sighting(RND, false, 0, "cellA"),
            sighting(RND, false, 1800, "cellB"),
            sighting(RND, false, 3600, "cellC"),
            sighting("3C:5A:B4:77:88:99", true, 0, "cellA"),
            sighting("3C:5A:B4:77:88:99", true, 1800, "cellB"),
            sighting("3C:5A:B4:77:88:99", true, 3600, "cellC"),
        ];
        let out = follower_candidates(&sightings, 2, 60);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].mac, lc(HW1));
        assert_eq!(out[0].distinct_cells, 3);
        assert_eq!(out[0].span_secs, 3600);
    }

    #[test]
    fn follower_detection_needs_both_distance_and_duration() {
        // Across two cells but only seconds apart: a brief co-presence (same
        // crowd crossing a boundary), not a sustained tail.
        let brief = [
            sighting(HW1, false, 0, "cellA"),
            sighting(HW1, false, 10, "cellB"),
        ];
        assert!(follower_candidates(&brief, 2, 300).is_empty());

        // Long span but a single cell: stationary, not following.
        let stationary = [
            sighting(HW1, false, 0, "cellA"),
            sighting(HW1, false, 100_000, "cellA"),
        ];
        assert!(follower_candidates(&stationary, 2, 300).is_empty());

        // Both conditions met: flagged.
        let tail = [
            sighting(HW1, false, 0, "cellA"),
            sighting(HW1, false, 100_000, "cellB"),
        ];
        assert_eq!(follower_candidates(&tail, 2, 300).len(), 1);
    }

    #[test]
    fn coverage_reports_the_fraction_of_operator_locations_shared() {
        // The operator visited five cells (evidenced by their own bonded kit at
        // each). HW1 was with them at three of the five -> coverage 0.6.
        let own = "3C:5A:B4:77:88:99";
        let mut sightings = Vec::new();
        for (i, cell) in ["A", "B", "C", "D", "E"].iter().enumerate() {
            sightings.push(sighting(own, true, i as u64 * 1000, cell));
        }
        for (i, cell) in ["A", "B", "C"].iter().enumerate() {
            sightings.push(sighting(HW1, false, i as u64 * 1000, cell));
        }
        let out = follower_candidates(&sightings, 2, 60);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].distinct_cells, 3);
        assert!(
            (out[0].coverage - 0.6).abs() < 1e-9,
            "coverage={}",
            out[0].coverage
        );

        // With HW1 at all five, coverage is 1.0 — the strong-tail signal that an
        // absolute cell count alone could not distinguish from the 0.6 case.
        let mut everywhere = Vec::new();
        for (i, cell) in ["A", "B", "C", "D", "E"].iter().enumerate() {
            everywhere.push(sighting(own, true, i as u64 * 1000, cell));
            everywhere.push(sighting(HW1, false, i as u64 * 1000, cell));
        }
        let out = follower_candidates(&everywhere, 2, 60);
        assert_eq!(out.len(), 1);
        assert!(
            (out[0].coverage - 1.0).abs() < 1e-9,
            "coverage={}",
            out[0].coverage
        );
    }

    #[test]
    fn follower_detection_clamps_the_cell_floor_and_ignores_blank_input() {
        // Asking for <2 distinct cells is clamped to 2, so one location never
        // counts as following however the caller sets the threshold.
        let one_cell = [
            sighting(HW1, false, 0, "cellA"),
            sighting(HW1, false, 100_000, "cellA"),
        ];
        assert!(follower_candidates(&one_cell, 0, 0).is_empty());
        assert!(follower_candidates(&one_cell, 1, 0).is_empty());

        // Blank mac or blank cell contributes nothing.
        let blanks = [
            sighting("", false, 0, "cellA"),
            sighting(HW1, false, 0, "  "),
        ];
        assert!(follower_candidates(&blanks, 2, 0).is_empty());
    }

    #[test]
    fn live_radar_walks_presence_states() {
        let mut radar = BtRadarState::default();
        let d1 = radar.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
        assert_eq!(d1.new, vec![lc(HW1)]);
        assert_eq!(radar.presence_of(HW1), Some(Presence::New));

        let d2 = radar.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
        assert_eq!(d2.present, vec![lc(HW1)]);
        assert_eq!(radar.presence_of(HW1), Some(Presence::Present));

        let d3 = radar.apply_tick(&[], BtReadOutcome::Read);
        assert_eq!(d3.missing, vec![lc(HW1)]);
        assert_eq!(radar.presence_of(HW1), Some(Presence::Missing(1)));

        let d4 = radar.apply_tick(&[], BtReadOutcome::Read);
        assert_eq!(d4.departed, vec![lc(HW1)]);
        assert_eq!(radar.presence_of(HW1), None);
    }

    #[test]
    fn live_radar_recovers_on_reappearance_and_respects_not_read() {
        let mut radar = BtRadarState::default();
        radar.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
        radar.apply_tick(&[], BtReadOutcome::Read);
        assert_eq!(radar.presence_of(HW1), Some(Presence::Missing(1)));
        let back = radar.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
        assert_eq!(back.present, vec![lc(HW1)]);
        assert_eq!(radar.presence_of(HW1), Some(Presence::Present));

        let not_read = radar.apply_tick(&[], BtReadOutcome::NotRead);
        assert_eq!(not_read.read, BtReadOutcome::NotRead);
        assert!(
            not_read.new.is_empty() && not_read.missing.is_empty() && not_read.departed.is_empty()
        );
        assert_eq!(radar.presence_of(HW1), Some(Presence::Present));
    }

    #[test]
    fn live_radar_counts_randomised_and_bonded_without_tracking_them() {
        let mut radar = BtRadarState::default();
        let d1 = radar.apply_tick(&[obs(RND)], BtReadOutcome::Read);
        assert_eq!(d1.randomized_seen, 1);
        assert!(radar.is_empty(), "randomized MAC must not create a track");
        let d2 = radar.apply_tick(&[bonded(HW1)], BtReadOutcome::Read);
        assert_eq!(d2.bonded_seen, 1);
        assert!(radar.is_empty(), "bonded device must not create a track");
    }

    #[test]
    fn capacity_pressure_reports_evictions_and_ranked_tracks() {
        let mut radar = BtRadarState::with_capacity(1);
        let first = radar.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
        assert_eq!(first.new, vec![lc(HW1)]);
        let second = radar.apply_tick(&[obs(HW1), obs(HW2)], BtReadOutcome::Read);
        assert_eq!(second.evicted, vec![lc(HW1)]);
        assert!(second.departed.is_empty(), "{:?}", second.departed);

        let mut dense = BtRadarState::with_capacity(4);
        let macs: Vec<String> = (0..20u32)
            .map(|i| format!("3C:5A:B4:00:00:{i:02X}"))
            .collect();
        let sightings: Vec<SweepObservation> = macs.iter().map(|mac| obs(mac)).collect();
        let delta = dense.apply_tick(&sightings, BtReadOutcome::Read);
        assert!(!delta.evicted.is_empty(), "20 sightings into capacity 4");
        for mac in delta.new.iter().chain(delta.present.iter()) {
            assert!(dense.presence_of(mac).is_some());
            assert!(!delta.evicted.contains(mac));
        }
        assert_eq!(dense.len(), 4);

        let ranked = dense.tracks_ranked();
        assert!(!ranked.is_empty(), "a full radar ranks no tracks");
    }

    #[test]
    fn clean_names_and_vendor_metadata_are_preserved() {
        let mut radar = BtRadarState::default();
        radar.apply_tick(
            &[named(HW1, "Pixel Buds"), named(HW2, "<unknown>")],
            BtReadOutcome::Read,
        );
        let ranked = radar.tracks_ranked();
        let first = ranked.iter().find(|track| track.mac == lc(HW1)).unwrap();
        assert_eq!(first.name.as_deref(), Some("Pixel Buds"));
        assert!(first.vendor.is_some());
        assert!(first.device_class.is_some());
        let second = ranked.iter().find(|track| track.mac == lc(HW2)).unwrap();
        assert_eq!(second.name, None);
    }
}
