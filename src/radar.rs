//! Cross-sweep and live-radar tracking rebuilt from `core::radar_track` and
//! `core::radar_live`.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::oui;
use crate::fsio::read_bounded;

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
            // Evict the least-recently-seen track, not the oldest-inserted. A
            // device present since the first tick is the one worth keeping under
            // pressure; dropping it for an idle newcomer would discard the very
            // persistence a radar exists to surface. Ties break on the lower
            // mac so eviction is deterministic.
            if let Some(victim) = self
                .tracks
                .values()
                .min_by(|a, b| {
                    a.last_seen_tick
                        .cmp(&b.last_seen_tick)
                        .then(a.mac.cmp(&b.mac))
                })
                .map(|track| track.mac.clone())
            {
                self.tracks.remove(&victim);
                evicted = Some(victim);
            }
        }
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

/// The most sweeps the track log keeps; an older sweep is dropped as a new one is added.
pub const MAX_TRACK_SWEEPS: usize = 256;
/// The most devices one logged sweep keeps, in the order the sweep listed them.
pub const MAX_TRACK_DEVICES: usize = 128;
/// The largest track log read or written.
pub const MAX_TRACK_LOG_BYTES: u64 = 4 * 1024 * 1024;
/// A follower must be seen in at least this many distinct cells: two places can be one commute.
pub const FOLLOWER_MIN_CELLS: usize = 3;
/// And over at least this long, so one crowded moment is not a tail.
pub const FOLLOWER_MIN_SPAN_SECS: u64 = 600;

/// One Wi-Fi sweep as the track log keeps it: when it was taken, the coarse place it was taken
/// at (the registered serving cell, when the phone had one), and the stable devices it saw.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoggedSweep {
    pub ts: u64,
    #[serde(default)]
    pub cell: Option<String>,
    pub devices: Vec<LoggedDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoggedDevice {
    pub mac: String,
    #[serde(default)]
    pub name: Option<String>,
}

impl LoggedSweep {
    /// A sweep of `devices` at `ts` in `cell`. Randomized and locally administered addresses are
    /// not kept: they cannot be told apart across sweeps, so keeping them would only record what
    /// the phone happened to hear. Duplicates are kept once, and at most [`MAX_TRACK_DEVICES`].
    #[must_use]
    pub fn new(
        ts: u64,
        cell: Option<String>,
        devices: impl IntoIterator<Item = LoggedDevice>,
    ) -> Self {
        let mut seen = HashSet::new();
        let devices = devices
            .into_iter()
            .filter_map(|device| {
                let mac = device.mac.trim().to_ascii_lowercase();
                (stable_identity(&mac, false) && seen.insert(mac.clone())).then(|| LoggedDevice {
                    mac,
                    name: device.name.filter(|name| !name.trim().is_empty()),
                })
            })
            .take(MAX_TRACK_DEVICES)
            .collect();
        Self {
            ts,
            cell: cell.filter(|cell| !cell.trim().is_empty()),
            devices,
        }
    }
}

/// The sweeps of a track log, one JSON object per line, oldest first. A line that does not parse
/// is skipped and counted, so one damaged line does not lose the rest of the history. **Pure.**
#[must_use]
pub fn parse_track_log(bytes: &[u8]) -> (Vec<LoggedSweep>, usize) {
    let mut skipped = 0;
    let sweeps = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .filter_map(|line| {
            let parsed = serde_json::from_slice::<LoggedSweep>(line).ok();
            skipped += usize::from(parsed.is_none());
            parsed
        })
        .collect();
    (sweeps, skipped)
}

/// Encode a bounded log and return exactly the sweeps retained on disk.
/// The first reverse-ordered entry is the newly supplied sweep. Preserve
/// `append_track_log`'s historical cap/selection semantics, but expose whether
/// the new row survived so `record_sweep` can reject a silent dropped write.
fn encode_retained_track_log(
    mut sweeps: Vec<LoggedSweep>,
    sweep: LoggedSweep,
) -> (Vec<u8>, Vec<LoggedSweep>, bool) {
    sweeps.push(sweep);
    let mut lines: Vec<(usize, LoggedSweep, Vec<u8>)> = sweeps
        .into_iter()
        .rev()
        .take(MAX_TRACK_SWEEPS)
        .enumerate()
        .filter_map(|(index, sweep)| {
            serde_json::to_vec(&sweep)
                .ok()
                .map(|line| (index, sweep, line))
        })
        .collect();
    let limit = usize::try_from(MAX_TRACK_LOG_BYTES).unwrap_or(usize::MAX);
    let mut total = 0usize;
    lines.retain(|(_, _, line)| {
        let bytes = line.len().saturating_add(1);
        if bytes > limit.saturating_sub(total) {
            return false;
        }
        total += bytes;
        true
    });
    let newest_retained = lines.first().is_some_and(|(index, _, _)| *index == 0);
    lines.reverse();
    let mut body = Vec::with_capacity(total);
    let mut retained = Vec::with_capacity(lines.len());
    for (_, sweep, line) in lines {
        body.extend_from_slice(&line);
        body.push(b'\n');
        retained.push(sweep);
    }
    (body, retained, newest_retained)
}

/// `sweeps` with `sweep` added, as the log's bytes: the newest [`MAX_TRACK_SWEEPS`] that fit in
/// [`MAX_TRACK_LOG_BYTES`], oldest first. **Pure.**
#[must_use]
pub fn append_track_log(sweeps: Vec<LoggedSweep>, sweep: LoggedSweep) -> Vec<u8> {
    encode_retained_track_log(sweeps, sweep).0
}

/// What the track log shows: devices that recur across sweeps, and devices seen in several of the
/// operator's distinct places, a personal-safety signal that something moved with the operator.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TrackReport {
    pub sweeps: usize,
    pub located_sweeps: usize,
    pub distinct_cells: usize,
    pub skipped_lines: usize,
    pub recurring: Vec<RecurringDevice>,
    pub followers: Vec<FollowerCandidate>,
}

/// The recurring devices and follower candidates of the logged `sweeps`. A sweep without a cell
/// counts towards recurrence but not towards following, which needs to know where it was taken.
/// **Pure.**
#[must_use]
pub fn track(sweeps: &[LoggedSweep], skipped_lines: usize) -> TrackReport {
    let as_sweeps: Vec<Sweep> = sweeps
        .iter()
        .enumerate()
        .map(|(index, sweep)| Sweep {
            scan_id: index.to_string(),
            ts: sweep.ts,
            devices: sweep
                .devices
                .iter()
                .map(|device| SweepObservation {
                    mac: device.mac.clone(),
                    name: device.name.clone(),
                    bonded: false,
                })
                .collect(),
        })
        .collect();
    let sightings: Vec<FollowerSighting> = sweeps
        .iter()
        .filter_map(|sweep| sweep.cell.as_ref().map(|cell| (sweep, cell)))
        .flat_map(|(sweep, cell)| {
            // A sighting with no address marks the place as one the operator was, so a place
            // where nothing stable was heard still counts against every device's coverage.
            let place = FollowerSighting {
                mac: String::new(),
                bonded: false,
                ts: sweep.ts,
                cell: cell.clone(),
            };
            std::iter::once(place).chain(sweep.devices.iter().map(|device| FollowerSighting {
                mac: device.mac.clone(),
                bonded: false,
                ts: sweep.ts,
                cell: cell.clone(),
            }))
        })
        .collect();
    let cells: HashSet<&str> = sweeps
        .iter()
        .filter_map(|sweep| sweep.cell.as_deref())
        .collect();
    TrackReport {
        sweeps: sweeps.len(),
        located_sweeps: sweeps.iter().filter(|sweep| sweep.cell.is_some()).count(),
        distinct_cells: cells.len(),
        skipped_lines,
        recurring: recurring_devices(&as_sweeps, 2),
        followers: follower_candidates(&sightings, FOLLOWER_MIN_CELLS, FOLLOWER_MIN_SPAN_SECS),
    }
}

/// Why a sweep could not be added to the track log. Nothing was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackLogError {
    /// The log exists but could not be read whole.
    Unreadable(String),
    /// The log's place could not be examined.
    Missing(String),
    /// The log, or the private directory for it, could not be written.
    Unwritable(String),
}

impl std::fmt::Display for TrackLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(why) | Self::Missing(why) | Self::Unwritable(why) => f.write_str(why),
        }
    }
}

/// One cooperative cross-process lock for the complete read–modify–write cycle.
/// A private adjacent file is created exclusively, so CLI and loopback Web UI
/// writers cannot silently overwrite each other's sweeps. A crash can strand
/// this file; fail closed rather than deleting a lock that might still be held.
struct TrackWriteGuard {
    path: std::path::PathBuf,
    inode: std::fs::Metadata,
}

impl TrackWriteGuard {
    fn acquire(log: &Path) -> Result<Self, TrackLogError> {
        let mut name = log.as_os_str().to_os_string();
        name.push(".lock");
        let path = std::path::PathBuf::from(name);
        let began = std::time::Instant::now();
        loop {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    let inode = file.metadata().map_err(|error| {
                        let _ = std::fs::remove_file(&path);
                        TrackLogError::Unwritable(format!("{}: {error}", path.display()))
                    })?;
                    if let Err(error) = std::io::Write::write_all(
                        &mut file,
                        std::process::id().to_string().as_bytes(),
                    ) {
                        let _ = std::fs::remove_file(&path);
                        return Err(TrackLogError::Unwritable(format!(
                            "{}: {error}",
                            path.display()
                        )));
                    }
                    return Ok(Self { path, inode });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if began.elapsed() >= std::time::Duration::from_secs(1) {
                        return Err(TrackLogError::Unwritable(format!(
                            "tracking log is busy or has a stale lock at {}; no sweep was written; remove the lock only after verifying no Huntsman writer is running",
                            path.display()
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => {
                    return Err(TrackLogError::Unwritable(format!(
                        "{}: {error}",
                        path.display()
                    )));
                }
            }
        }
    }
}

impl Drop for TrackWriteGuard {
    fn drop(&mut self) {
        // An externally replaced lock must not be removed by its old holder.
        if std::fs::symlink_metadata(&self.path).is_ok_and(|current| {
            current.is_file() && crate::fsio::same_inode(&self.inode, &current)
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Add `sweep` to the track log at `log` and report what the log then shows. The log is written
/// private to the user, in a directory created private when missing, keeps the newest
/// [`MAX_TRACK_SWEEPS`] sweeps within [`MAX_TRACK_LOG_BYTES`], and a line of it that does not
/// parse is skipped and counted. `radar track` and the web UI's `/api/radar/track` both record
/// through here, so one log holds every sweep however it was taken.
///
/// # Errors
/// [`TrackLogError`] when the log cannot be read or written.
pub fn record_sweep(log: &Path, sweep: LoggedSweep) -> Result<TrackReport, TrackLogError> {
    // Keep the directory creation and the lock within the same entry point so
    // all native CLI and browser handlers follow the same transaction boundary.
    private_parent(log).map_err(TrackLogError::Unwritable)?;
    let _guard = TrackWriteGuard::acquire(log)?;
    let existing = match std::fs::symlink_metadata(log) {
        Ok(_) => read_bounded(log, MAX_TRACK_LOG_BYTES)
            .map_err(|error| TrackLogError::Unreadable(error.to_string()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            return Err(TrackLogError::Missing(format!(
                "{}: {error}",
                log.display()
            )));
        }
    };
    let (sweeps, skipped) = parse_track_log(&existing);
    let (bytes, retained, newest_retained) = encode_retained_track_log(sweeps, sweep);
    if !newest_retained {
        return Err(TrackLogError::Unwritable(format!(
            "new radar sweep cannot fit within the {MAX_TRACK_LOG_BYTES}-byte tracking log; existing data was preserved"
        )));
    }
    crate::fsio::write_atomic_private(log, &bytes, MAX_TRACK_LOG_BYTES)
        .map_err(|error| TrackLogError::Unwritable(error.to_string()))?;
    // Both CLI and Web UI must describe what is actually retained, not
    // pre-truncation in-memory history. Avoid cloning the entire sweep list.
    Ok(track(&retained, skipped))
}

/// Validate the final parent path before creating the lock file. The
/// atomic writer rejects a symlinked parent too, but the lock exists earlier:
/// do not create even a temporary lock through a parent-directory symlink.
/// A pre-existing directory retains its existing permissions.
fn private_parent(log: &Path) -> Result<(), String> {
    let Some(parent) = log.parent().filter(|parent| !parent.as_os_str().is_empty()) else {
        return Ok(());
    };
    match std::fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!(
                "{}: symbolic-link parent refused",
                parent.display()
            ));
        }
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => return Err(format!("{}: parent is not a directory", parent.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", parent.display())),
    }
    // Set private permissions when directories are CREATED. A later
    // path-based chmod could instead modify an attacker-replaced symlink
    // target; DirBuilder also keeps pre-existing parent modes unchanged.
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(parent)
        .map_err(|error| format!("{}: {error}", parent.display()))?;
    // Detect a visible replacement before a lock is created. This is not
    // atomic protection against a malicious process racing path lookups.
    let meta = std::fs::symlink_metadata(parent)
        .map_err(|error| format!("{}: {error}", parent.display()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(format!("{}: not a regular directory", parent.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    fn device(mac: &str, name: &str) -> LoggedDevice {
        LoggedDevice {
            mac: mac.into(),
            name: Some(name.into()),
        }
    }

    /// A phone hotspot carried by someone else, a home access point and a randomized address.
    const TAIL: &str = "00:11:22:33:44:55";
    const HOME: &str = "00:aa:bb:cc:dd:ee";
    const RANDOM: &str = "da:a1:19:00:00:01";

    #[test]
    fn a_logged_sweep_keeps_stable_addresses_once_and_drops_randomized_ones() {
        let sweep = LoggedSweep::new(
            5,
            Some(" ".into()),
            [
                device(&TAIL.to_ascii_uppercase(), "car"),
                device(TAIL, "car again"),
                device(RANDOM, "phone"),
                device(HOME, ""),
            ],
        );
        assert_eq!(sweep.cell, None);
        assert_eq!(
            sweep.devices,
            [
                device(TAIL, "car"),
                LoggedDevice {
                    mac: HOME.into(),
                    name: None
                }
            ]
        );
        let many = (0..=MAX_TRACK_DEVICES)
            .map(|n| device(&format!("00:00:00:00:{:02x}:{:02x}", n / 256, n % 256), "x"));
        assert_eq!(
            LoggedSweep::new(1, None, many).devices.len(),
            MAX_TRACK_DEVICES
        );
    }

    /// A device heard in three of the operator's places over twenty minutes is a follower; the
    /// home access point heard twice at home only recurs; a sweep without a cell counts towards
    /// recurrence, never towards following.
    #[test]
    fn the_track_log_separates_a_follower_from_a_fixture() {
        let sweeps = [
            LoggedSweep::new(
                0,
                Some("lte:505-01-1-10".into()),
                [device(TAIL, "car"), device(HOME, "home")],
            ),
            LoggedSweep::new(300, Some("lte:505-01-1-20".into()), [device(TAIL, "car")]),
            LoggedSweep::new(900, Some("lte:505-01-2-30".into()), [device(TAIL, "car")]),
            LoggedSweep::new(
                1_200,
                Some("lte:505-01-1-10".into()),
                [device(HOME, "home")],
            ),
            LoggedSweep::new(1_500, None, [device(HOME, "home"), device(RANDOM, "phone")]),
            // A place where nothing stable was heard is still a place the operator was.
            LoggedSweep::new(1_800, Some("lte:505-01-3-40".into()), []),
        ];
        let report = track(&sweeps, 1);
        assert_eq!(
            (
                report.sweeps,
                report.located_sweeps,
                report.distinct_cells,
                report.skipped_lines
            ),
            (6, 5, 4, 1)
        );
        assert_eq!(report.followers.len(), 1, "{report:?}");
        let follower = &report.followers[0];
        assert_eq!(
            (
                follower.mac.as_str(),
                follower.distinct_cells,
                follower.span_secs
            ),
            (TAIL, 3, 900)
        );
        assert!(
            (follower.coverage - 0.75).abs() < 1e-9,
            "{}",
            follower.coverage
        );
        let recurring: Vec<(&str, usize)> = report
            .recurring
            .iter()
            .map(|device| (device.mac.as_str(), device.sweeps_seen))
            .collect();
        assert!(
            recurring.contains(&(HOME, 3)) && recurring.contains(&(TAIL, 3)),
            "{recurring:?}"
        );
        assert!(report.recurring.iter().all(|device| device.mac != RANDOM));

        // Two places, or three within a few minutes, are not a tail.
        assert!(track(&sweeps[..2], 0).followers.is_empty());
        let quick: Vec<LoggedSweep> = sweeps[..3]
            .iter()
            .cloned()
            .map(|mut sweep| {
                sweep.ts /= 10;
                sweep
            })
            .collect();
        assert!(track(&quick, 0).followers.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn new_nested_tracking_directories_are_private_without_chmod_race() {
        use std::os::unix::fs::PermissionsExt;

        let directory =
            std::env::temp_dir().join(format!("huntsman-track-private-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let nested = directory.join("level-one").join("level-two");
        let log = nested.join("sweeps.jsonl");
        assert_eq!(
            record_sweep(
                &log,
                LoggedSweep::new(1, Some("cell:coarse".into()), [device(TAIL, "test")])
            )
            .unwrap()
            .sweeps,
            1
        );
        for parent in [directory.join("level-one"), nested] {
            let mode = std::fs::metadata(parent).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "new tracking directory was not private");
        }
        assert!(!log.with_extension("jsonl.lock").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_tracking_directory_permissions_remain_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!(
            "huntsman-track-existing-mode-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let parent = directory.join("existing");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o750)).unwrap();
        let log = parent.join("sweeps.jsonl");
        assert_eq!(
            record_sweep(
                &log,
                LoggedSweep::new(1, Some("cell:coarse".into()), [device(TAIL, "test")])
            )
            .unwrap()
            .sweeps,
            1
        );
        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_is_refused_before_any_lock_or_data_write() {
        use std::os::unix::fs::symlink;

        let directory = std::env::temp_dir().join(format!(
            "huntsman-track-linked-parent-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let actual = directory.join("actual");
        std::fs::create_dir_all(&actual).unwrap();
        let alias = directory.join("alias");
        symlink(&actual, &alias).unwrap();

        let log = alias.join("radar.jsonl");
        let result = record_sweep(
            &log,
            LoggedSweep::new(7, Some("cell:coarse".into()), [device(TAIL, "sample")]),
        );
        assert!(matches!(result, Err(TrackLogError::Unwritable(_))));
        assert!(!actual.join("radar.jsonl.lock").exists());
        assert!(!actual.join("radar.jsonl").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn existing_non_directory_parent_is_refused_without_creating_lock() {
        let directory =
            std::env::temp_dir().join(format!("huntsman-track-file-parent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let parent = directory.join("not-a-directory");
        std::fs::write(&parent, b"protected").unwrap();

        let log = parent.join("radar.jsonl");
        let result = record_sweep(
            &log,
            LoggedSweep::new(8, Some("cell:coarse".into()), [device(TAIL, "sample")]),
        );
        assert!(matches!(result, Err(TrackLogError::Unwritable(_))));
        assert_eq!(std::fs::read(&parent).unwrap(), b"protected");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_writers_preserve_every_sweep_and_report_latest_storage() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-track-concurrent-writes-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let log = directory.join("radar.jsonl");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..12u64)
                .map(|ts| {
                    let barrier = std::sync::Arc::clone(&barrier);
                    let log = log.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        record_sweep(
                            &log,
                            LoggedSweep::new(
                                ts,
                                Some("lte:505-01-1-10".into()),
                                [device(TAIL, "test")],
                            ),
                        )
                    })
                })
                .collect();
            for handle in handles {
                assert!(handle.join().unwrap().is_ok());
            }
        });
        let bytes = std::fs::read(&log).unwrap();
        let (sweeps, rejected) = parse_track_log(&bytes);
        assert_eq!(rejected, 0);
        assert_eq!(sweeps.len(), 12);
        let times: std::collections::HashSet<u64> = sweeps.iter().map(|sweep| sweep.ts).collect();
        assert_eq!(times.len(), 12);
        assert!(!directory.join("radar.jsonl.lock").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn existing_lock_refuses_writes_without_touching_original_history() {
        let directory =
            std::env::temp_dir().join(format!("huntsman-track-locked-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let log = directory.join("radar.jsonl");
        let old = append_track_log(
            Vec::new(),
            LoggedSweep::new(1, Some("cell:old".into()), [device(HOME, "existing")]),
        );
        std::fs::write(&log, &old).unwrap();
        let lock = directory.join("radar.jsonl.lock");
        std::fs::write(&lock, b"occupied").unwrap();
        assert!(matches!(
            record_sweep(
                &log,
                LoggedSweep::new(2, Some("cell:new".into()), [device(TAIL, "new")])
            ),
            Err(TrackLogError::Unwritable(_))
        ));
        assert_eq!(std::fs::read(&log).unwrap(), old);
        assert_eq!(std::fs::read(&lock).unwrap(), b"occupied");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reported_track_history_matches_the_bounded_persisted_log() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-track-report-capacity-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let log = directory.join("radar.jsonl");
        let older = LoggedSweep::new(
            10,
            Some("cell:old".into()),
            [device(TAIL, &"a".repeat(2_500_000))],
        );
        let newer = LoggedSweep::new(
            900,
            Some("cell:new".into()),
            [device(TAIL, &"b".repeat(2_500_000))],
        );
        assert_eq!(record_sweep(&log, older).unwrap().sweeps, 1);
        let report = record_sweep(&log, newer).unwrap();
        let bytes = std::fs::read(&log).unwrap();
        assert!(u64::try_from(bytes.len()).unwrap() <= MAX_TRACK_LOG_BYTES);
        let (retained, skipped) = parse_track_log(&bytes);
        assert_eq!(skipped, 0);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].ts, 900);
        assert_eq!(report, track(&retained, skipped));
        assert!(report.recurring.is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oversized_incoming_sweep_is_rejected_without_modifying_the_log() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-track-oversized-new-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let log = directory.join("radar.jsonl");
        record_sweep(
            &log,
            LoggedSweep::new(1, Some("cell:old".into()), [device(TAIL, "old")]),
        )
        .unwrap();
        let before = std::fs::read(&log).unwrap();
        let oversized = LoggedSweep::new(
            2,
            Some("cell:new".into()),
            [device(
                HOME,
                &"z".repeat(usize::try_from(MAX_TRACK_LOG_BYTES).unwrap()),
            )],
        );
        assert!(matches!(
            record_sweep(&log, oversized),
            Err(TrackLogError::Unwritable(_))
        ));
        assert_eq!(std::fs::read(&log).unwrap(), before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_track_log_keeps_its_newest_sweeps_and_survives_a_damaged_line() {
        let mut bytes = Vec::new();
        for ts in 0..(MAX_TRACK_SWEEPS as u64 + 5) {
            let (sweeps, skipped) = parse_track_log(&bytes);
            assert_eq!(skipped, 0);
            bytes = append_track_log(
                sweeps,
                LoggedSweep::new(ts, Some("c".into()), [device(HOME, "home")]),
            );
        }
        let (sweeps, _) = parse_track_log(&bytes);
        assert_eq!(sweeps.len(), MAX_TRACK_SWEEPS);
        assert_eq!(sweeps[0].ts, 5);
        assert_eq!(
            sweeps.last().map(|sweep| sweep.ts),
            Some(MAX_TRACK_SWEEPS as u64 + 4)
        );

        let damaged =
            b"{\"ts\":1,\"devices\":[]}\nnot json\n\n{\"ts\":2,\"cell\":\"c\",\"devices\":[]}\n";
        let (sweeps, skipped) = parse_track_log(damaged);
        assert_eq!((sweeps.len(), skipped), (2, 1));
    }

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
    fn eviction_drops_the_least_recently_seen_not_the_oldest_inserted() {
        // HW1 and HW2 arrive first; next tick HW1 is seen again (so it is the
        // more recent, persistent device) while a new HW3 forces an eviction at
        // capacity 2. The idle HW2 must go, not the active HW1 — the opposite of
        // an insertion-order queue, which would have evicted HW1.
        let hw3 = "3C:5A:B4:AA:BB:CC";
        let mut radar = BtRadarState::with_capacity(2);
        radar.apply_tick(&[obs(HW1), obs(HW2)], BtReadOutcome::Read);
        let delta = radar.apply_tick(&[obs(HW1), obs(hw3)], BtReadOutcome::Read);
        assert_eq!(
            delta.evicted,
            vec![lc(HW2)],
            "the idle track must be evicted"
        );
        assert_eq!(
            radar.presence_of(HW1),
            Some(Presence::Present),
            "the active track survives"
        );
        assert_eq!(radar.presence_of(hw3), Some(Presence::New));
        assert_eq!(radar.presence_of(HW2), None);
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
