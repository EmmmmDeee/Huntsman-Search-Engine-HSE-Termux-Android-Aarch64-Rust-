//! Live Bluetooth radar — the pure per-device presence track model and the
//! per-tick reducer that turns a stream of one-shot sweeps into a continuously
//! updating "map" in discrete increments.
//!
//! This is the analysis nucleus of the live radar: given each sweep's observed
//! devices, it maintains a bounded map of persistent *tracks* and emits, per
//! tick, exactly what changed — which devices appeared, which are still present,
//! which just went missing, which departed. That per-tick [`TickDelta`] IS the
//! discrete increment the CLI repaints; the reducer owns the state machine, the
//! render layer only draws it.
//!
//! **Presence, not proximity.** No-root Termux exposes Bluetooth only through the
//! one-shot `termux-bluetooth-scaninfo` shim, whose parsed output today carries
//! no signal-strength field (see `modules::signal_radar::bluetooth::BtDevice`),
//! so this model deliberately has **no distance/RSSI axis** — a device is
//! *present* or *missing*, never "3 m away". If a real per-device RSSI field is
//! confirmed on-device later, it becomes an optional enrichment layer on
//! [`BtTrack`]; the model is correct and complete without it and never fabricates
//! a distance it cannot measure.
//!
//! **Defensive by construction** (mirrors [`crate::core::radar_track`], AU-122 /
//! AU-117):
//!   * Only **universally-administered** (real hardware) MACs earn a persistent
//!     track. A **randomized** (locally-administered) privacy address rotates
//!     ~every 15 min, so tracking one across ticks is meaningless — those are
//!     counted only as an anonymous [`TickDelta::randomized_seen`] aggregate
//!     ("N private/rotating addresses nearby this tick"), never a followable pin.
//!   * A **bonded** device is the operator's OWN paired kit. It earns no track
//!     either; it is surfaced as its own [`TickDelta::bonded_seen`] aggregate
//!     ("N of your own devices discoverable"), which is self-exposure
//!     information, never a foreign device to follow.
//!
//! **Read-vs-empty is a first-class distinction.** A tick where the Bluetooth
//! radio was never read ([`BtReadOutcome::NotRead`] — permission withheld,
//! Termux:API absent, tool error) is NOT evidence that nothing is nearby, so it
//! must never advance a present device toward "missing". Only a tick that
//! genuinely read the radio ([`BtReadOutcome::Read`]) and saw the device gone
//! ages its presence. This is the same two-state empty the existing radar loop
//! draws (`radar: no sensor readings` vs `radar: no new signals`), lifted into
//! pure logic so it is unit-tested without a radio.
//!
//! Pure and offline (its only dependency is the same [`crate::util::oui`]
//! U/L-bit classifier the rest of the radar stack uses), so it runs identically
//! on-device and in CI against synthetic sweep fixtures.

use std::collections::{HashMap, VecDeque};

use crate::core::radar_track::SweepObservation;
use crate::util::oui;

/// Consecutive *read* ticks a previously-present device may be unseen before it
/// is declared [`Presence::Departed`] (and dropped from the active map, so a
/// later re-sighting reads cleanly as new again). Two missed reads — not one —
/// so a single dropped BLE inquiry (common: advertising is bursty) does not
/// flap a stationary device out and back in.
const DEPART_AFTER_MISSED_READS: u32 = 2;

/// Maximum number of live tracks retained. Generous enough that a stationary
/// session never evicts, while bounding the memory a *moving* session accretes —
/// the same rationale as the CLI radar's cross-sweep seen-set. Oldest-observed
/// track is evicted first when full (a device left furthest behind is least
/// likely to recur; if it does, it re-tracks — bounded, correct rework).
const DEFAULT_TRACK_CAPACITY: usize = 4_096;

/// Where a tracked device stands as of the latest tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// First observed this tick.
    New,
    /// Observed this tick and previously — a continuing presence.
    Present,
    /// Not observed for the last `n` *read* ticks (`1..DEPART_AFTER_MISSED_READS`).
    /// Still tracked, decaying.
    Missing(u32),
    /// Unseen for [`DEPART_AFTER_MISSED_READS`] consecutive read ticks — gone.
    ///
    /// This is a **transition, not a resting state**: the track is reported once
    /// in [`TickDelta::departed`] and removed from the map in the same
    /// [`BtRadarState::apply_tick`] call, so it is deliberately NOT observable
    /// afterwards via [`BtRadarState::presence_of`] (which returns `None`) or
    /// [`BtRadarState::tracks_ranked`]. Consume a departure from the tick's
    /// delta; do not poll for it.
    Departed,
}

/// One persistent Bluetooth device the radar is tracking across ticks.
///
/// Only ever created for a **trackable** (universally-administered, non-bonded)
/// MAC — the defensive invariant enforced in [`BtRadarState::apply_tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtTrack {
    /// The device MAC, lowercased (the track key).
    pub mac: String,
    /// A human name if a sweep surfaced one (never the `<unknown>` placeholder).
    pub name: Option<String>,
    /// OUI vendor, when the address classifies to registered hardware.
    pub vendor: Option<String>,
    /// OUI device class, when known.
    pub device_class: Option<String>,
    /// Tick index this device was first observed.
    pub first_seen_tick: u64,
    /// Tick index this device was most recently observed.
    pub last_seen_tick: u64,
    /// Distinct ticks this device has been observed in.
    pub sweeps_seen: u32,
    /// Current presence state as of the latest tick.
    pub presence: Presence,
    /// Consecutive *read* ticks the device has been unseen (0 while present).
    missed_reads: u32,
}

/// Whether a tick actually read the Bluetooth radio. A `NotRead` tick leaves
/// every track untouched — absence of data is not absence of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtReadOutcome {
    /// The radio was read this tick (possibly seeing zero devices).
    Read,
    /// The radio was NOT read (permission withheld, tool absent/errored).
    NotRead,
}

/// What changed this tick — the discrete increment the map repaints from.
///
/// The lists carry lowercased MACs. `new` / `missing` / `departed` are the
/// *transitions* this tick; `present` is every device still in view (for the
/// live map body); `randomized_seen` is the anonymous count of rotating privacy
/// addresses observed this tick, which are never tracked individually.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickDelta {
    /// Whether the radio was read this tick. When `NotRead`, all transition
    /// lists are empty and `randomized_seen` is 0 — nothing was observed.
    pub read: BtReadOutcome,
    /// Trackable devices seen for the first time this tick.
    pub new: Vec<String>,
    /// Trackable devices seen this tick that were already tracked.
    pub present: Vec<String>,
    /// Trackable devices that transitioned to `Missing` this tick (a read tick
    /// in which a previously-seen device was not observed).
    pub missing: Vec<String>,
    /// Trackable devices that departed this tick (crossed the missed-read
    /// threshold) — reported once, then dropped from the active map.
    pub departed: Vec<String>,
    /// Devices dropped this tick because the track map hit its capacity
    /// ceiling, NOT because they left. Reported separately so a saturated map
    /// is visible rather than silent: a device here is no longer in the state,
    /// and is guaranteed absent from [`Self::new`] and [`Self::present`] for the
    /// same tick, so a render layer never paints a device the state does not
    /// contain.
    pub evicted: Vec<String>,
    /// Count of randomized / rotating privacy addresses observed this tick.
    /// Aggregate only — never attributed to an individual track.
    pub randomized_seen: usize,
    /// Count of the operator's OWN bonded (paired) devices observed this tick —
    /// their car, earbuds, watch. Surfaced as an aggregate for self-exposure
    /// awareness (AU-117: what of *yours* is discoverable), never tracked as a
    /// foreign device to follow.
    pub bonded_seen: usize,
}

impl TickDelta {
    /// The empty delta for a tick that never read the radio.
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

/// The live radar's evolving view: a bounded map of trackable devices plus the
/// tick clock. Fed one [`apply_tick`](Self::apply_tick) per sensor sweep.
pub struct BtRadarState {
    tracks: HashMap<String, BtTrack>,
    /// Insertion order of track keys, for oldest-first eviction at capacity.
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
    /// A radar state retaining at most `capacity` live tracks.
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

    /// Number of live tracks currently held (never exceeds `capacity`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.tracks.len()
    }

    /// True when no device is currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tracks.is_empty()
    }

    /// The current presence of a device, or `None` if it is not (or no longer)
    /// tracked. Keyed case-insensitively on MAC.
    #[must_use]
    pub fn presence_of(&self, mac: &str) -> Option<Presence> {
        self.tracks
            .get(&mac.trim().to_lowercase())
            .map(|t| t.presence)
    }

    /// True for a MAC that earns a persistent track: a real, universally-
    /// administered hardware address (not a randomized privacy address) that the
    /// operator is not bonded to. The same predicate `radar_track` uses.
    fn is_trackable(mac: &str, bonded: bool) -> bool {
        // Bonded ⇒ the operator's own kit, never a foreign device to follow.
        // Locally-administered (or unclassifiable) ⇒ a rotating privacy address,
        // meaningless to track across ticks.
        !bonded && oui::is_locally_administered(mac) == Some(false)
    }

    /// Advance the radar by one sweep and return what changed.
    ///
    /// A [`BtReadOutcome::NotRead`] tick is a no-op that leaves every track
    /// exactly as it was (and does not advance the tick clock's presence
    /// ageing) — it reports [`TickDelta::not_read`]. A [`BtReadOutcome::Read`]
    /// tick folds `sightings` into the track map: trackable devices seen become
    /// `New` (first time) or `Present`; trackable devices *not* seen this read
    /// age one step toward `Missing`/`Departed`; randomized addresses are counted
    /// but never tracked.
    pub fn apply_tick(&mut self, sightings: &[SweepObservation], read: BtReadOutcome) -> TickDelta {
        if read == BtReadOutcome::NotRead {
            // Absence of a reading is not absence of devices: change nothing.
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

        // Which trackable devices we saw this read, so the ageing pass below can
        // tell "seen" from "unseen" in one lookup.
        let mut seen_this_tick: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for dev in sightings {
            let mac = dev.mac.trim().to_lowercase();
            if mac.is_empty() {
                continue;
            }
            if !Self::is_trackable(&mac, dev.bonded) {
                // Neither earns a persistent track, but each is surfaced as its
                // own anonymous aggregate rather than silently dropped: bonded
                // devices are the operator's own kit (self-exposure awareness),
                // randomized addresses are rotating throwaways. Bonded is
                // checked first so an operator's own device with a randomized
                // address counts once, as theirs.
                if dev.bonded {
                    delta.bonded_seen += 1;
                } else {
                    delta.randomized_seen += 1;
                }
                continue;
            }

            seen_this_tick.insert(mac.clone());
            let name = clean_name(dev.name.as_deref());

            // `contains_key` first so the `get_mut` borrow does not span into the
            // else-branch's `insert_track` (NLL Problem Case #3 — still not
            // borrow-checkable on stable Rust as a get_mut/else-insert match).
            if self.tracks.contains_key(&mac) {
                let track = self
                    .tracks
                    .get_mut(&mac)
                    .expect("contains_key just confirmed the entry");
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

        // Age every track we did NOT see this read. A device crossing the
        // threshold departs and is removed (reported once in `departed`).
        let mut to_remove: Vec<String> = Vec::new();
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
            self.order.retain(|k| k != &mac);
        }

        // Reconcile the delta with the post-tick state. A device evicted under
        // capacity pressure is NOT in the map any more, so it must not also be
        // reported as new/present — a render layer trusting the delta would
        // otherwise paint a device `BtRadarState` does not contain. (A dense
        // single-tick overflow is exactly where this bites: the early entries of
        // one huge sighting list are evicted by the later ones.)
        if !delta.evicted.is_empty() {
            let evicted: std::collections::HashSet<&String> = delta.evicted.iter().collect();
            delta.new.retain(|m| !evicted.contains(m));
            delta.present.retain(|m| !evicted.contains(m));
            delta.missing.retain(|m| !evicted.contains(m));
        }

        delta.new.sort();
        delta.present.sort();
        delta.missing.sort();
        delta.departed.sort();
        delta.evicted.sort();
        delta
    }

    /// Insert a new track, evicting the oldest-observed one first if at
    /// capacity. Returns the evicted MAC, so the caller can report the drop
    /// rather than losing a device silently.
    fn insert_track(&mut self, track: BtTrack) -> Option<String> {
        let mut evicted = None;
        if self.tracks.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.tracks.remove(&oldest);
            evicted = Some(oldest);
        }
        self.order.push_back(track.mac.clone());
        self.tracks.insert(track.mac.clone(), track);
        evicted
    }

    /// Every live track, ranked for the map: most-persistent first (by
    /// `sweeps_seen`), then most-recently-seen, then MAC — the same deterministic
    /// order `radar_track::recurring_devices` uses.
    #[must_use]
    pub fn tracks_ranked(&self) -> Vec<&BtTrack> {
        let mut out: Vec<&BtTrack> = self.tracks.values().collect();
        out.sort_by(|a, b| {
            b.sweeps_seen
                .cmp(&a.sweeps_seen)
                .then(b.last_seen_tick.cmp(&a.last_seen_tick))
                .then(a.mac.cmp(&b.mac))
        });
        out
    }
}

/// A sweep-surfaced device name, trimmed, with the `<unknown>` placeholder and
/// blanks dropped — mirroring `radar_track`'s name filter.
fn clean_name(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|n| !n.is_empty() && *n != "<unknown>")
        .map(str::to_string)
}

/// OUI vendor + device class for a real hardware MAC, or `(None, None)` for an
/// unregistered / unknown / randomized address — the same partition
/// `radar_track` applies.
fn classify(mac: &str) -> (Option<String>, Option<String>) {
    match oui::classify_mac(mac) {
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
    }
}

#[cfg(test)]
mod tests;
