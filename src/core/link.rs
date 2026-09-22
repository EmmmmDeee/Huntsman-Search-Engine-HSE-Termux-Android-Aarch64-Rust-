//! The Wi-Fi link the device itself is on, one record per sweep — and what the
//! sweep history says about how that link is being disrupted (T6,
//! REQ-RESILIENCE-002).
//!
//! `device_sensors` has read `termux-wifi-connectioninfo` on every radar sweep
//! since the radar existed and flattened the answer into a `MacAddress` entity
//! tagged `wifi-connected`, with the level and the supplicant state in
//! evidence strings — the same dissolution [`crate::core::rf`] describes for
//! readings. A *disconnection* was not recorded at all: an empty answer was
//! "nothing to report". For the questions the resilience directive asks —
//! *was I thrown off the network while the access point was still right
//! there? is it happening on a schedule? is something impersonating my
//! network?* — the absence is the observation. This module keeps the typed
//! record ([`LinkState`]) and reads the history ([`review`]).
//!
//! Pure: no I/O, no storage, no clock. Sweeps arrive with their own times.

use serde::{Deserialize, Serialize};

/// The device's own Wi-Fi link as one sweep saw it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkState {
    /// Associated with an access point. False is a fact, not an absence: it
    /// is what a forced disconnection looks like from the phone.
    pub connected: bool,
    pub ssid: Option<String>,
    /// The access point's address, canonical lower-case.
    pub bssid: Option<String>,
    pub signal_dbm: Option<f64>,
    pub ip: Option<String>,
    pub link_speed_mbps: Option<i64>,
    /// The supplicant's own word for the state (`COMPLETED`, `DISCONNECTED`,
    /// `SCANNING`, …), verbatim.
    pub supplicant_state: Option<String>,
    /// When the sweep read it, Unix seconds.
    pub observed_epoch: Option<i64>,
}

impl LinkState {
    /// Off the network, nothing else known.
    #[must_use]
    pub fn disconnected(observed_epoch: Option<i64>) -> Self {
        Self {
            connected: false,
            ssid: None,
            bssid: None,
            signal_dbm: None,
            ip: None,
            link_speed_mbps: None,
            supplicant_state: None,
            observed_epoch,
        }
    }
}

/// Supplicant states that mean "not associated", whatever else the tool
/// reports (a stale BSSID beside `DISCONNECTED` is the last network, not the
/// current one).
pub const NOT_ASSOCIATED: &[&str] = &[
    "DISCONNECTED",
    "INACTIVE",
    "INTERFACE_DISABLED",
    "SCANNING",
    "DISCONNECTING",
];

/// An access point one sweep heard, as the review needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct HeardAp {
    pub bssid: String,
    pub ssid: Option<String>,
    pub signal_dbm: Option<f64>,
}

/// One sweep as the review sees it: when, the device's link, and every access
/// point it heard.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkSweep {
    pub scan_id: String,
    /// The sweep's time, Unix seconds.
    pub ts: u64,
    pub link: LinkState,
    pub heard: Vec<HeardAp>,
}

/// A forced disconnection needs the access point still heard at least this
/// loud: far enough into usable range that "the link just faded" is not the
/// explanation.
pub const FORCED_MIN_DBM: f64 = -75.0;
/// This many forced disconnections from one access point …
pub const DEAUTH_MIN: usize = 3;
/// … within this window is a deauthentication pattern, not bad luck.
pub const DEAUTH_WINDOW_SECS: u64 = 3600;
/// Outage starts whose gaps all sit within this fraction of their median are
/// on a schedule.
pub const PERIODIC_TOLERANCE: f64 = 0.15;
/// Fewer gaps than this cannot be called a period.
pub const PERIODIC_MIN_GAPS: usize = 3;

/// One thing the history shows. Serialised with a `kind` tag so the page and
/// the CLI switch on it by name.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Disruption {
    /// Off the network while the access point it was on is still heard at a
    /// usable level: the link did not fade, it was cut.
    ForcedDisconnect {
        at: u64,
        scan_id: String,
        bssid: String,
        ssid: Option<String>,
        heard_dbm: f64,
    },
    /// [`DEAUTH_MIN`] or more forced disconnections from one access point
    /// within [`DEAUTH_WINDOW_SECS`].
    DeauthSuspected {
        from: u64,
        to: u64,
        count: usize,
        bssid: String,
        ssid: Option<String>,
    },
    /// A network name the device knows, advertised by an address it has never
    /// seen, louder than the address it knows — while the known one is still
    /// heard, so this is not simply another site.
    EvilTwinSuspected {
        at: u64,
        scan_id: String,
        ssid: String,
        new_bssid: String,
        new_dbm: f64,
        known_bssid: String,
        known_dbm: f64,
    },
    /// Outages beginning at a regular interval.
    PeriodicOutage {
        period_secs: u64,
        occurrences: usize,
        from: u64,
        to: u64,
    },
    /// A run of sweeps off the network, whatever the cause — the timeline the
    /// other findings sit on.
    Outage { from: u64, to: u64, sweeps: usize },
}

impl Disruption {
    /// The sweep time the finding is placed at, for ordering.
    #[must_use]
    pub fn at(&self) -> u64 {
        match self {
            Self::ForcedDisconnect { at, .. } | Self::EvilTwinSuspected { at, .. } => *at,
            Self::DeauthSuspected { from, .. }
            | Self::PeriodicOutage { from, .. }
            | Self::Outage { from, .. } => *from,
        }
    }

    /// What an operator can do about it — the same words on the page and in
    /// the shell, so the two cannot drift.
    #[must_use]
    pub fn advice(&self) -> &'static str {
        match self {
            Self::ForcedDisconnect { .. } => {
                "The access point was in range when the link dropped, so this was not fading. \
                 One is noise; a pattern is not — watch for repeats here."
            }
            Self::DeauthSuspected { .. } => {
                "Repeated forced disconnections from one access point are what a deauthentication \
                 attack looks like from the phone. A client cannot stop it. If the network is yours, \
                 enable Protected Management Frames (802.11w / PMF, standard with WPA3); otherwise \
                 use cell data or move, and treat anything that asks you to log in again as hostile."
            }
            Self::EvilTwinSuspected { .. } => {
                "A network with a name you know is being advertised from an address you have never \
                 seen, louder than the real one. Do not join it; forget the network before you \
                 reconnect, verify your router's address, and never accept a login page on a network \
                 that never had one."
            }
            Self::PeriodicOutage { .. } => {
                "Outages on a schedule are a process, not weather: an access point rebooting or \
                 hopping channels, a timed jammer, a metered link. Note the period and look for \
                 what runs on it."
            }
            Self::Outage { .. } => {
                "Off the network for these sweeps. The findings above say whether it was cut, \
                 repeated, or on a schedule; this row is only the timeline."
            }
        }
    }
}

/// The review of a sweep history.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DisruptionReport {
    pub sweeps: usize,
    pub connected_sweeps: usize,
    pub disconnected_sweeps: usize,
    /// Oldest first.
    pub findings: Vec<Disruption>,
}

/// Read the history. Sweeps in any order of time: the review sorts them by
/// `ts`, and sweeps with the SAME second keep the order they were given —
/// `ts` is whole seconds, so that order is the caller's knowledge (the
/// store's creation order, oldest first, as
/// `app::signal::link_sweeps_from_history` hands it), never a guess from the
/// ids. Deterministic.
#[must_use]
pub fn review(sweeps: &[LinkSweep]) -> DisruptionReport {
    use std::collections::{HashMap, HashSet};

    let mut ordered: Vec<&LinkSweep> = sweeps.iter().collect();
    ordered.sort_by_key(|s| s.ts);

    let mut findings: Vec<Disruption> = Vec::new();
    let mut forced_by_ap: HashMap<String, Vec<(u64, Option<String>)>> = HashMap::new();
    // Every address each network name has been seen from, as the history
    // accumulates — the device's own link and every access point heard.
    let mut known: HashMap<String, HashSet<String>> = HashMap::new();
    let mut outage_start: Option<(u64, usize)> = None;
    let mut outage_starts: Vec<u64> = Vec::new();

    for (i, sweep) in ordered.iter().enumerate() {
        // Evil twin: judged against what was known BEFORE this sweep, then
        // this sweep's addresses join the known set.
        for ap in &sweep.heard {
            let (Some(ssid), Some(new_dbm)) = (ap.ssid.as_deref(), ap.signal_dbm) else {
                continue;
            };
            let Some(addresses) = known.get(ssid) else {
                continue;
            };
            if addresses.contains(&ap.bssid) {
                continue;
            }
            // The known address must be heard in the same sweep, weaker: an
            // unheard known address means another site, not an impostor.
            let strongest_known = sweep
                .heard
                .iter()
                .filter(|k| addresses.contains(&k.bssid))
                .filter_map(|k| k.signal_dbm.map(|d| (d, k.bssid.as_str())))
                .max_by(|a, b| a.0.total_cmp(&b.0));
            if let Some((known_dbm, known_bssid)) = strongest_known
                && new_dbm > known_dbm
            {
                findings.push(Disruption::EvilTwinSuspected {
                    at: sweep.ts,
                    scan_id: sweep.scan_id.clone(),
                    ssid: ssid.to_string(),
                    new_bssid: ap.bssid.clone(),
                    new_dbm,
                    known_bssid: known_bssid.to_string(),
                    known_dbm,
                });
            }
        }
        for ap in &sweep.heard {
            if let Some(ssid) = ap.ssid.as_deref() {
                known
                    .entry(ssid.to_string())
                    .or_default()
                    .insert(ap.bssid.clone());
            }
        }
        if let (Some(ssid), Some(bssid)) = (sweep.link.ssid.as_deref(), sweep.link.bssid.as_deref())
        {
            known
                .entry(ssid.to_string())
                .or_default()
                .insert(bssid.to_string());
        }

        // Forced disconnection: connected last sweep, off now, the last
        // access point still loud.
        if !sweep.link.connected
            && i > 0
            && let prev = ordered[i - 1]
            && prev.link.connected
            && let Some(last_ap) = prev.link.bssid.as_deref()
            && let Some(heard) = sweep
                .heard
                .iter()
                .find(|h| h.bssid == last_ap)
                .and_then(|h| h.signal_dbm)
            && heard >= FORCED_MIN_DBM
        {
            findings.push(Disruption::ForcedDisconnect {
                at: sweep.ts,
                scan_id: sweep.scan_id.clone(),
                bssid: last_ap.to_string(),
                ssid: prev.link.ssid.clone(),
                heard_dbm: heard,
            });
            forced_by_ap
                .entry(last_ap.to_string())
                .or_default()
                .push((sweep.ts, prev.link.ssid.clone()));
        }

        // The outage timeline.
        if sweep.link.connected {
            if let Some((from, n)) = outage_start.take() {
                findings.push(Disruption::Outage {
                    from,
                    to: ordered[i - 1].ts,
                    sweeps: n,
                });
            }
        } else if let Some((_, n)) = outage_start.as_mut() {
            *n += 1;
        } else {
            outage_start = Some((sweep.ts, 1));
            // A history that begins off the network has no start to time.
            if i > 0 {
                outage_starts.push(sweep.ts);
            }
        }
    }
    if let Some((from, n)) = outage_start.take()
        && let Some(last) = ordered.last()
    {
        findings.push(Disruption::Outage {
            from,
            to: last.ts,
            sweeps: n,
        });
    }

    // Deauthentication: the densest window per access point.
    let mut aps: Vec<&String> = forced_by_ap.keys().collect();
    aps.sort();
    for bssid in aps {
        let events = &forced_by_ap[bssid];
        let mut best: Option<(usize, u64, u64)> = None;
        for (start, (t0, _)) in events.iter().enumerate() {
            let end = events
                .iter()
                .skip(start)
                .take_while(|(t, _)| t.saturating_sub(*t0) <= DEAUTH_WINDOW_SECS)
                .count();
            let count = end;
            if count >= DEAUTH_MIN && best.is_none_or(|(c, ..)| count > c) {
                best = Some((count, *t0, events[start + end - 1].0));
            }
        }
        if let Some((count, from, to)) = best {
            findings.push(Disruption::DeauthSuspected {
                from,
                to,
                count,
                bssid: bssid.clone(),
                ssid: events.iter().find_map(|(_, s)| s.clone()),
            });
        }
    }

    // A schedule: gaps between outage starts all within tolerance of their
    // median.
    if outage_starts.len() > PERIODIC_MIN_GAPS {
        let mut gaps: Vec<u64> = outage_starts.windows(2).map(|w| w[1] - w[0]).collect();
        gaps.sort_unstable();
        let median = gaps[gaps.len() / 2];
        if median > 0 {
            #[allow(clippy::cast_precision_loss)]
            let regular = gaps
                .iter()
                .all(|g| (*g as f64 - median as f64).abs() <= PERIODIC_TOLERANCE * median as f64);
            if regular {
                findings.push(Disruption::PeriodicOutage {
                    period_secs: median,
                    occurrences: outage_starts.len(),
                    from: outage_starts[0],
                    to: *outage_starts.last().unwrap_or(&0),
                });
            }
        }
    }

    findings.sort_by_key(Disruption::at);
    let connected_sweeps = ordered.iter().filter(|s| s.link.connected).count();
    DisruptionReport {
        sweeps: ordered.len(),
        connected_sweeps,
        disconnected_sweeps: ordered.len() - connected_sweeps,
        findings,
    }
}

#[cfg(test)]
mod tests {
    include!("link_tests.rs");
}
