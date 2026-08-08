//! Shared Termux sensor-tool output contract for every consumer of
//! [`crate::util::termux::termux_cmd`] (`signal_radar`, `device_sensors`,
//! `wifi_intel`, `cell_intel`) — a `pub(crate)` HELPER (no `Module` impl).
//!
//! # The distinction this module owns
//!
//! `termux_cmd` returns `Option<Vec<u8>>` and collapses timeout, spawn failure
//! and non-zero exit into `None`. A `Some(stdout)` therefore means only "the
//! tool ran and exited 0" — it says nothing about whether the payload is
//! usable. Three outcomes hide behind that one value, and conflating them is
//! what makes a scanner lie:
//!
//! | Outcome | Meaning | Correct result |
//! |---|---|---|
//! | `None` | tool absent, timed out, or exited non-zero | empty `Ok` — nothing observed, nothing to attest |
//! | `Some(blank)` | tool answered with nothing | empty `Ok` — an honest "nothing to report" |
//! | `Some(garbage)` | tool answered with something broken | `Err` — a real malfunction |
//!
//! Blank output MUST stay an empty `Ok`. A Termux:API stub that exits 0 and
//! prints nothing is the ordinary state wherever a runtime permission is
//! withheld, so treating it as a hard failure would error on every sweep and
//! trip the circuit breaker (`SOFT_TRIP_THRESHOLD = 3`) on the primary target
//! platform — non-root Termux aarch64. That is a worse defect than the one this
//! contract exists to prevent.
//!
//! Non-blank unparseable output MUST be an `Err`. Reporting it as an empty
//! result makes "this sensor is broken" indistinguishable from "there is
//! nothing in range", and the two demand opposite operator responses. The
//! failure then reaches the engine as a real `ModuleError`, is counted in
//! `modules_errored`, and feeds the circuit breaker and the cross-scan
//! health streak — where `crate::util::scraper_health` classifies it as a hard
//! failure rather than as silent zero-yield drift, so the diagnosis an operator
//! sees matches what actually happened.
//!
//! # Why this is shared
//!
//! Four modules independently wrote this same rule around a
//! `serde_json::from_slice` of tool output, and four independently got it
//! wrong in the same way before it was fixed. Centralising the predicate and
//! the error construction makes the contract single-sourced, so the sensor
//! family cannot drift apart again. Like `breach_rich` and `device_fix`, this
//! stays `pub(crate)` so it is not caught by the
//! `every_declared_module_is_registered` architecture guard (which flags an
//! unregistered `pub mod` as dead-at-runtime).

use crate::core::error::Error;

/// One fixed-invocation Termux sensor tool: its name, its timeout budget, and
/// the label its malfunctions are reported under.
///
/// These three facts belong together and were previously written out by hand at
/// every call site, in two different vocabularies — the tool as
/// `"termux-wifi-scaninfo"` and the label as `"wifi-scaninfo"` — so nothing tied
/// them to each other or to the timeout. They drifted: `termux-wifi-scaninfo`
/// was invoked at 8 s by `signal_radar` and at 5 s by `wifi_intel`, which is not
/// merely untidy. Both callers key the same entry in
/// [`crate::util::termux`]'s skip cache (same binary, same empty argv), so the
/// 5 s caller could time out and back the tool off for the 8 s caller — which
/// might have succeeded had it been allowed its own budget. One tool cannot
/// coherently have two deadlines; this type is where it gets one.
///
/// `termux-location` is deliberately absent. It is invoked as a ladder of four
/// differently-parameterised stages with per-stage budgets (12 s fresh GPS lock
/// down to 3 s cache reads), so it has no single timeout to own; that ladder is
/// already single-sourced in `signal_radar::gps` and `crate::modules::device_fix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sensor {
    /// Full Wi-Fi AP scan — the radar's primary sighting source.
    WifiScan,
    /// The currently-associated network only (fast, no scan).
    WifiConnection,
    /// Serving + neighbour cell towers.
    CellInfo,
    /// BLE/BT beacon scan.
    ///
    /// Unlike its three siblings, this tool is **not part of the official
    /// Termux:API** — `termux/termux-api-package` installs 62 `termux-*`
    /// scripts and none of them is a Bluetooth command. It ships only in a
    /// third-party fork, and the upstream PRs that would add one are still
    /// open. The variant is kept because the fork is real and installable, and
    /// because an absent tool is already handled correctly (an attributable
    /// capability gap, not an empty observation) — but a Bluetooth sweep
    /// returning nothing on a stock device is the expected case, not a fault.
    /// See `crate::modules::signal_radar::bluetooth` for the full evidence and
    /// the wire shapes that fork actually emits.
    BluetoothScan,
}

impl Sensor {
    /// Every variant, so the invariant tests below cover the whole family
    /// rather than whichever variants someone remembered to list.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 4] = [
        Self::WifiScan,
        Self::WifiConnection,
        Self::CellInfo,
        Self::BluetoothScan,
    ];

    /// The `termux-*` executable.
    pub(crate) const fn tool(self) -> &'static str {
        match self {
            Self::WifiScan => "termux-wifi-scaninfo",
            Self::WifiConnection => "termux-wifi-connectioninfo",
            Self::CellInfo => "termux-telephony-cellinfo",
            Self::BluetoothScan => "termux-bluetooth-scaninfo",
        }
    }

    /// Hard timeout for this tool, in milliseconds — the single deadline every
    /// caller shares.
    ///
    /// Where callers disagreed, the LONGER budget wins: a scan that genuinely
    /// needs 8 s must not be killed at 5 s and reported as "nothing in range",
    /// and since a timeout now backs the invocation off along an escalating
    /// ladder rather than latching, a truly wedged tool costs its full budget
    /// rarely instead of once per sweep.
    pub(crate) const fn timeout_ms(self) -> u64 {
        match self {
            // Was 8 s (signal_radar) vs 5 s (wifi_intel) — reconciled upward.
            Self::WifiScan => 8_000,
            Self::WifiConnection => 3_000,
            Self::CellInfo => 5_000,
            // A BT scan is a timed radio sweep, not a query; it is slow by design.
            Self::BluetoothScan => 10_000,
        }
    }

    /// Short name used when reporting a malfunction — the tool without its
    /// `termux-` prefix. Kept in lockstep with [`Self::tool`] by
    /// `label_is_the_tool_without_its_prefix`, so the two spellings of one fact
    /// cannot drift.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::WifiScan => "wifi-scaninfo",
            Self::WifiConnection => "wifi-connectioninfo",
            Self::CellInfo => "telephony-cellinfo",
            Self::BluetoothScan => "bluetooth-scaninfo",
        }
    }

    /// Run the tool under its own timeout, returning stdout on a clean exit.
    ///
    /// The `None` arm collapses tool-absent, timed-out and non-zero-exit into
    /// one value. Prefer [`Self::read_outcome`] where the difference matters —
    /// it is the difference between "nothing is nearby" and "nothing looked".
    pub(crate) async fn read(self) -> Option<Vec<u8>> {
        self.read_outcome().await.stdout()
    }

    /// Run the tool, preserving WHY it produced no data.
    ///
    /// The non-lossy read. A `Sensor` speaks for a radio on a phone that may not
    /// have Termux:API installed, may have had its Android permission refused,
    /// or may not carry the hardware at all; each of those is a capability gap,
    /// not an observation of an empty world.
    pub(crate) async fn read_outcome(self) -> crate::util::termux::TermuxOutcome {
        crate::util::termux::termux_exec(self.tool(), &[], self.timeout_ms()).await
    }
}

/// Read `sensor` and hand its stdout to `parse`, applying the absent-tool row of
/// this module's contract table: no output at all is an empty `Ok` — nothing was
/// observed, and nothing malfunctioned that the caller can attest to.
///
/// That row was documented here but *implemented* separately by each of the four
/// sensor call sites, every one re-deriving the same `match … { Some => parse,
/// None => empty }` and re-stating the same reasoning in a comment. Documenting a
/// contract in one place while implementing it in four is how the family drifted
/// apart the first time; this is the contract as code.
///
/// The blank and unparseable rows stay with `parse`, because only the caller
/// knows the payload's shape — it applies [`is_blank`] and [`unparseable_for`].
pub(crate) async fn read_and_parse<F>(
    sensor: Sensor,
    parse: F,
) -> crate::core::error::Result<crate::core::module::ModuleResult>
where
    F: FnOnce(&[u8]) -> crate::core::error::Result<crate::core::module::ModuleResult>,
{
    let outcome = sensor.read_outcome().await;
    if let Some(reason) = outcome.failure_reason() {
        // The tool did not run, so the empty result below is NOT an observation
        // that nothing is nearby — it is the absence of a look. Both orders are
        // explicit that a sensor failure must never be presented as a zero
        // finding, and previously every one of these arms returned the same
        // silent empty `Ok` as a genuine empty read. The result stays empty (a
        // missing optional sensor must not fail a scan on a device that simply
        // has no Termux:API), but it is now attributable: the operator sees
        // WHICH tool and WHY, rather than an unexplained gap in the report.
        tracing::warn!(
            sensor = sensor.tool(),
            reason,
            "termux sensor did not run — this is a capability gap, not an empty observation"
        );
        return Ok(crate::core::module::ModuleResult::new());
    }
    match outcome.stdout() {
        Some(stdout) => parse(&stdout),
        // Unreachable: `failure_reason()` is `None` only for `Ok`, whose stdout
        // is always `Some` — including a legitimately EMPTY payload, which is a
        // real observation of nothing and is handed to `parse` above.
        None => Ok(crate::core::module::ModuleResult::new()),
    }
}

/// True when a sensor tool exited 0 but printed nothing meaningful.
///
/// Whitespace-only counts as blank: a tool that emits a bare newline has
/// answered "nothing to report" just as much as one that emits zero bytes.
#[must_use]
pub(crate) fn is_blank(stdout: &[u8]) -> bool {
    stdout.iter().all(u8::is_ascii_whitespace)
}

/// Build the canonical error for a sensor tool that answered with output which
/// could not be parsed — a genuine malfunction, distinct from both an absent
/// tool and an empty answer.
///
/// `src` is the emitting module's evidence-source tag (its `SRC`/`SOURCE`
/// constant); `sensor` names the specific tool (e.g. `"wifi-scaninfo"`) so a
/// multi-sensor module's error identifies which one failed.
///
/// Prefer [`unparseable_for`], which takes the [`Sensor`] itself and so cannot
/// name a tool the caller did not actually read. This string form remains for
/// the one sensor outside [`Sensor`]'s remit — `termux-location`, whose ladder
/// lives in [`crate::modules::device_fix`].
pub(crate) fn unparseable(src: &'static str, sensor: &str, e: &serde_json::Error) -> Error {
    Error::module(src, format!("{sensor}: unparseable tool output ({e})"))
}

/// [`unparseable`] with the sensor's label taken from the [`Sensor`] itself, so
/// the reported tool is necessarily the one that was read.
pub(crate) fn unparseable_for(src: &'static str, sensor: Sensor, e: &serde_json::Error) -> Error {
    unparseable(src, sensor.label(), e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_whitespace_are_blank() {
        for blank in [&b""[..], b" ", b"\n", b"\t", b"  \n\t ", b"\r\n"] {
            assert!(
                is_blank(blank),
                "{:?} must count as blank",
                String::from_utf8_lossy(blank)
            );
        }
    }

    /// The load-bearing half: real payloads — including a legitimately empty
    /// JSON array, which means "scanned, found nothing" — must NOT be treated
    /// as blank, or a genuine answer would be silently discarded.
    #[test]
    fn real_payloads_are_not_blank() {
        for payload in [&b"[]"[..], b"{}", b"[{\"bssid\":\"x\"}]", b"not json", b"0"] {
            assert!(
                !is_blank(payload),
                "{:?} must not count as blank",
                String::from_utf8_lossy(payload)
            );
        }
    }

    /// The two spellings of one fact must stay in lockstep. Without this, a new
    /// sensor can be added whose error label names a different tool than the one
    /// actually invoked — which is precisely the class of drift this type exists
    /// to end.
    #[test]
    fn label_is_the_tool_without_its_prefix() {
        for s in Sensor::ALL {
            assert_eq!(
                s.tool().strip_prefix("termux-"),
                Some(s.label()),
                "{s:?}: label must be its tool minus the `termux-` prefix"
            );
        }
    }

    /// Every sensor is a distinct tool, and every budget is a real one. A zero
    /// timeout would make `termux_cmd` cancel the spawn instantly and cache the
    /// tool as backing-off, silently disabling the sensor forever.
    #[test]
    fn every_sensor_is_distinct_and_has_a_usable_budget() {
        let mut tools: Vec<&str> = Sensor::ALL.iter().map(|s| s.tool()).collect();
        tools.sort_unstable();
        let before = tools.len();
        tools.dedup();
        assert_eq!(before, tools.len(), "two variants name the same tool");

        for s in Sensor::ALL {
            assert!(
                s.timeout_ms() > 0,
                "{s:?}: a zero budget disables the sensor"
            );
            assert!(
                s.tool().starts_with("termux-"),
                "{s:?}: not a termux-api tool"
            );
        }
    }

    /// The drift that motivated this type: one tool, one deadline. Both callers
    /// of the Wi-Fi scan share a skip-cache entry, so two budgets meant the
    /// shorter one could back the tool off for the longer one. Pinned at the
    /// reconciled (longer) value so a future edit back to 5s is a test failure,
    /// not a silent regression.
    #[test]
    fn the_wifi_scan_budget_is_the_reconciled_longer_one() {
        assert_eq!(Sensor::WifiScan.timeout_ms(), 8_000);
    }

    #[test]
    fn unparseable_for_derives_the_label_from_the_sensor() {
        let e = serde_json::from_slice::<Vec<u32>>(b"nope").expect_err("must fail to parse");
        for s in Sensor::ALL {
            let msg = unparseable_for("m", s, &e).to_string();
            assert!(msg.contains(s.label()), "{s:?}: label missing from {msg}");
        }
    }

    #[test]
    fn unparseable_names_both_the_module_and_the_sensor() {
        let e = serde_json::from_slice::<Vec<u32>>(b"not json").expect_err("must fail to parse");
        let err = unparseable("signal_radar", "wifi-scaninfo", &e);
        let msg = err.to_string();
        assert!(msg.contains("wifi-scaninfo"), "sensor must be named: {msg}");
        assert!(
            msg.contains("unparseable tool output"),
            "canonical phrasing must be preserved: {msg}"
        );
    }
}
