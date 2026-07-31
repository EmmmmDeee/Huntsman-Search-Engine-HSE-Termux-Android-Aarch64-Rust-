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
pub(crate) fn unparseable(src: &'static str, sensor: &str, e: &serde_json::Error) -> Error {
    Error::module(src, format!("{sensor}: unparseable tool output ({e})"))
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
