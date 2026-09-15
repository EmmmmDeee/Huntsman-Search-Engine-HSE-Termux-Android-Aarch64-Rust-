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
    /// The `None` arm keeps [`crate::util::termux::termux_cmd`]'s contract: tool
    /// absent, timed out, or exited non-zero — nothing observed, and nothing
    /// this module can attest to. Most callers want [`read_and_parse`], which
    /// applies that contract for them.
    pub(crate) async fn read(self) -> Option<Vec<u8>> {
        crate::util::termux::termux_cmd(self.tool(), &[], self.timeout_ms()).await
    }
}

/// The stock Termux:API sensor surface HSE's radar and sensor modules depend
/// on: the `termux-api` PACKAGE's four core tools, in canonical order. This is
/// the ONE definition on the Rust side. `install.sh`'s detection block and
/// `scripts/reconcile.sh` each carry the same list as a shell array, and
/// `shell_side_core_tool_lists_match_this_definition` below holds all three
/// in lockstep so none can drift.
///
/// Bluetooth is deliberately absent. `termux-bluetooth-scaninfo` is not part of
/// the stock `termux-api` package, so it is an independent optional provider
/// ([`Sensor::BluetoothScan`]) and never a condition for declaring the GNSS /
/// Wi-Fi / cell substrate ready.
pub(crate) const TERMUX_API_CORE_TOOLS: [&str; 4] = [
    crate::modules::device_fix::LOCATION_TOOL,
    Sensor::WifiConnection.tool(),
    Sensor::WifiScan.tool(),
    Sensor::CellInfo.tool(),
];

/// The harmless, permission-free, bounded call that proves the Termux ↔ Android
/// bridge is answering. A sensor tool cannot serve here: each needs a runtime
/// permission, so its failure would not tell "bridge dead" from "permission
/// withheld". Mirrored by `scripts/reconcile.sh` (held in lockstep by the same
/// test as the tool list).
pub(crate) const TERMUX_API_BRIDGE_PROBE: &str = "termux-battery-status";

/// The core tools NOT executable on `PATH`: a `command -v` over
/// [`TERMUX_API_CORE_TOOLS`] that runs nothing. Empty means the `termux-api`
/// package's sensor surface is installed. It says nothing about whether the
/// Android side answers; that is [`TERMUX_API_BRIDGE_PROBE`]'s question.
///
/// This is the probe `hse selftest` reports on. An earlier revision ran
/// `termux-info -h` instead, and `termux-info` ships in `termux-tools` on
/// EVERY Termux install, so the check said "termux-api CLI present" on devices
/// that had no sensor tool at all.
pub(crate) fn missing_core_tools() -> Vec<&'static str> {
    missing_core_tools_on(&std::env::var_os("PATH").unwrap_or_default())
}

/// [`missing_core_tools`] against an explicit `PATH` value, so the lookup is
/// testable without mutating the process environment.
pub(crate) fn missing_core_tools_on(path: &std::ffi::OsStr) -> Vec<&'static str> {
    let dirs: Vec<std::path::PathBuf> = std::env::split_paths(path).collect();
    TERMUX_API_CORE_TOOLS
        .into_iter()
        .filter(|tool| !dirs.iter().any(|dir| is_executable(&dir.join(tool))))
        .collect()
}

/// `command -v`'s notion of "found": a regular file with an execute bit.
fn is_executable(p: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
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
    match sensor.read().await {
        Some(stdout) => parse(&stdout),
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

    /// The `NAME=(a b c)` shell array literal(s) defining `name` in `text`.
    /// A line whose array holds an `@…@` token is the reconciler's render
    /// template, not a definition, and is skipped.
    fn shell_arrays<'a>(text: &'a str, name: &str) -> Vec<Vec<&'a str>> {
        let open = format!("{name}=(");
        text.lines()
            .filter_map(|l| l.trim().strip_prefix(open.as_str()))
            .filter_map(|rest| rest.strip_suffix(')'))
            .map(|inner| inner.split_whitespace().collect::<Vec<_>>())
            .filter(|items| !items.iter().any(|i| i.starts_with('@')))
            .collect()
    }

    /// The one shell-side copy of a scalar `NAME=value` definition in `text`.
    fn shell_scalar<'a>(text: &'a str, name: &str) -> &'a str {
        let open = format!("{name}=");
        let mut hits = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix(open.as_str()))
            .map(|v| v.trim_matches(|c| c == '"' || c == '\''));
        let first = hits
            .next()
            .unwrap_or_else(|| panic!("`{name}=` is not defined"));
        assert!(
            hits.next().is_none(),
            "`{name}=` must be defined exactly once"
        );
        first
    }

    /// The core-tool list exists once per language, and the shell copies —
    /// install.sh's detection block and scripts/reconcile.sh — must equal this
    /// definition exactly, in order. Parsed from the real files so the lock
    /// holds against what ships, not against a comment.
    #[test]
    fn shell_side_core_tool_lists_match_this_definition() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for rel in ["install.sh", "scripts/reconcile.sh"] {
            let text =
                std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            let arrays = shell_arrays(&text, "TERMUX_API_CORE_TOOLS");
            assert_eq!(
                arrays.len(),
                1,
                "{rel}: TERMUX_API_CORE_TOOLS must be defined exactly once, saw {arrays:?}"
            );
            assert_eq!(
                arrays[0], TERMUX_API_CORE_TOOLS,
                "{rel}: TERMUX_API_CORE_TOOLS drifted from the Rust definition"
            );
        }
        let reconciler =
            std::fs::read_to_string(root.join("scripts/reconcile.sh")).expect("reconciler");
        assert_eq!(
            shell_scalar(&reconciler, "TERMUX_API_BRIDGE_PROBE"),
            TERMUX_API_BRIDGE_PROBE,
            "scripts/reconcile.sh: the bridge probe drifted from the Rust definition"
        );
    }

    /// Every core tool is a real `termux-api` executable name, distinct, and
    /// the Bluetooth provider stays OUT of the readiness set.
    #[test]
    fn core_tools_are_distinct_termux_api_tools_without_bluetooth() {
        let mut seen = std::collections::HashSet::new();
        for tool in TERMUX_API_CORE_TOOLS {
            assert!(tool.starts_with("termux-"), "{tool}: not a termux-api tool");
            assert!(seen.insert(tool), "{tool}: listed twice");
        }
        assert!(
            !TERMUX_API_CORE_TOOLS.contains(&Sensor::BluetoothScan.tool()),
            "Bluetooth is an optional provider, never a readiness condition"
        );
        assert!(
            !TERMUX_API_CORE_TOOLS.contains(&TERMUX_API_BRIDGE_PROBE),
            "the bridge probe is not a sensor and must not be in the sensor set"
        );
    }

    /// The lookup is `command -v`: a tool counts only as an executable file in
    /// a `PATH` directory, and the report keeps canonical order.
    #[test]
    fn missing_core_tools_is_a_path_lookup_in_canonical_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let present = [TERMUX_API_CORE_TOOLS[1], TERMUX_API_CORE_TOOLS[3]];
        for tool in present {
            let p = dir.path().join(tool);
            std::fs::write(&p, "#!/bin/sh\n").expect("stub");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }
        }
        // A file without the execute bit is NOT found — `command -v` would not
        // find it either. (Same name in a second directory, not executable.)
        let shadow = tempfile::tempdir().expect("tempdir");
        std::fs::write(shadow.path().join(TERMUX_API_CORE_TOOLS[0]), "").expect("stub");

        let path = std::env::join_paths([dir.path(), shadow.path()]).expect("join");
        let missing = missing_core_tools_on(&path);
        #[cfg(unix)]
        assert_eq!(
            missing,
            vec![TERMUX_API_CORE_TOOLS[0], TERMUX_API_CORE_TOOLS[2]]
        );
        #[cfg(not(unix))]
        assert_eq!(missing, vec![TERMUX_API_CORE_TOOLS[2]]);

        assert_eq!(
            missing_core_tools_on(std::ffi::OsStr::new("")).len(),
            TERMUX_API_CORE_TOOLS.len(),
            "an empty PATH finds nothing"
        );
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
