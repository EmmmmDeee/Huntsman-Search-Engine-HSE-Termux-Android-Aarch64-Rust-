//! Shared `termux-telephony-cellinfo` primitives for its consumers
//! (`signal_radar`, `cell_intel`) — a `pub(crate)` HELPER (no `Module` impl).
//!
//! Both modules parse the same tool output into the same `mcc-mnc-lac-cid`
//! tower identity, and both had independently written the same wrong rule for
//! reading it. This is the single definition of the cell shape and of what
//! counts as a usable identity, so the two cannot drift again — the same reason
//! [`crate::modules::device_fix`] owns the `termux-location` shape.
//!
//! # The identity field is named differently per radio
//!
//! Taken from the emitter (`termux-api`'s `TelephonyAPI.java`), not assumed:
//!
//! | radio | cell identity | area code | mcc/mnc |
//! |---|---|---|---|
//! | GSM   | `cid` | `lac` | int |
//! | WCDMA | `cid` | `lac` | int |
//! | LTE   | **`ci`**  | `tac` | int |
//! | NR/5G | **`nci`** | `tac` | String (`getMccString`) |
//! | CDMA  | — (`basestation`/`network`/`system`, no mcc/mnc) | — | — |
//!
//! Both consumers read only `cid`. On any LTE or 5G cell the identity was
//! therefore absent, the "no CID" skip fired, and the row was dropped in
//! silence — so on a modern handset, which is every device this project
//! targets, `signal_radar` reported no towers and `cell_intel` had nothing to
//! geolocate. Both had already noticed that LTE reports its AREA code as `tac`
//! ("`lac` falls back to `tac` (LTE reports `tac`)"), which is what makes the
//! omission legible: the per-radio difference was half-known.
//!
//! CDMA remains unsupported, now deliberately: it carries no MCC/MNC at all, so
//! it cannot form this identity, and the networks are decommissioned.
//!
//! # Sentinels
//!
//! `TelephonyAPI` wraps most fields in `writeIfKnown`, which OMITS the key when
//! the platform reports `Integer.MAX_VALUE` ("unavailable"), so an absent field
//! — not a sentinel value — is the normal unavailable case and `Option` handles
//! it. `dbm` is the documented exception: for LTE, NR and CDMA it is written
//! unconditionally, so `2147483647` reaches the parser as a real number. See
//! [`Cell::usable_dbm`].

use std::borrow::Cow;

use serde::Deserialize;

/// Android's "value unavailable" sentinel, as an `i64`.
pub(crate) const UNAVAILABLE: i64 = i32::MAX as i64;

/// One cell record from `termux-telephony-cellinfo`.
///
/// The union of what both consumers read. Every field is optional because
/// `writeIfKnown` omits whatever the platform could not supply, and which keys
/// appear at all depends on the radio.
#[derive(Deserialize)]
pub(crate) struct Cell {
    #[serde(rename = "type")]
    pub(crate) cell_type: Option<String>,
    pub(crate) registered: Option<bool>,
    pub(crate) asu: Option<i64>,
    pub(crate) dbm: Option<i64>,
    pub(crate) level: Option<i64>,
    /// GSM / WCDMA cell identity.
    pub(crate) cid: Option<i64>,
    /// LTE cell identity (`CellIdentityLte.getCi()`).
    pub(crate) ci: Option<i64>,
    /// NR cell identity (`CellIdentityNr.getNci()`).
    pub(crate) nci: Option<i64>,
    pub(crate) lac: Option<i64>,
    pub(crate) tac: Option<i64>,
    /// String on NR (`getMccString`) and an int elsewhere, so it is kept as a
    /// raw value and normalised by [`Self::mcc_str`].
    pub(crate) mcc: Option<serde_json::Value>,
    pub(crate) mnc: Option<serde_json::Value>,
    pub(crate) pci: Option<i64>,
}

impl Cell {
    /// The cell identity under whichever key this radio uses.
    ///
    /// `0` is treated as absent alongside `None`: it is not a valid identity on
    /// any of these radios and was already both consumers' sentinel for
    /// "missing", so keeping that meaning preserves the existing skip behaviour
    /// rather than quietly starting to emit `…-0` towers.
    pub(crate) fn identity(&self) -> Option<i64> {
        self.cid
            .or(self.ci)
            .or(self.nci)
            .filter(|&v| v != 0 && v != UNAVAILABLE)
    }

    /// The area code — `lac` on GSM/WCDMA, `tac` on LTE/NR — or `0` when the
    /// platform supplied neither.
    pub(crate) fn area_code(&self) -> i64 {
        self.lac
            .or(self.tac)
            .filter(|&v| v != UNAVAILABLE)
            .unwrap_or(0)
    }

    /// Signal strength in dBm, or `None` when there was no reading.
    ///
    /// `dbm` is written unconditionally for LTE, NR and CDMA, so an unavailable
    /// reading arrives as `Integer.MAX_VALUE` rather than as an absent key.
    /// Recording it verbatim publishes a signal strength of +2147483647 dBm as
    /// an observation; defaulting it to `0` publishes an implausibly strong one.
    pub(crate) fn usable_dbm(&self) -> Option<i64> {
        self.dbm.filter(|&v| v != UNAVAILABLE)
    }

    /// Mobile Country Code as text, normalising the int/String split.
    pub(crate) fn mcc_str(&self) -> Cow<'_, str> {
        json_to_str(&self.mcc)
    }

    /// Mobile Network Code as text.
    pub(crate) fn mnc_str(&self) -> Cow<'_, str> {
        json_to_str(&self.mnc)
    }
}

/// A JSON scalar as text, or `""` — `mcc`/`mnc` arrive as `"505"` on some
/// Android versions and `505` on others.
pub(crate) fn json_to_str(v: &Option<serde_json::Value>) -> Cow<'_, str> {
    v.as_ref()
        .and_then(crate::util::json::scalar_str)
        .unwrap_or(Cow::Borrowed(""))
}

/// True when `s` is a non-empty run of ASCII digits — the shape every segment of
/// an `mcc-mnc-lac-cid` [`crate::core::entity::EntityKind::DeviceId`] must have.
///
/// `Target::validate` rejects a `DeviceId` whose segments are not all non-empty
/// and numeric, and only `mcc` was ever checked. `mnc` also goes through
/// `writeIfKnown`, so it is simply ABSENT when the platform does not know it,
/// producing `"505--678-12345"` — four segments, one empty, emitted as an entity
/// that `Target::validate` would refuse. An identifier that cannot be fed back
/// as a target is not a usable pivot.
pub(crate) fn is_numeric_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(json: &str) -> Cell {
        serde_json::from_str(json).expect("fixture parses")
    }

    /// The defect this module exists to end: every radio names its identity
    /// differently, and reading only `cid` blinded both consumers to LTE and NR
    /// — which is every cell on a modern handset.
    #[test]
    fn identity_reads_the_key_each_radio_actually_emits() {
        assert_eq!(cell(r#"{"type":"gsm","cid":111}"#).identity(), Some(111));
        assert_eq!(cell(r#"{"type":"lte","ci":222}"#).identity(), Some(222));
        assert_eq!(cell(r#"{"type":"nr","nci":333}"#).identity(), Some(333));
    }

    #[test]
    fn identity_rejects_absent_zero_and_the_unavailable_sentinel() {
        assert_eq!(cell(r#"{"type":"lte"}"#).identity(), None);
        assert_eq!(cell(r#"{"type":"lte","ci":0}"#).identity(), None);
        assert_eq!(cell(r#"{"type":"lte","ci":2147483647}"#).identity(), None);
    }

    /// LTE/NR report their area code as `tac`, GSM/WCDMA as `lac`.
    #[test]
    fn area_code_accepts_either_name() {
        assert_eq!(cell(r#"{"lac":10}"#).area_code(), 10);
        assert_eq!(cell(r#"{"tac":20}"#).area_code(), 20);
        assert_eq!(cell(r#"{}"#).area_code(), 0);
        assert_eq!(cell(r#"{"tac":2147483647}"#).area_code(), 0);
    }

    #[test]
    fn usable_dbm_rejects_the_unconditionally_written_sentinel() {
        assert_eq!(cell(r#"{"dbm":-80}"#).usable_dbm(), Some(-80));
        assert_eq!(cell(r#"{"dbm":2147483647}"#).usable_dbm(), None);
        assert_eq!(cell(r#"{}"#).usable_dbm(), None);
    }

    /// `mcc`/`mnc` are ints on most radios and strings on NR.
    #[test]
    fn mcc_and_mnc_normalise_across_the_int_string_split() {
        let c = cell(r#"{"mcc":505,"mnc":1}"#);
        assert_eq!(c.mcc_str(), "505");
        assert_eq!(c.mnc_str(), "1");
        let nr = cell(r#"{"mcc":"505","mnc":"01"}"#);
        assert_eq!(nr.mcc_str(), "505");
        assert_eq!(nr.mnc_str(), "01");
        assert_eq!(cell(r#"{}"#).mcc_str(), "");
    }

    #[test]
    fn only_non_empty_digit_runs_are_valid_device_id_segments() {
        assert!(is_numeric_segment("505"));
        assert!(!is_numeric_segment(""));
        assert!(!is_numeric_segment("-1"));
        assert!(!is_numeric_segment("5a"));
    }
}
