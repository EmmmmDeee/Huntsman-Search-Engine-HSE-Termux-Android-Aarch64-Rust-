//! Cell-tower identity vocabulary — single-sourced.
//!
//! Four modules derive a cell tower's canonical `DeviceId` value from raw
//! network fields: `cell_intel` (termux cellinfo + OpenCelliD), `signal_radar`
//! (termux cellinfo), `cell_local` (on-device DB), and `opencellid` (area/tower
//! lookup). The tower-id string **is** the `DeviceId` entity value, which is the
//! scan's correlation/dedup key — so all four MUST format it identically. A
//! divergent format would split one physical tower into distinct entities and
//! break correlation. That format, plus the two coercions that feed it (MCC/MNC
//! string-or-number normalisation and the LAC/TAC fallback), live here once
//! rather than re-inlined per module.

use std::borrow::Cow;
use std::fmt::Display;

/// Canonical cell-tower identity string: `<mcc>-<mnc>-<lac>-<cid>`. Generic over
/// [`Display`] so every caller — whether its components arrive as `Cow<str>`
/// (coerced cellinfo), `String`, or `i64` (a typed DB row) — produces a
/// byte-identical `DeviceId` for the same tower.
///
/// ```
/// use huntsman_search_engine::util::cell::tower_id;
///
/// assert_eq!(tower_id("505", "1", 12345, 67890), "505-1-12345-67890");
/// // Component type is irrelevant — a coerced-string caller and a typed-int
/// // caller agree on the identity of the same tower.
/// assert_eq!(tower_id(505, 1, 12345, 67890), "505-1-12345-67890");
/// ```
pub fn tower_id(
    mcc: impl Display,
    mnc: impl Display,
    lac: impl Display,
    cid: impl Display,
) -> String {
    format!("{mcc}-{mnc}-{lac}-{cid}")
}

/// MCC/MNC arrive as a JSON string (`"505"`) on some Android versions and a bare
/// number (`505`) on others; `termux-telephony-cellinfo` is inconsistent across
/// vendors. Normalise either scalar form to its string; a missing / null /
/// bool / array / object value becomes empty (a `true` is not tower data). The
/// string form is borrowed, the stringified number owned.
#[must_use]
pub fn mcc_mnc_str(v: &Option<serde_json::Value>) -> Cow<'_, str> {
    match v {
        Some(serde_json::Value::String(s)) => Cow::Borrowed(s.as_str()),
        Some(serde_json::Value::Number(n)) => Cow::Owned(n.to_string()),
        _ => Cow::Borrowed(""),
    }
}

/// A tower's location-area code. LTE/NR report it as `tac`, older radios (GSM/
/// UMTS) as `lac`; a cellinfo record carries whichever applies. Prefer `lac`,
/// fall back to `tac`, default `0` when neither is present.
#[must_use]
pub fn resolve_lac(lac: Option<i64>, tac: Option<i64>) -> i64 {
    lac.or(tac).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tower_id_is_identical_across_component_types() {
        // The whole point: a coerced-string caller (cell_intel/signal_radar) and
        // a typed-int caller (cell_local/opencellid) yield the SAME DeviceId for
        // the same tower — without this, one physical tower splits into two
        // entities and correlation breaks.
        let from_strs = tower_id(
            Cow::Borrowed("505"),
            String::from("1"),
            12345_i64,
            67890_i64,
        );
        let from_ints = tower_id(505_i64, 1_i64, 12345_i64, 67890_i64);
        assert_eq!(from_strs, "505-1-12345-67890");
        assert_eq!(from_ints, "505-1-12345-67890");
        assert_eq!(from_strs, from_ints);
    }

    #[test]
    fn mcc_mnc_str_normalises_string_and_number_forms() {
        assert_eq!(
            mcc_mnc_str(&Some(serde_json::json!("505"))),
            Cow::Borrowed("505")
        );
        assert_eq!(mcc_mnc_str(&Some(serde_json::json!(310))).as_ref(), "310");
        assert_eq!(
            mcc_mnc_str(&Some(serde_json::Value::Null)),
            Cow::Borrowed("")
        );
        assert_eq!(mcc_mnc_str(&None), Cow::Borrowed(""));
        // A bool / array is not tower data — normalises to empty, never "true".
        assert_eq!(
            mcc_mnc_str(&Some(serde_json::json!(true))),
            Cow::Borrowed("")
        );
        assert_eq!(
            mcc_mnc_str(&Some(serde_json::json!([1, 2]))),
            Cow::Borrowed("")
        );
    }

    #[test]
    fn resolve_lac_prefers_lac_then_tac_then_zero() {
        assert_eq!(resolve_lac(Some(100), Some(200)), 100); // lac wins
        assert_eq!(resolve_lac(None, Some(200)), 200); // tac fallback (LTE/NR)
        assert_eq!(resolve_lac(Some(100), None), 100); // lac only (GSM/UMTS)
        assert_eq!(resolve_lac(None, None), 0); // neither present
    }
}
