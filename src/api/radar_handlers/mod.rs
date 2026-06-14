//! HTTP handlers for the signal-radar live snapshot endpoint.
//!
//! The [`RadarSnapshot`] type aggregates the latest RF sensor readings into a
//! single JSON response suitable for the Termux Android aarch64 UI.

use serde::Serialize;

/// An NFC tag observed by `termux-nfc-scan`.
#[derive(Debug, Clone, Serialize)]
pub struct NfcTag {
    /// Hardware tag identifier (hex string as reported by the OS).
    pub id: String,
    /// Detection confidence in `[0, 1]`.
    pub confidence: f64,
}

/// A point-in-time snapshot of all signal-radar sensor output, returned by
/// `GET /api/v1/radar/snapshot`.
#[derive(Debug, Clone, Serialize)]
pub struct RadarSnapshot {
    /// NFC tags detected during this scan pass.
    pub nfc_tags: Vec<NfcTag>,
}

impl RadarSnapshot {
    /// Build a [`RadarSnapshot`] from the entities produced by the
    /// `signal_radar` module.  Only NFC-tagged [`crate::core::entity::EntityKind::DeviceId`]
    /// entities are mapped into [`NfcTag`] entries; all other entity kinds are
    /// silently ignored so new kinds added to the module never break this view.
    pub fn from_entities(entities: &[crate::core::entity::Entity]) -> Self {
        let nfc_tags = entities
            .iter()
            .filter(|e| e.kind == crate::core::entity::EntityKind::DeviceId && e.has_tag("nfc-tag"))
            .map(|e| NfcTag {
                id: e.value.clone(),
                confidence: e.confidence,
            })
            .collect();

        Self { nfc_tags }
    }
}
