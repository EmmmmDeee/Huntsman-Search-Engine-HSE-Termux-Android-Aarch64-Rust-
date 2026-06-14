//! NFC tag scanner — wraps `termux-nfc-scan` (Termux:API ≥ 0.50).
//! Returns empty on permission denial or hardware absence.

use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::util::termux::termux_cmd;

use super::SRC;

#[derive(Deserialize)]
struct NfcTagRaw {
    id: String,
}

/// Parse a raw JSON byte slice from `termux-nfc-scan` into [`ModuleResult`].
///
/// Exposed for unit testing without requiring the Termux binary.
pub(super) fn parse_tags(raw: &[u8], scan_id: &str) -> ModuleResult {
    let tags: Vec<NfcTagRaw> = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult::with_capacity(tags.len());

    for tag in tags {
        if tag.id.is_empty() {
            continue;
        }

        let mut e = Entity::new(EntityKind::DeviceId, &tag.id, 0.75, scan_id);
        e.tag("nfc");
        e.tag("nfc-tag");

        e.add_evidence(
            Evidence::new(SRC, format!("NFC tag: {}", tag.id)).with_attr("nfc_id", &tag.id),
        );

        result.push(e);
    }

    result
}

/// Scan for NFC tags via `termux-nfc-scan`.
///
/// Returns an empty [`ModuleResult`] on permission denial, hardware absence,
/// or any parse error — the caller never has to handle errors from this sensor.
pub(super) async fn scan(scan_id: &str) -> ModuleResult {
    let stdout = match termux_cmd("termux-nfc-scan", &[], 5_000).await {
        Some(b) if !b.is_empty() => b,
        _ => return ModuleResult::new(),
    };

    parse_tags(&stdout, scan_id)
}
