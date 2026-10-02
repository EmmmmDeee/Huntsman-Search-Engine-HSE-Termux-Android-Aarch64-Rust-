//! AU-117 — Operator's paired-hardware constellation (self-OPSEC exposure).
//!
//! The signal radar plots every Bluetooth device it sees as a map pin, but a
//! device the operator's phone is **bonded** (paired) to is categorically
//! different from a stranger's: it is the operator's OWN hardware — a car
//! head-unit, earbuds, a smartwatch, a fitness band. Bond state
//! (`termux-bluetooth-scaninfo`'s `bond_state`, tagged `bond:bonded`) is a
//! strong ownership signal no other rule uses.
//!
//! Those paired devices matter for the operator's own OPSEC: each one that
//! broadcasts a **universally-administered** MAC (a real, non-rotating hardware
//! address — see AU-122 and the shared [`crate::util::oui`] classifier) is a
//! persistent identifier the operator PHYSICALLY CARRIES. Together they form a
//! device constellation — a hardware fingerprint that recurs across every place
//! and scan the operator's phone appears, and that a passive observer can use to
//! recognise the same person again. This rule surfaces that constellation and
//! names the persistently-trackable members, so the operator sees the fingerprint
//! their own kit emits.
//!
//! It complements AU-122 (which partitions ALL observed MACs into trackable vs.
//! randomized): AU-122 answers "which pins are followable devices"; AU-117
//! answers "which of the followable ones are the operator's own, and therefore
//! track the operator". Fires only when the operator's phone is bonded to ≥2
//! devices and ≥1 of them is universally-administered (an actual exposure) —
//! never on a lone pairing or an all-privacy-MAC kit (good OPSEC, nothing to
//! flag). Severity Medium: a real, self-inflicted tracking surface, not a
//! compromise.

use super::*;
use crate::util::oui;

/// AU-117 — Operator's paired-hardware constellation.
///
/// Entity-only: collects the bonded (`bond:bonded`) Bluetooth `MacAddress`
/// entities, classifies each by the U/L bit, and — when ≥2 are paired and ≥1 is
/// a persistent hardware address — emits one Medium finding naming the trackable
/// members. `entity_uids` carries the whole bonded constellation in entity order.
pub(in crate::core::correlator) fn rule_au_117_personal_device_constellation(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    let bonded: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::MacAddress && e.has_tag("bluetooth") && e.has_tag("bond:bonded")
        })
        .collect();
    if bonded.len() < 2 {
        return Vec::new();
    }

    let mut trackable = 0usize;
    let mut vendors: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for e in &bonded {
        if oui::is_locally_administered(&e.value) == Some(false) {
            trackable += 1;
            if let Some(info) = oui::classify_mac(&e.value)
                && !matches!(
                    info.class,
                    oui::DeviceClass::Unregistered
                        | oui::DeviceClass::Unknown
                        | oui::DeviceClass::Randomized
                )
            {
                vendors.insert(format!("{} {}", info.vendor, info.class.as_str()));
            }
        }
    }

    // No persistent-hardware pairing → the operator's kit uses privacy MACs
    // (good OPSEC), nothing to flag.
    if trackable == 0 {
        return Vec::new();
    }

    let n = bonded.len();
    let uids: Vec<String> = bonded.iter().map(|e| e.uid.clone()).collect();
    let vendor_clause = if vendors.is_empty() {
        String::new()
    } else {
        let listed: Vec<&str> = vendors.iter().map(String::as_str).take(6).collect();
        format!(" ({})", listed.join(", "))
    };

    vec![Correlation::new(
        "AU-117",
        "Operator paired-hardware constellation",
        Severity::Medium,
        format!(
            "the operator's phone is paired with {n} Bluetooth device{}, {trackable} of which \
             broadcast{} a persistent universally-administered MAC{vendor_clause} — a hardware \
             fingerprint the operator physically carries that recurs across every place and scan \
             their phone appears, letting a passive observer re-identify the same person. AU-122 \
             flags these as trackable; being bonded, they track the OPERATOR.",
            if n == 1 { "" } else { "s" },
            if trackable == 1 { "s" } else { "" },
        ),
        uids,
        scan_id,
        ts,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;

    fn bonded_bt(value: &str) -> Entity {
        let mut e = Entity::new(
            EntityKind::MacAddress,
            value,
            confidence::HIGH_PLUSPLUS,
            "s",
        );
        e.tag("bluetooth");
        e.tag("bond:bonded");
        e
    }

    #[test]
    fn au117_fires_on_a_bonded_kit_with_a_trackable_member() {
        // Two paired devices; one is universally-administered (0x3C, trackable),
        // the other randomized (0x36) — the operator carries a hardware fingerprint.
        let car = bonded_bt("3C:5A:B4:11:22:33");
        let buds = bonded_bt("36:32:62:36:31:33");
        let out = rule_au_117_personal_device_constellation(
            &RuleContext::new(&[car.clone(), buds]),
            "s",
            0,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-117");
        assert_eq!(out[0].severity, Severity::Medium);
        assert_eq!(
            out[0].entity_uids.len(),
            2,
            "the whole bonded kit is listed"
        );
    }

    #[test]
    fn au117_silent_on_a_single_pairing() {
        let only = bonded_bt("3C:5A:B4:11:22:33");
        assert!(
            rule_au_117_personal_device_constellation(&RuleContext::new(&[only]), "s", 0)
                .is_empty(),
            "a lone pairing is not a constellation"
        );
    }

    #[test]
    fn au117_silent_when_all_bonded_devices_use_privacy_macs() {
        // Both paired devices rotate privacy MACs — good OPSEC, no persistent
        // fingerprint, nothing to flag.
        let a = bonded_bt("36:32:62:36:31:33");
        let b = bonded_bt("7A:11:22:33:44:55");
        assert!(
            rule_au_117_personal_device_constellation(&RuleContext::new(&[a, b]), "s", 0)
                .is_empty(),
            "an all-privacy-MAC kit carries no persistent fingerprint"
        );
    }

    #[test]
    fn au117_ignores_unbonded_devices() {
        // A trackable device that is NOT bonded is a stranger's (AU-122's domain),
        // not part of the operator's constellation.
        let mine = bonded_bt("3C:5A:B4:11:22:33");
        let mut stranger = Entity::new(
            EntityKind::MacAddress,
            "3C:5A:B4:99:88:77",
            confidence::HIGH_PLUSPLUS,
            "s",
        );
        stranger.tag("bluetooth"); // seen, but not bonded
        let out =
            rule_au_117_personal_device_constellation(&RuleContext::new(&[mine, stranger]), "s", 0);
        assert!(
            out.is_empty(),
            "only one BONDED device — an unbonded stranger doesn't join the constellation"
        );
    }
}
