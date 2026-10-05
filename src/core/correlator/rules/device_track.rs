//! AU-122 — Trackable RF device vs. privacy-randomized address.
//!
//! A live signal-radar or WiGLE sweep plots every observed BLE / Wi-Fi MAC as a
//! map pin — but the pins are not equal, and treating them alike is a real
//! attribution error. A **universally-administered** address is the device's
//! true, persistent hardware identity: followable across time and place. A
//! **locally-administered** (randomized / private) address is a throwaway a
//! modern phone, AirTag, or SmartTag rotates every ~15 minutes — useless as a
//! tracking key and unattributable to any vendor (its prefix bytes are random).
//! The distinction is one bit: bit 1 (`0x02`) of the first octet.
//!
//! This rule partitions a sweep's MAC observations on exactly that bit — via the
//! shared [`crate::util::oui`] classifier the WiGLE path already uses, so "which
//! addresses are real hardware" never drifts between the two (Rule 4: delegate,
//! never copy) — and surfaces the operationally-actionable subset: the trackable
//! hardware devices present, vendor-named where the curated OUI table knows
//! them. It gates on RF-observation provenance (a `bluetooth` / `wifi-ap` /
//! `wigle` tag) so a breach-sourced router BSSID — AU-106's domain — never
//! masquerades as "a device in the operator's vicinity".
//!
//! Severity is **Medium**: a persistently-trackable device broadcasting in a
//! survey is an actionable privacy / attribution signal, not a critical
//! compromise. It fires only when the sweep holds ≥1 trackable hardware MAC and
//! ≥2 RF observations total — a partition worth stating, never a single-pin scan.

use super::*;
// Pure, offline, dependency-free OUI classifier (const table + a U/L-bit test;
// no I/O, no deps) — the same leaf-utility category `core` already draws on for
// `util::geometry` / `util::spf` CIDR maths / `util::abn` checksums. It is the
// one MAC classifier the WiGLE emit path also uses, so this rule and the radar
// tags can never disagree on which addresses are real hardware.
use crate::util::oui;

/// AU-122 — Trackable RF device vs. privacy-randomized address.
///
/// Entity-only: classifies every RF-observed `MacAddress` entity by the U/L bit
/// and emits one correlation naming the trackable hardware devices (the pins a
/// real device broadcasts) versus the randomized privacy addresses (rotated,
/// unfollowable). `entity_uids` carries the trackable MACs — the actionable
/// subset — in entity order for a stable render.
pub(in crate::core::correlator) fn rule_au_122_trackable_rf_device(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    /// A MacAddress entity is an RF observation (radar / WiGLE), not a
    /// breach-sourced BSSID, iff it carries one of these provenance tags.
    fn is_rf_observed(e: &Entity) -> bool {
        e.has_tag("bluetooth")
            || e.has_tag("bluetooth-beacon")
            || e.has_tag(crate::core::tags::WIFI_AP)
            || e.has_tag("wigle")
    }

    let mut trackable_uids: Vec<String> = Vec::new();
    let mut vendors: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut randomized = 0usize;

    for e in entities {
        if e.kind != EntityKind::MacAddress || !is_rf_observed(e) {
            continue;
        }
        match oui::is_locally_administered(&e.value) {
            Some(false) => {
                // Universally-administered — a real, persistent hardware MAC.
                trackable_uids.push(e.uid.clone());
                if let Some(info) = oui::classify_mac(&e.value) {
                    // Only name a vendor the curated table actually resolved;
                    // "Unknown" / "Unregistered" carry no attribution.
                    if !matches!(
                        info.class,
                        oui::DeviceClass::Unregistered
                            | oui::DeviceClass::Unknown
                            | oui::DeviceClass::Randomized
                    ) {
                        vendors.insert(info.vendor.to_string());
                    }
                }
            }
            Some(true) => randomized += 1,
            None => {} // unparseable first octet — ignore
        }
    }

    let t = trackable_uids.len();
    // Fire only on a real multi-observation sweep that holds ≥1 followable
    // device — never a trivial one-pin scan of the operator's own single AP.
    if t == 0 || t + randomized < 2 {
        return Vec::new();
    }

    let vendor_clause = if vendors.is_empty() {
        String::new()
    } else {
        let listed: Vec<&str> = vendors.iter().map(String::as_str).take(6).collect();
        format!(" (vendors: {})", listed.join(", "))
    };
    let randomized_clause = if randomized > 0 {
        format!(
            "; {randomized} further address{} locally-administered (randomized/private), rotated \
             for privacy and NOT trackable",
            if randomized == 1 { " is" } else { "es are" }
        )
    } else {
        String::new()
    };

    vec![Correlation::new(
        "AU-122",
        "Trackable RF device present",
        Severity::Medium,
        format!(
            "{t} broadcasting device{} carry a persistent, universally-administered MAC{vendor_clause} \
             — a real hardware identity followable across time and place{randomized_clause}. RF \
             pins are not equal: only the hardware MACs identify a device that can be tracked.",
            if t == 1 { "" } else { "s" },
        ),
        trackable_uids,
        scan_id,
        ts,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;

    fn rf_mac(value: &str, tag: &str) -> Entity {
        let mut e = Entity::new(
            EntityKind::MacAddress,
            value,
            confidence::HIGH_PLUSPLUS,
            "s",
        );
        e.tag(tag);
        e
    }

    #[test]
    fn au115_fires_and_lists_only_the_trackable_hardware_mac() {
        // A universally-administered device (0x3C, U/L bit clear) alongside the
        // screenshot's randomized address (0x36, U/L bit set) — both radar pins,
        // but only the first is a followable device.
        let hw = rf_mac("3C:5A:B4:11:22:33", "bluetooth");
        let rnd = rf_mac("36:32:62:36:31:33", "bluetooth");
        let out =
            rule_au_122_trackable_rf_device(&RuleContext::new(&[hw.clone(), rnd.clone()]), "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-122");
        assert_eq!(out[0].severity, Severity::Medium);
        assert!(
            out[0].entity_uids.contains(&hw.uid),
            "hardware MAC is actionable"
        );
        assert!(
            !out[0].entity_uids.contains(&rnd.uid),
            "a randomized privacy MAC must never be listed as trackable"
        );
    }

    #[test]
    fn au115_silent_when_only_randomized_addresses_are_seen() {
        // Every pin is a rotating privacy address — nothing followable.
        let a = rf_mac("36:32:62:36:31:33", "bluetooth");
        let b = rf_mac("7A:11:22:33:44:55", "wifi-ap"); // 0x7A U/L bit set
        assert!(
            rule_au_122_trackable_rf_device(&RuleContext::new(&[a, b]), "s", 0).is_empty(),
            "an all-randomized sweep has no trackable device"
        );
    }

    #[test]
    fn au115_ignores_a_non_rf_breach_sourced_mac() {
        // A universally-administered MAC WITHOUT an RF provenance tag (e.g. a
        // breach-sourced router BSSID) is AU-106's domain, not a radar sighting.
        let breach_bssid = Entity::new(
            EntityKind::MacAddress,
            "3C:5A:B4:11:22:33",
            confidence::MEDIUM_PLUS,
            "s",
        );
        let rnd = rf_mac("36:32:62:36:31:33", "bluetooth");
        assert!(
            rule_au_122_trackable_rf_device(&RuleContext::new(&[breach_bssid, rnd]), "s", 0)
                .is_empty(),
            "only RF-observed MACs count toward a vicinity device finding"
        );
    }
}
