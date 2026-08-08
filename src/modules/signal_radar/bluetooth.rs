//! Bluetooth scanner for signal_radar — parses `termux-bluetooth-scaninfo`
//! output.
//!
//! # Availability on the target platform — verified, and narrower than it looks
//!
//! **The official Termux:API ships no Bluetooth command at all.** Checked
//! against `termux/termux-api-package`'s `CMakeLists.txt`, which installs 62
//! `termux-*` scripts: `termux-wifi-scaninfo`, `termux-wifi-connectioninfo` and
//! `termux-wifi-enable` are all present, and the string "bluetooth" does not
//! occur anywhere in the file. The two upstream PRs that would add one —
//! `termux-api-package#187` and `termux-api#686`, and note they propose
//! `termux-bluetooth-scan`, a DIFFERENT name — are both still open with
//! changes requested.
//!
//! `termux-bluetooth-scaninfo` exists only in a third-party fork
//! (`StevenSalazarM/termux-app-bluetooth`), which needs a separately built APK
//! signed with the same key as the Termux app.
//!
//! Consequences this module is written around, rather than against:
//!
//!   * On a stock install the tool is simply absent.
//!     [`crate::modules::termux_sensor::read_and_parse`] already handles that
//!     correctly — it logs a capability gap and returns an empty result, and
//!     never presents "nothing looked" as "nothing is nearby".
//!   * Where the fork IS installed, its output is a JSON **object**, not the
//!     array of device records this file used to be the only consumer of. Its
//!     first invocation returns `{"message": "scanning bluetooth devices…"}`
//!     (an acknowledgement, not a result set) and a later one returns device
//!     entries. A parser that accepts only an array reported BOTH as
//!     `unparseable` — a hard `Err` that counts in `modules_errored` and feeds
//!     the circuit breaker, on a tool that was working exactly as designed.
//!   * That fork reports device NAMES ONLY, with no address whatsoever
//!     (`BluetoothAPI.java` does `deviceList.add(deviceName)`). A name is not a
//!     MAC and must never be minted as one — see [`ScanShape`].
//!
//! So this parser accepts every shape a real tool is known to emit, and the
//! rich-record shape the upstream PRs are heading toward, and mints entities
//! only from the fields actually present. What it will not do is invent an
//! address that was never observed.
//!
//! No `hcitool scan` fallback: this project's exclusive target is a no-root
//! Termux/Android install, where classic-BT `hcitool` is neither packaged
//! (no `bluez` in Termux's repo) nor usable even if sideloaded (an HCI
//! inquiry needs a raw Bluetooth socket/ioctl stock Android gates behind
//! privileges Termux cannot grant without root) — the fallback could never
//! actually fire on the real target device, only ever silently no-op.

use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleResult,
};

use super::SRC;

/// One device record from a tool that reports structured devices.
///
/// Every field is optional except by convention: the fork emits none of them,
/// and the upstream proposals disagree on which are present. `address` is
/// therefore `Option`, and a record without one still yields its name.
#[derive(Deserialize)]
pub(super) struct BtDevice {
    pub(super) address: Option<String>,
    pub(super) name: Option<String>,
    #[serde(rename = "type")]
    pub(super) bt_type: Option<String>,
    #[serde(rename = "bondState")]
    pub(super) bond_state: Option<String>,
}

/// The wire shapes `termux-bluetooth-scaninfo` is known to produce.
///
/// Untagged, so serde picks the arm that actually deserialises rather than
/// requiring a discriminant no tool emits. Order matters: `Devices` is tried
/// first so a rich record set is never degraded into the name-only arm.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum ScanShape {
    /// `[{"address": …, "name": …}, …]` — the structured form the upstream
    /// proposals are converging on, and the only form this file used to accept.
    Devices(Vec<BtDevice>),
    /// The fork's object form. `message` is a scan-lifecycle acknowledgement
    /// carrying no devices; `device` collects the name-only entries.
    ///
    /// Names alone cannot become `MacAddress` entities, so they are emitted as
    /// [`EntityKind::Ssid`] — the same kind `wifi::parse_scan` uses for a
    /// network name, and for the same reason: a broadcast friendly name is a
    /// searchable identifier in its own right (they are routinely personal —
    /// `"<given name>'s iPhone"` — which is precisely their OSINT value) but is
    /// trivially spoofed and names no hardware.
    Fork {
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        device: Option<String>,
    },
}

/// Parse whatever `termux-bluetooth-scaninfo` emitted.
pub(super) fn parse_bt_json(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
    if super::is_blank(stdout) {
        return Ok(ModuleResult::new());
    }
    let shape: ScanShape = serde_json::from_slice(stdout)
        .map_err(|e| super::unparseable(super::Sensor::BluetoothScan, &e))?;

    match shape {
        ScanShape::Devices(devices) => Ok(parse_devices(devices, scan_id)),
        // An acknowledgement is a successful, device-free answer — an empty
        // `Ok`, never an error. Reporting the fork's own start-of-scan message
        // as a malfunction is how a working tool trips the circuit breaker.
        //
        // It is also the single most likely reason an on-device sweep reports
        // no Bluetooth: the fork's protocol is a THREE-call toggle (permission
        // prompt, then start, then stop-and-report) and a scan issues exactly
        // ONE call, so the first sweep can only ever receive this
        // acknowledgement. Surfacing the tool's own words is the difference
        // between an operator seeing "no devices in range" and seeing that
        // nothing has been scanned yet.
        ScanShape::Fork {
            message,
            device: None,
        } => {
            if let Some(msg) = message {
                tracing::info!(
                    module = SRC,
                    sensor = super::Sensor::BluetoothScan.tool(),
                    response = %msg,
                    "bluetooth scan acknowledged but returned no devices — this tool \
                     reports results on a LATER invocation, so an empty Bluetooth \
                     result here is not an observation that nothing is nearby"
                );
            }
            Ok(ModuleResult::new())
        }
        ScanShape::Fork {
            device: Some(name), ..
        } => Ok(name_only_result(&name, scan_id)),
    }
}

/// Emit entities for a structured device list.
fn parse_devices(devices: Vec<BtDevice>, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::with_capacity(devices.len());

    for dev in devices {
        let name = dev.name.as_deref().map(str::trim).unwrap_or_default();
        let bt_type = dev.bt_type.as_deref().unwrap_or("unknown");
        let bond_state = dev.bond_state.as_deref().unwrap_or("unknown");
        let address = dev.address.as_deref().map(str::trim).unwrap_or_default();

        // Delegate to the canonical placeholder predicate instead of the
        // hand-rolled `is_empty() || == "00:00:00:00:00:00"` this used to
        // carry. That copy caught two of the three sentinels and missed
        // `02:00:00:00:00:00` — which is not an arbitrary third value but
        // `BluetoothAdapter.DEFAULT_MAC_ADDRESS`, the constant AOSP returns
        // from `getAddress()` to any caller without the signature-level
        // `LOCAL_MAC_ADDRESS` permission (Android 6+). Bluetooth is the exact
        // radio that sentinel comes from, so of the two sensors sharing this
        // guard, the one that hand-rolled it was the one that needed it most.
        //
        // `is_mac_address` is the second half: the fork reports names with no
        // address at all, and `classify_mac` reads a hex prefix, so without a
        // full-address check a friendly name like "Facade" would be minted as
        // a MacAddress and attributed to a vendor.
        let usable_address = !crate::util::oui::is_placeholder_bssid(address)
            && crate::util::oui::is_mac_address(address);

        if !usable_address {
            // No address, but a name is still a real observation. Dropping the
            // whole record (as this did) discards the only identifier the fork
            // — the sole shipping implementation — ever produces.
            if !name.is_empty() {
                result.extend(name_only_result(name, scan_id).entities);
            }
            continue;
        }

        let mut e = Entity::new(
            EntityKind::MacAddress,
            address,
            confidence::HIGH_PLUSPLUS,
            scan_id,
        );
        e.tag("bluetooth");
        e.tag(format!("bt-{}", bt_type.to_lowercase()));
        e.tag(format!("bond:{}", bond_state.to_lowercase()));

        let ev = Evidence::new(
            SRC,
            format!(
                "Bluetooth device: {}",
                if name.is_empty() { "<unknown>" } else { name }
            ),
        )
        .with_attr("name", if name.is_empty() { "<unknown>" } else { name })
        .with_attr("address", address)
        .with_attr("type", bt_type)
        .with_attr("bond_state", bond_state);

        // OUI classification — shared with the Wi-Fi sensor so both radios say
        // the same thing about a hardware address, including the
        // trackable/randomized partition AU-122 depends on.
        let ev = super::tag_oui(&mut e, ev, address);
        e.add_evidence(ev);

        result.push(e);

        // A Bluetooth friendly name is an identifier in its own right, exactly
        // as an SSID is, and is emitted alongside the address for the same
        // reason `wifi::parse_scan` emits one: it is independently searchable
        // and frequently carries a person's given name.
        result.entities.extend(name_entity(name, scan_id));
    }

    result
}

/// The `Ssid` entity for a Bluetooth broadcast name, or `None` when there is no
/// usable name. `"null"` is rejected explicitly: the fork stringifies a missing
/// name through `String.valueOf`, so the literal four characters reach the
/// parser as though they were the device's name.
fn name_entity(name: &str, scan_id: &str) -> Option<Entity> {
    let name = name.trim();
    if name.is_empty() || name == "null" {
        return None;
    }
    let mut e = Entity::new(EntityKind::Ssid, name, confidence::MEDIUM_HIGH, scan_id);
    e.tag("bluetooth");
    e.tag("device-sensor");
    e.add_evidence(Evidence::new(SRC, format!("Bluetooth device name: {name}")));
    Some(e)
}

/// Entities for a device known ONLY by its broadcast name.
fn name_only_result(name: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();
    result.entities.extend(name_entity(name, scan_id));
    result
}

/// Run bluetooth scan via `termux-bluetooth-scaninfo` (the Termux:API BLE/BT
/// scan shim — no root, no raw socket).
pub(super) async fn scan_bluetooth(scan_id: &str) -> Result<ModuleResult> {
    crate::modules::termux_sensor::read_and_parse(super::Sensor::BluetoothScan, |stdout| {
        parse_bt_json(stdout, scan_id)
    })
    .await
}
