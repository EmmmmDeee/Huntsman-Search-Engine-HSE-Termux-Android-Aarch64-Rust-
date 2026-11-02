//! Rhinser native interoperability boundary: a bounded, read-only, operator-submitted
//! fixture format. No JNI, Android framework, radio control, card emulation, network,
//! remote agent, BLE pairing or BLE scanning occurs here.
//!
//! Android companion apps may export schema-versioned JSON after explicit user
//! interaction. This parser does not authenticate a companion or its claims.

use serde::{Deserialize, Serialize};

use crate::rhinser_nfc::{self, ApduInspection, NdefInspection};

pub const MAX_CAPTURE_BYTES: u64 = 64 * 1024;
const MAX_EVENTS: usize = 64;

/// An intentionally minimal, non-identifying interchange envelope. All timestamps
/// and consent flags are *claims supplied by the caller*, not device attestations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureEnvelope {
    schema_version: u8,
    captured_unix_ms: u64,
    operator_consented: bool,
    events: Vec<CaptureEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BluetoothTransport {
    Ble,
    Classic,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CaptureEvent {
    Ndef {
        hex: String,
    },
    Apdu {
        hex: String,
    },
    Bluetooth {
        transport: BluetoothTransport,
        rssi_dbm: i16,
        bonded: bool,
        randomized_address: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeObservation {
    Ndef {
        inspection: NdefInspection,
    },
    Apdu {
        inspection: ApduInspection,
    },
    Bluetooth {
        transport: &'static str,
        signal_class: &'static str,
        bonded: bool,
        address_class: &'static str,
    },
}

#[derive(Debug, Serialize)]
pub struct NativeCaptureReport {
    pub schema_version: u8,
    pub captured_unix_ms_claim: u64,
    pub evidence_role: &'static str,
    pub transport_verified: bool,
    pub device_attested: bool,
    pub radio_access: bool,
    pub observations: Vec<NativeObservation>,
}

/// Parse an offline Android companion fixture. No hidden defaults, no network,
/// no raw NFC payload, MAC, device name or proximity distance in the report.
///
/// # Errors
/// Invalid schema, missing consent flag, excessive event count, bad frame or
/// impossible RSSI. The caller must verify companion authenticity separately.
pub fn inspect_capture_json(bytes: &[u8]) -> Result<NativeCaptureReport, String> {
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CAPTURE_BYTES {
        return Err("capture file must contain 1-65536 bytes".to_owned());
    }
    let input: CaptureEnvelope =
        serde_json::from_slice(bytes).map_err(|_| "capture JSON schema invalid".to_owned())?;
    if input.schema_version != 1 {
        return Err("unsupported capture schema version".to_owned());
    }
    if !input.operator_consented {
        return Err("capture requires an explicit operator consent flag".to_owned());
    }
    if input.captured_unix_ms == 0 {
        return Err("capture timestamp must be supplied".to_owned());
    }
    if input.events.is_empty() || input.events.len() > MAX_EVENTS {
        return Err("capture must contain 1-64 events".to_owned());
    }

    let mut observations = Vec::with_capacity(input.events.len());
    for event in input.events {
        let observation = match event {
            CaptureEvent::Ndef { hex } => {
                let data = rhinser_nfc::decode_hex(&hex)?;
                NativeObservation::Ndef {
                    inspection: rhinser_nfc::inspect_ndef(&data)?,
                }
            }
            CaptureEvent::Apdu { hex } => {
                let data = rhinser_nfc::decode_hex(&hex)?;
                NativeObservation::Apdu {
                    inspection: rhinser_nfc::inspect_apdu(&data)?,
                }
            }
            CaptureEvent::Bluetooth {
                transport,
                rssi_dbm,
                bonded,
                randomized_address,
            } => {
                if !(-127..=20).contains(&rssi_dbm) {
                    return Err("Bluetooth RSSI is outside the accepted range".to_owned());
                }
                // RSSI is not a trustworthy distance measurement.
                let signal_class = if rssi_dbm >= -55 {
                    "high"
                } else if rssi_dbm >= -75 {
                    "medium"
                } else {
                    "low"
                };
                NativeObservation::Bluetooth {
                    transport: match transport {
                        BluetoothTransport::Ble => "ble",
                        BluetoothTransport::Classic => "classic",
                    },
                    signal_class,
                    bonded,
                    address_class: if randomized_address {
                        "randomized_or_private"
                    } else {
                        "as_reported_nonrandom"
                    },
                }
            }
        };
        observations.push(observation);
    }
    Ok(NativeCaptureReport {
        schema_version: 1,
        captured_unix_ms_claim: input.captured_unix_ms,
        evidence_role: "operator_submitted_unverified",
        transport_verified: false,
        device_attested: false,
        radio_access: false,
        observations,
    })
}

/// Deterministically emulate the visual scoring range of the separate prank
/// application. Output is ALWAYS marked simulation, never a finding or sensor
/// observation. This is not cryptographic randomness.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DemoSweep {
    pub mode: &'static str,
    pub evidence_role: &'static str,
    pub sensor_observation: bool,
    pub elapsed_seconds: u8,
    pub score_tenths: u16,
}

#[must_use]
pub fn simulate_demo(seed: u64) -> DemoSweep {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    DemoSweep {
        mode: "simulation_only",
        evidence_role: "not_evidence",
        sensor_observation: false,
        elapsed_seconds: 11 + (state % 7) as u8,
        score_tenths: 940 + ((state >> 13) % 60) as u16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        br#"{"schema_version":1,"captured_unix_ms":1730000000000,"operator_consented":true,"events":[{"kind":"ndef","hex":"D101055402656E4869"},{"kind":"apdu","hex":"00A40400023F00"},{"kind":"bluetooth","transport":"ble","rssi_dbm":-66,"bonded":false,"randomized_address":true}]}"#.to_vec()
    }

    #[test]
    fn fixture_classifies_without_identity_or_network_access() {
        let report = inspect_capture_json(&sample()).unwrap();
        assert_eq!(report.observations.len(), 3);
        assert_eq!(report.evidence_role, "operator_submitted_unverified");
        assert!(!report.radio_access);
        assert!(!report.device_attested);
        assert!(matches!(
            &report.observations[0],
            NativeObservation::Ndef { inspection } if inspection.records == 1
        ));
        assert!(matches!(
            &report.observations[1],
            NativeObservation::Apdu { inspection } if inspection.data_bytes == 2
        ));
        assert!(matches!(
            &report.observations[2],
            NativeObservation::Bluetooth { transport: "ble", signal_class: "medium", .. }
        ));
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains("D1010554"));
        assert!(!rendered.contains("00A40400"));
        assert!(!rendered.contains("distance"));
    }

    #[test]
    fn refuse_untrusted_or_unbounded_envelopes() {
        for data in [
            br#"{}"#.as_slice(),
            br#"{"schema_version":2,"captured_unix_ms":1,"operator_consented":true,"events":[]}"#,
            br#"{"schema_version":1,"captured_unix_ms":1,"operator_consented":false,"events":[{"kind":"apdu","hex":"9000"}]}"#,
            br#"{"schema_version":1,"captured_unix_ms":1,"operator_consented":true,"events":[{"kind":"bluetooth","transport":"ble","rssi_dbm":-999,"bonded":false,"randomized_address":true}]}"#,
            br#"{"schema_version":1,"captured_unix_ms":1,"operator_consented":true,"events":[{"kind":"apdu","hex":"9000","secret":"injected"}]}"#,
        ] {
            assert!(inspect_capture_json(data).is_err());
        }
        assert!(inspect_capture_json(&vec![b' '; 65_537]).is_err());
    }

    #[test]
    fn demo_is_deterministic_and_never_evidence() {
        let a = simulate_demo(42);
        assert_eq!(a, simulate_demo(42));
        assert_eq!(a.mode, "simulation_only");
        assert!(!a.sensor_observation);
        assert!((11..=17).contains(&a.elapsed_seconds));
        assert!((940..=999).contains(&a.score_tenths));
    }
}
