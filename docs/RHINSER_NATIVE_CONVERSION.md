# Rhinser native Rust conversion — integration contract

**Engineering status:** new native Rust compatibility *interfaces*, **not** an assertion that the three Android APKs have been completely translated or executed. Target: Android Termux AArch64 without root; Rust owns every parser and decision, Bash remains orchestration-only. Existing catalogue, casebook, evidence and NFC readers are reused.

## Source files and verified static coverage

- \`rhinse-osint.apk\`: SHA-256 \`e6be6b6bbff2128cf72a34d1a64d25fbaf7c121a0ce803e60e45bdb97f363036\`, 132 app classes and 700 distinct application class/method-name pairs.
- \`Rhinser.apk\`: SHA-256 \`6a41162f2cf1d59a8689c01a685cd6cde06752c57a02b7177ef009bed7c9593a\`, 38 app classes and 316 name pairs.
- \`RHINSE-SCAN-DETECT.apk\`: SHA-256 \`30833ef95b4f504cd4db0919bfc5dc6743590d9e33d25ed424fc1cb1d42d68c4\`, 12 app classes and 35 name pairs.

**Total enumerated:** 182 class entries, 1,051 distinct class/method-name pairs, 950 ZIP resources. DEX method-name enumeration is not a method-body decompilation and cannot establish complete behavioural parity. Preserve original packages separately. The original APKs use **three different signing certificates**.

## Pure Rust components

| Original area | Huntsman native owner | Status |
| --- | --- | --- |
| 83 Australian public-source entries | \`rhinser_catalog\` | Existing typed, offline directory; link validity separate |
| Case records, notes, evidence leads, bookmarks, favourites, recent tools and settings | \`rhinser_workspace\` | Existing bounded JSON workspace |
| ISO 7816 APDUs, NDEF headers/types | \`rhinser_nfc\` | Existing read-only offline decoder |
| Saved NFC capture envelope and BLE observations | \`rhinser_native\` | New input validator; untrusted operator-controlled fixture |
| Simulated prank scanner scores/timing | \`rhinser_native::simulate_demo\` | New deterministic **simulation-only**, never evidence |
| Android NFC and Bluetooth runtime | No direct Termux equivalent | Native Android companion + explicit permissions and user-driven export required |
| Payment card emulation, card writing and key-attack routines | Not integrated | Distinct sensitive capabilities; no physical-card parity asserted |
| Remote-control listener and Python agent | Not integrated | Excluded from passive OSINT; any diagnostics companion must require authentication, user visibility and consent |
| Original Android activities/Room migration/UI | Partial Web UI and workspace | Full original runtime/UI parity **not established** |

## Offline capture envelope

Minimal operator-supplied JSON:
\`\`\`json
{
  "schema_version": 1,
  "captured_unix_ms": 1730000000000,
  "operator_consented": true,
  "events": [
    {"kind": "ndef", "hex": "D101055402656E4869"},
    {"kind": "apdu", "hex": "00A40400023F00"},
    {"kind": "bluetooth", "transport": "ble", "rssi_dbm": -66,
     "bonded": false, "randomized_address": true}
  ]
}
\`\`\`

Save this locally, then run \`huntsman-recon osint native CAPTURE.json\`. A Bluetooth event contains no MAC/name, the output contains no unredacted NFC payload, a timestamp is explicitly marked a client claim, and RSSI only maps to an approximate signal class—not distance. Inputs exceeding 64 KiB, 64 events, an incompatible schema, missing consent, malformed NDEF/APDU or invalid RSSI are rejected. This **does not access or authenticate a physical sensor**.

Demo: \`huntsman-recon osint demo 42\` emits the original scanner's approximate timing and score range but is hard-labelled \`simulation_only\` / \`not_evidence\`.

## Real-device dependencies and verification

A genuinely functioning NFC/Bluetooth bridge requires an Android UI/permission layer using Android NFC/Bluetooth APIs, with an explicit opt-in export to this Rust schema. A pure Termux CLI cannot acquire those framework callbacks solely by parsing code. The companion must authenticate the observation source and record permissions, collection timestamps, manufacturer capabilities, SDK compatibility and cryptographic provenance separately.

Run \`cargo fmt --all -- --check\`, \`cargo clippy --all-targets -- -D warnings\`, \`cargo test --locked\`, Android aarch64 cross-build, host-browser/UI checks, and **actual physical Termux acceptance**. Cross-compilation or a JSON fixture alone does not establish 100% application conversion.
