# Repository boundary: HSE and the HSE BLE Radar

Two repositories, two purposes. Each stays distinct; each uses the strongest part of the other through one narrow, tested seam.

| | **Huntsman Search Engine (HSE)** — this repository | **HSE BLE Radar** — [`EmmmmDeee/HSE-BLE-API-`](https://github.com/EmmmmDeee/HSE-BLE-API-) |
|---|---|---|
| Purpose | All-source OSINT / GEOINT / NETINT reconnaissance: 194 modules, one CLI/Web-UI binary, run in Termux on Android aarch64 | A standalone Android ARM64 wireless-intelligence app (BLE radar today) and the safe-Rust engine library behind it (`bleradar-core`) |
| Ships | A Termux binary (`install.sh`, source build) | An installable `HSE-BLE-Radar-arm64-<version>.apk`, published as a GitHub release |
| Owns | Modules, scan engine, correlator rules, storage, the HTTP API and UI, the installer | BLE/Wi-Fi reading rules, advertisement decoding, identity across address rotation, device history, signal/proximity math, the self-updater |
| Does not own | Any radio-reading rule the radar owns | Any OSINT module, scan engine, or Termux tooling |

## Dependency direction

```
HSE  ──(git dependency, pinned to a commit)──▶  bleradar-core
BLE Radar  ──────────── nothing from HSE at build time ─────────▶ (none)
```

- HSE depends on `bleradar-core`, exactly one git dependency, pinned to a full 40-hex `rev` (never a branch or tag), allowed by `deny.toml` for that repository alone.
- The radar never depends on HSE. Knowledge flows to it by the rule being written once, in `bleradar-core`, and pulled into HSE.
- Neither repository copies the other's code. A rule has one authority: the radar for every reading-interpretation rule (real-vs-placeholder address, RSSI reliability tiers, 802.11 channel, proximity band, BLE address type, advertisement decoding); HSE for everything else.

## The one seam in HSE

HSE consumes `bleradar-core` only in `src/modules/signal_radar/`, which parses the Termux sensor tools' output and maps the radar's answers onto HSE entities:

| Rule (radar authority) | Used for |
|---|---|
| `bleradar_core::is_real_device_address` | dropping placeholder / malformed BSSIDs and Bluetooth addresses |
| `bleradar_core::wifi_rssi_reliability` | the Wi-Fi observation confidence tier |
| `bleradar_core::wifi_channel` | the `channel:<n>` tag |
| `bleradar_core::wifi_proximity` | the `proximity:<band>` tag |

`tests/architecture.rs` enforces this: `ble_radar_dependency_is_pinned_and_consumed` fails if the dependency is not pinned to a commit, if it is referenced anywhere but `signal_radar`, if `signal_radar/wifi.rs` re-implements one of these rules, or if any other git dependency appears.

## Changing the seam

- **A new radar rule HSE needs:** add it to `bleradar-core` (with its tests and the radar's gates), bump the pinned `rev` here to the merged commit, call it from `signal_radar`.
- **A new use outside `signal_radar`:** change `ble_radar_dependency_is_pinned_and_consumed` and this document in the same commit, on purpose.
- **Bumping the pin:** only to a commit merged to the radar's `main` with its CI green.
- **Not shared, deliberately:** HSE's cell-tower vocabulary (`modules/device_cell`, `util::cell`) serves four HSE modules and has no in-app caller in the radar; it stays HSE's until the radar gains a cell-scanning surface.
