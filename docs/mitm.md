# MITM Wi-Fi evidence gate

Huntsman's MITM module performs passive SSID, BSSID, and Wi-Fi security-advertisement checks in rootless Termux. It does not provide full MITM detection. Reports distinguish suspected, review, no_indicators_observed, and inconclusive; none is proof an attack has occurred or that a network is safe.

## Usage

1. Capture the Android OS-cached scan with termux-wifi-scaninfo > scan.json.
2. Independently confirm the permitted BSSIDs and security of the access point via its known trusted admin interface.
3. Enroll using: huntsman-recon mitm baseline 'MySSID' --file scan.json --output baseline.json --confirmed
4. Inspect via: huntsman-recon mitm assess --baseline baseline.json --file latest-scan.json
5. Or examine the device's current cache: huntsman-recon mitm assess --baseline baseline.json

The --confirmed flag records human confirmation, not cryptographic authentication. Baselines must not be enrolled from untrusted network inventories. Creating a baseline fails if its output path already exists.

## Remediation

For suspected or reviewed findings, do not connect to the suspicious access point; use Android Wi-Fi settings to disconnect or forget a questionable network if already joined, switch to cellular data if needed, and verify approved AP BSSIDs and security using trusted router management. Verify the actual Wi-Fi association before reconnecting. No automatic deauthentication, network disruption, credential rewriting, or unsupported Android association controls are attempted.

Unknown or changed BSSIDs can reflect legitimate mesh, multi-band radios, upgrades or management changes. Cached Android results and offline replays do not prove present signal proximity or observation UTC.

## Excluded coverage

The Android OS-cached Wi-Fi scan cannot prove ARP, DHCP, DNS or TLS interception, rogue VPNs, certificate substitution, cellular signalling attacks, or Wi-Fi deauthentication. The method does not implement ML or RSSI positioning algorithms from the cited papers: available data lack the required training, AP reference positions, timestamps and signalling traces. Detection accuracy for this implementation is unmeasured.

## Research

- https://arxiv.org/abs/2406.01927 — Wenjie Liu and Panos Papadimitratos, Position-based Rogue Access Point Detection (2024). Independent subset consistency and uncertainty motivate corroboration.
- https://arxiv.org/abs/2505.07724 — Shifat et al., Securing WiFi Fingerprint-based Indoor Localization Systems from Malicious Access Points (2025). Requires an adequately validated fingerprinting baseline.
- https://arxiv.org/abs/2401.04958 — Mubasshir, Karim and Bertino, Gotta Detect 'Em All (2024/2025). Reliably studied cellular detection relies on deeper L3 traces.
- https://arxiv.org/abs/2605.19232 — Oh et al., Devilray (2026). Reveals substantial blind spots in rogue-cell detectors, limiting what cell IDs alone can establish.

These papers motivate architecture and error bounds, rather than being represented as direct reproductions of their algorithms.

## Verification

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked --test mitm_cli
cargo test --locked mitm

CI verification and real Android AArch64 execution are release gates, not assumed successes.
