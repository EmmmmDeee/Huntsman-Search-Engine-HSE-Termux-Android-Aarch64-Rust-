# Huntsman mobile Radar and BLE companion

The Radar tab at `#/radar` renders **Wi-Fi** observations from Android's Termux:API
scan cache and, when the operator explicitly enables it, **BLE** devices from
the separate `HSE-BLE-API-` Android application. Huntsman itself does not
access BLE hardware. The companion app remains the authoritative BLE collector
and is not bundled into the `huntsman-recon` Termux binary.

## Use both apps on one unrooted Android phone

1. Install the HSE BLE Radar Android APK from its own trusted project release.
   Launch the app, grant the Android Bluetooth/location permissions it requests,
   and start its BLE scan. Its local API is bound to `127.0.0.1:8080`.
2. In Termux, run Huntsman on a **different loopback port**, with the bridge
   explicitly enabled:

   ```sh
   HUNTSMAN_BLE_RADAR=1 huntsman-recon serve --bind 127.0.0.1:8090
   ```

3. On the same phone, open `http://127.0.0.1:8090/#/radar` and press **Scan**.

The BLE companion at `127.0.0.1:8080` and Huntsman at `127.0.0.1:8090`
cannot share a port. Huntsman fails before binding if the bridge is enabled
with its default port 8080 or with a non-loopback/public listening address.
Without `HUNTSMAN_BLE_RADAR=1`, the `GET /api/radar/ble` endpoint answers
404 and the UI reports BLE as unavailable rather than manufacturing results.

**Scan** makes one request to Huntsman's Wi-Fi cache adapter and one read-only
request to the companion snapshot. **Stop** stops repeated browser reads; it
does not stop the companion's Android scanner. Use the companion app to start
or stop active BLE scanning. Low / Balanced / Fast adjust *read cadence* only
(60 / 30 / 15 seconds), not Android's hardware scan policy. Hidden/inactive
Android processes and permission changes can make the companion unavailable.

## Transport and trust boundary

Huntsman exposes `GET /api/radar/ble` only after opt-in and only on a
loopback listener. It uses the same lookup-header, same-origin, rate-limit,
no-body and no-query guards as its Wi-Fi radar. The binary makes one bounded
read-only HTTP GET to **exactly** `127.0.0.1:8080/api/devices`; no arbitrary
URL, host, port, credential forwarding, remote endpoint or active scan
request is accepted. The adapter checks HTTP status, Content-Type,
Content-Length and JSON structure, with 128 KiB maximum response size and
short socket timeouts. The source label
`local_ble_companion_unverified` means that **a response from that local
port is not cryptographic proof of the responding app's identity**. Android
permission grants and sensor readings cannot be attested from this bridge.

Wi-Fi markers are squares and BLE markers are circles, based on observed RSSI
when present. The **angle** comes from a deterministic hash only, not a
measured bearing. Ring radius is a relative signal indicator; signal bars
are not metres. Where the BLE app reports `distance_m`, the UI explicitly
marks it as an *RSSI estimate* (not confirmed distance). BLE manufacturer,
name, identity and device association are device-reported or derived claims.
Unknown Bluetooth Classic devices are not counted as zero; that sensor has
no connected live source yet.

The `trackers` filter is the existing, separately initiated, unconfirmed
Wi-Fi **cross-cell recurrence** report, not a finding that a person was
followed or monitored. The original Wi-Fi, cellular, and recurrence evidence
tables remain available below the visualisation.

## Acceptance checks

- Page load performs **zero** radio or companion fetches.
- Explicit Scan reads the Wi-Fi cache and BLE snapshot without cross-site
  requests or changing Android scanning state.
- Android companion absent/disabled/busy => no fabricated BLE observation.
- Mock BLE fixture renders one circle and one BLE card; Wi-Fi still renders
  square markers and evidence.
- Radio filters, source fields and combined JSON/CSV preserve distinctions.
- A spoofed/malformed or oversized local HTTP response is refused.
- Android device acceptance requires both apps running concurrently with
  permissions granted; desktop CI/browser fixtures cannot prove that.
