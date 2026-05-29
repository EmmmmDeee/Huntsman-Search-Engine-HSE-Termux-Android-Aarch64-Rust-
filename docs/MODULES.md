# Modules

A **module** is a self-contained collector that takes one `Target`, hits a
data source (or runs a local computation), and emits zero-or-more `Entity`
records. The engine knows nothing else — every module is a one-file change.

## Catalogue (86 modules)

### Network / identity modules (target-driven)

All free, no API key required. Sorted by priority (engine runs
higher-priority first; ordering doesn't affect output).

| Module | Targets | Cost | Passive | Priority | Output kinds |
|--------|---------|------|---------|----------|--------------|
| [`phone_intl`](#phone_intl)                 | `phone`               | free | **yes** | 140 | Phone (E.164, country) — offline |
| [`hudsonrock`](#hudsonrock)                 | `email`, `domain`     | free | no  | 130 | Email / Domain (stealer-log evidence) |
| `xposed_or_not`                             | `email`               | free | no  | 128 | Email (named-breach list) — pairs with hudsonrock for AU-001 |
| `username_search`                           | `username`            | free | no  | 110 | Url × N (per-platform profile links) — Sherlock/Maigret-style |
| `github_user`                               | `username`            | free | no  | 108 | Username + Person + Email + Url (GitHub public profile) |
| [`email_to_username`](#email_to_username)   | `email`               | free | **yes** | 95  | Username × N candidates |
| `gravatar`                                  | `email`               | free | no  | 85  | Email (Gravatar profile metadata) |
| [`alienvault_otx`](#alienvault_otx)         | `ip`, `domain`        | free | no  | 78  | IpAddress / Domain (threat-intel pulses + tags + TLP) |
| `wayback`                                   | `domain`              | free | no  | 38  | Domain (snapshot count + first/last seen) |
| [`crtsh`](#crtsh)                           | `domain`              | free | no  | 35  | Domain (subdomains via certificate transparency) |
| [`whois`](#whois)                           | `domain`, `ip`        | free | no  | 32  | Domain / IpAddress + contact Emails + nameserver Domains (18 fields) |
| [`dns_resolver`](#dns_resolver)             | `domain`              | free | no  | 30  | IpAddress (A/AAAA), Domain (MX/NS/SOA), Email (SOA admin) |
| `reverse_dns`                               | `ip`                  | free | no  | 29  | Domain × N (PTR records) |
| [`ip_geo`](#ip_geo)                         | `ip`                  | free | no  | 28  | Coordinates, Organisation |
| `bgpview`                                   | `asn`, `ip`           | free | no  | 25  | Asn (holder + contacts) — also reverse-maps IPs to announcing ASN |

### OSINT orchestration modules (v1.0+)

| Module | Targets | Cost | Passive | Priority | Output kinds |
|--------|---------|------|---------|----------|--------------|
| `keybase`          | `username`              | free      | no | 100 | Username + Person + Address + Domain (identity graph with crypto proofs) |
| `seon`             | `email`, `phone`        | key-gated | no | 95  | Email/Phone (cross-platform presence across 250+ services) |
| `epieos`           | `email`                 | key-gated | no | 92  | Email + Person + Username + Address (Google profile, Maps reviews, Skype) |
| `emailrep`         | `email`                 | key-gated | no | 90  | Email (reputation score, breach exposure, social profiles) |
| `proxycurl`        | `username`, `url`, `email` | paid      | no | 88  | Person + Email + Phone + Organisation + Address (LinkedIn extraction) |
| `opencorporates`   | `organisation`, `name`, `abn_acn` | free      | no | 80  | Organisation + Address (AU company registry) |
| `photon`           | `address`, `coordinates`| free      | no | 20  | Coordinates / Address (Komoot geocoder for corroboration) |
| `mylnikov`         | `mac_address`           | free      | no | 17  | Coordinates (free BSSID-to-GPS, no auth) |
| `overpass`         | `coordinates`           | free      | no | 15  | Coordinates (OSM infrastructure — towers, substations, cameras) |
| `pwned_passwords`  | `email`, `username`     | free      | yes| 115 | Email/Username (HIBP k-Anonymity SHA-1 breach check) |
| `sunrise_sunset`   | `coordinates`           | free      | no | 10  | Coordinates (solar phase timestamps for chronolocation) |

### Termux sensors (v0.6+, environmental — accept any target)

> **v0.6+ consolidation:** the earlier split sensors (`gps_fix`, `wifi_scan`,
> `wifi_connect`, `cell_survey`, `arp_scan`, `net_interfaces`) were merged into
> the four modules below.

| Module | Cost | Passive | Termux binary / source | Output kinds | Needs `termux-api` |
|--------|------|---------|------------------------|--------------|---------------------|
| [`device_sensors`](#device_sensors) | free | **yes** | `termux-location`, `termux-wifi-connectioninfo` | Coordinates (GPS), MacAddress (connected AP), IpAddress | yes |
| [`wifi_intel`](#wifi_intel)         | free | **yes** | `termux-wifi-scaninfo`                          | MacAddress × N (visible APs) + BSSID geo | yes |
| [`cell_intel`](#cell_intel)         | free | **yes** | `termux-telephony-cellinfo`                     | cell-tower info; offline MCC→country fallback | partial |
| [`local_net`](#local_net)           | free | **yes** | `/sys/class/net`, `/proc/net/arp` (file I/O)    | IpAddress + MacAddress (ARP), local interfaces | no |

All sensor modules are **free** (no API key required) and **passive**. They fire
on every scan as environmental enrichment. Off-device — or without the
`termux-api` package + Termux:API APK — the `termux-*`-backed modules **no-op
cleanly** (return empty, never a `module_error`); `local_net` is pure file I/O
and works wherever those paths exist. `hse doctor --bundle` lists which sensor
binaries are present.

### Target-kind coverage matrix

| Target | Modules that fire |
|---|---|
| `email`       | hudsonrock + xposed_or_not + email_to_username + gravatar + seon + emailrep + epieos + pwned_passwords + hibp + dehashed + contact_enrich |
| `username`    | username_search + github_user + keybase + proxycurl + social_probe |
| `phone`       | phone_intl + seon + contact_enrich |
| `full_name`   | dehashed + opencorporates + proxycurl |
| `domain`      | hudsonrock + alienvault_otx + crtsh + dns_resolver + whois + wayback + dehashed |
| `ip`          | alienvault_otx + whois + reverse_dns + ip_geo + bgpview + shodan |
| `asn`         | bgpview |
| `coordinates` | wigle + overpass + sunrise_sunset + photon + geocode |
| `address`     | geocode + photon |
| `mac_address` | wigle + mylnikov |
| `url`         | proxycurl + web_crawler + wayback + exif_geo + doc_meta |
| `organisation`| opencorporates + abn_lookup |

Any target also fires the 4 Termux sensor modules (passive; no-op without
`termux-api`, except `local_net` which uses local file I/O).

Suppress the sensor suite for a particular scan with:
```bash
hse scan --kind email --value foo@bar.com \
  --exclude device_sensors,wifi_intel,cell_intel,local_net
```
…or use the allowlist `--modules` flag to opt in only the modules you
want.

---

## Synergy map

The expansion engine chains modules by producing entities whose `EntityKind`
maps to a `TargetKind` other modules accept. With **`hse scan --depth 2`**
the following chains emerge automatically from the 5 modules above:

```
Seed: Email (foo@example.com)
├─ hudsonrock       → Email (with breach evidence — same as input)
└─ email_to_username → Username × N
   └─ (no v0.2 module accepts Username yet — chain ends here)

Seed: Domain (example.com)
├─ hudsonrock      → Domain (with breach evidence)
├─ crtsh           → Domain × N subdomains  ↘
│                                            ↓ depth=2 round
└─ dns_resolver    → IpAddress, Domain (MX) — re-feed via expansion
   └─ per subdomain (depth=1): dns_resolver, hudsonrock, crtsh
      └─ per discovered IP (depth=2): ip_geo → Coordinates, Organisation
```

`min_expand_confidence` (default 0.75) prevents low-confidence speculative
expansions from runaway. Adjust as needed via `--min-expand-confidence`.

---

## Modules in detail

### `hudsonrock`

Public stealer-log lookup. Free, no key. Source: HudsonRock Cavalier API
(`cavalier.hudsonrock.com/api/json/v2/osint-tools/...`).

**Targets accepted**: `email`, `domain`.

**Returns**: the input as an `Email` or `Domain` entity, tagged
`breach` + `stealer-log`, with one evidence record per affected machine
containing aggregate metadata only:

- `computer_name`
- `operating_system`
- `date_compromised`
- `malware_path`
- `credential_count` (integer count — **no credentials themselves**)

**Security**: credential field arrays are read for counting purposes only;
their contents are never persisted. This is enforced by the module's
`Deserialize` only pulling `serde_json::Value` and immediately discarding it.

**Quirks**: returns HTTP 404 for unknown targets — handled as "no hits"
rather than an error.

### `email_to_username`

Pure local derivation. **No network**. Marked `is_passive() == true`.

**Targets accepted**: `email`.

**Algorithm**: from the email local part it produces these `Username`
candidates (deduplicated, each `length > 2`):

1. The full local part (`john.doe+work`).
2. Local part with `+tag` suffix stripped (`john.doe`).
3. De-tagged local with trailing digits stripped (`john.doe` → `john.doe`,
   `joe42` → `joe`).
4. De-tagged local with separators collapsed (`john.doe` → `johndoe`).
5. Each token from splitting on `.`, `_`, `-` (`john`, `doe`).

Confidence: 0.45 (Probable) — low enough that, with the default
`min_expand_confidence = 0.75`, derived usernames do NOT auto-trigger
further scans. Pass `--min-expand-confidence 0.4` to opt into chaining.

### `crtsh`

Certificate-transparency subdomain enumeration. Free, no key. Source:
`crt.sh?q=%.<domain>&output=json`.

**Targets accepted**: `domain`.

**Returns**: one `Domain` entity per unique subdomain found (excluding the
parent), confidence 0.88, tagged `ct-log`. Evidence records the issuer
name and not-before timestamp.

**Quirks**: `crt.sh` occasionally returns truncated JSON when the result
set is huge — modules that fail this way return a `module error` event
rather than crashing the scan.

### `dns_resolver`

Cloudflare DNS resolver (`hickory-resolver` 0.24 with `cloudflare()`
config). Free, no key.

**Targets accepted**: `domain`.

**Returns**:
- One `IpAddress` entity per A record (confidence 0.95).
- One `Domain` entity per MX record exchange (confidence 0.85, tagged `mx`).
- One enriched `Domain` entity for the parent if any TXT records exist
  (confidence 0.90, with `txt_records` evidence attribute joining them with
  ` | `).

**Quirks**: errors from any individual record type (A / MX / TXT) are
silently swallowed inside the module — partial results are still returned.

### `alienvault_otx`

Public threat-intel pulse count from
[AlienVault OTX](https://otx.alienvault.com/). Free, no key.

**Targets accepted**: `ip`, `domain`.

**Returns**: one `IpAddress` or `Domain` entity (depending on target kind),
confidence 0.72, tagged `threat-intel`. Evidence records `pulse_count` and
`indicator_type`. No entity is emitted if the target has zero pulses.

**Quirks**: 404 (unknown indicator) is treated as "no findings"
rather than an error. Rate limits are generous for the public endpoint;
no throttling needed for normal use.

### `whois`

Raw whois protocol over TCP port 43. Free, no key, no root.

**Targets accepted**: `domain`, `ip`.

**Algorithm**: queries `whois.iana.org:43` for the target, follows one
referral hop to the authoritative whois server, and parses the response
for `registrar`, `created`, `expires`, `name_servers`, and
`registrant_email`. The parser is line-prefix based and case-insensitive
to handle the half-dozen mostly-but-not-quite-RFC-3912 dialects in use.

**Returns**: one `Domain` (or `IpAddress`) entity, confidence 0.85,
with evidence containing whatever fields the response actually included.
Returns an empty `ModuleResult` if none of those fields could be parsed
(no entity is better than a noisy empty one).

**Quirks**: each lookup makes 1–2 TCP connections; each is bounded by a
4 s timeout. Failures (network, timeout, malformed response) produce a
`module_error` event and contribute no entities, but never crash the scan.

### `local_net`

Pure passive observation of the device's own network position — reads
`/sys/class/net/*/address` + `/operstate` (interfaces) then
`/proc/net/arp` (the kernel's resolved ARP table) via `tokio::fs`. No
`termux-api`, no network traffic, no root. Consolidates the former
`net_interfaces` + `arp_scan` modules.

**Targets accepted**: any (sensor) — local-network data is environmental
and independent of the scan target.
**Off-device**: no `/sys/class/net` or `/proc/net/arp` on macOS/Windows →
empty `ModuleResult` (clean no-op, no `module_error`).

**Returns**:
- one `MacAddress` entity per non-loopback interface, confidence 0.95,
  tagged `local-interface`; evidence records the interface name (`wlan0`
  etc.) and `operstate` (`up`/`down`/`unknown`).
- one `IpAddress` + one `MacAddress` per complete ARP row (rows with the
  placeholder `00:00:00:00:00:00` MAC are skipped), confidence 0.95;
  evidence carries the cross-reference (IP↔MAC↔interface).

### `wifi_intel`

Unified WiFi intelligence in a **single** `termux-wifi-scaninfo`
invocation — AP enumeration *and* BSSID geolocation. Consolidates the
former `wifi_scan` (AP → `MacAddress`) and `bssid_locate` (strongest
BSSIDs → WiGLE detail → `Coordinates`/`Address`), halving the radio-scan
overhead on-device. WiGLE auth via `HUNTSMAN_WIGLE_USER` /
`HUNTSMAN_WIGLE_TOKEN` (HTTP Basic, hardcoded fallback, same as `wigle`).

**Targets accepted**: any (sensor).
**Off-device** or `termux-api` missing: helper returns `None` → empty
`ModuleResult` (no `module_error`).

**Returns**:
- one `MacAddress` entity per visible AP (BSSID-keyed), confidence 0.95,
  tagged `wifi-ap`; evidence: SSID (or `<hidden>`), frequency, RSSI,
  timestamp.
- for the top-5 strongest BSSIDs, a WiGLE detail lookup yields
  `Coordinates` (+ `Address` where available) entities geolocating the AP.

### `device_sensors`

Device location sensors in one passive pass — invokes
`termux-wifi-connectioninfo` (3 s ceiling) then
`termux-location -p network -r once` (15 s ceiling). Consolidates the
former `wifi_connect` + `gps_fix` modules. Free, no key. Requires the
Termux:API APK with Location permission granted in Android Settings.

**Targets accepted**: any (sensor).
**Off-device** or `termux-api` missing: clean no-op.

**Returns**:
- *Connected WiFi* (skipped if disconnected — `02:00:00:00:00:00` MAC and
  `0.0.0.0` IP are filtered): one `MacAddress` for the connected AP
  tagged `wifi-connected` (evidence: SSID, frequency, RSSI, link-speed,
  supplicant-state) + one `IpAddress` for the device's local IP tagged
  `local-wifi`.
- *Location fix*: one `Coordinates` entity (`lat,lon`, 7-dp), tagged
  `geoint` and `provider:<network|gps>`, confidence 0.90 for GPS / 0.65
  for network; evidence captures latitude, longitude, altitude,
  accuracy-metres, speed, bearing, provider.

**Quirks**: the network provider is much faster than `gps` (~1 s vs
minutes) and works indoors. The 15 s timeout caps the wait when the
device genuinely can't acquire a fix.

### `cell_intel`

Cell-tower survey **and** geolocation in a single
`termux-telephony-cellinfo` call. Consolidates the former `cell_survey` +
`cell_locate` modules. Free; Android Q+ restricts cell info to apps with
foreground location permission, so ensure Termux:API is location-allowed.

**Targets accepted**: any (sensor).
**Off-device** or `termux-api` missing: clean no-op.

**Returns**, per visible cell:
- one `DeviceId` entity keyed `<mcc>-<mnc>-<lac|tac>-<cid>` (TAC for
  LTE/NR, LAC for GSM/UMTS), confidence 0.80, tagged `cell-tower` and
  `radio:<lte|gsm|umts|nr>`; evidence: type, MCC, MNC, LAC/TAC, CID, PCI,
  dBm, ASU, level, registered.
- one `Coordinates` entity geolocating the tower, via OpenCelliD /
  UnwiredLabs (free tier 100 req/day, `HUNTSMAN_OPENCELLID_KEY`) when a
  key is set, falling back to a built-in **offline** MCC→country centroid
  (coarse) so the module still produces geo even with no key and no
  network.

**Quirks**: `mcc`/`mnc` arrive as either `"505"` (string) or `505`
(integer) across Android versions; the parser normalises both.

### `ip_geo`

ip-api.com IP geolocation. Free tier, **HTTP only** (HTTPS requires paid plan).

**Targets accepted**: `ip`.

**Returns**:
- One `Coordinates` entity (`lat,lon` with 6-dp precision) if lat/lon present,
  tagged `geoint`, confidence 0.70. Evidence captures country, region, city.
- One `Organisation` entity from the `org` field if present, confidence 0.65.
  Evidence carries the ASN.

**Quirks**: ip-api free tier is rate-limited to 45 req/min from a single IP.
For bulk use, throttle with `--throttle 1400` (≈ 43 req/min). Failures
return an empty `ModuleResult` rather than an error.

---

## Adding a module

The full walkthrough is in [`CONTRIBUTING.md`](../CONTRIBUTING.md#adding-a-new-module).
TL;DR — three changes, all in one PR:

1. `src/modules/your_module.rs` — implement `Module`.
2. `src/modules/mod.rs` — `pub mod your_module;` + push `Arc::new(your_module::YourModule)` into `registry()`.
3. `docs/MODULES.md` — add a row to the catalogue and a section explaining
   what it returns and its quirks.

### Module-author checklist

Before opening the PR, confirm:

- [ ] `name()` is `snake_case` and unique
- [ ] `priority()` slots sensibly into the existing ordering
- [ ] `cost()` is correctly `Free` / `KeyGated` / `Paid`
- [ ] `is_passive()` returns `true` only for genuinely zero-network modules
- [ ] `accepts()` covers every `TargetKind` the module can handle and only those
- [ ] If key-gated: uses `ctx.key("HUNTSMAN_FOO_KEY")?` (returns `Error::MissingKey`,
  which the engine handles as a logged skip rather than scan failure)
- [ ] All errors go through `Error::module("module_name", "message")`
- [ ] Passwords / credentials are never written to evidence — even if the
  upstream API returns them (see `hudsonrock` for the pattern)
- [ ] At least one unit test (the `accepts()` test is the minimum)
- [ ] Module survives upstream API outage: 4xx / 5xx / malformed JSON /
  timeout are handled without panicking
