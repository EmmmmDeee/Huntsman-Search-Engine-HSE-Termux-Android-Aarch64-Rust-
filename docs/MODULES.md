# Modules

A **module** is a self-contained collector that takes one `Target`, hits a
data source (or runs a local computation), and emits zero-or-more `Entity`
records. The engine knows nothing else — every module is a one-file change.

## Catalogue (85 modules: 62 free · 18 key-gated · 5 paid)

> This section is generated from the registry (`hse modules --json`).
> The `modules_md_lists_every_registered_module` test in
> `tests/architecture.rs` fails CI if a registered module is missing here,
> so the catalogue cannot silently drift from the code again.

### dns_recon (12)

| Module | Targets | Cost | Passive | Priority | Output kinds |
|--------|---------|------|---------|----------|--------------|
| [`phone_intl`](#phone_intl)                 | `phone`               | free | **yes** | 140 | Phone (E.164, country) — offline |
| [`hudsonrock`](#hudsonrock)                 | `email`, `domain`     | free | no  | 130 | Email / Domain (stealer-log evidence) |
| `xposed_or_not`                             | `email`               | free | no  | 128 | Email (named-breach list) — pairs with hudsonrock for AU-001 |
| `username_search`                           | `username`            | free | no  | 110 | Url × N (per-platform profile links) — Sherlock/Maigret-style |
| `github_user`                               | `username`            | free | no  | 108 | Username + Person + Email + Url (GitHub public profile) |
| [`name_intel`](#name_intel)                 | `name`                | free | **yes** | 97  | Username + Email + Url (NAMINT-style permutations + Gravatar + search pivots) — offline |
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

### infrastructure (16)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `hudsonrock` | free | no | 130 | — |
| `shodan` | free | no | 105 | domain, url, asn, organisation, address |
| `criminal_ip` | key_gated | no | 103 | asn, organisation |
| `ipqs` | key_gated | no | 100 | — |
| `ip_reputation` | free | no | 78 | ip_address |
| `abuseipdb` | key_gated | no | 52 | ip_address |
| `bgpview` | free | no | 35 | asn, domain, ip_address |
| `censys` | key_gated | no | 35 | ip_address, coordinates, address |
| `greynoise` | free | no | 30 | ip_address |
| `ip_whois_geo` | free | no | 27 | address, asn, coordinates, organisation |
| `ipquery` | free | no | 27 | address, asn, coordinates, organisation |
| `ip2location` | free | no | 26 | address, asn, coordinates, organisation |
| `ipapi` | free | no | 26 | address, asn, coordinates, domain, organisation |
| `ipinfo` | free | no | 25 | address, asn, coordinates, domain, organisation |
| `ip_registry` | free | no | 23 | asn, email, ip_address, url |
| `urlscan` | free | no | 15 | ip_address |

### breach (6)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `xposed_or_not` | free | no | 128 | — |
| `see_know` | paid | no | 126 | email, username, phone, person, ip_address, domain, address, coordinates, organisation, asn, credential, api_key |
| `hibp` | key_gated | no | 120 | email, domain |
| `dehashed` | paid | no | 118 | — |
| `intelx` | paid | no | 116 | — |
| `leakix` | key_gated | no | 102 | — |

### threat (3)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `urlhaus` | free | no | 110 | — |
| `threatfox` | key_gated | no | 109 | domain, ip_address, url |
| `virustotal` | key_gated | no | 55 | — |

### geo (18)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `geo_domain_classifier` | free | yes | 94 | address |
| `phone_area_geo` | free | yes | 93 | address |
| `email_header_geo` | free | yes | 92 | address |
| `phone_carrier_geo` | free | yes | 92 | address |
| `email_locale` | free | yes | 91 | address |
| `wifi_intel` | key_gated | yes | 65 | address, coordinates, mac_address |
| `exif_geo` | free | no | 28 | coordinates |
| `ip_geo` | free | no | 28 | coordinates, address, asn, organisation |
| `geo_intel` | free | no | 22 | coordinates |
| `geocode` | free | no | 21 | coordinates, address |
| `photon` | free | no | 20 | address, coordinates |
| `wigle` | key_gated | no | 18 | coordinates, address, mac_address, organisation |
| `mylnikov` | free | no | 17 | coordinates |
| `overpass` | free | no | 15 | coordinates |
| `social_location` | free | no | 15 | address |
| `mls` | free | no | 12 | coordinates |
| `sunrise_sunset` | free | no | 10 | coordinates |
| `breach_timezone` | free | yes | 7 | address |

### social (5)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `username_search` | free | no | 111 | url, username |
| `social_probe` | free | no | 108 | url, username, person |
| `github_user` | free | no | 107 | address, domain, email, organisation, person, url, username |
| `keybase` | free | no | 100 | address, domain, email, person, username |
| `name_to_username` | free | yes | 97 | username |

### people (6)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `oathnet_pro` | paid | no | 127 | address, credential, domain, email, ip_address, password, person, phone, url, username |
| `seon` | key_gated | no | 95 | person |
| `employer_pivot` | free | no | 92 | address, email, phone, url |
| `epieos` | key_gated | no | 92 | address, person, username |
| `proxycurl` | paid | no | 88 | address, domain, email, organisation, person, phone |
| `contact_enrich` | free | no | 85 | address, person, url, username |

### email (5)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `disposable_check` | free | yes | 97 | — |
| `email_parse` | free | yes | 96 | domain, person, username |
| `emailrep` | key_gated | no | 90 | — |
| `smtp_vrfy` | free | no | 85 | email |
| `hunter_io` | key_gated | no | 62 | email, person, organisation |

### phone (1)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `phone_intl` | free | yes | 140 | phone |

### corporate (2)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `abn_lookup` | key_gated | no | 80 | abn_acn, address, organisation, person |
| `opencorporates` | free | no | 80 | abn_acn, address, organisation |

### search (2)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `exa_search` | key_gated | no | 87 | domain, email, phone, url |
| `search_engines` | free | no | 25 | url, domain, email, username, phone, address, person, organisation |

### web (5)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `wayback` | free | no | 38 | — |
| `webserver_banner` | free | no | 36 | — |
| `waf_detect` | free | no | 30 | domain |
| `cloud_storage` | free | no | 25 | url |
| `web_crawler` | free | no | 20 | email, url, domain, phone, api_key |

### sensor (3)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `device_sensors` | free | yes | 70 | coordinates, mac_address |
| `cell_intel` | free | yes | 64 | coordinates, device_id |
| `local_net` | free | yes | 58 | ip_address, mac_address |

### other (1)

| Module | Cost | Passive | Pri | Produces |
|---|---|---|---|---|
| `api_key_probe` | free | yes | 200 | api_key, domain |


---

## Synergy map

The expansion engine chains modules by producing entities whose `EntityKind`
maps to a `TargetKind` other modules accept. With **`hse scan --depth 2`**
chains like the following emerge automatically (module names current as of
the generated Catalogue above):

```
Seed: Email (foo@example.com)
├─ hudsonrock        → Email (with breach evidence — same as input)
└─ name_to_username  → Username × N
   └─ username_search / github_user / keybase accept Username → profiles

Seed: Domain (example.com)
├─ hudsonrock      → Domain (with breach evidence)
├─ crtsh           → Domain × N subdomains  ↘
│                                            ↓ depth=2 round
└─ dns_intel       → IpAddress, Domain (MX) — re-feed via expansion
   └─ per subdomain (depth=1): dns_intel, hudsonrock, crtsh
      └─ per discovered IP (depth=2): ip_geo → Coordinates, Organisation
```

`min_expand_confidence` (default 0.75) prevents low-confidence speculative
expansions from runaway. Adjust as needed via `--min-expand-confidence`.

---

## Modules in detail

> **Legacy / illustrative.** The deep-dives below were written for the
> original module set and have not been kept in lockstep with the registry.
> Several describe modules that were since merged or renamed (e.g.
> `wifi_scan` + `bssid_locate` → `wifi_intel`, `cell_survey` → `cell_intel`,
> `dns_resolver` → `dns_intel`, `email_to_username` → `name_to_username`).
> They remain as worked examples of how a module is structured. For the
> authoritative, always-current list of what ships, see the generated
> **Catalogue** above or run `hse modules` / `hse modules --json`.

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

### `name_intel`

Pure local derivation. **No network**. Marked `is_passive() == true`. A bounded
port of [NAMINT](https://seintpl.github.io/NAMINT/).

**Targets accepted**: `name`. An optional 2–4 digit run is captured as a
year/number (`"Jordan Leigh Meyers 1987"`).

**Emits** (all `MAX_*`-capped so a name target is constant-bounded):

1. **Usernames** (≤24, scored best-first): `first.last`, `firstlast`, `flast`,
   `firstl`, reversed (`last.first`), hyphen/underscore joins, middle-initial
   blends (`fmiddlel`, `fmil`), and year-suffixed variants. Weights:
   primary 0.42, secondary/year 0.30, middle 0.28.
2. **Emails** (≤16): the highest-signal handle shapes crossed with a provider
   set — Gmail/Outlook/iCloud/Yahoo/Hotmail/Proton by default, overridable via
   the `HUNTSMAN_EMAIL_DOMAINS` env var (comma-separated). Confidence 0.30. Each
   email's evidence carries a **Gravatar** URL (`MD5(lowercased email)`).
3. **Search pivots** (≤18) as `Url` entities (confidence 0.20, tagged
   `search-pivot`): Google web/face/email/phone/document/paste dorks, Bing,
   DuckDuckGo, Yandex face, LinkedIn, Facebook, X, Instagram, TikTok, GitHub,
   WhatsMyName, and Epieos (when an email was derived). Query values are
   percent-encoded; the Web UI renders them as clickable links.

All outputs sit below the default `min_expand_confidence = 0.50`, so a `--depth`
scan does not auto-spend API budget on guesses. Pass `--min-expand-confidence
0.40` to chain on the strongest usernames.

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

### `arp_scan`

Parses `/proc/net/arp` — the kernel's resolved ARP table. No `termux-api`
binary, no network traffic, no root. Pure passive observation.

**Targets accepted**: any (sensor).
**Off-device**: no `/proc/net/arp` on macOS/Windows → empty `ModuleResult`.

**Returns**: one `IpAddress` and one `MacAddress` entity per complete
ARP row (rows with the placeholder `00:00:00:00:00:00` MAC are skipped).
Confidence 0.95 for both. Evidence carries the cross-reference (the IP's
evidence has the MAC + interface; the MAC's evidence has the IP +
interface).

### `net_interfaces`

Reads `/sys/class/net/*/address` and `/operstate` — the kernel's view
of each local network interface. No `termux-api`, no network traffic.

**Targets accepted**: any (sensor).
**Off-device**: no `/sys/class/net` on macOS → empty `ModuleResult`.

**Returns**: one `MacAddress` entity per non-loopback interface,
confidence 0.95, tagged `local-interface`. Evidence records the
interface name (`wlan0` etc.) and `operstate` (`up`/`down`/`unknown`).

### `wifi_scan`

Invokes `termux-wifi-scaninfo` — a synchronous WiFi scan that lists all
APs the radio can see. Free, no key, no root.

**Targets accepted**: any (sensor).
**Off-device** or `termux-api` missing: helper returns `None` → empty
`ModuleResult` (no `module_error` event).

**Returns**: one `MacAddress` entity per AP (BSSID-keyed), confidence
0.95, tagged `wifi-ap`. Evidence: SSID (or `<hidden>`), frequency,
RSSI, timestamp.

### `wifi_connect`

Invokes `termux-wifi-connectioninfo` — info about the currently-connected
AP. Free, no key, no root.

**Targets accepted**: any (sensor).
**Returns**: zero entities if disconnected (`02:00:00:00:00:00` MAC
placeholder and `0.0.0.0` IP are filtered). Otherwise:
- one `MacAddress` for the connected AP, tagged `wifi-connected`,
  evidence has SSID, frequency, RSSI, link-speed, supplicant-state
- one `IpAddress` for the device's local IP on that network, tagged
  `local-wifi`

### `gps_fix`

Invokes `termux-location -p network -r once` for a single fast fix via
the network location provider (fast indoor, m-scale accuracy). Free,
no key. Requires the Termux:API Android app to have Location permission
granted in Android Settings.

**Targets accepted**: any (sensor).
**Returns**: one `Coordinates` entity (`lat,lon` with 7-decimal-place
precision), tagged `geoint` and `provider:<network|gps>`. Confidence
0.90 for GPS provider, 0.65 for network. Evidence captures latitude,
longitude, altitude, accuracy-metres, speed, bearing, provider.

**Quirks**: a 15 s timeout caps the wait when the device genuinely can't
acquire a fix. The default network provider is much faster than `gps`
(~1 s vs minutes) and works indoors; use `--exclude gps_fix` and a
custom modified module if you specifically need GPS-provider data.

### `cell_survey`

Invokes `termux-telephony-cellinfo` — every registered cell the modem
can see. Free, no key. Android Q+ restricts cell info to apps with
foreground location permission; ensure Termux:API has location-allowed
in Android Settings.

**Targets accepted**: any (sensor).
**Returns**: one `DeviceId` entity per cell, keyed
`<mcc>-<mnc>-<lac|tac>-<cid>` (TAC for LTE/NR, LAC for GSM/UMTS).
Confidence 0.80. Tagged `cell-tower` and `radio:<lte|gsm|umts|nr>`.
Evidence: type, MCC, MNC, LAC/TAC, CID, PCI, dBm, ASU, level,
registered.

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
- [ ] `is_passive()` returns `true` only for zero-network modules — the
      sole exceptions are the on-device sensors in
      `engine::LOCAL_PASSIVE_MODULES` (`wifi_intel`, `cell_intel`), which read
      local radios but may enrich them via an API; see the passive caveat above.
      The `non_passive_modules_budget_above_default` test also requires any
      non-passive module to set `max_timeout_ms()` above the 3s default.
- [ ] `accepts()` covers every `TargetKind` the module can handle and only those
- [ ] If key-gated: uses `ctx.key("HUNTSMAN_FOO_KEY")?` (returns `Error::MissingKey`,
  which the engine handles as a logged skip rather than scan failure)
- [ ] All errors go through `Error::module("module_name", "message")`
- [ ] Passwords / credentials are never written to evidence — even if the
  upstream API returns them (see `hudsonrock` for the pattern)
- [ ] At least one unit test (the `accepts()` test is the minimum)
- [ ] Module survives upstream API outage: 4xx / 5xx / malformed JSON /
  timeout are handled without panicking
