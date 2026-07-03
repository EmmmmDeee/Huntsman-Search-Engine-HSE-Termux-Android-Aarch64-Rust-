# Modules

A **module** is a self-contained collector that takes one `Target`, hits a
data source (or runs a local computation), and emits zero-or-more `Entity`
records. The engine knows nothing else — every module is a one-file change.

## Catalogue (162 modules: 129 free · 28 key-gated · 5 paid)

> Generated from `hse modules --json`; kept honest by the
> `modules_md_lists_every_registered_module` CI test. Each module's
> `category` is the SpiderFoot-style bucket it appears under in the Web UI.

### search (3)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `exa_search` | email, username, phone, full_name, domain, organisation | key_gated | no | 87 | url, domain, email, phone |
| `search_engines` | email, username, phone, full_name, ip_address, domain, url, asn, coordinates, address, organisation, abn_acn | free | no | 113 | url, domain, email, username, phone, address, coordinates, person, organisation, abn_acn |
| `tor_search_pivot` | email, username, full_name, domain, crypto_address | free | yes | 90 | url |

### social (34)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `username_search` | username | free | no | 111 | url, username |
| `gaming_profile` | username | free | no | 106 | username, url |
| `social_probe` | username, full_name | free | no | 108 | url, username, person, domain |
| `streaming_probe` | username | free | no | 108 | url, username |
| `steam_profile` | username | free | no | 105 | person, username, url, address, coordinates |
| `structured_id` | username | free | **yes** | 103 | username, mac_address |
| `fediverse` | email | free | no | 104 | username, url, email |
| `nostr` | username, email | free | no | 105 | url, username, email |
| `github_code_search` | email, username | free | no | 85 | url, username, email |
| `github_user` | username | free | no | 107 | person, email, username, domain, url, organisation, address, credential |
| `github_commits` | email | free | no | 106 | person, username, url |
| `hacker_news` | username | free | no | 106 | username, email, url |
| `lobsters` | username | free | no | 106 | username, email, url, domain |
| `gitlab_user` | username | free | no | 106 | username, person, email, url, domain, address, organisation |
| `gitea_user` | username | free | no | 98 | username, person, email, url, domain, address |
| `sourceforge_user` | username | free | no | 94 | username, person, email, url, address |
| `discord_snowflake` | username | free | **yes** | 104 | username |
| `cpan_user` | username | free | no | 55 | username, person, email, url, domain, address |
| `rubygems_user` | username | free | no | 54 | username, person, url, domain |
| `pypi_user` | username | free | no | 56 | username, person, email, url, domain |
| `reddit_user` | username | free | no | 105 | username, email, url |
| `stackoverflow_user` | username | free | no | 105 | username, person, url, domain, address |
| `bluesky_user` | username | free | no | 104 | username, person, email, url, domain |
| `codeberg_user` | username | free | no | 105 | username, person, email, url, domain, address |
| `devto` | username | free | no | 103 | username, person, email, url, domain, address |
| `mastodon_user` | username | free | no | 103 | username, person, email, url, domain, address |
| `huggingface_user` | username | free | no | 52 | username, person, email, url, domain, organisation |
| `hexpm_user` | username | free | no | 51 | username, person, url |
| `launchpad_user` | username | free | no | 53 | username, person, email, url |
| `dockerhub_user` | username | free | no | 50 | username, person, email, url, domain, organisation, address |
| `codewars_user` | username | free | no | 49 | username, person, url, organisation, address |
| `bitbucket_user` | username | free | no | 97 | username, person, url, domain, address |
| `npm_author` | username | free | no | 104 | username, email, url, domain |
| `crates_io` | username | free | no | 103 | username, person, url |
| `keybase` | username | free | no | 100 | person, username, email, domain, address |
| `username_variants` | username | free | **yes** | 98 | username |

### people (16)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `oathnet_pro` | email, username, phone, full_name, ip_address, domain | paid | no | 127 | email, username, phone, person, ip_address, address, url, domain |
| `name_intel` | full_name | free | **yes** | 97 | username, email, url |
| `wikidata` | full_name, organisation | free | no | 96 | person, organisation, domain, username, url |
| `seon` | email, phone | key_gated | no | 95 | person |
| `pgp` | email | free | no | 91 | person, email |
| `employer_pivot` | email, domain | free | no | 92 | address, phone, email, url |
| `epieos` | email | key_gated | no | 92 | person, username, address |
| `gravatar` | email | free | no | 90 | person, username, url, address |
| `fullcontact` | email, phone | key_gated | no | 89 | person, organisation, address, username, url |
| `proxycurl` | email, username, url | paid | no | 88 | person, address, email, domain, phone, organisation |
| `contact_enrich` | email, phone | free | no | 85 | person, username, address, url |
| `au_people` | full_name | free | no | 88 | address, phone, email, person |
| `au_electoral` | full_name | free | no | 85 | address, coordinates |
| `au_property` | full_name | free | no | 84 | address, coordinates |
| `ahpra` | full_name, organisation | free | no | 86 | person, organisation |
| `payid` | email, phone, abn_acn | free | **yes** | 80 | email, phone, abn_acn |

### email (6)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `disposable_check` | email | free | **yes** | 97 | — |
| `email_parse` | email | free | **yes** | 96 | domain, username, person |
| `email_canonical` | email | free | **yes** | 95 | email |
| `emailrep` | email | key_gated | no | 90 | — |
| `smtp_vrfy` | email | free | no | 85 | email |
| `hunter_io` | domain | key_gated | no | 62 | email, person, organisation |

### phone (4)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `hlr_cnam` | phone | key_gated | no | 138 | person, phone |
| `numverify` | phone | key_gated | no | 139 | address |
| `phone_au` | phone | free | **yes** | 138 | phone |
| `phone_intl` | phone | free | **yes** | 140 | phone |

### breach (11)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `xposed_or_not` | email | free | no | 128 | — |
| `osintcat` | email | key_gated | no | 128 | email, username |
| `niamonx` | email, username, ip_address, domain | key_gated | no | 122 | email, username, phone, person |
| `see_know` | email, username, phone, full_name, ip_address, domain | paid | no | 126 | email, username, phone, person, ip_address, domain, address, coordinates, organisation, asn, credential, api_key |
| `psbdmp` | email, username, domain | free | no | 125 | url |
| `hibp` | email, domain | key_gated | no | 120 | email, domain |
| `dehashed` | email, username, phone, full_name, ip_address, domain | paid | no | 118 | — |
| `intelx` | email, username, phone, full_name, ip_address, domain | paid | no | 116 | — |
| `pwned_passwords` | email, username | free | no | 115 | — |
| `leakix` | ip_address, domain | key_gated | no | 102 | — |
| `hudsonrock` | email, username, domain | free | no | 130 | — |
| `comb_search` | email, username, domain | free | no | 129 | email, password |

### threat (3)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `urlhaus` | ip_address, domain | free | no | 110 | — |
| `threatfox` | ip_address, domain | key_gated | no | 109 | domain, ip_address, url |
| `virustotal` | ip_address, domain | key_gated | no | 55 | — |

### corporate (13)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `au_business_id` | abn_acn | free | **yes** | 104 | abn_acn |
| `asic_director` | full_name | free | no | 89 | organisation, abn_acn, address |
| `asic_persons` | full_name | free | no | 112 | person, organisation, abn_acn, address |
| `asic_business_names` | organisation | free | no | 111 | organisation, abn_acn |
| `asic_banned_orgs` | organisation | free | no | 112 | organisation, abn_acn |
| `au_unclaimed` | full_name, organisation | free | no | 114 | address, coordinates, organisation, person |
| `abn_lookup` | full_name, organisation, abn_acn | key_gated | no | 118 | abn_acn, address, organisation, person |
| `opencorporates` | full_name, organisation, abn_acn | free | no | 116 | organisation, abn_acn, address |
| `acnc_charities` | organisation | free | no | 112 | organisation, abn_acn, address, domain |
| `gleif_lei` | organisation | free | no | 111 | organisation, abn_acn, address |
| `trove_au` | organisation, abn_acn | key_gated | no | 57 | organisation |
| `acma_rrl` | organisation, abn_acn, coordinates | free | no | 48 | organisation, abn_acn |
| `austlii` | full_name, organisation | free | no | 55 | url, organisation |

### dns_recon (13)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `dns_axfr` | domain | free | no | 60 | domain |
| `whoisxml` | domain | key_gated | no | 58 | email, person, organisation, domain |
| `securitytrails` | ip_address, domain | key_gated | no | 45 | domain |
| `subdomain_takeover` | domain | free | no | 40 | domain |
| `doh_resolver` | domain, url | free | no | 34 | ip_address, domain, email |
| `cert_intel` | ip_address, domain | free | no | 33 | domain |
| `whois` | ip_address, domain, url | free | no | 32 | domain, email, person, organisation, address |
| `dns_intel` | ip_address, domain, url | free | no | 31 | ip_address, domain, email |
| `rdap_domain` | domain, url | free | no | 31 | domain |
| `crtsh` | email, domain, url | free | no | 29 | domain, email, organisation |
| `typosquat` | domain | free | no | 34 | domain |
| `hackertarget` | ip_address, domain, url | free | no | 24 | domain, ip_address |
| `domainsdb` | full_name, domain, organisation | free | no | 19 | domain |

### infrastructure (20)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `ripestat` | ip_address, asn | free | no | 107 | asn, organisation, email |
| `onyphe` | ip_address, domain | key_gated | no | 34 | ip_address, coordinates, address, asn, organisation, domain |
| `zoomeye` | ip_address, domain | key_gated | no | 34 | ip_address, coordinates, address, asn, organisation |
| `shodan` | ip_address | free | no | 105 | domain, url, asn, organisation, address, ip_address |
| `criminal_ip` | ip_address | key_gated | no | 103 | organisation, asn |
| `ipqs` | email, phone, ip_address | key_gated | no | 100 | — |
| `ip_reputation` | ip_address, domain | free | no | 78 | ip_address |
| `abuseipdb` | ip_address | key_gated | no | 52 | ip_address |
| `bgpview` | ip_address, asn | free | no | 35 | ip_address, domain, asn |
| `netblock` | cidr | free | **yes** | 60 | ip_address |
| `portscan` | ip_address | free | no | 22 | ip_address, url |
| `censys` | ip_address | key_gated | no | 78 | ip_address, coordinates, address |
| `greynoise` | ip_address | free | no | 30 | ip_address |
| `ip_whois_geo` | ip_address | free | no | 27 | coordinates, address, asn, organisation |
| `ipquery` | ip_address | free | no | 27 | coordinates, address, asn, organisation |
| `ip2location` | ip_address | free | no | 26 | coordinates, address, asn, organisation |
| `ipinfo` | ip_address | free | no | 25 | coordinates, address, asn, organisation, domain |
| `ip_registry` | ip_address, asn | free | no | 23 | ip_address, asn, email, url |
| `urlscan` | ip_address, domain, url | free | no | 15 | ip_address |
| `netlas` | ip_address, domain, email | key_gated | no | 79 | ip_address, email, domain, organisation, coordinates, address |

### web (7)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `url_extract` | url | free | yes | 97 | domain, ip_address |
| `wayback` | domain, url | free | no | 38 | — |
| `webserver_banner` | ip_address, domain, url | free | no | 36 | domain, ip_address, url |
| `waf_detect` | domain, url | free | no | 30 | domain |
| `cloud_storage` | domain, organisation | free | no | 25 | url |
| `web_crawler` | domain, url | free | no | 20 | email, url, domain, phone, api_key |
| `app_links` | domain | free | no | 90 | domain |

### geo (22)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `geo_domain_classifier` | domain, url | free | **yes** | 94 | address |
| `phone_geo` | phone | free | **yes** | 93 | address, coordinates |
| `email_header_geo` | email | free | **yes** | 92 | address |
| `email_locale` | email | free | **yes** | 91 | address |
| `au_geo` | coordinates | free | no | 70 | coordinates |
| `au_seifa` | coordinates | free | no | 69 | coordinates |
| `wifi_intel` | email, username, phone, full_name, ip_address, domain, url, asn, coordinates, address, organisation, abn_acn, mac_address, api_key | key_gated | **yes** | 65 | mac_address, coordinates, address |
| `cell_local` | coordinates | free | no | 66 | device_id, coordinates |
| `opencellid` | coordinates | key_gated | no | 65 | device_id, coordinates |
| `exif_geo` | — | free | no | 28 | coordinates |
| `ip_geo` | ip_address | free | no | 28 | coordinates, address, asn, organisation |
| `geo_intel` | phone, ip_address | free | no | 22 | coordinates |
| `geocode` | coordinates, address | free | no | 21 | coordinates, address |
| `photon` | coordinates, address | free | no | 20 | coordinates, address |
| `qld_cadastre` | coordinates | free | no | 18 | coordinates, address |
| `mylnikov` | mac_address | free | no | 17 | coordinates |
| `overpass` | coordinates | free | no | 15 | coordinates |
| `social_location` | — | free | no | 15 | address |
| `mls` | mac_address | free | no | 12 | coordinates |
| `wigle` | coordinates, mac_address, ssid | key_gated | no | 10 | coordinates, address, mac_address, organisation |
| `sunrise_sunset` | coordinates | free | no | 10 | coordinates |
| `breach_timezone` | email, username, phone | free | **yes** | 7 | address |

### sensor (4)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `device_sensors` | email, username, phone, full_name, ip_address, domain, url, asn, coordinates, address, organisation, abn_acn, mac_address, api_key | free | **yes** | 70 | coordinates, mac_address, ip_address |
| `cell_intel` | email, username, phone, full_name, ip_address, domain, url, asn, coordinates, address, organisation, abn_acn, mac_address, api_key | free | **yes** | 64 | coordinates |
| `signal_radar` | email, username, phone, full_name, ip_address, domain, url, asn, coordinates, address, organisation, abn_acn, mac_address, api_key | free | **yes** | 60 | mac_address, ip_address, coordinates, device_id |
| `local_net` | email, username, phone, full_name, ip_address, domain, url, asn, coordinates, address, organisation, abn_acn, mac_address, api_key | free | **yes** | 58 | mac_address, ip_address |

### other (3)

| Module | Targets | Cost | Passive | Pri | Produces |
|---|---|---|---|---|---|
| `classifier` | full_name, organisation, address | free | **yes** | 200 | email, username, phone, ip_address, domain, url, asn, cidr, coordinates, abn_acn, mac_address, crypto_address, device_id |
| `api_key_probe` | api_key | free | **yes** | 200 | api_key, domain |
| `chain_intel` | crypto_address | free | no | 90 | crypto_address, username |

## Synergy map

The expansion engine chains modules by producing entities whose `EntityKind`
maps to a `TargetKind` other modules accept. With **`hse scan --depth 2`**
chains like the following emerge automatically (module names current as of
the generated Catalogue above):

```
Seed: Email (foo@example.com)
├─ hudsonrock        → Email (with breach evidence — same as input)
└─ name_intel        → Username × N
   └─ username_search / github_user / keybase accept Username → profiles

Seed: Domain (example.com)
├─ hudsonrock      → Domain (with breach evidence)
├─ crtsh           → Domain × N subdomains  ↘
│                                            ↓ depth=2 round
└─ dns_intel       → IpAddress, Domain (MX) — re-feed via expansion
   └─ per subdomain (depth=1): dns_intel, hudsonrock, crtsh
      └─ per discovered IP (depth=2): ip_geo → Coordinates, Organisation
```

`min_expand_confidence` (default 0.50, the Probable tier) prevents
low-confidence speculative expansions from running away. Adjust via
`--min-expand-confidence` (set 0.75 to expand Verified-tier only).

---

## Modules in detail

> **Legacy / illustrative.** The deep-dives below were written for the
> original module set and have not been kept in lockstep with the registry.
> Several describe modules that were since merged or renamed (e.g.
> `wifi_scan` + `bssid_locate` → `wifi_intel`, `cell_survey` → `cell_intel`,
> `dns_resolver` → `dns_intel`, `email_to_username` → `name_intel`). **Do not
> rely on any module name in this section** — it is frozen as a structural
> worked-example of how a module is built, not a list of what ships. For the
> authoritative, always-current list, see the generated **Catalogue** above or
> run `hse modules` / `hse modules --json`.

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
   primary 0.38, secondary/year 0.30, middle 0.28 — all below the 0.40 Probable
   floor, so derived handles stay Candidates until a discovery module confirms
   them.
2. **Emails** (≤8): the highest-signal handle shapes crossed with a provider
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

Three changes, all in one PR:

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
