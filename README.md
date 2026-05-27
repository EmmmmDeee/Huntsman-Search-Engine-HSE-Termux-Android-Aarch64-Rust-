# Huntsman Search Engine (HSE)

[![CI](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/workflows/ci.yml/badge.svg)](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#licence)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![Termux aarch64](https://img.shields.io/badge/Termux-aarch64-darkgreen.svg)](https://termux.dev/)

Pure-Rust OSINT / GEOINT platform with **60+ modules** that runs entirely
inside **Termux on Android aarch64** with no root. Single binary, embedded
SpiderFoot-style Web UI, zero native dependencies.

---

## One-Click Install (Termux Android)

Open Termux and paste:

```bash
pkg install -y git rust && git clone --depth 1 https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git ~/hse && cd ~/hse && cargo build --release && cp target/release/hse $PREFIX/bin/
```

Then launch the Web UI:

```bash
hse serve
```

Open **Chrome or Firefox** on your phone and go to `http://127.0.0.1:8080`.
You'll see a SpiderFoot-identical dark-navbar UI with Dashboard, New Scan
wizard, entity browser with D3 force graph, correlations, and settings.

### Update existing install

```bash
cd ~/hse && git pull origin main && cargo build --release && cp target/release/hse $PREFIX/bin/
```

### Full installer (handles all edge cases)

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

Also works on Debian/Ubuntu and macOS. See [`docs/INSTALL.md`](docs/INSTALL.md)
for all install paths and Termux quirks.

---

## Quick Start

```bash
hse doctor                                                  # verify environment
hse modules                                                 # list all 60+ modules
hse scan --kind name --value "Jordan Leigh Meyers" --depth 2 # person scan with expansion
hse scan --kind domain --value example.com --depth 2        # domain recon
hse scan --kind email --value user@example.com --free-only  # email pivot (free only)
hse scan --kind ip --value 1.1.1.1                          # IP geolocation
hse scan --kind domain --value example.com --output json    # machine-readable output
hse serve                                                   # Web UI → http://127.0.0.1:8080
hse live --kind domain --value example.com --interval 60    # continuous monitoring
```

---

## Seed Types (12 supported)

| Seed | Flag | Example | Modules |
|------|------|---------|---------|
| Email | `--kind email` | `user@example.com` | 34 |
| Username | `--kind username` | `johndoe` | 13 |
| Phone | `--kind phone` | `+61400000000` | 8 |
| Full Name | `--kind name` | `Jordan Leigh Meyers` | 6 |
| IP Address | `--kind ip` | `1.1.1.1` | 33 |
| Domain | `--kind domain` | `example.com` | 39 |
| ASN | `--kind asn` | `AS13335` | 1 |
| Coordinates | `--kind coords` | `-27.47,153.02` | 6 |
| Address | `--kind address` | `Nundah, QLD 4012` | 2 |
| URL | `--kind url` | `https://example.com/page` | 2 |
| Organisation | `--kind org` | `ACME Pty Ltd` | 2 |
| ABN/ACN | `--kind abn` | `51824753556` | 1 |
| MAC Address | `--kind mac` | `AA:BB:CC:DD:EE:FF` | 3 |

---

## Module Overview (60+ modules)

**API-Free (no keys required):**
- **Search engines** (13 engines): Yahoo, Bing, AOL, DuckDuckGo, Google,
  Brave, Mojeek, Startpage, Yandex, Ecosia, Qwant, Dogpile, Swisscows —
  paginated crawling with CAPTCHA detection, recursive entity recycling,
  and username variant generation
- **Breach/identity**: `hudsonrock`, `xposed_or_not`, `username_search`
  (150+ sites), `social_probe` (20+ platforms), `github_user`, `gravatar`,
  `keybase`, `pwned_passwords`
- **DNS/domain**: `crtsh`, `dns_resolver`, `dns_brute`, `reverse_dns`,
  `ssl_probe`, `whois`, `rdap_domain`, `caa_records`, `wayback`
- **IP/infrastructure**: `ip_geo`, `ip_whois_geo`, `ip_rdap`, `bgpview`,
  `shodan_internetdb`, `tor_exit_check`, `dns_blocklist`
- **Geolocation**: `geocode` (OSM Nominatim), `photon` (Komoot),
  `overpass` (OSM infrastructure), `sunrise_sunset` (chronolocation),
  `mylnikov` (BSSID geolocation)
- **Threat intel**: `alienvault_otx`, `threatfox`, `urlhaus`
- **Web analysis**: `web_crawler`, `webserver_banner`, `search_engines`
- **Phone**: `phone_intl` (offline, 175 country prefixes)
- **Corporate**: `opencorporates` (AU jurisdiction focus)
- **Termux sensors**: `gps_fix`, `wifi_scan`, `wifi_connect`, `arp_scan`,
  `cell_survey`, `net_interfaces`

**Key-gated / Paid:**
- `shodan`, `dehashed`, `intelx`, `securitytrails`, `leakix`,
  `criminal_ip`, `ipqs`, `numverify`, `wigle`, `oathnet_pro`,
  `abn_lookup`, `api_key_probe`, `seon`, `emailrep`, `epieos`,
  `proxycurl`

---

## Web UI (SpiderFoot-style)

`hse serve` launches a localhost-only HTTP server with an embedded
single-file SPA using SpiderFoot's exact vendor stack (Bootstrap 3,
jQuery, D3 v3, tablesorter, alertify):

- **Dashboard** — stats cards, scan status breakdown, quick actions
- **New Scan** — target input + module grid with tooltips + depth/throttle
  controls + use-case presets
- **Scan Results** — tabbed: Status, Browse (sortable entity table with
  inline expand), D3 Force Graph (entity relationship visualization),
  Correlations (severity-tagged), Event Log (real-time SSE), Info
- **Settings** — API key management with validation
- **Dark mode** toggle

Binds to `127.0.0.1:8080` only — no LAN exposure (architecture invariant).

---

## Geolocation Pipeline

Every seed type has a pathway to geographic coordinates:

```
Name/Email/Username → search_engines (13 engines, free)
                    → discovered emails/phones/addresses
                    → oathnet_pro (breach IPs)
                    → ip_geo + ip_whois_geo (free HTTPS)
                    → Coordinates
                    → reverse_geocode (Nominatim, free) → Address
                    → wigle (WiFi density + SSID intel + AP MAC addresses)

IP Address → ip_geo (free) + ip_whois_geo (free) → Coordinates + Address
           → reverse_geocode → precise Address

Address → forward_geocode (Nominatim, free) → Coordinates
        → search_engines → name/phone/business associations

Coordinates → reverse_geocode → Address
            → wigle (adaptive bbox, conserves API quota)
            → search_engines → map/property associations
```

Australian-optimised: 70+ QLD/NSW/VIC suburbs in the address extractor,
postcode detection, court/electoral/property record dorks, ABN/ACN
extraction from search results.

---

## Autonomous Expansion

```bash
hse scan --kind name --value "Jordan Leigh Meyers" --depth 2
```

Round 0 (seed): `"Jordan Leigh Meyers"` dispatched to all accepting modules.
Round 1: High-confidence entities (C_eff ≥ 0.75) become new targets.
Round 2: Discovered IPs → geo modules → coordinates → address.

| Knob | Default | Purpose |
|------|---------|---------|
| `--depth N` | `0` | Max expansion rounds |
| `--min-expand-confidence F` | `0.75` | Only Verified-tier entities expand |
| `--max-entities N` | none | Stop at N total entities |
| `--max-wall-time SECS` | none | Stop after SECS wall-time |
| `--max-concurrent N` | `0` | Parallel module dispatch (0=sequential) |

---

## Architecture

- `#![forbid(unsafe_code)]` — entire codebase
- rustls + bundled-sqlite only — no OpenSSL, no native TLS, no C deps
- `StoragePort` trait — engine/API decoupled from SQLite via Strangler Fig
- 700+ tests (unit + API integration + architecture boundary enforcement)
- 25 correlator rules (AU-001 through AU-025)
- 2 tokio worker threads (tuned for Termux low-power devices)
- Release binary ~5 MB stripped (opt-level="s", LTO, codegen-units=1)

---

## Documentation

| Document | Content |
|----------|---------|
| [`docs/INSTALL.md`](docs/INSTALL.md) | All install paths + Termux quirks |
| [`docs/USAGE.md`](docs/USAGE.md) | Full CLI reference + HTTP API |
| [`docs/MODULES.md`](docs/MODULES.md) | Module catalogue + synergy map |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Design invariants + data flow |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common errors + fixes |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history |

---

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE)
at your option.
