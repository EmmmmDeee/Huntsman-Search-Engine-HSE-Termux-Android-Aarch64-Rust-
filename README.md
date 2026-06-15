# Huntsman Search Engine (HSE)

[![CI](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/workflows/ci.yml/badge.svg)](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#licence)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![Termux aarch64](https://img.shields.io/badge/Termux-aarch64-darkgreen.svg)](https://termux.dev/)

Pure-Rust OSINT / GEOINT platform with **118 modules** that runs entirely
inside **Termux on Android aarch64** with no root. Single binary, embedded
SpiderFoot-style Web UI, zero native dependencies.

---

## Install (Termux Android aarch64, no root)

### ⭐ The installer — one line, all-in-one

This **single command is the installation** — it always tracks the latest
`main`, does **absolutely everything**, and is **safe to re-run** (re-running
upgrades an existing install in place to the newest version):

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

It installs the toolchain (`rust`, `clang`, `binutils`, `git`, …), clones **or
updates** the source, builds the release binary (retrying on flaky mobile
networks), installs `hse` to `$PREFIX/bin`, sets up the `hse-bg` background
wrapper + optional Termux:Boot autostart, writes the keys template, and runs
`hse doctor` to verify. **Existing installs are fully handled**: it fetches +
rebuilds, **preserves your `~/.huntsman.env` keys**, auto-rotates the embedded
keys on first run, swaps the binary **atomically** (safe even while a server is
live), and **restarts a running `hse-bg` onto the new build** so the upgrade
takes effect immediately. Idempotent — re-run any time to upgrade.

**No-build fast path:** if a precompiled aarch64 `hse` (named `hse` or
`hse-aarch64-linux-android`) is sitting in your **Downloads** folder, the
installer validates it (ELF + optional `.sha256` + a run-test) and installs it
directly — no Rust toolchain, no compile. And after a *source* build it caches
the binary back to Downloads, so your next install (or another aarch64 phone)
takes that instant path automatically. Point at a specific file with
`HSE_PREBUILT=/path/to/hse`, or force a source build with `HSE_PREFER_BUILD=1`.

Also works on Debian/Ubuntu and macOS. Full log at `~/.cache/hse-install.log`.
See [`docs/INSTALL.md`](docs/INSTALL.md) for every install path, knobs
(`HSE_REF`, `HSE_INSTALL_DIR`, …) and Termux quirks.

Then launch the Web UI:

```bash
hse serve   # binds 127.0.0.1:8080
```

Open **Chrome or Firefox** on your phone and go to `http://127.0.0.1:8080`.
You'll see a SpiderFoot-identical dark-navbar UI with Dashboard, New Scan
wizard, entity browser with D3 force graph, correlations, and a **Settings
page where you can paste & save API keys** straight from the browser.

### Manual build (advanced — the installer already does this)

The one-line installer above **is** the supported installation — it always
pulls and builds the latest `main`, and its built-in no-build fast path
(Downloads cache, above) covers the prebuilt-binary case. If you'd rather drive
the build by hand:

```bash
pkg install -y git rust binutils clang && git clone --depth 1 https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git ~/hse && cd ~/hse && cargo build --release --locked && cp target/release/hse $PREFIX/bin/
```

To upgrade a manual clone, either re-run the all-in-one installer above (it
detects and updates an in-place clone), or:

```bash
cd ~/hse && git pull origin main && cargo build --release --locked && cp target/release/hse $PREFIX/bin/
```

> **Seeing a `Username for 'https://github.com':` prompt?** A public repo
> never asks for credentials — that prompt means the repository is currently
> **private**. No password is required once it's public; until then, clone
> over SSH with a key already on your GitHub account (no typed password):
> ```bash
> pkg install -y git rust binutils clang openssh && git clone --depth 1 git@github.com:EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git ~/hse && cd ~/hse && cargo build --release --locked && cp target/release/hse $PREFIX/bin/
> ```

---

## Quick Start

```bash
hse doctor                                                  # verify environment
hse modules                                                 # list all 118 modules
hse engines                                                 # search-engine liveness panel
hse config                                                  # capability toggles (features/engines/modules)
hse scan --kind name --value "Jordan Leigh Meyers" --depth 2 # person scan with expansion
hse scan --kind domain --value example.com --depth 2        # domain recon
hse scan --kind email --value user@example.com --free-only  # email pivot (free only)
hse scan --kind ip --value 1.1.1.1                          # IP geolocation
hse scan --kind domain --value example.com --output json    # machine-readable output
hse scan                                                    # bare scan: uses HUNTSMAN_DEFAULT_SEED (optional, see docs/INSTALL.md)
hse serve                                                   # Web UI → http://127.0.0.1:8080
hse live --kind domain --value example.com --interval 60    # continuous monitoring

# Australian corpus harvest (run once to build offline data)
hse wigle-harvest --dry-run                                 # preview AU Wi-Fi/cell/BT tile plan
hse wigle-harvest --kinds wifi,cell,bluetooth               # download full AU corpus to wigle_au
hse opencellid-harvest                                      # download AU cell towers to opencellid_au
hse oathnet-harvest --dry-run                               # preview AU breach sweep plan
hse seeknow-harvest --dry-run                               # preview AU people-search sweep plan

# Corpus enrichment (run after harvest)
hse wigle-enrich                                            # OUI vendor + SSID tags + cell cross-ref

# Native-format export (lossless round-trip)
hse wigle-export --format wigle-csv --output au_wifi.csv   # WiGLE CSV v1.4 (WiGLE-uploadable)
hse wigle-export --format kml --output au_wifi.kml         # KML for Google Earth
hse opencellid-export --output au_cells.csv                # OpenCelliD cell_towers.csv format
hse oathnet-export --surface breach                        # OathNet records as NDJSON
hse seeknow-export --output au_people.ndjson               # SeekNow records as NDJSON

# Offline scanning (after corpus built)
hse scan --kind mac --value "AA:BB:CC:DD:EE:FF" --offline  # BSSID lookup from local corpus only
hse live --kind domain --value example.com --interval 60 --delta  # delta-only change alerts

# Operator self-monitoring
hse self-scan                                               # scan HUNTSMAN_SELF_SEED, show delta
hse self-scan --seed "your@email.com" --delta-only         # show only new findings
```

**Standard acceptance run** — one command exercises the free, keyless pipeline
end-to-end on a canonical seed and prints every result **in full with complete
URLs** (liveness + toggles + a scan dossier), against a throwaway `HOME` so it
never touches your keys/config:

```bash
scripts/standard-test.sh             # canonical seed (Kylo4kylo)
scripts/standard-test.sh "<seed>"    # any handle/username
```

---

## Seed Types (13 supported)

| Seed | Flag | Example | Modules |
|------|------|---------|---------|
| Email | `--kind email` | `user@example.com` | 35 |
| Username | `--kind username` | `johndoe` | 14 |
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

## Module Overview (118 modules — 93 free, 20 key-gated, 5 paid)

> Generated from `hse modules --json`. The full catalogue with target
> kinds and output entities (kept honest by the
> `modules_md_lists_every_registered_module` CI test) lives in
> [`docs/MODULES.md`](docs/MODULES.md); run `hse modules` for the live list.

**API-Free (no keys required):**
- **Breach/identity**: `pwned_passwords`, `xposed_or_not`
- **Social**: `github_user`, `hacker_news`, `reddit_user`, `npm_author`, `crates_io`, `keybase`, `social_probe`, `username_search`, `username_variants`
- **People**: `contact_enrich`, `employer_pivot`, `name_intel`, `wikidata`
- **DNS/domain**: `cert_intel`, `crtsh`, `dns_axfr`, `dns_intel`, `doh_resolver`, `domainsdb`, `hackertarget`, `rdap_domain`, `subdomain_takeover`, `whois`
- **IP/infrastructure**: `bgpview`, `greynoise`, `hudsonrock`, `ip2location`, `ip_registry`, `ip_reputation`, `ip_whois_geo`, `ipapi`, `ipinfo`, `ipquery`, `shodan`, `urlscan`
- **Geolocation**: `breach_timezone`, `email_header_geo`, `email_locale`, `exif_geo`, `geo_domain_classifier`, `geo_intel`, `geocode`, `ip_geo`, `mls`, `mylnikov`, `overpass`, `phone_area_geo`, `phone_carrier_geo`, `photon`, `social_location`, `sunrise_sunset`
- **Threat intel**: `urlhaus`
- **Email**: `disposable_check`, `email_canonical`, `email_parse`, `smtp_vrfy`
- **Phone**: `phone_intl`
- **Corporate**: `acnc_charities`, `gleif_lei`, `opencorporates`
- **Search**: `search_engines`
- **Web analysis**: `cloud_storage`, `waf_detect`, `wayback`, `web_crawler`, `webserver_banner`
- **Termux sensors**: `cell_intel`, `device_sensors`, `local_net`
- **Other**: `api_key_probe`, `qld_unclaimed`

**Key-gated / Paid:**
- `abn_lookup`, `abuseipdb`, `censys`, `criminal_ip`, `dehashed`, `emailrep`
- `epieos`, `exa_search`, `hibp`, `hunter_io`, `intelx`, `ipqs`
- `leakix`, `oathnet_pro`, `proxycurl`, `securitytrails`, `see_know`, `seon`
- `threatfox`, `virustotal`, `whoisxml`, `wifi_intel`, `wigle`


## Web UI (SpiderFoot-style)

`hse serve` launches a localhost-only HTTP server with an embedded
single-file SPA using SpiderFoot's exact vendor stack (Bootstrap 3,
jQuery, D3 v3, tablesorter, alertify):

- **Dashboard** — stats cards, scan status breakdown, quick actions
- **New Scan** — target input + module grid with tooltips + depth/throttle
  controls + use-case presets
- **Scan Results** — tabbed: Status, Browse (sortable entity table with
  inline expand), D3 Force Graph (entity relationship visualization, incl.
  typed relation edges — subdomain/lineage/co-location — dashed, kind on hover),
  Correlations (severity-tagged), Event Log (real-time SSE), Info
- **Settings** — API key management with validation
- **Dark mode** toggle

Binds to `127.0.0.1:8080` only — no LAN exposure (architecture invariant).

---

## Geolocation Pipeline

Every seed type has a pathway to geographic coordinates:

```
Name/Email/Username → search_engines (17 engines, free)
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

## Australian Corpus Harvest

HSE can build a permanent offline-first database of every Australian Wi-Fi
network, Bluetooth device, and cell tower from WiGLE and OpenCelliD, plus
Australian breach and people-search records from OathNet and SeekNow. Once
built, all lookups become instant local reads with zero API quota consumed.

### 1. Build the corpus (one-time, then refresh periodically)

```bash
# Wi-Fi, Bluetooth and cell towers from WiGLE
hse wigle-harvest --kinds wifi,cell,bluetooth   # ~days on free tier (100 req/day)
hse wigle-enrich                                # OUI vendor + SSID tagging + cell cross-ref

# Cell towers from OpenCelliD (faster — single bulk download)
hse opencellid-harvest                          # ~30 seconds, ~500k AU towers

# Breach records from OathNet
hse oathnet-harvest --max 5000                  # AU domain + phone prefix sweep

# People-search from SeekNow
hse seeknow-harvest --abn --postcodes           # ABN + postcode anchored sweep
```

### 2. Export in native formats

All corpus data is exportable in the service's own native format — lossless
round-trip, no conversion required:

| Command | Output |
|---|---|
| `hse wigle-export --format wigle-csv` | WiGLE CSV v1.4 (uploadable to WiGLE) |
| `hse wigle-export --format kml` | KML for Google Earth / Maps |
| `hse opencellid-export` | OpenCelliD `cell_towers.csv` format |
| `hse oathnet-export` | OathNet records as NDJSON |
| `hse seeknow-export` | SeekNow records as NDJSON |

### 3. Offline scans

After building the corpus, use `--offline` to restrict all lookups to the
local database — no network calls, no rate limits, instant results:

```bash
hse scan --kind mac --value "AA:BB:CC:DD:EE:FF" --offline
hse scan --kind coordinates --value "-33.865,151.209" --offline
```

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
| `--min-expand-confidence F` | `0.50` | Min C_eff to expand (0.75 = Verified-only) |
| `--max-entities N` | none | Stop at N total entities |
| `--max-wall-time SECS` | none | Stop after SECS wall-time |
| `--max-concurrent N` | `0` | Parallel module dispatch (0=sequential) |
| `--expand-all-identities` | off | Expand every discovered username/person, even uncorroborated aliases that don't overlap the subject's handle (lifts the wrong-identity gate; implied by `--full`). Higher recall, more unrelated footprints to prune |

**Nothing is a black box.** Every pivot the engine *declines* to follow — a
below-confidence entity, a wrong-identity alias, an already-dispatched target, a
non-pivotable kind — is recorded as an `entity_excluded` event with its reason,
and every value rejected at intake (a `@gmail`-style fragment, a placeholder, a
bogus IP) is logged the same way. The scored self-audit
(`hse audit --scan-id <id>`, or the web **Audit** panel) rolls these up into an
**expansion ledger** and raises a `recursion-recall` finding — pointing you at
`--expand-all-identities` — when the wrong-identity gate suppressed enough
aliases to risk a coverage blind spot.

---

## Name Intelligence (NAMINT-style)

The `name_intel` module is a bounded, offline port of
[NAMINT](https://seintpl.github.io/NAMINT/). From a full name (plus an
optional trailing year, e.g. `"Jordan Leigh Meyers 1987"`) it derives — with
**no network calls and zero native deps** — the identifiers and pivots a human
analyst would build by hand:

```bash
hse scan --kind name --value "Jordan Leigh Meyers 1987" --modules name_intel --output json
```

- **Usernames** (≤24, scored): `first.last`, `flast`, `firstl`, reversed,
  hyphen/underscore joins, middle-initial blends, year suffixes → feed
  `username_search`, `social_probe`, `github_user`, `keybase`.
- **Emails** (≤8): top handle shapes × a provider set (Gmail/Outlook/iCloud/
  Yahoo/Hotmail/Proton, override with `HUNTSMAN_EMAIL_DOMAINS`) → feed the email
  pipeline (`hibp`, `hunter_io`, `epieos`, `emailrep`, …). Each email carries its
  **Gravatar** avatar URL (`MD5(email)`).
- **Search pivots** (≤18): ready-to-click Google (web/face/email/phone/document/
  paste) dorks, Bing, DuckDuckGo, Yandex face, LinkedIn, Facebook, X, Instagram,
  TikTok, GitHub, WhatsMyName, Epieos — surfaced as clickable `Url` entities in
  the Web UI Browse table.

Permutations are low-confidence *candidates*, so they enrich the graph and the
correlator without auto-spending API budget. To recurse on them, lower the
expansion floor:

```bash
hse scan --kind name --value "Jordan Leigh Meyers" --depth 1 --min-expand-confidence 0.35
```

---

## Architecture

- `#![forbid(unsafe_code)]` — entire codebase
- **Runtime AI-independence** — zero AI/ML/LLM/inference/vector/embedding deps; every result is deterministic Rust, identical on Termux aarch64 (no root), Linux and CI with no AI available (CI-enforced; charter: [`docs/RUNTIME_INDEPENDENCE.md`](docs/RUNTIME_INDEPENDENCE.md))
- rustls + bundled-sqlite only — no OpenSSL, no native TLS, no C deps
- `StoragePort` trait — engine/API decoupled from SQLite via Strangler Fig
- 1600+ tests (unit + API integration + architecture boundary enforcement)
- 43 correlator rules (AU-001 through AU-043), incl. 2 graph-aware edge rules
- 2 tokio worker threads (tuned for Termux low-power devices)
- Release binary ~5 MB stripped (opt-level="s", LTO, codegen-units=1)

---

## Documentation

| Document | Content |
|----------|---------|
| [`docs/INSTALL.md`](docs/INSTALL.md) | All install paths + Termux quirks |
| [`docs/USAGE.md`](docs/USAGE.md) | Full CLI reference + HTTP API |
| [`docs/MODULES.md`](docs/MODULES.md) | Module catalogue + synergy map |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common errors + fixes |
| [`docs/FAULT_TREE_ANALYSIS.md`](docs/FAULT_TREE_ANALYSIS.md) | System-wide FTA: failure modes, controls + open risks |
| [`docs/RUNTIME_INDEPENDENCE.md`](docs/RUNTIME_INDEPENDENCE.md) | Runtime AI-independence, parity & reproducibility charter |
| [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) | Source-tree conventions: layering, one-module-per-file, single-source vocabularies, determinism, drift-guards |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history |

---

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE)
at your option.
