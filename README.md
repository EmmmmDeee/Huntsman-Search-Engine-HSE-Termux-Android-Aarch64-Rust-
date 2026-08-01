# Huntsman Search Engine (HSE)

[![CI](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/workflows/ci.yml/badge.svg)](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/workflows/ci.yml)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary%20%C2%B7%20All%20Rights%20Reserved-red.svg)](#licence)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![Termux aarch64](https://img.shields.io/badge/Termux-aarch64-darkgreen.svg)](https://termux.dev/)

**All-source OSINT / GEOINT / NETINT reconnaissance in the GhostSec tradition —
SpiderFoot-inspired breadth without the daemon or the footprint.**

Pure-Rust OSINT / GEOINT platform with **170 modules** that runs entirely
inside **Termux on Android aarch64** with no root. Single binary, embedded
dark-console Web UI, zero native dependencies, keyless-first.

### Application architecture

`src/app` is the public application/composition layer shared by the CLI and
HTTP adapters. It exclusively owns concrete SQLite and engine construction,
including shared runtime assembly and store-backed audit, benchmark, diff,
doctor, and gap workflows; `app::update` owns the update lifecycle. CLI and API
code provide transport and presentation only, and architecture tests prevent
presentation code from importing CLI internals or concrete storage.

---

## Install (Termux Android aarch64, no root)

### ⭐ The installer — one line, all-in-one

This **single command is the installation** — it always tracks the latest
`main`, does **absolutely everything**, and is **safe to re-run** (re-running
upgrades an existing install in place to the newest version):

> **Termux prerequisite:** Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the [GitHub release](https://github.com/termux/termux-app/releases) — **not** the Play Store (abandoned 2020, broken packages). The installer detects and rejects the Play Store build automatically.

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

**No-build fast path:** the installer prefers a prebuilt aarch64 binary over a
source compile, trying in order: (1) a precompiled `hse` /
`hse-aarch64-linux-android` in your **Downloads** folder, then (2) the binary
published on this repo's [GitHub Releases](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/latest)
— **downloaded and verified automatically** (size + ELF + `.sha256` + a
run-test). Either way: no Rust toolchain, no compile. This is also the
**fallback when the on-device build can't proceed** — e.g. a broken Termux
`rust` package that ships no static std — so the install still succeeds. After
a *source* build it caches the binary back to Downloads, so your next install
(or another aarch64 phone) takes the instant path automatically. Knobs: point
at a file with `HSE_PREBUILT=/path/to/hse`, pin a release with
`HSE_PREBUILT_TAG=vX.Y.Z`, skip the download with `HSE_NO_DOWNLOAD=1`, force a
source build with `HSE_PREFER_BUILD=1`, or keep your own Termux mirror with
`HSE_KEEP_MIRROR=1`.

Also works on Debian/Ubuntu and macOS. Full log at `~/.cache/hse-install.log`.
See [`docs/INSTALL.md`](docs/INSTALL.md) for every install path, knobs
(`HSE_REF`, `HSE_INSTALL_DIR`, …) and Termux quirks.

Then launch the Web UI:

```bash
hse serve   # binds 127.0.0.1:8080 (loopback only)
```

Open **Chrome** (or Firefox) on the phone and go to `http://127.0.0.1:8080`.
You'll get a dark-console UI — **Dashboard · New Scan · Scans ·
Live · Engines · Settings** — where **New Scan** drives the engine and each
scan's results page tabs through a sortable entity browser, a D3 force graph,
severity-tagged correlations, and a real-time (SSE) event log. The **Settings
page lets you paste & save API keys** straight from the browser (loopback-only,
so keys never leave the device).

> That's the whole install: **one command, then `hse serve`, then open
> `http://127.0.0.1:8080` in Chrome.** Everything below is reference detail.

> **Web & API scans are as thorough as the CLI.** A scan launched from the
> Chrome SPA's **New Scan** wizard, or via `POST /api/v1/scans` with `options`
> omitted, uses the same comprehensive defaults as `hse scan` — depth 3,
> expansion floor 0.20, entity cap 2500 — so you get the full seed → identifiers
> → pivots → infrastructure sweep without tuning anything.

> **Value-per-query is maximised by default (v1.14+).** Every scan — CLI, API,
> and Web wizard — now runs with **convex (optionality / barbell) budget
> allocation** on: under the device's bounded budget it spends on cheap,
> high-upside identity leads (an email, a username) before expensive, already-
> saturated infrastructure fan-out, so a phone scan returns more of what matters
> per unit of work. The confident identity core keeps its order — only the
> uncertain tail and the pricey infrastructure are re-sorted. Opt out with
> `hse scan --no-convex-budget` or `"convex_budget": false` in the API `options`.
>
> **Convex ordering now reaches the queries themselves (v1.19+).** The same
> barbell logic that ranks *which lead to pivot on* now also orders *which
> modules fire first for a target* — because a module dispatch **is** a query
> (bounded HTTP, wall-time, battery, and for paid providers real quota). Under
> the convex flag the engine dispatches by **query value = optionality ÷ cost**:
> cheap, keyless, identity-/key-unlocking modules run before expensive, terminal
> ones, so a scan cut short by the phone's budget (an entity cap, a wall-clock
> limit, a cancel, a dying battery) has already spent it on the queries that
> compound. Membership is unchanged — every accepting module still runs when the
> budget allows — only the order differs, and it is precomputed once so the hot
> path pays nothing. Preview it per seed at **New Scan → Preview plan** (chips
> ordered by query value, badged high/moderate/terminal) or
> `GET /api/v1/plan?value=…`.

> **Capability-aware dispatch (v1.18+) — no budget wasted on dead sources.**
> The same scans also skip any module whose parser has **provably gone dead**
> across recent runs — persistent failures or silent zero-yield drift, from the
> cross-scan health signal — so its dispatch slot goes to a source that still
> works. It only culls the automatic comprehensive fan-out: an explicit
> `--modules` set or `hse scan --full` still runs everything, and a quarantined
> module recovers automatically the moment it returns one healthy result. Opt
> out with `--no-skip-dead-modules` / `"skip_dead_modules": false`. Together with
> the live capability probe below, HSE now both *sees* a dead capability and
> *routes around it* — the durability loop, closed.

> **Live capability probe (v1.14+) — know a source works before you rely on it.**
> A third-party provider can silently change its response shape and a module's
> parser goes quiet while its unit tests stay green. **Engines → Run live
> capability probe** (in the Web UI), `hse doctor --live` (CLI), or
> `GET /api/v1/capabilities/probe` fires one bounded request per keyless module
> at its real endpoint and reports **alive / empty / unreachable / drift** per
> module — the proactive complement to the cross-scan *Scraper health* panel.
> Loopback-only and bounded, so it is Termux-safe.

> **Termux battery & background (required for long scans):** Android → Settings → Apps → Termux → Battery → set to **Unrestricted** and enable "Allow background data". Without this Android kills Termux mid-scan.

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
hse modules                                                 # list all 170 modules
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

## Seed Types (16 supported)

| Seed | Flag | Example | Modules |
|------|------|---------|---------|
| Email | `--kind email` | `user@example.com` | 35 |
| Username | `--kind username` | `johndoe` | 14 |
| Phone | `--kind phone` | `+61400000000` | 7 |
| Full Name | `--kind name` | `Jordan Leigh Meyers` | 6 |
| IP Address | `--kind ip` | `1.1.1.1` | 33 |
| Domain | `--kind domain` | `example.com` | 39 |
| ASN | `--kind asn` | `AS13335` | 1 |
| CIDR | `--kind cidr` | `1.1.1.0/24` | 3 |
| Coordinates | `--kind coords` | `-27.47,153.02` | 6 |
| Address | `--kind address` | `Nundah, QLD 4012` | 2 |
| URL | `--kind url` | `https://example.com/page` | 2 |
| Organisation | `--kind org` | `ACME Pty Ltd` | 2 |
| ABN/ACN | `--kind abn` | `51824753556` | 1 |
| MAC Address | `--kind mac` | `AA:BB:CC:DD:EE:FF` | 3 |
| Crypto Address | `--kind crypto` | `bc1q…` | 2 |
| API Key | `--kind apikey` | `AKIA…` | 1 |

---

## Module Overview (170 modules — 134 free, 36 key-gated/paid)

> A curated highlight of the modules below (not the full list). The complete, always-current catalogue
> with target kinds and output entities lives in the running software — run
> `hse modules` or open the web UI's module wizard — never a static doc that
> can drift from the registry.

**API-Free (no keys required) — 92:**
- **Breach/identity**: `psbdmp`, `pwned_passwords`, `xposed_or_not`
- **Social**: `crates_io`, `github_code_search`, `github_user`, `hacker_news`, `keybase`, `npm_author`, `reddit_user`, `social_probe`, `streaming_probe`, `username_search`, `username_variants`
- **People**: `ahpra`, `au_electoral`, `au_people`, `au_property`, `contact_enrich`, `employer_pivot`, `gravatar`, `name_intel`, `payid`, `pgp`, `wikidata`
- **DNS/domain**: `cert_intel`, `crtsh`, `dns_axfr`, `dns_intel`, `doh_resolver`, `domainsdb`, `hackertarget`, `mnemonic_pdns`, `rdap_domain`, `subdomain_takeover`, `typosquat`, `whois`
- **IP/infrastructure**: `bgpview`, `greynoise`, `hudsonrock`, `ip2location`, `ip_registry`, `ip_reputation`, `ip_whois_geo`, `ipinfo`, `ipquery`, `netblock`, `portscan`, `ripestat`, `shodan`, `urlscan`
- **Geolocation**: `beacondb`, `breach_timezone`, `cell_local`, `email_header_geo`, `email_locale`, `exif_geo`, `geo_domain_classifier`, `geo_intel`, `geocode`, `ip_geo`, `mls`, `mylnikov`, `open_meteo_geo`, `overpass`, `phone_geo`, `photon`, `qld_cadastre`, `social_location`, `sunrise_sunset`
- **Threat intel**: `urlhaus`
- **Email**: `disposable_check`, `email_canonical`, `email_parse`, `smtp_vrfy`
- **Phone**: `phone_au`, `phone_intl`
- **Corporate**: `acma_rrl`, `acnc_charities`, `asic_director`, `au_unclaimed`, `austlii`, `gleif_lei`, `opencorporates`
- **Search**: `search_engines`
- **Web analysis**: `cloud_storage`, `sitemap`, `waf_detect`, `wayback`, `web_crawler`, `webserver_banner`
- **Termux sensors**: `cell_intel`, `device_sensors`, `local_net`, `signal_radar`
- **Other**: `api_key_probe`, `chain_intel`

**Key-gated / Paid — 33 (28 key-gated · 5 paid):**
- `abn_lookup`, `abuseipdb`, `censys`, `criminal_ip`, `dehashed`, `emailrep`
- `epieos`, `exa_search`, `fullcontact`, `hibp`, `hlr_cnam`, `hunter_io`, `intelx`, `ipqs`
- `leakix`, `netlas`, `niamonx`, `numverify`, `oathnet_pro`, `onyphe`, `opencellid`, `osintcat`, `proxycurl`
- `securitytrails`, `see_know`, `seon`, `threatfox`, `trove_au`, `virustotal`, `whoisxml`
- `wifi_intel`, `wigle`, `zoomeye`

### MITRE ATT&CK alignment (in the data, not a side report)

The tool carries the **complete** MITRE ATT&CK Enterprise matrix as reference
vocabulary — all 14 tactics and every current technique/sub-technique (v17.1),
as pure static data (`src/core/attack/`), so any `Tnnnn[.nnn]` id the tool emits
resolves to its canonical name and owning tactic. But HSE only *claims coverage*
of the one tactic it actually performs: **Reconnaissance** (TA0043). Holding the
whole framework while claiming one tactic is the invariant, not a contradiction —
reference vocabulary is never a coverage assertion, so the per-scan coverage /
gap report is computed against Reconnaissance alone and a technique HSE performs
no collection for (e.g. `T1598` Phishing for Information) surfaces as a real,
named gap.

Every module is mapped to the Reconnaissance technique(s) it implements, and that
mapping is **woven into every scan**: as each finding is admitted, the engine
stamps it inline with its producing module's technique(s) as
`attack:<TECHNIQUE_ID>` tags (e.g. `attack:T1589.002` "Email Addresses"). So the
technique that collected a datum travels with the datum — visible in the entity's
`tags` in JSON output, on each entity in the full dossier
(`hse export <id> --format full`) and `hse scan --output dossier`, and in the
database — with no separate coverage report to reconcile. A finding corroborated
by several modules carries all of their techniques (merges union the tags).


## Web UI (dark-console, zero vendored UI framework)

`hse serve` launches a localhost-only HTTP server with an embedded SPA split
into native ES modules (`src/web/js/`) on a from-scratch dark-console design
system (`src/web/css/app.css`). D3 v3 is the one remaining vendored library
(the force-directed graph rendering engine); Bootstrap, jQuery, tablesorter,
and alertify — SpiderFoot's original UI-framework stack — have been dropped
in favour of our own CSS and a small vanilla-JS compatibility layer
(`src/web/js/ui.js`) for navbar collapse, the About modal, sortable tables,
and toast/confirm/prompt dialogs. The navigation structure and scan workflow
still follow SpiderFoot's mental model for operator familiarity; the visual
design and every dependency underneath it are HSE's own:

- **Dashboard** — stats cards, scan status breakdown, quick actions
- **New Scan** — target input + module grid with tooltips + depth/throttle
  controls + use-case presets
- **Scan Results** — tabbed: Status, Browse (sortable entity table with
  inline expand), D3 Force Graph (entity relationship visualization, incl.
  typed relation edges — subdomain/lineage/co-location — dashed, kind on hover),
  Correlations (severity-tagged), Event Log (real-time SSE), Info
- **Settings** — API key management with validation
- **Dark mode** by default, light mode opt-out toggle

Binds to `127.0.0.1:8080` by default — no LAN exposure. This is the
operator-followed default, not an enforced restriction: `--bind`/`HSE_BIND`
accept any address, and binding non-loopback exposes scan/live/radar
**triggering** (not just viewing results) to anyone who can reach that
address, with no authentication — only key-writing (`PUT /settings/keys`)
stays loopback-only regardless of bind. Use 127.0.0.1 unless you specifically
need LAN access and understand that trade-off.

---

## Geolocation Pipeline

Every seed type has a pathway to geographic coordinates:

```
Name/Email/Username → search_engines (17 engines, free)
                    → discovered emails/phones/addresses
                    → oathnet_pro (breach IPs)
                    → ip_geo + ip_whois_geo (free HTTPS)
                    → Coordinates
                    → geocode (Nominatim, free) → Address
                    → wigle (WiFi density + SSID intel + AP MAC addresses)

IP Address → ip_geo (free) + ip_whois_geo (free) → Coordinates + Address
           → geocode → precise Address

Address → geocode (Nominatim, free) → Coordinates
        → search_engines → name/phone/business associations

Coordinates → geocode → Address
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
| `--depth N` | `2` | Max expansion rounds (0 = single seed round) |
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
- **Runtime AI-independence** — zero AI/ML/LLM/inference/vector/embedding deps; every result is deterministic Rust, identical on Termux aarch64 (no root), Linux and CI with no AI available (CI-enforced by `runtime_carries_no_ai_ml_inference_dependency` in `tests/architecture.rs`)
- rustls + bundled-sqlite only — no OpenSSL, no native TLS, no C deps
- `StoragePort` trait — engine/API decoupled from SQLite via Strangler Fig
- 4,300+ tests (unit + API integration + architecture boundary enforcement)
- Deterministic correlator: 121 rules (107 entity + 14 graph-aware relation), no LLM/fuzzy matching
- 121 correlator rules (AU-001 through AU-123, with some IDs reserved for engine-emitted cross-scan findings such as AU-065/AU-066), incl. graph-aware edge, transitive, multi-pathway corroboration, gap-analysis, jurisdiction cross-check (coordinate / address / phone-region), prediction-confirmed identity bridges (name-derived username AU-077 / email AU-086), sanctions/debarment/PEP screening (AU-114), personal-WiFi geolocation (AU-115), pathway-template, resolved-identity-cluster, anonymous-SIM, high-integrity-connection (max-bottleneck route), connection-broker (identity articulation-point), robustly-corroborated-identity-cluster (no-single-point-of-failure k-redundant cluster), transitive-infrastructure-closure (AU-116 — a multi-server hosting footprint chained across IPs no single-hop rule sees), paired-hardware-constellation (AU-117 — the operator's own bonded Bluetooth kit as a self-carried tracking fingerprint), look-alike-domain-impersonation (AU-118 — homoglyph/typo phishing domains flagged across every discovered domain, dnstwist at the correlation layer), dating-platform-exposure (AU-119 — a subject's confirmed dating-app profiles surfaced as a location-bearing personal-exposure surface), monetized-creator-exposure (AU-120 — confirmed subscription-creator/webcam/adult profiles as an identity-linked payment/KYC surface), transitive credential-reuse blast-radius (AU-121 — the reuse-chain closure no single secret spans), trackable-RF-device (AU-122 — persistent hardware MACs separated from randomized privacy addresses in a radar/WiGLE sweep), and numeric-variant-handle-persona (AU-123 — links base-handle-plus-number username variants like `jdiegmann`/`jdiegmann92` across ≥2 sources into one persona, the digit-suffix reuse the exact-match handle rules never join) rules — deterministic, no LLM/fuzzy matching
- 2 tokio worker threads (tuned for Termux low-power devices)
- Release binary ~5 MB stripped (opt-level="s", LTO, codegen-units=1)

Run `hse selftest` or `hse diagnostics` for a live, self-checked account of
the module registry, dispatch graph, and core invariants — or pull the
one-click system debug bundle (Settings → Diagnostics → "Download full
diagnostic bundle") for the complete engine state in one file.

---

## Documentation

| Document | Content |
|----------|---------|
| [`docs/INSTALL.md`](docs/INSTALL.md) | All install paths + Termux quirks |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common install/runtime errors + fixes |
| [`docs/OSINT_API_REFERENCE.md`](docs/OSINT_API_REFERENCE.md) | External OSINT-provider API reference (free tiers, key shapes, integration status) |
| [`docs/SEEKNOW_SETUP.md`](docs/SEEKNOW_SETUP.md) | SeekNow (see-know.ru) API setup + full endpoint reference |
| [`docs/OATHNET_API_GUIDE.txt`](docs/OATHNET_API_GUIDE.txt) | OathNet API contract reference |
| [`docs/OPERATIONAL_CONSTITUTION.md`](docs/OPERATIONAL_CONSTITUTION.md) | Reasoning, evidence, and analysis standards governing HSE work |
| [`docs/PERSISTENT_INTELLIGENCE.md`](docs/PERSISTENT_INTELLIGENCE.md) | How understanding accumulates across reasoning cycles (constitution companion) |

For everything else — module catalogue, CLI reference, architecture — the
running software is the source of truth: `hse --help`, `hse modules`, the web
UI, and `hse selftest`/`hse diagnostics` never drift from the code the way a
static doc can.

---

## Licence

**Proprietary — © 2026 Huntsman Search Engine. All rights reserved.** See
[`LICENSE`](LICENSE). The source is published for reference and evaluation
only; it may **not** be used, copied, modified, redistributed, **resold**, or
otherwise commercialised — in whole or in part — without the copyright
holder's prior written permission.

### Commercial use & licensing

A commercial licence — for internal business use, hosted/SaaS deployment,
OEM/embedding, or redistribution — is available by separate written agreement.
Contact the repository owner to discuss licensing, support, or a pilot.

### Authorised & lawful use

HSE is built for **authorised** security, fraud-prevention, due-diligence, and
investigative work only. You are responsible for establishing a lawful basis
for every scan. Do **not** use it to harass, stalk, or surveil individuals, or
to process personal data without a lawful basis under the applicable privacy law
(e.g. the Australian *Privacy Act 1988*, the EU GDPR, or your local equivalent).
The software is provided for legitimate use; the maintainers disclaim
responsibility for misuse. See [`SECURITY.md`](SECURITY.md) for vulnerability
disclosure.
