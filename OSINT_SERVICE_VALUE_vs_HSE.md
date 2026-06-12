# OSINT Service Value Analysis — Commercial Services vs. Huntsman Search Engine

**Prepared for:** Haigen Bamford
**Date:** 2026-06-12
**Analyst tool reference:** Huntsman Search Engine (HSE) v1.0.0 — 112 modules (87 free · 25 key-gated/paid)
**Purpose:** Price a range of OSINT services (cheapest → most expensive) and weigh each
against what HSE already delivers natively or through bring-your-own-key (BYO-key) integration.

> **Scope note / caveat.** This analysis does **not** have the specific "previous website" that
> prompted the request in session context. Instead it prices the live commercial offerings of the
> seven services named in `DOSSIER_OSINT_Service_Usernames.md` (IntelligenceX, OathNet, DeHashed,
> Epieos, UserSearch, Shodan, WiGLE) plus the adjacent commercial platforms HSE either integrates
> with or competes against (HIBP, Hunter.io, Censys, Maltego, SpiderFoot HX, OSINT Industries).
> All figures were pulled from vendor pricing pages and reputable secondary sources in **June 2026**
> and are reproduced with sources at the foot of this document. Currency conversions are
> **approximate** (≈ €1 = $1.08, £1 = $1.27) and for ranking only — pay in the vendor's native
> currency. Where a vendor does not publish a number ("contact sales"), it is marked **POA**.

---

## 1. Pricing — cheapest to most expensive

Ranked by the **realistic entry price an individual analyst pays to start using the service
meaningfully**, with the ceiling shown alongside. "Free tier" means a genuinely usable no-cost mode.

| # | Service | Free tier | Entry paid price | Ceiling / top tier | What the money buys |
|---|---------|-----------|------------------|--------------------|---------------------|
| 1 | **WiGLE** (wigle.net) | ✅ Free, non-commercial, daily query cap | — (free) | **POA** commercial licence (currently *suspended*) | Wardriving DB: WiFi/Bluetooth BSSID → geolocation, SSID intel |
| 2 | **Shodan** (membership) | Limited free account | **$49 one-time** (lifetime membership) | — | Internet-wide host/port/banner search; lifetime, not subscription |
| 3 | **Have I Been Pwned** | k-anonymity password API free | **$4.39/mo** (Core 1, 10 RPM; $52.68/yr) | **$5,833/mo** (High RPM 24 000) | Breach presence by email/domain; Pro tiers add k-anonymity + high throughput |
| 4 | **DeHashed** | Search free, pay to *view* results; 10 monitor tasks | **~$5.49/week** (≈$15/mo; **$180/yr**) | Enterprise POA | Raw breached credentials/records; API credits **$3 / 100** |
| 5 | **UserSearch.org** | Limited free lookups | **$6.99–$14.97/mo** ($159.97/yr) | Premium + credits | Username/email → social & people-search pivots; +$10/mo partner-data credits |
| 6 | **OathNet** (oathnet.org) | ✅ Free, 10 lookups/day | Starter (50/day) — **low, exact $ not public** | Enterprise 1000+/day POA | Breach + stealer-log search & OSINT enrichment via one API |
| 7 | **OSINT Industries** | Trial | **£19/mo** (~$24, 30 searches) | £99/mo (~$126, 300, +API) | Email/phone/username → account-existence across 100s of sites |
| 8 | **Epieos** | ✅ Visitor + Member (free) | **€29.99/mo** (~$32, Osinter) | €49/mo (~$53) Pro, 500 lookups +API | Email/phone reverse lookup, Google/registration footprints |
| 9 | **Hunter.io** | Free, 50 credits/mo | **$49/mo** (Starter, $34 annual) | $299/mo (Scale, 25k credits) | Corporate email discovery/verification by domain |
| 10 | **Shodan** (API subs) | — | **$69/mo** (Freelancer) | $1,099/mo (Corporate); Enterprise POA | Programmatic query/scan credits on top of membership |
| 11 | **Censys** | ✅ Free < 250 queries/mo | **~$99/mo** | ~$1,000/mo | Internet asset/attack-surface search (Shodan competitor) |
| 12 | **Intelligence X** | 7-day trial; free for universities | **€2,500/yr** (~$2,700; Researcher) | €7,500/yr (~$8,100) Identity Portal; API €5,000/yr | Historical/dark-web data, leaks, document & selector search |
| 13 | **SpiderFoot HX** | Open-source SpiderFoot is free | **POA** (Freelancer/Business/Enterprise, annual) | Enterprise POA | *Hosted* OSINT **automation/orchestration** + team features |
| 14 | **SecurityTrails** | Limited free API | **POA** (API tier public-ish; rest custom) | Enterprise POA | Deep DNS/WHOIS history, subdomains, infra pivots |
| 15 | **Maltego** | ✅ Basic (free, community) | Entry (individual) → **$6,600/yr** (~$550/mo, Professional) | Enterprise POA | Desktop link-analysis graph + 100+ paid data "transforms" |

**Reading the table.** The market splits into three economic bands:

- **Data-provider services** (HIBP, DeHashed, OathNet, IntelX, UserSearch, Shodan, WiGLE, Censys,
  SecurityTrails, Hunter.io, Epieos) — you pay for access to a **proprietary dataset** or
  **scanning infrastructure** you cannot otherwise obtain. Entry is cheap ($4–$50/mo); the price
  scales with *throughput/volume*, not features.
- **Aggregator/lookup services** (OSINT Industries, UserSearch, Epieos) — you pay a markup for a
  **convenience layer** that fans one selector out across many sources and presents a tidy report.
- **Orchestration/analysis platforms** (Maltego, SpiderFoot HX) — you pay the **most** ($550/mo+)
  for the *workflow engine* that chains sources, correlates results, and visualises the graph.

That third band is exactly the layer HSE occupies — for **$0**.

---

## 2. What Huntsman Search Engine actually provides

HSE is an open-source (MIT/Apache-2.0), pure-Rust OSINT/GEOINT **orchestration engine** that runs as
a single ~5 MB binary on Termux/Android aarch64 with no root, plus desktop Linux. It is the
SpiderFoot-style automation + correlation layer, not a data vendor. Its 112 modules divide into:

**87 free / keyless modules** that reproduce much of the *free-tier* value of the priced services:

| Capability | HSE free modules | Overlaps (priced service) |
|---|---|---|
| Breach / stealer presence | `hudsonrock` (stealer-log lookup), `pwned_passwords`, `xposed_or_not`, `psbdmp` | HIBP, DeHashed, OathNet *(presence only — no raw creds)* |
| Username / people pivots | `username_search`, `social_probe`, `username_variants`, `name_intel` (offline NAMINT port), `github_user`, `keybase`, `reddit_user`, `hacker_news` | UserSearch, OSINT Industries, Epieos |
| Email intelligence | `email_parse`, `email_canonical`, `disposable_check`, `smtp_vrfy`, `gravatar`, `contact_enrich`, `employer_pivot`, `pgp` | Hunter.io, Epieos, emailrep |
| DNS / domain / infra | `crtsh`, `cert_intel`, `whois`, `rdap_domain`, `dns_intel`, `doh_resolver`, `subdomain_takeover`, `typosquat`, `hackertarget`, `bgpview`, `shodan` (free), `greynoise`, `urlscan`, 5× IP-geo providers | SecurityTrails, Censys, Shodan |
| Geolocation pipeline | `ip_geo`, `ip_whois_geo`, `geocode`/`photon` (Nominatim), `overpass`, `mylnikov`/`mls`, `phone_*_geo`, `exif_geo` | (most commercial tools charge for or omit this) |
| Corporate / public records | `opencorporates`, `gleif_lei`, `acnc_charities`, AU `asic_director`/`au_electoral`/`au_property`/`au_unclaimed` | (AU-specific niche few competitors cover) |
| On-device GEOINT (Termux) | `device_sensors`, `cell_intel`, `local_net` (WiFi/cell/GPS/ARP) | (no cloud OSINT service can do this — it needs the handset) |

**25 key-gated/paid modules** that turn HSE into a **single front-end for the priced services**, each
called with **your own API key** so you pay the vendor's metered rate directly, with no aggregator
markup: `dehashed`, `intelx`, `hibp`, `hunter_io`, `epieos`, `emailrep`, `censys`, `securitytrails`,
`virustotal`, `abuseipdb`, `ipqs`, `leakix`, `oathnet_pro`, `proxycurl`, `seon`, `wigle`, `whoisxml`,
`see_know`, `criminal_ip`, `threatfox`, `fullcontact`, `numverify`, `abn_lookup`, `exa_search`.

On top of collection, HSE adds what the *expensive* band charges for: autonomous multi-round
expansion, 43 correlator rules, a D3 relationship graph, a scored self-audit/expansion ledger, and
MITRE ATT&CK Reconnaissance (TA0043) mapping — deterministically, with zero AI/ML dependencies.

---

## 3. Head-to-head — can HSE replace, complement, or not match each service?

| Service | HSE verdict | Rationale |
|---|---|---|
| **WiGLE** | **Complement (BYO-key)** | `wigle` module drives WiGLE's API; HSE adds adaptive-bbox quota conservation + the geo pipeline. The *dataset* is still WiGLE's. WiGLE non-commercial access is free anyway. |
| **Shodan** | **Mostly replace at free tier; complement at scale** | Free `shodan` module + `greynoise` + `urlscan` + `webserver_banner` + `cert_intel` cover host/banner/cert recon. For high-volume scan/query credits you still buy Shodan. |
| **HIBP** | **Replace presence-checks free; complement for raw** | `pwned_passwords`/`xposed_or_not` answer "is it breached?" free. HIBP's paid API (via the `hibp` module) is only needed for authoritative domain-wide breach enumeration. |
| **DeHashed** | **Complement only (data moat)** | HSE has **no breach corpus of its own**. `hudsonrock` gives stealer-log *presence*, but raw leaked credentials require DeHashed behind the `dehashed` key. HSE = the interface + correlation, not the data. |
| **UserSearch / OSINT Industries / Epieos** | **Largely replace** | HSE's free `username_search` + `social_probe` + `name_intel` + email modules reproduce the username/email fan-out these aggregators charge £19–€49/mo for. Epieos/`epieos` still wins on a few proprietary modules (LinkedIn/Fitbit), available BYO-key. |
| **OathNet** | **Complement (data moat)** | The in-repo dossier shows HSE already orchestrating OathNet Pro via `oathnet_pro`. HSE does all the structural/cross-reference analysis; OathNet owns the breach/stealer data **and the paywall** — e.g. the dossier's `***UPGRADE_TO_SEE***` redactions are OathNet's, not something HSE can lift. |
| **Censys / SecurityTrails** | **Replace much free; complement for depth** | Free `crtsh`/`cert_intel`/`dns_intel`/`subdomain_takeover`/`bgpview` cover everyday DNS/cert/infra recon. Historical DNS depth and full asset search still need the paid `securitytrails`/`censys` keys. |
| **Hunter.io** | **Partial replace** | `employer_pivot`/`contact_enrich`/`crtsh` infer corporate emails free; Hunter's verified-email dataset (via `hunter_io`) is better for bulk B2B email discovery. |
| **Intelligence X** | **Complement only (data moat)** | IntelX's historical/dark-web corpus is proprietary; HSE reaches it via the `intelx` key. At €2,500–€7,500/yr this is the dataset you rent, not rebuild. |
| **SpiderFoot HX** | **Replace (direct competitor)** | This is HSE's closest analogue — the hosted OSINT *automation* layer. HSE delivers the same orchestration + correlation + web UI **free and self-hosted**, and uniquely runs on a phone with no root. |
| **Maltego** | **Replace the engine; rent the transforms** | HSE's expansion engine + D3 graph + correlator replace Maltego's $6,600/yr link-analysis core. Maltego's paid third-party "transforms" map to HSE's BYO-key modules — same economics, no $550/mo platform fee. |

---

## 4. Value verdict

**Where HSE wins outright (displaces spend):**

1. **The orchestration/analysis band — the most expensive layer.** Maltego ($6,600/yr) and
   SpiderFoot HX (POA, typically four figures/yr) sell the workflow engine, correlation, and graph
   that HSE ships for **$0**, self-hosted, on a handset. This is the single largest cost avoidance.
2. **Free-tier parity with the aggregators.** UserSearch ($7–$15/mo), OSINT Industries
   (£19–£99/mo), and Epieos's free modules are substantially reproduced by HSE's free
   username/email/social fan-out — the convenience markup mostly evaporates.
3. **Breach/infra *presence* checks** (HIBP password API, Shodan/Censys free recon, HudsonRock
   stealer-log presence) — covered free, deferring paid tiers until you need authoritative volume.
4. **Capabilities no cloud OSINT service sells at all:** on-device WiFi/cell/GPS GEOINT via Termux
   sensors, a free end-to-end geolocation pipeline (Nominatim/Photon/Overpass), and
   Australia-specific public-records dorking (ASIC/AEC/land titles/ABN-ACN).

**Where HSE cannot win (you still pay the vendor):**

- **Proprietary datasets are moats.** DeHashed, Intelligence X, OathNet, and HIBP's full corpus own
  data HSE does not have and cannot scrape. For *raw* leaked credentials/records, historical
  dark-web selectors, or authoritative domain-wide breach enumeration, you rent their access. HSE's
  value there is being the **single pane of glass** that calls them via your own key — so you pay
  the vendor's published metered rate (e.g. DeHashed $3/100 credits, IntelX €2,500/yr) instead of an
  aggregator's bundled premium, and you get HSE's correlation on top.
- **Managed extras.** SLAs, hosted infrastructure, team seats, and vendor support are things a
  free self-hosted binary does not provide.

**Bottom line for budgeting.** Treat HSE as the **free replacement for the $550/mo+ orchestration
tier (Maltego/SpiderFoot HX) and the $7–$126/mo aggregator tier (UserSearch/OSINT Industries/
Epieos)**, and as a **cost-neutral BYO-key front-end** for the data-provider tier you genuinely need
(start with the cheapest meaningful keys — HIBP at $4.39/mo, DeHashed at ~$15/mo, OathNet free→low —
and only climb to IntelX/Maltego-class spend when a specific dataset demands it). The recurring spend
HSE *eliminates* is the platform/aggregator markup; the spend it *cannot* eliminate is the raw-data
access fee — but it lets you pay that once, directly, instead of twice.

---

## 5. Security hygiene note (incidental, flagged in good faith)

`DOSSIER_OSINT_Service_Usernames.md` §8 commits what it labels live API keys (OathNet Pro, HIBP v3,
WiGLE) into the repository in plaintext. If any are real and active, committed secrets are exposed to
anyone with repo access and to Git history even after deletion. Recommended: rotate those keys at the
vendors, move them to `~/.huntsman.env` (which the installer already preserves and the code reads via
`ctx.key("HUNTSMAN_*")`), and scrub them from history. Not part of the pricing question, but worth
fixing before this repo is shared.

---

## Sources

- DeHashed — <https://dehashed.com/>, pricing/credits via <https://bellingcat.gitbook.io/toolkit/more/all-tools/dehashed> and <https://leakradar.io/en/alternatives/dehashed>
- Intelligence X — <https://intelx.io/product>, <https://blog.intelx.io/2022/11/19/price-increase-2023/>
- Shodan — <https://account.shodan.io/billing>, <https://developer.shodan.io/pricing>
- Epieos — <https://epieos.com/pricing>
- UserSearch — <https://usersearch.org/features.php>, <https://usersearch.ai/help/doku.php?id=subscriptions>
- Have I Been Pwned — <https://haveibeenpwned.com/Subscription>, <https://www.troyhunt.com/the-have-i-been-pwned-api-now-has-different-rate-limits-and-annual-billing/>
- OathNet — <https://oathnet.org/pricing>
- Hunter.io — <https://hunter.io/pricing>
- Maltego — <https://www.maltego.com/pricing/>
- WiGLE — <https://wigle.net/faq>, <https://api.wigle.net/>
- SpiderFoot HX — <https://www.spiderfoot.net/>
- OSINT Industries — <https://www.osint.industries/pricing>
- Censys — <https://censys.com/resources/pricing/>
- SecurityTrails — <https://securitytrails.com/corp/pricing>

*Prices change frequently and several vendors gate exact figures behind "contact sales"; verify against the live pages before committing budget. Currency conversions are approximate (June 2026).*
