# OSINT Service Value Analysis — Commercial Services vs. Huntsman Search Engine

**Prepared for:** Haigen Bamford
**Date:** 2026-06-12
**Analyst tool reference:** Huntsman Search Engine (HSE) v1.0.0 — 112 modules (87 free · 25 key-gated/paid)
**Purpose:** Price a range of OSINT services on a like-for-like basis and weigh each, capability by
capability, against what HSE delivers natively or through bring-your-own-key (BYO-key) integration.
**See also:** [`OSINT_MATRIX_GAP_ANALYSIS.md`](OSINT_MATRIX_GAP_ANALYSIS.md) — gap register, closeability
classification (KEY / BUILD / MOAT / CHARTER / MANAGED), and a prioritised closure roadmap built on the parity matrix below.

> **Scope note / caveat.** This analysis does **not** have the specific "previous website" that
> prompted the request in session context. It prices the live commercial offerings of the seven
> services named in `DOSSIER_OSINT_Service_Usernames.md` (IntelligenceX, OathNet, DeHashed, Epieos,
> UserSearch, Shodan, WiGLE) plus the adjacent platforms HSE integrates with or competes against
> (HIBP, Hunter.io, Censys, Maltego, SpiderFoot HX, OSINT Industries). Figures are from vendor
> pricing pages and reputable secondary sources, **June 2026**, cited at the foot. Conversions are
> **approximate** (≈ €1 = $1.08, £1 = $1.27) and for ranking only. "POA" = price on application
> ("contact sales").

---

## 1. Pricing — normalised to annualised USD, cheapest to most expensive

The previous draft ranked by "entry price," which silently mixed one-time ($49), weekly ($5.49),
monthly, and yearly figures — not a true ranking. **This version normalises every service to its
cheapest committed annual cost in USD**, so the order is genuinely comparable. Native price and
billing unit are kept beside it.

| # | Service | Native price | **Annualised USD** | Free tier (real limit) | You're paying for |
|---|---------|--------------|--------------------|------------------------|-------------------|
| 1 | **WiGLE** | free (non-commercial) | **$0** | ✅ daily query cap | WiFi/BT BSSID → geolocation DB |
| 2 | **Shodan** (membership) | $49 **one-time** | **$49 once → ~$0/yr** | limited account | lifetime host/banner search access |
| 3 | **Have I Been Pwned** (Core 1) | $4.39/mo · $52.68/yr | **$53/yr** | ✅ password k-anonymity API | breach presence by email/domain |
| 4 | **UserSearch.org** | $14.97/mo · $159.97/yr | **$160/yr** | ✅ limited lookups | username/people-search pivots |
| 5 | **DeHashed** | $5.49/wk · $180/yr | **$180/yr** | search free, pay to view | raw breached records (API $3/100) |
| 6 | **OathNet** | free 10/day; paid low | **POA (low)** | ✅ 10 lookups/day | breach + stealer-log search API |
| 7 | **OSINT Industries** | £19/mo (£228/yr) | **~$290/yr** | trial | email/phone/user account-existence |
| 8 | **Epieos** (Osinter) | €29.99/mo · €27.08/mo annual | **~$351/yr** | ✅ Visitor + Member | email/phone reverse footprint |
| 9 | **Hunter.io** (Starter) | $49/mo · $34/mo annual | **~$408/yr** | ✅ 50 credits/mo | corporate email discovery |
| 10 | **Shodan** (API Freelancer) | $69/mo (+ membership) | **~$828/yr** | — | scan/query credits at volume |
| 11 | **Censys** | ~$99/mo | **~$1,188/yr** | ✅ < 250 queries/mo | internet asset/attack-surface search |
| 12 | **Intelligence X** (Researcher) | €2,500/yr | **~$2,700/yr** | 7-day trial; free for edu | historical/dark-web & document search |
| 13 | **Maltego** (Professional) | $6,600/yr | **$6,600/yr** | ✅ Basic (community) | link-analysis engine + paid transforms |
| 14 | **SpiderFoot HX** | annual, tiered | **POA** (OSS edition free) | OSS SpiderFoot free | hosted OSINT automation + team features |
| 15 | **SecurityTrails** | API tier public-ish; rest custom | **POA** | limited free API | deep DNS/WHOIS history, infra pivots |

**What the normalisation changes.** Re-ranking by true annual cost moves **UserSearch ($160)
*below* DeHashed ($180)** — the opposite of the entry-price order, because DeHashed's $5.49 *weekly*
teaser annualises to ~$285 while its committed annual plan is $180. Shodan's **one-time $49**
membership is, over any multi-year horizon, the cheapest paid item on the board — a structurally
different deal from everything else, which is recurring.

**Three economic bands** (now with numbers attached):

- **Data-provider tier ($0–$2,700/yr): HIBP, DeHashed, OathNet, IntelX, UserSearch, Shodan, Censys,
  SecurityTrails, Hunter.io, Epieos, WiGLE.** You rent a **proprietary dataset or scanning
  infrastructure**. Price scales with *volume/throughput*, not features.
- **Aggregator tier ($160–$408/yr): UserSearch, OSINT Industries, Epieos.** You pay a markup for a
  **convenience layer** fanning one selector across many sources into a tidy report.
- **Orchestration tier ($6,600/yr+ / POA): Maltego, SpiderFoot HX.** The dearest band — you pay for
  the **workflow engine** that chains sources, correlates, and graphs the result.

The orchestration tier is exactly what HSE *is*, for **$0**; the aggregator tier is largely what HSE
*reproduces free*; the data-provider tier is what HSE *fronts via your own key*.

---

## 2. What Huntsman Search Engine provides

Open-source (MIT/Apache-2.0), pure-Rust orchestration engine; single ~5 MB binary on Termux/Android
aarch64 (no root) and desktop Linux. **87 free/keyless modules** reproduce much of the *free-tier*
value of the priced services; **25 key-gated modules** make HSE a single front-end that calls the
paid services with **your own key** (vendor's metered rate, no aggregator markup). On top it adds the
orchestration-tier value: autonomous multi-round expansion, 43 correlator rules, a D3 relationship
graph, a scored self-audit/expansion ledger, MITRE ATT&CK Reconnaissance (TA0043) mapping — all
deterministic, zero AI/ML dependencies. Inventory of free coverage:

- **Breach/stealer presence:** `hudsonrock`, `pwned_passwords`, `xposed_or_not`, `psbdmp`
- **Username/people:** `username_search`, `social_probe`, `username_variants`, `name_intel`
  (offline NAMINT port), `github_user`, `keybase`, `reddit_user`, `hacker_news`, `npm_author`, `crates_io`
- **Email:** `email_parse`, `email_canonical`, `disposable_check`, `smtp_vrfy`, `gravatar`,
  `contact_enrich`, `employer_pivot`, `pgp`
- **DNS/domain/infra:** `crtsh`, `cert_intel`, `whois`, `rdap_domain`, `dns_intel`, `doh_resolver`,
  `subdomain_takeover`, `typosquat`, `hackertarget`, `bgpview`, `shodan` (free), `greynoise`,
  `urlscan`, `webserver_banner`, 5× IP-geo providers
- **Geolocation pipeline:** `ip_geo`, `ip_whois_geo`, `geocode`/`photon` (Nominatim), `overpass`,
  `mylnikov`/`mls`, `phone_*_geo`, `exif_geo`
- **Corporate/public records:** `opencorporates`, `gleif_lei`, `acnc_charities`, AU `asic_director`/
  `au_electoral`/`au_property`/`au_unclaimed`
- **On-device GEOINT (Termux):** `device_sensors`, `cell_intel`, `local_net` (WiFi/cell/GPS/ARP)

---

## 3. Capability-parity matrix (the core comparison)

Read this as: *for each thing an analyst actually wants to do*, what is the best commercial option
and its annual cost, what does HSE field, how close is parity, and what — if anything — you still
have to pay for. Parity grades: **Full (free)** · **Partial** (HSE covers the common case, paid tool
deeper) · **Presence-only** (HSE confirms existence/counts, not the raw data) · **None — data moat**
(HSE cannot substitute; the value is the dataset) · **HSE-exclusive** (no commercial equivalent sold).

| Capability | Best commercial (annualised) | HSE equivalent | Parity | Residual paid need |
|---|---|---|---|---|
| Password/breach **presence** ("is this exposed?") | HIBP Core 1 **$53** | `pwned_passwords`, `xposed_or_not` | **Full (free)** | none |
| **Domain-wide** breach enumeration | HIBP Pro **$4,548+** | `hibp` (BYO-key) | **None — data moat** | HIBP key |
| **Raw** leaked credentials / records | DeHashed **$180** / IntelX **$2,700** | `hudsonrock` (counts only) | **Presence-only** | DeHashed / IntelX / OathNet key |
| Stealer-log intelligence | OathNet (POA, low) | `hudsonrock` free + `oathnet_pro` BYO | **Partial** | OathNet for record-level detail |
| Historical / dark-web selectors | IntelX **$2,700** | `intelx` (BYO-key) | **None — data moat** | IntelX key |
| Username → social fan-out | OSINT Industries **$290** / UserSearch **$160** | `username_search`, `social_probe`, `username_variants`, `github_user`, `keybase`, `reddit_user`, `hacker_news` | **Full (free)** | none |
| Email reverse / footprint | Epieos **$351** | `email_parse`, `gravatar`, `contact_enrich`, `pgp`, `employer_pivot`, `smtp_vrfy` | **Partial → Full** | Epieos for niche modules (LinkedIn/Fitbit) |
| Corporate email discovery (bulk B2B) | Hunter.io **$408** | `employer_pivot`, `contact_enrich`, `crtsh` | **Partial** | Hunter.io for verified bulk |
| Host / port / banner recon | Shodan **$828** (+$49 once) | `shodan` free, `greynoise`, `urlscan`, `webserver_banner` | **Partial → Full at low volume** | Shodan/Censys for scale + scan credits |
| Internet asset / attack surface | Censys **$1,188** | `crtsh`, `cert_intel`, `dns_intel`, `subdomain_takeover`, `bgpview` | **Partial** | Censys/SecurityTrails for depth |
| Historical DNS / WHOIS | SecurityTrails (POA) | `whois`, `rdap_domain`, `dns_intel`, `crtsh` | **Partial** | SecurityTrails for time-series depth |
| WiFi BSSID geolocation | WiGLE (free / commercial POA) | `wigle` (BYO), `mylnikov`, `mls` | **Full (free/BYO)** | WiGLE key (free non-commercial) |
| **OSINT automation / orchestration** | SpiderFoot HX (POA) / Maltego **$6,600** | the entire HSE engine | **Full (free) — direct replacement** | none |
| **Link-analysis graph + correlation** | Maltego **$6,600** | D3 force graph + 43 correlator rules | **Full (free)** | none |
| On-device WiFi/cell/GPS GEOINT | *(none sold)* | `device_sensors`, `cell_intel`, `local_net` | **HSE-exclusive** | n/a |
| AU public records (ASIC/AEC/titles/ABN) | *(niche / unserved)* | `asic_director`, `au_electoral`, `au_property`, `au_unclaimed`, `opencorporates` | **Full (mostly free)** | `abn_lookup` key optional |

**The dividing line.** Every **None — data moat** row is a *dataset* HSE has no copy of and cannot
scrape; every **Full (free)** row is *tooling or public-API work* HSE does itself. Parity tracks the
data/tooling axis almost perfectly: HSE owns the tooling end completely and the data end not at all,
with **Presence-only** as the honest middle (it can tell you a credential *exists* in a stealer log —
via `hudsonrock` — but not show you the credential).

---

## 4. Per-service verdict — keep paying, or not?

| Service | Annualised | Verdict | What you still pay for (if anything) |
|---|---|---|---|
| **Maltego** | $6,600 | **Replace** | nothing — HSE replaces the engine; its paid transforms map to HSE BYO-key modules |
| **SpiderFoot HX** | POA | **Replace** | nothing — HSE is the same automation layer, free and self-hosted, even on a phone |
| **OSINT Industries** | $290 | **Replace** | nothing material — free HSE modules reproduce the fan-out |
| **UserSearch** | $160 | **Replace** | nothing material |
| **Epieos** | $351 | **Mostly replace** | a few proprietary modules (LinkedIn/Fitbit), available BYO-key |
| **Hunter.io** | $408 | **Partial** | verified bulk B2B email datasets |
| **Censys** | $1,188 | **Partial** | full asset search + historical depth beyond free DNS/cert recon |
| **SecurityTrails** | POA | **Partial** | historical DNS/WHOIS time-series |
| **Shodan** | $49 once / $828 API | **Complement** | $49 membership is worth it; API only at scan/query volume |
| **HIBP** | $53 → $4,548+ | **Complement** | authoritative domain-wide breach enumeration (Pro tier) |
| **WiGLE** | $0 / POA | **Complement** | nothing for non-commercial; HSE fronts the free API |
| **DeHashed** | $180 | **Data moat** | raw leaked records — HSE gives presence only |
| **OathNet** | POA (low) | **Data moat** | record-level breach/stealer detail (HSE drives it via `oathnet_pro`) |
| **Intelligence X** | $2,700 | **Data moat** | the historical/dark-web corpus itself |

The in-repo dossier is a live illustration of the **Data moat** verdict: HSE drove OathNet Pro,
ran all the structural cross-referencing, but the `***UPGRADE_TO_SEE***` redactions are OathNet's
paywall — exactly the boundary HSE cannot cross by tooling alone.

---

## 5. Worked cost scenarios (illustrative)

Concrete arithmetic from the prices above. The "commercial stack" is *one plausible assembly* an
analyst might buy, not the only one; HSE figures assume the free engine plus only the keys whose data
is a genuine moat for that workload. Year-1 figures shown.

**A — Solo investigator / journalist (identity & breach focus)**

| Commercial stack | $/yr | HSE alternative | $/yr |
|---|---|---|---|
| DeHashed $180 + Epieos $351 + OSINT Industries $290 + HIBP $53 | **$874** | HSE (free) + DeHashed key (the one real moat) | **$180** |
| …same, but add Maltego Professional for the graph | **$7,474** | same as above (graph is built in) | **$180** |

> **Net saving ≈ $694/yr** without Maltego, **≈ $7,294/yr** with it.

**B — Small pentest / attack-surface team**

| Commercial stack | $/yr (yr 1) | HSE alternative | $/yr (yr 1) |
|---|---|---|---|
| Shodan $49 + Shodan API $828 + Censys $1,188 + HIBP Core 2 $259 + Maltego Pro $6,600 | **$8,924** | HSE (free) + Shodan membership $49 + HIBP Core 1 $53 (API/Censys only if volume demands) | **$102** |

> **Net saving ≈ $8,800/yr**; residual paid only where data *volume/depth* genuinely exceeds free tiers.

**C — Hobbyist / learner**

| Commercial stack | $/yr | HSE alternative | $/yr |
|---|---|---|---|
| OSINT Industries £19/mo + Epieos free | **~$290** | HSE (free) covers username/email/breach-presence/DNS/geo | **$0** |

> **Net saving ≈ $290/yr, with $0 spend.**

---

## 6. Value verdict

1. **HSE zeroes the two most-marked-up bands.** It is a free, self-hosted replacement for the
   **orchestration tier** (Maltego $6,600/yr, SpiderFoot HX POA) and substantially for the
   **aggregator tier** ($160–$408/yr). Across the scenarios that is **~$290 to ~$8,800/yr** of
   recurring spend removed, before counting capabilities no one sells (on-device GEOINT, the free
   geolocation pipeline, AU public-records dorking).
2. **HSE cannot beat a data moat — and doesn't pretend to.** DeHashed, IntelX, OathNet, and HIBP's
   full corpus own data HSE has no copy of. There its role is the **single pane of glass** that calls
   them with your own key, so you pay the vendor's published rate *once* (e.g. DeHashed $3/100
   credits, IntelX €2,500/yr) instead of a vendor rate *plus* an aggregator markup — and you get
   HSE's correlation, expansion, and graph layered on for free.
3. **Spend ladder.** Run HSE free; add keys cheapest-moat-first only as a workload demands —
   HIBP $53/yr, DeHashed $180/yr, OathNet free→low, then Shodan/Censys at volume, and IntelX/
   Maltego-class spend only when a specific dataset or compliance need forces it.

**One line:** HSE eliminates the *platform and convenience* markup entirely and lets you pay the
*raw-data* fee once, directly — turning a typical $900–$8,900/yr commercial OSINT stack into a
$0–$180/yr one for most individual and small-team workflows.

---

## 7. Security hygiene note (incidental, flagged in good faith)

`DOSSIER_OSINT_Service_Usernames.md` §8 commits what it labels live API keys (OathNet Pro, HIBP v3,
WiGLE) into the repository in plaintext. If any are real and active, committed secrets are exposed to
anyone with repo access and remain in Git history even after deletion. Recommended: rotate those keys
at the vendors, move them to `~/.huntsman.env` (which the installer preserves and the code reads via
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

*Prices change frequently and several vendors gate exact figures behind "contact sales"; verify against the live pages before committing budget. Currency conversions are approximate (June 2026). Scenario totals are illustrative arithmetic from the cited list prices.*
