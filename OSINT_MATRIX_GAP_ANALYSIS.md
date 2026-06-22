# OSINT Matrix Gap Analysis — Huntsman Search Engine vs. Commercial Market

**Prepared for:** Haigen Bamford
**Date:** 2026-06-12
**Companion to:** [`OSINT_SERVICE_VALUE_vs_HSE.md`](OSINT_SERVICE_VALUE_vs_HSE.md) (pricing + parity matrix)
**Subject:** Huntsman Search Engine (HSE) v1.5.0 — 125 modules (92 free · 33 key-gated/paid; module baseline refreshed 2026-06-22)

This document takes the capability-parity matrix from the value analysis and turns it into a **gap
register**: for every capability where HSE is *not* at full free parity, it names the gap, sizes it,
classifies *why* it exists, and decides whether HSE should close it, rent past it, or refuse it by
principle. The goal is a prioritised, honest picture of where HSE is weak — and where its "weakness"
is actually a deliberate design boundary.

---

## 1. Method

**Gap = (market best-in-class capability) − (HSE's free, self-hosted capability).** Each gap is scored
on two axes, which together drive the recommendation:

**Severity (1–5)** — how much the missing capability hurts a typical individual / small-team analyst
(HSE's apparent target: AU-focused, mobile/Termux, budget-conscious):

| Sev | Meaning |
|-----|---------|
| 5 | Core OSINT workflow blocked without it |
| 4 | Major capability; frequent need |
| 3 | Useful; periodic need |
| 2 | Niche / jurisdictional / occasional |
| 1 | Edge case |

**Closeability** — *why* the gap exists and therefore what to do about it:

| Code | Meaning | Implication |
|------|---------|-------------|
| **KEY** | Already bridged (or trivially) by a BYO-key module | Not an HSE *product* gap — just a vendor bill. Already solved architecturally. |
| **BUILD** | A free public API or local computation exists | **Roadmap candidate** — HSE could close it with a new free module. |
| **MOAT** | Depends on proprietary data HSE cannot obtain | Frontable via key, never replicable. Accept and rent. |
| **CHARTER** | Would require AI/ML deps (forbidden by `RUNTIME_INDEPENDENCE`) or break an architecture invariant | **Won't-do by principle.** Document, don't build. |
| **MANAGED** | SLA / hosting / seats / support | Out of scope for a free self-hosted binary by design. |

Priority falls out of the two: **high severity + BUILD = quick win**; high severity + MOAT/KEY =
*not HSE's gap to close* (already bridged); any severity + CHARTER/MANAGED = *won't-do*.

---

## 2. Gap register (the matrix)

| # | Capability | HSE current state | Market best (annualised) | The gap | Sev | Closeability | Recommended action |
|---|------------|-------------------|--------------------------|---------|-----|--------------|--------------------|
| G1 | **Raw leaked credentials / records** | `hudsonrock` = presence + counts only; credentials never persisted (by design) | DeHashed $180 · IntelX $2,700 | The credential *values* themselves | 5 | **KEY + MOAT** | Keep BYO-key (`dehashed`/`intelx`/`oathnet_pro`). **Never host a breach corpus** — the "no-store" stance is a security feature, not a gap to fill. |
| G2 | **Historical / dark-web selector search** | none free | IntelX $2,700 | The dark-web/historical corpus | 4 | **MOAT** | Rent via `intelx` key. Unreplicable. |
| G3 | **Authoritative domain-wide breach enumeration** | `pwned_passwords`/`xposed_or_not` = presence | HIBP Pro $4,548+ | Full per-domain breach list | 3 | **KEY + MOAT** | `hibp` key when domain coverage is the job. |
| G4 | **Stealer-log record-level detail** | `hudsonrock` free (presence) | OathNet (POA, low) | Per-record fields behind the paywall (the dossier's `***UPGRADE_TO_SEE***`) | 3 | **KEY + MOAT** | `oathnet_pro` key; HSE already does the cross-referencing on top. |
| G5 | **Bulk verified corporate email** | `smtp_vrfy` (live SMTP) + `employer_pivot`/`contact_enrich` (inference) | Hunter.io $408 | A *pre-verified* B2B email dataset; SMTP VRFY is widely blocked | 3 | **KEY + BUILD** | `hunter_io` key for bulk; **BUILD**: strengthen `smtp_vrfy` with MX/SPF/catch-all heuristics to raise free-tier confidence. |
| G6 | **Host/banner & internet-asset depth** | `shodan` (free InternetDB), `greynoise`, `urlscan`, `webserver_banner`, `cert_intel` | Shodan API $828 · Censys $1,188 | Full historical banners, scan credits, faceted asset search | 3 | **KEY** | Shodan $49 one-time membership + `censys` key only when volume/depth exceeds free recon. |
| G7 | **Historical DNS / WHOIS time-series** | `whois`, `rdap_domain`, `dns_intel`, `crtsh` (current state) | SecurityTrails (POA) | Time-series / passive-DNS history | 3 | **KEY** | `securitytrails` key for historical depth. |
| G8 | **Reverse-image / face search** | none (`exif_geo` reads image GPS only) | PimEyes-class; UserSearch facial scoring (in $160 tier) | No image→identity matching at all | 3 | **CHARTER** | **Won't-do natively** — requires an ML/embedding stack that `RUNTIME_INDEPENDENCE` forbids *and* a proprietary face index. Option: a thin BYO-key wrapper to an external face API (no bundled ML) — flag legal/ethical constraints. |
| G9 | **Phone → owner / caller-ID (CNAM) / HLR** | `phone_intl`, `phone_*_geo`, `numverify` (validity) | UserSearch / SEON / IPQS phone intel | Subscriber identity + live HLR status | 3 | **BUILD + MOAT** | **BUILD** a BYO-key HLR/CNAM module (free public HLR APIs exist); subscriber *identity* stays MOAT. |
| G10 | **Deep social content** (posts, follower graph, timelines) | account-existence only (`social_probe`, `username_search`) | Maltego transforms; aggregators | Content & relationship graph, not just "account exists" | 3 | **BUILD (ToS-limited)** | Add public-API content modules **only where platform ToS permits** (e.g. public GitHub/Reddit/HN already done); the rest is ToS/anti-scraping-blocked, not a tooling gap. |
| G11 | **Connector breadth** (commercial data sources) | 25 key-gated integrations | Maltego 100+ transforms; OSINT Industries 100s of modules | Long tail of niche commercial datasets | 2 | **BUILD + KEY** | Incrementally add BYO-key modules driven by demand; breadth is a backlog, not a wall. |
| G12 | **Tor / onion-site collection** | `web_crawler` (clearnet) | IntelX, dark-web suites | No onion crawling | 2 | **BUILD (gated)** | Optional, opt-in module; weigh perf/safety on Termux. Low priority. |
| G13 | **Chat-platform intel** (Telegram/Discord channels) | none | dark-web monitoring suites | Channel/membership intelligence | 2 | **BUILD + MOAT** | Public-API slices BUILD-able; historical archives are MOAT. Niche. |
| G14 | **Non-AU court / property / vehicle records** | AU-rich (`asic_director`, `au_electoral`, `au_property`, `au_unclaimed`) | jurisdiction-specific commercial | Coverage outside AU | 2 | **BUILD (per-jurisdiction)** | Large per-country effort; build only for jurisdictions you operate in. By design HSE is AU-optimised. |
| G15 | **Managed service** (SLA, hosting, team seats, vendor support) | self-hosted localhost-only binary | SpiderFoot HX, Maltego Enterprise | No hosted/SLA/multi-seat offering | 2 (solo) → 4 (enterprise) | **MANAGED** | **Won't-do by design** — `127.0.0.1`-only bind is an architecture invariant. If enterprise hosting is ever needed it's a separate product, not a module. |
| G16 | **Continuous breach monitoring + alerting** | `hse live` (interval re-scan) already exists | DeHashed/HIBP/OathNet monitoring | Only the *data feed* behind it is paid | 2 | **KEY** | Largely **already closed** — HSE owns the monitoring loop free; pair with a BYO breach key for the feed. |

---

## 3. Gap-profile rollup

Counting the register by closeability reveals the *shape* of HSE's gaps — and the headline is that
very few are HSE's to fix:

| Closeability | Gaps | Share | Reading |
|--------------|------|-------|---------|
| **KEY** (already bridged) | G1·G3·G4·G6·G7·G16 (+G5/G11 partial) | ~6–8 | **Not product gaps.** Architecture already solves these; cost is a vendor bill, not missing capability. |
| **MOAT** (rent, can't replicate) | G1·G2·G3·G4·G13 (+G9 partial) | ~4–5 | Permanent by nature. The correct posture is *front via key*, which HSE does. |
| **BUILD** (free module possible) | G5·G9·G10·G11·G12·G13·G14 | ~5–7 | **The actual roadmap.** Every genuine, closeable HSE gap lives here. |
| **CHARTER** (won't-do on principle) | G8 | 1 | Deliberate boundary (no AI/ML deps). |
| **MANAGED** (out of scope) | G15 | 1 | Deliberate boundary (self-hosted, localhost-only). |

**Interpretation.** Of 16 gaps, only the **BUILD** set represents work HSE *should* consider, and most
of those are moderate-severity (Sev 3) enhancements rather than missing pillars. The high-severity
gaps (G1 Sev 5, G2 Sev 4) are **MOAT/KEY** — i.e. they are not deficiencies in HSE the *tool*, they are
the price of data HSE deliberately doesn't warehouse. **HSE's gap surface is dominated by other
people's data, not by missing HSE features.**

---

## 4. Prioritised closure roadmap

Plotting **severity × closeability** sorts the register into four actions:

**▶ Quick wins — BUILD now (free modules, Sev 3):**
1. **G5** — harden `smtp_vrfy` with MX/SPF/catch-all heuristics → lifts free email-verification confidence toward Hunter.io's without a key.
2. **G9** — add a BYO-key **HLR/CNAM phone module** → closes the most-requested phone gap cheaply.
3. **G10** — extend public-API social modules where ToS allows → more content depth, zero data cost.

**▶ Strategic — accept as KEY/MOAT (don't build, rent):**
- **G1, G2, G3, G4, G6, G7** — breach corpora, dark-web, asset depth, historical DNS. HSE's job here
  is to be the *single front-end* (already is). Closing them in-house is impossible (MOAT) or
  undesirable (warehousing credentials breaks HSE's no-store security stance).

**▶ Won't-do — by principle:**
- **G8** (face search) — violates the no-AI/ML charter; at most a thin external-API wrapper, never bundled.
- **G15** (managed/SLA/hosting) — violates the localhost-only, self-hosted design.

**▶ Backlog — low severity, demand-driven:**
- **G11** connector breadth, **G12** onion crawling, **G13** chat intel, **G14** non-AU records.
  Build per concrete need; none are blockers.

---

## 5. Reverse gaps — where the *commercial market* trails HSE

A two-way matrix is incomplete without the other direction. These are capabilities HSE has that the
priced services **cannot match at any price** — i.e. gaps in *their* offering:

| HSE capability | Commercial gap |
|----------------|----------------|
| **On-device WiFi/cell/GPS GEOINT** (`device_sensors`, `cell_intel`, `local_net`) | No cloud OSINT service can read a handset's radios — it needs the device. **Unmatchable.** |
| **Free, self-hosted orchestration + correlation + graph** | Maltego ($6,600/yr) / SpiderFoot HX (POA) charge precisely for this. |
| **Runs on Android/Termux, no root, ~5 MB, offline-capable** | No commercial OSINT platform ships as a no-root mobile binary. |
| **Deterministic, zero-AI, reproducible & auditable** (`RUNTIME_INDEPENDENCE`) | Aggregators are opaque black boxes; HSE's `entity_excluded` ledger + audit explains every pivot. |
| **AU public-records depth** (ASIC/AEC/land titles/ABN-ACN) | Few global tools cover AU registries to this depth. |
| **MITRE ATT&CK TA0043 mapping per module** | No consumer OSINT service maps collection to ATT&CK reconnaissance techniques. |
| **$0 platform cost** | Every orchestration/aggregator competitor is recurring spend. |

---

## 6. Verdict

The matrix gap analysis confirms and sharpens the value analysis's conclusion:

1. **HSE has almost no *tooling* gap.** Where it trails the market, the gap is overwhelmingly
   **other people's proprietary data** (MOAT) or **a vendor bill it already routes via BYO-key**
   (KEY) — not a missing HSE feature. Its single highest-severity gap (G1, raw credentials, Sev 5) is
   one HSE *chooses* not to close, because warehousing credentials would break its no-store posture.
2. **The genuine, closeable roadmap is small and modest.** Three Sev-3 BUILD items (email-verification
   heuristics, phone HLR/CNAM, deeper public-social content) are the whole list of worthwhile native
   improvements. Everything else is rent, niche, or won't-do.
3. **Two gaps are deliberate boundaries, not failures.** Face search (CHARTER — no AI/ML) and managed
   hosting/SLA (MANAGED — localhost-only, self-hosted) should be documented as out-of-scope, not
   treated as backlog.
4. **The reverse gaps are HSE's moat.** On-device GEOINT, free orchestration, no-root mobile
   operation, determinism/auditability, AU depth, and ATT&CK mapping are things the $160–$6,600/yr
   field cannot offer at any price.

**Bottom line:** HSE's gap profile is the inverse of a typical OSINT product's. Commercial tools have
data and lack tooling/transparency; HSE has tooling and transparency and rents data. The handful of
closeable gaps are incremental, the high-severity ones are structural-to-the-domain (not to HSE), and
HSE's own reverse gaps are unmatchable — which is exactly the profile you want from a free
orchestration layer that fronts paid data.

---

*Severity and closeability scores are analyst judgements calibrated to an individual / small-team,
AU-focused, mobile workflow; an enterprise SOC would re-score G15 (managed) and G6/G7 (asset depth)
higher. Module facts are drawn from the CI-verified catalogue in `docs/MODULES.md`; pricing from the
sources cited in the companion value analysis.*
