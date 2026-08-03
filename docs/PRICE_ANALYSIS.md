# Huntsman Search Engine — Price Analysis

**Version analysed:** v1.40.0 (commit `a18da2e`)
**Date:** 2026-08-03
**Scope:** current commercial price for HSE as a licensed product, derived from
its features and functionality, benchmarked against its closest competitors,
with per-competitor gap analysis.

**Explicitly out of scope, at the requester's direction:** customer base,
installed base, traction, revenue history, and any goodwill or network-effect
premium. Every figure below is derived from capability and comparable-market
evidence alone.

---

## 0. Method, and what is and isn't verified

This document follows [`OPERATIONAL_CONSTITUTION.md`](OPERATIONAL_CONSTITUTION.md):
observations are separated from inferences, and confidence tracks evidence.

**What I did:** built `v1.40.0` from source (`cargo build --release --locked`,
clean exit) and ran `hse modules`, `hse selftest`, `hse diagnostics`,
`hse engines`, two live `hse scan` runs and `hse audit` against a throwaway
`HOME`; read the module registry, correlator, API router, CLI, and export
layers; pulled competitor pricing from vendor pricing pages, a UK G-Cloud
public price list, and third-party procurement aggregators.

**What I did not do:** run the test suite (`cargo test --all`), run the gate
(`scripts/gate.sh`), build for `aarch64-linux-android`, or test on a real
Termux device. No claim below depends on those, and where a figure is
unverified it is marked as such.

**Environment caveat that matters:** all live runs were from a cloud
datacentre IP behind an HTTP proxy — the single worst environment for the
free-scraping layer, and the opposite of HSE's design target (a phone on a
mobile carrier IP). Section 2.2 reports what that produced and separates the
measurement from what it does and doesn't imply.

**FX rates used** (3 Aug 2026, approximate, for comparison only):
AUD/USD 0.6981 · EUR/AUD 1.6441 · GBP/AUD 1.9158.

---

## 1. What HSE actually is — verified capability inventory

All figures in this section are **observations** from the running v1.40.0
binary or from direct inspection of the source tree.

### 1.1 Measured from the running software

| Fact | Value | How verified |
|---|---|---|
| Modules registered | **170** | `hse modules` → "170 module(s) total" |
| — free (no key) | **135** | `hse diagnostics` module breakdown |
| — key-gated | **31** | same |
| — paid | **4** | same |
| Module reachability | 100% — all 170 reachable from every realistic seed kind | `hse selftest` → `modules.reachability` |
| Self-test | **10/10 pass, 0 warn, 0 fail** in 63 ms | `hse selftest` |
| Module metadata probes | 3,230, no panic | `hse selftest` → `modules.probe` |
| Search engines | 17 | `hse engines` |
| Optional API keys supported | 51 | `hse diagnostics` |
| Module categories | 14 (social 37, geo 24, infrastructure 20, dns_recon 17, people 16, corporate 14, breach 12, web 8, email 6, sensor 4, phone 4, threat 3, other 3, search 2) | `hse modules` |

### 1.2 Measured from the source tree

| Fact | Value | How verified |
|---|---|---|
| Rust source | **305,007 lines across 922 files** | `find src -name '*.rs'` + `wc -l` |
| Correlator rule IDs | **122 distinct** `AU-001`–`AU-123` (AU-065 reserved) | `grep` over `src/core/correlator/` |
| Correlator rule files | 30 | `ls src/core/correlator/rules/` |
| Test annotations | **6,081** `#[test]` / `#[tokio::test]` / `#[rstest]` across `src/` + `tests/` | `grep -c` |
| HTTP API routes | 83 | `grep 'route(' src/api/routes/mod.rs` |
| Seed types | 16 | README + `src/cli/command.rs` |
| CLI subcommands | 18 | `hse --help` |
| Public releases | 43, v1.4.0 (2026-06-18) → v1.40.0 (2026-08-03) | GitHub Releases API |

> **Note on the test figure.** The README states "4,300+ tests"; I counted
> 6,081 test annotations by grep. I did not run the suite, so I cannot
> reconcile the two numbers and am not asserting either as the true test
> count. The annotation count is what I measured.

### 1.3 Capabilities with no direct priced equivalent in the comparable set

These are the ones that carry pricing weight, because a buyer cannot obtain
them elsewhere at any price in this product category:

1. **On-device execution.** Single ~20 MB binary, Termux/Android aarch64, no
   root, no daemon, no cloud, no native dependencies. Scan data never leaves
   the handset. `#![forbid(unsafe_code)]`; rustls + bundled SQLite; zero
   AI/ML/inference dependencies, CI-enforced.
2. **Scored self-audit that refuses to certify its own output.** `hse audit`
   grades a scan 0–100, names its own weaknesses, and **exits non-zero** on
   HIGH/CRITICAL findings (demonstrated in §2.1). I found no competitor that
   ships an adversarial self-critic.
3. **Deterministic correlation, 122 rules.** No LLM, no fuzzy matching —
   every finding is explainable and reproducible. Includes graph-aware,
   transitive, multi-pathway, k-redundancy, and articulation-point rules.
4. **Inline MITRE ATT&CK tagging.** Findings are stamped `attack:Tnnnn[.nnn]`
   as they are admitted, so the collecting technique travels with the datum
   into JSON, dossier, and DB — not a separate coverage report. Full
   Enterprise v17.1 matrix carried as static data; coverage claimed for
   Reconnaissance (TA0043) only.
5. **RF/sensor radar.** `hse radar` sweeps the device's own Wi-Fi, Bluetooth,
   GNSS, cell and ARP radios and feeds observed signals into the same pivot
   pipeline as a typed seed. Nothing in the comparable set senses; the closest
   commercial analogue is purchased location data (§3).
6. **Convex/barbell budget allocation and capability-aware dispatch.** Query
   ordering by optionality ÷ cost, plus automatic quarantine of provably-dead
   parsers with automatic recovery. Designed for a bounded battery/quota
   budget — a mobile-native concern no desktop or cloud competitor models.
7. **Explainability of omission.** Every declined pivot and rejected intake
   value is recorded as an `entity_excluded` event with a reason, rolled up
   into an expansion ledger.
8. **Benchmark, diff, and gap analysis** (`hse benchmark`, `hse diff`,
   `hse gaps`) — reproducible head-to-head scan scorecards, entity-level scan
   comparison, and "which validated seeds are unconnected, and what would
   connect them."

---

## 2. Verified weaknesses — the measured case against a high price

A price analysis that only inventories strengths is worthless. Everything
here is measured, not speculated.

### 2.1 Precision is the weak axis, and HSE knows it

**Observation.** `hse scan --kind domain --value mozilla.org --depth 0
--free-only` produced **902 entities** — 751 of them domains. `hse audit
--scan-id latest` graded that scan:

```
score      : 44/100   (D — significant weaknesses)
entities   : 905  —  658 verified · 247 probable · 0 candidate

  [CRITICAL] infrastructure-pollution — 41 CDN/registrar/provider entities …
  [HIGH]     role-mailbox-as-pii — 1 role/provider mailbox treated as subject email
  [MEDIUM]   generic-domain-noise — 39 low-confidence bare external domains
  [MEDIUM]   missed-pii — 2 enrichment gap(s) detected

error: audit: HIGH/CRITICAL findings detected — address the weaknesses above
       before treating these results as reliable
```

**Observation.** A second run at `--depth 1` on the same domain produced
correlations that materialised a *person* named "Dmarc Agg" and usernames
`dmarc_agg`, `d.agg`, `dagg`, `dmarca` — artefacts of the DMARC DNS record's
mailbox label being read as a human name. The same run asserted
`AU-056 Jurisdiction corroborated`, `AU-085 Phone region corroborates
location`, and `AU-099 Coordinate reverse-geocoded` placing "the subject" in
ACT/NSW/QLD and reverse-geocoding to Canberra, Sydney and Maroochydore — for
a US-headquartered organisation.

**Inference (high confidence).** HSE optimises recall over precision. The
identity-derivation and AU-geo layers generate confident-sounding artefacts
from infrastructure metadata. The severity ladder (LOW/MEDIUM) and the
`--redact`/audit machinery mitigate this, and the self-audit catching its own
CRITICAL pollution is genuinely strong engineering — but the raw output of an
unattended scan is not client-deliverable without analyst triage.

**Pricing consequence.** This caps HSE in the *analyst-assisted tool* band
and excludes it from the *automated report generation* band where Skopenow
prices (§3). Buyers pay a large premium for output they can hand to a client
or a court without re-verification; HSE cannot yet claim that.

### 2.2 The free layer is structurally fragile against anti-bot defence

**Observation.** `hse engines` from this datacentre IP: **2 up, 12 blocked, 3
down of 17**. Google, DuckDuckGo, Ecosia, Mojeek, Presearch and You returned
"anti-bot/CAPTCHA interstitial — needs a residential IP or
HUNTSMAN_SEARCH_PROXY"; Qwant, Yahoo and Yandex were down. Only Bing (4
results) and Startpage (10 results) parsed.

**What this does and does not show.** It does *not* show HSE is broken on its
target platform — a Termux handset sits on a residential/mobile carrier IP,
which is precisely the condition these engines don't block, and this result
is arguably evidence *for* the on-device thesis. It *does* show that the
"135 free modules" value proposition rests on scraped endpoints that
adversarially resist automation, that the free layer's yield is
environment-dependent, and that HSE cannot warrant a service level over
sources it does not own. HSE's capability-probe, health-tracking and
dead-module quarantine are real mitigations for exactly this, and they are a
differentiator — but they route around failure, they don't prevent it.

**Pricing consequence.** No SLA can be offered on free-source yield. This
argues for a perpetual/annual **licence** model over a subscription that
implies a service, and against any usage- or result-metered pricing.

### 2.3 Missing commercial-product scaffolding

All verified by inspection:

| Missing | Evidence | Blocks |
|---|---|---|
| Authentication / RBAC / SSO | `src/cli/serve/mod.rs:279` — server is "reachable from the local network with no authentication"; only `PUT /settings/keys` is loopback-restricted | Any team or multi-seat sale |
| Multi-user / case management / collaboration | No user model in `src/storage/` | Agency and enterprise buyers |
| PDF / DOCX reporting | Export formats are JSON, CSV, GEXF, report, full, debug only | Investigator and legal buyers |
| Chain-of-custody / evidence hashing | `util/raw_archive` retains paid-provider responses verbatim, but there is no evidentiary hash-and-timestamp workflow | The court-exhibit use case Hunchly owns |
| Persistent live sessions | `src/core/live/mod.rs` — "Sessions are in-memory only. Restart → cleared." | Monitoring/alerting sale |
| Support, SLA, training, certification | None published | Procurement at any enterprise |
| Compliance artefacts (SOC 2, DPA, pen-test report, insurance) | None in repo | Regulated buyers |
| Published commercial terms | `LICENSE` is proprietary all-rights-reserved; README says "available by separate written agreement" | Self-serve purchase |

### 2.4 Structural constraints

- **HSE owns no data.** It is an orchestrator over free public endpoints plus
  31 key-gated and 4 paid providers the *customer* pays for separately. This
  is the single most important pricing fact in this document (§4).
- **Track record is 7 weeks.** 43 public releases spanning 2026-06-18 to
  2026-08-03. The codebase is large and disciplined; the operating history is
  not yet long enough to have de-risked itself for a conservative buyer.
- **Narrow primary platform.** Termux aarch64 is the design target. Debian/
  Ubuntu and macOS are supported by the installer, but the differentiated
  capabilities (radar, sensors, on-device sovereignty) only exist on Android.
- **AU specialisation cuts both ways.** ~14 corporate/people modules and the
  address/postcode/cadastre pipeline are Australian. That is a genuine moat
  in AU and dead weight elsewhere.
- **Key-bearer risk.** 35 of 170 modules require the customer's own paid keys,
  so HSE's *effective* capability at a given price is partly bought elsewhere.

---

## 3. The market — verified competitor pricing

Prices as published. Where a vendor does not publish, the source is named and
its reliability flagged.

| Product | Price | Basis | Source quality |
|---|---|---|---|
| **SpiderFoot** (open source) | **Free** (GPL) | Self-hosted | Vendor |
| **SpiderFoot HX** (commercial) | **No public price**; commercial product absorbed into Intel 471. Acquired 2022-11-02; `spiderfoot.net` now redirects to `intel471.com` | — | Vendor blog + advisory |
| **Maltego** Basic | **€0/yr** — 200–1,000 credits/mo | Per org | Vendor pricing page |
| **Maltego** Entry | **€3,000/yr** — 10,000 credits, + Hunchly, Maltego Search | Per org | Vendor |
| **Maltego** Professional | **€7,500/yr** — 20k–40k credits, unlimited commercial data | **Per seat**, up to 5 users | Vendor |
| **Maltego** Enterprise | Custom | Per org, 5+ users | Vendor |
| **OSINT Industries** Basic | **£19/mo** — 30 credits | Per user | Vendor |
| **OSINT Industries** Intermediate | **£49/mo** — 100 credits, API | Per user | Vendor |
| **OSINT Industries** Advanced | **£99/mo** — 300 credits, API | Per user | Vendor |
| **Intelligence X** Researcher | **€2,500/yr** | Individual | Vendor blog (Dec 2022 announcement) |
| **Intelligence X** API | **€5,000/yr** — 500 daily searches | Org | same |
| **Intelligence X** Identity Portal | **€7,500/yr** | Org | same |
| **Skopenow** | **US$23,760/yr median** (range $14,850–$32,438) | Per contract | Procurement aggregator (Vendr); sample size undisclosed |
| **ShadowDragon** Horizon Investigate+ (incl. SocialNet) | **£8,350/yr** | Per user, 12 mo | **UK G-Cloud 14 public price list** |
| **ShadowDragon** Horizon Investigate+ Monitor | **£12,350/yr** | Per user | same |
| **ShadowDragon** Horizon **Mobile** | **£1,100/yr** | Per user, *add-on, requires an Investigate licence* | same |
| **ShadowDragon** Breach Data add-on (500 queries/mo) | **£13,500/yr** | Add-on | same |
| **ShadowDragon** Location-Based Insights (6,000 credits/yr) | **£41,650/yr** | Per user, add-on | same |
| **ShadowDragon** Teams Monitor Enterprise | **£67,550/yr** | Team | same |
| **Constella Intelligence** | **~US$315k–415k/yr** (avg ~$365k) | Enterprise | Procurement aggregator |
| **Hunchly** | **US$129.99/yr** | Per user | Third party |
| **Lampyre** | **~US$32/mo · ~US$313/yr** | Per user | Third party |
| **Shodan** | **US$49** one-time membership; **US$69 / $359 / $1,099 per month** API tiers | Per user | Third party (shodan.io returned HTTP 403 to direct fetch) |
| **Recon-ng, theHarvester, Maigret, Sherlock, sn0int** | **Free** | Self-hosted | — |

**The shape of that table is the whole analysis.** Prices in this market
cluster into two populations that barely overlap:

- **Tools** — software that automates collection and analysis but ships no
  data: **US$0 – ~US$400/yr** (SpiderFoot OSS, Recon-ng, Hunchly, Lampyre,
  Maltego CE).
- **Data** — subscriptions whose price *is* an index, corpus, or platform
  coverage the vendor maintains: **US$3,000 – US$400,000/yr** (Maltego's paid
  tiers, IntelX, OSINT Industries, Skopenow, ShadowDragon, Constella).

---

## 4. The structural pricing determinant

> **HSE is a tool, not a data subscription — and in this market that is the
> difference between a US$300 price and a US$30,000 one.**

Every competitor above US$3,000/yr is charging for data it owns or licenses:

- Maltego Professional at €7,500/seat is "unlimited commercial data access"
  plus 20–40k credits. The Maltego *graph application* is free.
- IntelX Researcher at €2,500/yr is access to IntelX's index.
- OSINT Industries at £19–99/mo is priced in credits — units of their data.
- ShadowDragon's Breach Data add-on is £13,500/yr for 500 queries a month.
  Their Location-Based Insights add-on is £41,650/yr for 6,000 credits.
- Constella at ~US$365k/yr is a breach corpus with a UI attached.

HSE has **none of this**. Its `intelx`, `dehashed`, `hibp`, `shodan`,
`censys` and `wigle` modules are BYO-key clients *to those same vendors*. A
buyer who wants IntelX data still pays IntelX. HSE sells the orchestration,
correlation, and explanation layer around data the customer sources.

This is not a defect — it is a deliberate and coherent architecture, and it
gives HSE a cost structure none of them have (135 modules at zero marginal
cost per scan). But it means **HSE cannot be priced against ShadowDragon or
Skopenow on feature-list breadth**, because the majority of their price is
something HSE does not sell. Attempting that comparison is the single most
likely way to misprice this product upward and then fail to close.

The correct comparison set for the price is the *tool* population — and
within it, HSE is comfortably the most capable member.

---

## 5. Gap analysis — HSE vs each closest competitor

Eight comparators, ordered by closeness. For each: what HSE has that they
don't, what they have that HSE doesn't, and the price implication.

### 5.1 SpiderFoot (OSS + HX) — the closest architectural peer

HSE's README names SpiderFoot as its lineage, and the resemblance is
structural: modular collectors, recursive expansion, a correlation layer, a
localhost web UI, scan profiles.

**HSE has that SpiderFoot doesn't:** runs on Android/Termux with no root, no
daemon and no Python runtime (SpiderFoot is Python; HSE is a single ~20 MB
static binary); 122 deterministic correlation rules against SpiderFoot's
smaller correlation ruleset; scored self-audit with non-zero exit; inline
ATT&CK tagging; RF/sensor radar; convex budget allocation and dead-module
quarantine; benchmark/diff/gap commands; `#![forbid(unsafe_code)]` and a
CI-enforced no-AI-dependency invariant.

**SpiderFoot has that HSE doesn't:** ~200+ modules (more than HSE's 170); a
decade of production hardening and a large public user base; a permissive
open-source licence, so it is free to evaluate, fork, audit and deploy at any
scale; a broad ecosystem of integrations (e.g. Sumo Logic).

**Price implication — this is HSE's hardest competitive problem.** The
closest functional peer is free and has more modules. The commercial version
that once monetised this exact shape (SpiderFoot HX) has been absorbed into
Intel 471 and no longer sells self-serve, which **opens the niche** — but it
also suggests the standalone market for it was not large enough to sustain a
standalone product. Every dollar HSE charges must be justified against "just
run SpiderFoot for free," and the honest answer is: *on a phone, with no
cloud, with correlation you can defend and a scan that grades itself.* That
is worth a real premium to a specific buyer, and nothing at all to a buyer
with a laptop and an internet connection.

### 5.2 Maltego — the closest link-analysis peer

**HSE has:** fully automated collection and expansion (Maltego is
analyst-driven, transform by transform); zero marginal cost per query on 135
modules (Maltego meters credits at every tier); on-device/no-cloud operation;
self-audit; ATT&CK tagging; a free-forever full-capability local deployment.

**Maltego has:** the market-standard graph UI and analyst workflow; a
transform hub with hundreds of commercial data partners; commercial data
bundled into the price; Hunchly (acquired 2025) for evidence capture; Cases,
Admin, Monitor and Evidence products; multi-seat licensing, SSO and
enterprise support; a very large trained analyst population — Maltego skills
are a hiring criterion, HSE skills are not.

**Price implication.** Maltego Entry at €3,000/yr (≈ A$4,932) is the nearest
credible ceiling reference, but roughly half that price is data credits and
Hunchly. The software-layer-only share is perhaps €1,200–1,800/yr. **HSE
should price below Maltego Entry, not above it** — and can defend a price in
the same order of magnitude only on the sovereignty and automation axes.

### 5.3 OSINT Industries — the closest identity-enumeration peer

**HSE has:** vastly broader scope (170 modules across 14 categories vs
email/phone/username/name/crypto lookups); a correlation engine and entity
graph; unmetered operation; local data residency; infrastructure, corporate,
geo and threat coverage OSINT Industries does not attempt.

**OSINT Industries has:** a maintained, tested aggregation across social
platforms that reliably returns clean, deduplicated account hits — precisely
the precision HSE lacks (§2.1); PDF and Word report export; cloud cases and
storage (5–100 GB); team SSO and shared credit pools at Enterprise; a
polished consumer-grade product with self-serve billing; credits that don't
expire and survive cancellation.

**Price implication.** At £49/mo (£588/yr ≈ A$1,126) for the popular tier,
this is the **most realistic price ceiling for an individual operator** in
this market, because it is what a working investigator already pays and gets
clean output for. HSE's annual price for a solo user should land *below* that
number to be an easy yes, given HSE additionally requires the user to bring
their own keys and triage their own noise.

### 5.4 Skopenow — the closest investigator-workflow peer

**HSE has:** on-device operation; a 170-module technical/infrastructure
surface Skopenow does not cover; deterministic explainable correlation; ~1/50
of the price.

**Skopenow has:** automated, court-usable report generation — the actual
product; social media coverage with maintained platform parsers; case
management and team workflows; insurance/legal/HR-defensible output and
process; compliance posture (FCRA-adjacent handling, audit trails); vendor
support and training.

**Price implication.** Skopenow's US$23,760/yr median is **not** a reference
point for HSE. Their buyer pays for a defensible report, not for collection
breadth. HSE cannot enter this band without §2.3's reporting and
chain-of-custody gaps closed, and even then it would be competing on the
weakest axis it has (precision).

### 5.5 ShadowDragon Horizon / SocialNet — the closest field-and-mobile peer

This is the most instructive comparator, because ShadowDragon publishes a
line-item price list and it prices exactly the capabilities HSE bundles free.

| ShadowDragon SKU | Price | HSE's equivalent |
|---|---|---|
| Horizon Investigate+ w/ SocialNet | £8,350/user/yr | The 37 social + 16 people modules — broader tooling, far thinner social coverage |
| Horizon **Mobile** | £1,100/user/yr, *add-on only* | Native. HSE **is** the mobile product, not a thin client to a cloud |
| Breach Data add-on, 500 q/mo | £13,500/yr | BYO-key (`hibp`, `dehashed`, `intelx`, `oathnet_pro`, `see_know`) — customer pays the provider |
| Location-Based Insights, 6,000 credits/yr | £41,650/yr | Keyless geo pipeline + `hse radar` on-device sensing — different mechanism, no per-credit cost, lower fidelity |

**HSE has:** genuinely on-device processing, not a mobile viewer for a cloud
backend — the data never leaves the handset; live RF/Bluetooth/Wi-Fi/GNSS
sensing feeding the pivot pipeline, which ShadowDragon sells as *purchased
location data* at £41,650/yr; no per-query credit metering anywhere.

**ShadowDragon has:** maintained SocialNet parsers across a large, curated
platform set; a licensed breach corpus; monitoring with delivery SLAs; team
tiers, government procurement presence (G-Cloud), support and training; a
long track record with LE and government buyers.

**Price implication — this is where HSE's ceiling actually lives.** A
ShadowDragon field operator pays **£9,450/seat/yr** (£8,350 + £1,100 mobile)
≈ **A$18,105/seat/yr** for a mobile-accessible investigation capability that
still processes in the cloud. A buyer whose mandate forbids cloud processing
has, as far as I can find, **no commercial option at all**. That is HSE's
highest-value segment — and reaching it is gated entirely on §2.3, not on
features.

### 5.6 Intelligence X — the breach/dark-web index peer

**HSE has:** `--dark` exposure search via Ahmia at zero cost; a full recon
platform around any breach data rather than a search box; local processing.

**IntelX has:** a proprietary historical index of leaks, pastes, dark web and
WHOIS that HSE cannot replicate at any engineering budget — it is accumulated
data, not code.

**Price implication.** IntelX's €2,500/yr is a data price and is not
addressable by HSE. HSE's `intelx` module is a *client* to it. This comparator
mainly demonstrates §4.

### 5.7 Lampyre — the desktop-tool peer

**HSE has:** ~5× the module count, a correlation engine, on-device mobile
operation, an HTTP API, self-audit, and no credit metering.

**Lampyre has:** a mature Windows desktop UI with tables/graphs/maps analysts
find approachable; simple self-serve credit purchase; years in market.

**Price implication.** Lampyre's **~US$313/yr** (≈ A$448) is the closest
like-for-like *tool licence* price in the market and is my primary anchor for
HSE's solo tier.

### 5.8 Constella Intelligence — the data-vendor extreme

**HSE has:** essentially nothing in common. Included to establish the
boundary.

**Constella has:** a breach corpus, and a price (~US$365k/yr) that is entirely
that corpus.

**Price implication.** Cited only to make §4 concrete: capability adjacency in
this market does not imply price adjacency, because the price is the data.

---

## 6. Price derivation — three independent methods

### 6.1 Comparable-licence anchoring

Positioning HSE within the *tool* population:

| Anchor | Price | HSE vs it |
|---|---|---|
| SpiderFoot OSS, Recon-ng | US$0 | HSE is materially more capable per §5.1, but free is free |
| Hunchly | US$130/yr | HSE does far more, but Hunchly's output is court-usable and HSE's is not |
| Lampyre | US$313/yr | HSE has ~5× the modules, correlation, API, on-device — clearly above |
| OSINT Industries Intermediate | US$~790/yr (£49/mo) | HSE is broader; OSINT Industries is cleaner and needs no keys — roughly a wash, HSE should sit below |
| Maltego Entry | US$~3,440/yr (€3,000) | Roughly half is data + Hunchly; HSE's software layer is comparable, its ecosystem is not — HSE should sit well below |

**Band: US$250–650/yr per operator.**

### 6.2 Value-substitution — what the bundle honestly replaces

The naïve stack-replacement sum (Maltego Entry + OSINT Industries + IntelX +
Shodan + Hunchly ≈ **A$11,500/yr**) is **not defensible**, because HSE
replaces none of the *data* in it — its modules are BYO-key clients to those
same vendors.

The honest substitution figure is the software layer only:

| Replaced | Honest value |
|---|---|
| Maltego Entry's graph/analysis software (excl. credits + Hunchly) | ≈ A$2,000–2,500/yr |
| SpiderFoot HX's automation tier | No public price; the niche is now vacant |
| Bespoke scripting an analyst would otherwise maintain | ≈ A$500–1,500/yr of avoided time |
| Shodan / IntelX / OSINT Industries data | **A$0 — not substituted** |

**Band: A$2,500–4,000/yr of gross substituted value**, before discounting for
the noise-triage burden (§2.1), the missing enterprise scaffolding (§2.3) and
the absence of support. A 40–60% discount for those is normal for an
unsupported single-vendor tool with a 7-week track record.

**Discounted band: A$1,000–2,000/yr per operator.**

### 6.3 Cost-to-replicate — asset value, not market price

**Inference, stated assumptions, weak proxy — LOC is a poor measure of
engineering value and I am using it only for an order of magnitude.**

305,007 lines of Rust across 922 files with 6,081 test annotations,
architecture-enforcement tests, fuzz targets and Criterion benches. Assuming
a sustained 2,500–6,000 LOC/engineer-month for well-tested systems code —
the wide band reflects that the 170 modules are repetitive (fast) while the
correlator, engine and convex allocator are not (slow) — gives **51–122
engineer-months ≈ 4.2–10.2 engineer-years**. At a fully-loaded senior Rust
engineer cost of A$180k–260k/yr:

**Replacement cost ≈ A$0.8M – A$2.6M.**

This is relevant to an OEM licence, a source licence, or an acquisition — not
to a per-seat price. It does say that pricing HSE at hobbyware levels
understates the asset materially.

---

## 7. Recommended price ladder

Three of the four rungs below are **not shippable today**. That is the point:
the ladder shows what the current build is worth and what specifically
unlocks each step up. Prices in AUD, with USD at 0.6981.

### Rung 0 — Community (free)

**A$0.** Full capability, single operator, non-commercial use, no support.

**Why it is necessary, not optional:** SpiderFoot is free with more modules
(§5.1). Without a free rung, every evaluation begins with "why not just run
SpiderFoot?" and ends there. This rung's job is to make the comparison happen
on capability instead of on price.

### Rung 1 — Professional (ship today) · **A$495/yr per operator** (≈ US$345)

Commercial-use licence, all 170 modules, BYO keys, self-serve, community
support, 12 months of updates.

**Derivation:** §6.1 gives US$250–650; §6.2 discounted gives A$1,000–2,000.
A$495 sits at the lower-middle of the overlap. Deliberately: above Lampyre
(A$448) and Hunchly (A$186) because HSE does more; below OSINT Industries
Intermediate (A$1,126) because that product returns clean output and HSE
requires triage; far below Maltego Entry (A$4,932) because Maltego bundles
data.

**Why not higher today:** no support obligation can be offered against
free-source yield (§2.2); a solo buyer must absorb the noise burden (§2.1);
the track record is 7 weeks (§2.4).

**Why not lower:** at A$0–200 the product reads as hobbyware, which
contradicts a 305k-line, 122-rule, self-auditing engine and poisons the
enterprise conversation later. Price is a positioning signal before it is a
revenue number.

### Rung 2 — Team · **A$1,450/seat/yr** (≈ US$1,010), 3-seat minimum

**Blocked. Requires:** authentication + RBAC on the HTTP server (§2.3 — today
it explicitly runs with no auth off-loopback); shared case/scan storage;
PDF/DOCX report export; persistent live sessions; a published support SLA.

**Anchor:** below Maltego Professional (€7,500/5 seats = A$2,466/seat) and
below Skopenow's per-contract median, positioned as "the team tool for
organisations that cannot put investigation data in a vendor cloud."

### Rung 3 — Sovereign / Field deployment · **A$3,500–6,000/seat/yr**, or **A$45k–120k** site licence (≤25 seats)

**Blocked. Requires** everything in Rung 2 plus: chain-of-custody hashing and
timestamping on collected evidence; signed reproducible builds; verified
offline/air-gapped mode; MDM-compatible deployment; a real support contract;
and the compliance artefacts in §2.3.

**Why this rung exists and why it is the real prize:** a ShadowDragon field
operator pays ≈ **A$18,105/seat/yr** (Investigate+ £8,350 + Mobile £1,100)
for mobile access to a capability that still processes in the cloud (§5.5). A
buyer under a no-cloud mandate — field law enforcement, defence, a corporate
investigations team under strict data-handling rules, a journalist in a
hostile environment — appears to have **no commercial option at all**. In that
segment HSE is not competing on features; it is the only product whose
architecture satisfies the constraint. A$3,500–6,000/seat is a 3–5× saving
against ShadowDragon and still 7–12× Rung 1.

**This rung is worth more than every other rung combined, and it is gated
entirely on §2.3 scaffolding — not on a single new OSINT module.**

### Rung 4 — OEM / source / acquisition

Anchor on **A$0.8M–2.6M** replacement cost (§6.3), adjusted for the buyer's
build-vs-buy timeline. Note `publish = false` and the all-rights-reserved
licence keep this option fully open.

---

## 8. What moves the price, ranked by A$ per unit of effort

1. **Authentication + RBAC on the HTTP server.** Days of work. Unlocks Rungs
   2 and 3 — a ~3× and ~10× price step. Nothing else on this list comes close
   on return per hour.
2. **PDF/DOCX report export.** The single most-cited gap against every
   investigator-market competitor (§5.3, §5.4). The dossier renderer already
   exists; this is a rendering target, not new intelligence work.
3. **Chain-of-custody hashing + timestamping.** Opens the legal/LE evidentiary
   use case and is table stakes for Rung 3. `util::raw_archive` is most of the
   retention half already.
4. **Precision work on the identity/AU-geo layer.** §2.1 is the credibility
   ceiling. The self-audit already names the exact defects — infrastructure
   pollution, role mailboxes, name-derived phantoms. Closing them raises the
   audit grade from D, and a demoable A-grade scan is worth more in a sales
   conversation than twenty new modules.
5. **A published SLA-backed support tier.** Cheap to write, required by
   procurement, and the thing that makes Rung 2's price defensible.
6. **More modules.** Deliberately last. HSE has 170 and is beaten on count by
   free SpiderFoot; module count is not where the price is.

---

## 9. Risks to this pricing thesis

- **The free-competitor problem is not solvable by pricing.** SpiderFoot is
  free and broader by module count. If a buyer is not constrained to a
  handset and does not value the correlation/audit layer, HSE has no price at
  which it wins. Segment accordingly rather than discounting.
- **SpiderFoot HX's absorption into Intel 471 is ambiguous evidence.** It
  vacates the niche (good) and may indicate the standalone niche was too small
  to sustain a product (bad). I cannot distinguish these from public
  information and am not assuming the favourable reading.
- **Source durability.** §2.2 — a coordinated tightening of anti-bot defence
  across the free engines would degrade the free-module value proposition
  materially. The quarantine/probe machinery limits the blast radius; it does
  not remove the dependency.
- **Legal and reputational exposure.** A tool that geolocates individuals from
  public data sits close to privacy-law lines in every jurisdiction. The
  README's authorised-use framing and `SECURITY.md`'s defensive-only posture
  are necessary but will not by themselves satisfy an enterprise legal review.
  This is a real constraint on the enterprise rungs and should be budgeted for.
- **Key-currency risk.** 35 of 170 modules depend on third-party providers
  whose terms, pricing and existence are outside HSE's control (the repo has
  already removed one permanently-sunset provider, `proxycurl`).
- **Single-maintainer concentration.** For Rung 3 buyers, source escrow or a
  continuity arrangement will be a procurement condition.

---

## 10. Bottom line

**As it stands today — v1.40.0, single operator, BYO keys, no support, no
auth — Huntsman Search Engine is worth A$495/yr per operator (≈ US$345),
alongside a free community rung.** That figure is set by the *tool* market it
actually competes in, not by the data-subscription market whose feature lists
it superficially resembles.

The gap analysis makes the strategic position clear. HSE is over-built for
Rung 1 and under-scaffolded for Rung 3. Its engineering — 305k lines, 122
deterministic correlation rules, a self-audit that fails its own output, full
on-device operation — is already in the class of products selling for
A$8,000–18,000 a seat. What separates it from that price is not intelligence
capability. It is authentication, a PDF renderer, evidence hashing, a support
contract, and precision work the tool has already diagnosed in itself.

The £1,100/user/yr ShadowDragon charges for a *mobile client to a cloud*, and
the £41,650/yr they charge for *purchased location data*, are the clearest
available evidence that the market pays for what HSE does natively — provided
it arrives wrapped in the commercial scaffolding that buyer's procurement
requires.

---

# Part II — Price under the "all features work" assumption

Sections 1–10 priced the software **as measured**, including the precision
defects and source-yield failures I observed. This part re-derives the price
on the requested assumption that every shipped capability functions correctly
and reliably at its stated purpose.

Everything is expressed as tables. Part I's evidence base and FX rates carry
over unchanged (AUD/USD 0.6981 · EUR/AUD 1.6441 · GBP/AUD 1.9158, 3 Aug 2026).

## 11. Exactly what the assumption relaxes

The assumption is read as: *capabilities that exist are assumed to work.* It
does not conjure capabilities that are absent, and it does not change facts
that are not about software behaviour.

| Part I constraint | Type | Under the assumption | Price effect |
|---|---|---|---|
| §2.1 Precision — audit graded a live scan **44/100 (D)**, 1 CRITICAL finding, phantom identities, spurious AU geo | Functional defect | **Removed** — output is client-deliverable without triage | **Large ↑** |
| §2.2 Free-source yield — **2 up / 12 blocked / 3 down of 17** engines | Functional/environmental | **Removed** — all 17 engines yield; 135 free modules deliver full value | **Large ↑** |
| Module reliability across all 170 | Functional | **Removed** — all return correct data | **Moderate ↑** |
| §2.3 No auth / RBAC / SSO | **Absent feature** | Still absent | No change |
| §2.3 No PDF/DOCX report export | **Absent feature** | Still absent | No change |
| §2.3 No chain-of-custody hashing | **Absent feature** | Still absent | No change |
| §2.3 Live sessions in-memory only | **Absent feature** | Still absent | No change |
| §2.3 No support / SLA / training | Not software | Still absent | No change |
| §2.3 No SOC 2 / DPA / pen-test / insurance | Not software | Still absent | No change |
| §2.4 7-week track record (43 releases) | Not software | Unchanged | No change |
| §2.4 Termux aarch64 primary platform | By design | Unchanged | No change |
| **§4 HSE owns no proprietary data** | **Architecture** | **Unchanged — still the binding constraint** | **No change** |

> The single most important line in that table is the last one. Perfect
> function does not turn a tool into a data vendor. HSE still prices against
> the tool population, just at the top of it instead of the middle.

## 12. HSE quantified capability metrics

All verified from the running v1.40.0 binary or the source tree (Part I §1).

| Metric | Value | Source |
|---|---|---|
| Modules registered | **170** | `hse modules` |
| — free / key-gated / paid | **135 / 31 / 4** (79.4% / 18.2% / 2.4%) | `hse diagnostics` |
| Module categories | 14 | `hse modules` |
| Module reachability | **100%** from every realistic seed kind | `hse selftest` |
| Seed types accepted | 16 | CLI |
| Correlator rules | **122** deterministic (`AU-001`–`AU-123`, AU-065 reserved) | source |
| Search engines | 17 | `hse engines` |
| Optional provider keys supported | 51 | `hse diagnostics` |
| HTTP API routes | 83 | source |
| CLI subcommands | 18 | `hse --help` |
| Source size | **305,007 lines / 922 files** | `wc -l` |
| Test annotations | 6,081 | `grep` |
| Self-test | **10/10 pass, 0 fail**, 63 ms | `hse selftest` |
| Module metadata probes | 3,230, no panic | `hse selftest` |
| Release binary | 20.6 MB (x86_64 release build) | `ls -l` |
| Release cadence | 43 releases / 47 days = **0.91 per day** | GitHub API |
| **Marginal cost per query, 135 free modules** | **A$0.00** | Architecture |
| **Metering** | **None — unlimited scans, entities, seats-of-one** | Architecture |
| **Data egress off-device** | **Zero** (loopback default) | Architecture |

## 13. Competitor price table with unit economics

Published prices, converted to AUD, with the metered unit rate each implies.
This is the table that decides the price.

| Product / SKU | Price (native) | **A$/yr** | Metered units/yr | **A$ per unit** | Deployment |
|---|---|---:|---:|---:|---|
| SpiderFoot OSS | Free | **0** | unmetered | 0.00 | Self-hosted |
| Recon-ng / theHarvester / Maigret | Free | **0** | unmetered | 0.00 | Self-hosted |
| Maltego Basic | €0 | **0** | 2,400–12,000 | 0.00 | Desktop + cloud |
| Hunchly | US$129.99 | **186** | unmetered | — | Browser plug-in |
| Lampyre (annual) | US$313 | **448** | credits extra | — | Desktop |
| OSINT Industries Basic | £19/mo | **437** | 360 | **1.21** | SaaS |
| OSINT Industries Intermediate | £49/mo | **1,126** | 1,200 | **0.94** | SaaS |
| Shodan Freelancer | US$69/mo | **1,186** | not published | — | SaaS |
| OSINT Industries Advanced | £99/mo | **2,276** | 3,600 | **0.63** | SaaS |
| ShadowDragon Horizon Mobile *(add-on only)* | £1,100 | **2,107** | — | — | Cloud + mobile client |
| IntelX Researcher | €2,500 | **4,110** | not published | — | SaaS |
| Maltego Entry | €3,000 | **4,932** | 10,000 | **0.49** | Desktop + cloud |
| IntelX API | €5,000 | **8,220** | 182,500 | **0.05** | API |
| ShadowDragon Monitor +500/day | £6,000 | **11,495** | 182,500 | **0.06** | Cloud |
| Maltego Professional (5 seats) | €7,500 | **12,331** | 20,000–40,000 | **0.31–0.62** | Desktop + cloud |
| ShadowDragon Horizon Investigate+ | £8,350 | **15,997** | — | — | Cloud |
| ShadowDragon Breach Data 500/mo | £13,500 | **25,863** | 6,000 | **4.31** | Cloud |
| Skopenow (median contract) | US$23,760 | **34,035** | not published | — | SaaS |
| ShadowDragon LBI 6,000/yr | £41,650 | **79,793** | 6,000 | **13.30** | Cloud |
| ShadowDragon Breach Data 2,000/mo | £44,800 | **85,828** | 24,000 | **3.58** | Cloud |
| ShadowDragon LBI 12,000/yr | £58,200 | **111,500** | 12,000 | **9.29** | Cloud |
| ShadowDragon Teams Monitor Enterprise | £67,550 | **129,412** | 1,460,000 | **0.09** | Cloud |
| Constella Intelligence (avg) | US$365,000 | **522,848** | not published | — | Cloud |
| **HSE (recommended, §15)** | **A$1,395** | **1,395** | **unmetered** | **0.00** | **On-device** |

## 14. Quantified gap analysis — HSE vs each competitor

Verified metrics only. "n/p" = not published by the vendor; I am not
estimating it.

| Competitor | Their A$/yr | HSE Δ price | Modules/sources | Metering | Their edge, quantified | HSE edge, quantified |
|---|---:|---:|---|---|---|---|
| **SpiderFoot OSS** | 0 | **+1,395** | "200+" (third-party figure, not verified by me) vs HSE **170** (verified) | none | Free; more modules; decade of hardening; open licence | 122 correlation rules; on-device Android; self-audit; ATT&CK inline; radar; 0 Python deps |
| **Maltego Entry** | 4,932 | **−3,537 (−72%)** | n/p transforms | 10,000 credits | Bundled commercial data; standard analyst UI; Hunchly included | Unmetered (breaks even at **2,828 queries/yr**); automated expansion vs manual transforms; on-device |
| **Maltego Professional** | 12,331 / 5 seats = **2,466/seat** | **−1,071/seat (−43%)** | n/p | 20–40k credits | Unlimited commercial data; SSO; Cases/Admin | Unmetered; on-device; 1 seat minimum vs 5 |
| **OSINT Industries Intermediate** | 1,126 | **+269 (+24%)** | 5 published search types vs HSE **170 modules / 14 categories** | 1,200 credits | Clean output; PDF+Word export; cloud cases; no keys needed | **34× the module count**; unmetered (breaks even at **1,486 queries/yr**); on-device |
| **OSINT Industries Advanced** | 2,276 | **−881 (−39%)** | as above | 3,600 credits | as above + 100 GB storage | as above; breaks even at **2,207 queries/yr** |
| **IntelX Researcher** | 4,110 | **−2,715 (−66%)** | 1 proprietary index | n/p | **A proprietary corpus HSE cannot replicate at any engineering budget** | Full platform vs a search box; HSE's `intelx` module is a client to them |
| **Skopenow** | 34,035 | **−32,640 (−96%)** | n/p | n/p | Court-usable automated reports; case management; compliance posture | 170-module technical surface; on-device; 1/24 the price |
| **ShadowDragon field seat** (Investigate+ £8,350 + Mobile £1,100) | **18,104** | **−16,709 (−92%)** | n/p SocialNet platforms | per-SKU credits | Maintained social parsers; licensed breach corpus; G-Cloud presence; support | **Mobile is native, not an add-on**; their mobile SKU alone is A$2,107/yr and is a *cloud client* |
| **ShadowDragon Breach 500/mo** | 25,863 | — | — | 6,000 q/yr @ **A$4.31** | Licensed corpus | HSE breaks even at **324 queries/yr** — but BYO-key, so not a true substitute |
| **ShadowDragon LBI 6k** | 79,793 | — | — | 6,000 @ **A$13.30** | Purchased location data | `hse radar` senses on-device at A$0.00; breaks even at **105 queries/yr** |
| **Constella** | 522,848 | **−521,453 (−99.7%)** | Breach corpus | n/p | The corpus *is* the product | Not comparable — included to bound the market |

## 15. Revised price ladder

| Rung | Product | **A$/yr** | US$/yr | Basis | Ship today? |
|---|---|---:|---:|---|---|
| 0 | **Community** | **0** | 0 | Answers "why not free SpiderFoot?"; full capability, non-commercial, no support | ✅ Yes |
| 1 | **Professional** (1 operator) | **1,395** | 974 | Band A$1,200–1,800; three methods converge (§16) | ✅ **Yes** |
| 2 | **Team** (3-seat min) | **2,950/seat** | 2,059 | Below Maltego Professional's A$2,466/seat only if data excluded; positioned as the no-cloud team tool | ❌ Needs auth/RBAC, PDF export, persistent sessions, SLA |
| 3 | **Sovereign / Field** | **6,500–11,000/seat** | 4,538–7,679 | 1.65–2.79× under ShadowDragon's A$18,104 field seat | ❌ Needs Rung 2 + chain-of-custody, signed builds, compliance artefacts |
| 3b | Sovereign site licence (≤25 seats) | **95,000–210,000** | 66,320–146,600 | Volume-discounted Rung 3 | ❌ As above |
| 4 | OEM / source / acquisition | **1.8M–2.6M+** | 1.26M–1.82M | Upper half of the A$0.8M–2.6M replacement-cost band (§6.3); a *working* asset commands the top | — |

## 16. Rung 1 derivation — three methods

| Method | Calculation | Band |
|---|---|---|
| **Comparable-licence anchoring** | Above OSINT Industries Intermediate (A$1,126, 34× fewer module types, metered); below OSINT Industries Advanced (A$2,276) and Maltego Entry's software share (~A$2,466) | **A$1,200–2,300** |
| **Value-substitution** | Gross substituted software value A$2,500–4,000, discounted 30–45% for absent scaffolding + no support + 7-week track record (was 40–60% in Part I; the precision discount comes off) | **A$1,375–2,800** |
| **Unmetered break-even** | An operator running 3,000 identity queries/yr pays A$1,890 (OSINT Ind. Advanced rate) to A$4,932 (Maltego Entry). HSE unmetered undercuts every metered rival above ~1,500 queries/yr | **A$1,400–2,000** |
| **Overlap of all three** | — | **A$1,400–2,000** |
| **Recommended** | Priced at the lower edge of the overlap to stay an easy yes against free SpiderFoot | **A$1,395** |

## 17. Break-even — where unmetered wins

Annual queries at which HSE at A$1,395 unmetered costs less than each metered rival.

| Rival | A$/unit | **Break-even (queries/yr)** | Per working day (250/yr) |
|---|---:|---:|---:|
| ShadowDragon LBI 6k | 13.30 | **105** | 0.4 |
| ShadowDragon LBI 12k | 9.29 | **150** | 0.6 |
| ShadowDragon Breach 500/mo | 4.31 | **324** | 1.3 |
| ShadowDragon Breach 2000/mo | 3.58 | **390** | 1.6 |
| OSINT Industries Basic | 1.21 | **1,150** | 4.6 |
| OSINT Industries Intermediate | 0.94 | **1,486** | 5.9 |
| OSINT Industries Advanced | 0.63 | **2,207** | 8.8 |
| Maltego Professional | 0.62 | **2,263** | 9.1 |
| Maltego Entry | 0.49 | **2,828** | 11.3 |
| Maltego Prof. Advanced | 0.31 | **4,525** | 18.1 |
| ShadowDragon Teams Enterprise | 0.09 | **15,738** | 63.0 |
| ShadowDragon Monitor +500/day | 0.06 | **22,148** | 88.6 |
| IntelX API | 0.05 | **30,970** | 123.9 |

**Read:** a single investigator doing ~6 identity lookups a working day already
beats OSINT Industries Intermediate. HSE's unmetered model is a genuine
economic weapon against low-volume, high-unit-cost SKUs — and a weak one
against high-volume bulk API tiers.

## 18. Value density at each price

| Price | A$/module | A$/correlation rule | A$/day | A$/query at 3,000 q/yr |
|---|---:|---:|---:|---:|
| A$495 (Part I, as-measured) | 2.91 | 4.06 | 1.36 | 0.17 |
| **A$1,395 (Part II, assume-works)** | **8.21** | **11.43** | **3.82** | **0.47** |
| A$2,950 (Rung 2) | 17.35 | 24.18 | 8.08 | 0.98 |
| A$6,500 (Rung 3 low) | 38.24 | 53.28 | 17.81 | 2.17 |
| A$11,000 (Rung 3 high) | 64.71 | 90.16 | 30.14 | 3.67 |

Even at Rung 3, A$3.67 per query undercuts ShadowDragon's breach (A$4.31) and
location (A$13.30) unit rates.

## 19. What the assumption is worth — the ROI of fixing §2.1 and §2.2

| Rung | Part I (as measured) | Part II (assume works) | **Delta** | Multiple |
|---|---:|---:|---:|---:|
| Professional | A$495 | **A$1,395** | **+A$900/seat/yr** | 2.82× |
| Team | A$1,450 | **A$2,950** | **+A$1,500/seat/yr** | 2.03× |
| Sovereign (low) | A$3,500 | **A$6,500** | **+A$3,000/seat/yr** | 1.86× |
| Sovereign (high) | A$6,000 | **A$11,000** | **+A$5,000/seat/yr** | 1.83× |
| OEM / source | A$0.8M–2.6M | **A$1.8M–2.6M** | **+A$1.0M at the floor** | 2.25× at floor |

**This is the most actionable number in the document.** The gap between
Part I and Part II is not a market judgement — it is the price of the four
defects HSE's own `hse audit` already names: infrastructure pollution, role
mailboxes treated as PII, name-derived phantom identities, and generic domain
noise. Closing them is worth **+A$900 per seat per year at Rung 1 alone**, and
roughly **+A$1.0M on the asset value**.

## 20. Caveat carried forward

Part II is a **conditional** valuation. The condition — that all features work
— is not something I verified; Part I §2.1 and §2.2 record what I actually
measured, and they measured otherwise. Both parts should be read together: Part
I is the price today, Part II is the price on delivery of correctness, and §19
is the value of the work between them.

---

# Part III — Customer-base projection and whole-project valuation

Answers two distinct questions: *how many paying customers is it realistic to
expect year-by-year with average-quality marketing/SEO*, and *what is the
whole project — source code and all — worth today.* Both are estimates built
on stated, sourced assumptions, not measurements. Nothing here should be read
with the confidence of Parts I–II.

## 21. Method and its limits

**What I could not get:** no competitor publishes paying-customer counts.
SpiderFoot (the closest peer) discloses GitHub stars/forks but not commercial
HX subscriber counts; Maltego, OSINT Industries, Skopenow and ShadowDragon
disclose none of user, customer, or revenue figures. "Use competitors as base
rates" is therefore implemented as: **anchor the traffic/conversion inputs to
published category benchmarks** (freemium devtool conversion, organic SaaS
traffic ramps) and to the one hard competitor data point that exists
(SpiderFoot's GitHub trajectory), not to fabricated competitor customer
counts.

**Sourced benchmark inputs:**

| Input | Value used | Source |
|---|---|---|
| Devtool freemium free→paid conversion | 1.0–2.4%, rising with maturity | OpenView SaaS Benchmarks (median 2–5% all SaaS; devtool sub-segment 1–3%) |
| Mature niche B2B organic traffic ceiling | ~1,500–6,500 sessions/mo by Yr 2–5 | Industry SEO-benchmark aggregates for niche tool categories |
| Organic trial/try conversion | 4.5–8% of sessions | SaaS organic-traffic benchmark aggregates (2–5% typical; higher used here because HSE's free tier is instant/no-signup, closer to a download-page CVR than a trial-signup CVR) |
| Free-user annual retention | 45–65% | Assumption — devtool community tiers typically show high first-year drop-off; not vendor-sourced |
| Paid-customer annual churn | 18–35% | Assumption, single-product/no-support-contract SMB SaaS norm; not vendor-sourced |
| SpiderFoot GitHub trajectory (reference only) | 18–29k stars, 2,892 forks, built over **years**, not months | GitHub |

**Explicitly an estimate, explicitly average-quality:** "average" is
operationalised as organic SEO/GitHub/community-post growth only — no paid
acquisition, no dedicated marketing hire, no conference/analyst presence
(the things ShadowDragon, Maltego and Skopenow all have and HSE's team of one
does not).

**Pricing basis:** the customer-base model prices at **Part I's ship-today
figure, A$495/yr per operator** — the project **as it exists now**, not the
Part II hypothetical. Team/Sovereign tiers are excluded because they require
features that do not exist yet (Part I §2.3); modelling revenue from an
unshippable SKU would overstate the as-is case.

## 22. Year-by-year customer and revenue projection

Three scenarios — LOW (weak execution), BASE (average, as specified), HIGH
(above-average execution and unusually strong niche fit) — from the same
funnel: organic sessions → free-tier installs (with retention) → paid
conversion (with churn) → ARR at A$495/seat.

### BASE case (average-quality marketing/SEO — the requested scenario)

| Year | Avg. organic sessions/mo | New free users | Active free base (EOY) | New paid | **Paid customers (EOY)** | **ARR (A$)** | **ARR (US$)** |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 200 | 144 | 144 | 1 | **1** | **713** | 498 |
| 2 | 950 | 684 | 763 | 11 | **13** | **6,201** | 4,329 |
| 3 | 2,350 | 1,692 | 2,112 | 42 | **52** | **25,557** | 17,841 |
| 4 | 4,100 | 2,952 | 4,113 | 91 | **129** | **63,964** | 44,653 |
| 5 | 5,750 | 4,140 | 6,402 | 154 | **251** | **124,033** | 86,587 |

### LOW case (weak execution — floor)

| Year | **Paid customers (EOY)** | **ARR (A$)** |
|---:|---:|---:|
| 1 | 0 | 160 |
| 2 | 3 | 1,415 |
| 3 | 10 | 5,169 |
| 4 | 24 | 11,861 |
| 5 | 43 | 21,237 |

### HIGH case (above-average execution — ceiling for "average" framing)

| Year | **Paid customers (EOY)** | **ARR (A$)** |
|---:|---:|---:|
| 1 | 5 | 2,495 |
| 2 | 48 | 23,765 |
| 3 | 210 | 103,983 |
| 4 | 591 | 292,495 |
| 5 | 1,269 | 628,336 |

**Read against the SpiderFoot anchor:** SpiderFoot's OSS project needed
multiple years to reach ~18–29k GitHub stars. BASE's Year-5 active free base
of ~6,400 is well short of that trajectory even after five years — consistent
with HSE being a narrower-audience (Termux-Android-only, AU-optimised),
proprietary-licensed tool competing against a free, permissively-licensed,
decade-old category leader. **The BASE case should be read as the realistic
scenario; the HIGH case requires SEO/marketing performance HSE's current
single-maintainer, no-budget posture gives no evidence of.**

## 23. What the customer-base model implies for pricing tier mix

At A$495/yr flat (Rung 1 only, since Rungs 2–3 aren't shippable), the
model **cannot validate Part II's higher rungs** — there is no projected
customer segment paying A$2,950 or A$6,500+/seat until Rungs 2–3 actually
ship (Part I §2.3, Part II §11). Revenue from those rungs is upside not yet
modellable from today's product.

## 24. Whole-project valuation — reconciling asset cost against revenue traction

Two independent valuation approaches, reconciled rather than averaged.

### 24.1 Cost/asset-floor approach

Part I §6.3 derived a **replacement-cost band of A$0.8M–2.6M** from 305,007
lines of tested, architecturally-enforced Rust (4.2–10.2 engineer-years at
A$180k–260k/yr fully loaded).

That figure is *reproduction* cost, not *acquisition* value — a buyer does
not pay full rebuild cost for an asset carrying:

| Discount factor | Why | Evidence |
|---|---|---|
| Single-maintainer concentration risk | No team continuity; Part I §9 flags source-escrow as a procurement condition at scale | 43 releases, apparently solo-cadenced |
| Unresolved precision defects | Buyer inherits the CRITICAL/HIGH findings `hse audit` already names | Part I §2.1 |
| Missing commercial scaffolding | Auth/RBAC, PDF export, chain-of-custody, support — all absent | Part I §2.3 |
| 7-week public track record | Too short to de-risk for a conservative acquirer | Part I §2.4 |

Applying a **40% discount** (standard for concentrated, early-stage technical
assets in down-market tuck-in valuation) to the replacement-cost band:

| | Low | High |
|---|---:|---:|
| Replacement cost | A$800,000 | A$2,600,000 |
| **Discounted asset floor (−40%)** | **A$480,000** | **A$1,560,000** |

### 24.2 Revenue-multiple approach

Applying niche/micro-SaaS multiples (2.0–3.5× ARR — "standalone single-product
vendors struggle to break 5×," per cybersecurity-M&A benchmark sources) to the
**BASE-case Year-3 ARR** (the earliest year revenue is non-trivial enough to
value rather than round to zero):

| | Low (2.0×) | High (3.5×) |
|---|---:|---:|
| Y3 ARR (BASE) | A$25,557 | A$25,557 |
| **Revenue-multiple value** | **A$51,000** | **A$89,000** |

**This is the central finding of Part III: at every year in the LOW and BASE
scenarios, and until roughly Year 5 even in the HIGH scenario, the
revenue-multiple value stays one to two orders of magnitude below the
discounted asset floor.** For an under-monetised technical asset like this
one, revenue traction is a secondary signal, not the primary valuation
driver — the code itself is worth more than what it has sold so far.

### 24.3 Reconciliation

Standard practice for an early-revenue technical asset is the **greater of**
the discounted cost floor and the capitalized revenue value, plus a modest
premium for the de-risking that even small revenue traction provides (proof
the product converts real users, not just a hypothesis):

| Component | Low | High |
|---|---:|---:|
| Discounted asset floor | A$480,000 | A$1,560,000 |
| + traction premium (partial weight on Y3 revenue-multiple value) | +A$25,000 | +A$150,000 |
| **Whole-project valuation, as-is, source code included** | **A$505,000** | **A$1,710,000** |
| **In USD** | **US$353,000** | **US$1,194,000** |
| **Point estimate** | **A$1,107,500 (US$773,000)** | |

## 25. What would move this number

| Lever | Effect |
|---|---:|
| A second engineer joins (removes single-maintainer discount) | **+~A$200k–400k** (partial discount reversal) |
| Precision fixes land (§2.1) + auth/RBAC ships (Part II §11) | **+~A$300k–600k** (asset re-rates toward the undiscounted replacement-cost band, and Rung 2/3 revenue becomes modellable) |
| 12 more months of release cadence at current pace with no regressions | **+~A$100k–200k** (track-record discount narrows) |
| BASE case realised through Year 3 (52 paying customers, A$25.6k ARR) | Validates the revenue-multiple floor but does not yet change which approach dominates (§24.3) |
| HIGH case realised (1,269 customers by Yr 5, A$628k ARR) | **Revenue-multiple value (A$1.26M–2.2M) overtakes the asset floor** — valuation basis flips to a revenue multiple |

## 26. Caveat

Every number in Part III is a model output built on stated assumptions and
category benchmarks, not on measured competitor data — no comparator in this
market publishes customer or revenue figures, so "use competitors as base
rates" could only be implemented via published conversion/traffic benchmarks
plus the one disclosed competitor trajectory (SpiderFoot's GitHub growth).
Treat the ranges, not the point estimates, as the honest output.
