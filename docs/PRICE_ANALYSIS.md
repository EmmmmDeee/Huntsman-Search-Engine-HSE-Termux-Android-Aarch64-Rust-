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
