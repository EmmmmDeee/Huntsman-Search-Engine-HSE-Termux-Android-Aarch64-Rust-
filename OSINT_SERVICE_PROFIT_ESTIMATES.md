# OSINT Service Profit Estimates — Annual, Per Service

**Prepared for:** Haigen Bamford
**Date:** 2026-06-12
**Companion to:** [`OSINT_SERVICE_VALUE_vs_HSE.md`](OSINT_SERVICE_VALUE_vs_HSE.md) · [`OSINT_MATRIX_GAP_ANALYSIS.md`](OSINT_MATRIX_GAP_ANALYSIS.md)

> ## ⚠️ Read this first — these are modelled estimates, not accounts
> All but one of these companies are **private and disclose no financials**. Even their *revenue* is
> third-party guesswork (Latka/Growjo/Kona/ZoomInfo/Owler figures routinely disagree by 2–5×), and
> their **cost structure is invisible**, so **profit — revenue minus costs — is the single hardest
> number to estimate and the least reliable on this page.** Treat every figure as an **order of
> magnitude with a wide error bar**, not a fact. The value here is the *model and its assumptions*
> (stated below so you can adjust them), and the *relative ranking*, which is more robust than any
> absolute number.

---

## 1. Method & assumptions

**Profit ≈ Revenue − (headcount × loaded cost/employee) − (infrastructure + upstream-data costs).**

| Assumption | Value used | Note |
|---|---|---|
| Loaded cost / employee | US ~$150k · EU/UK ~$120k · blended **~$135k** | Salary + benefits + overhead; engineering-heavy teams |
| Micro-team discount | founders often underpay themselves | lowers effective cost for 1–5-person shops |
| Scanning infra (Shodan/Censys) | $1–3M/yr | global internet-wide scanning is capital-heavy |
| Breach-corpus storage (DeHashed/IntelX) | $0.5–2M/yr | large datasets, high egress |
| Aggregator upstream-data credits (Epieos/OSINT Ind./UserSearch) | 20–40% of revenue | they **pay other vendors** per lookup, compressing margin |

**Confidence scale:** **Med** = a credible founder-reported or news figure anchors it · **Low** =
one stale/third-party estimate · **V.Low** = inferred from headcount + user-base + pricing only.

**Revenue ≠ profit, sharply, in this sector.** A sanity check on revenue-per-employee exposes the
margin story before any cost modelling: Shodan and HIBP run at **$0.5–1M+ revenue/employee** (wildly
profitable), Hunter.io at a healthy **~$235k**, while Maltego sits at **~$110k/employee — *below*
loaded cost**, and VC-funded Censys spends far more than it earns by design. Those four data points
alone predict the ranking below.

---

## 2. Estimated annual profit, highest to lowest

| Service | Est. annual revenue | Est. team | Est. **annual profit** | Conf. | Why |
|---|---|---|---|---|---|
| **Shodan** | $8–15M | ~5–13 | **+$5M to +$9M** | Low–Med | Famously lean, bootstrapped, founder-led since 2012; one-time $49 + API subs at near-zero marginal cost. Highest absolute profit on the board. |
| **Hunter.io** | ~$8M (Latka, founder-reported) | ~31–37 | **+$2M to +$3M** | Med | Bootstrapped, profitable B2B SaaS; ~$235k rev/employee = normal-healthy margin. |
| **Have I Been Pwned** | ~$2–4M | ~1–3 | **+$1.5M to +$3M** | Low | Near-solo (Troy Hunt); Cloudflare subsidises much of the infra → extreme margin on the new tiered API + enterprise. |
| **DeHashed** | ~$4M (Kona, possibly stale) | ~5–15 | **+$1M to +$2M** | Low | Breach data is high-margin once acquired; bootstrapped; thousands of LE/Fortune-500 seats. |
| **Intelligence X** | $2–4M (<$5M, ZoomInfo) | ~5–15 | **+$0.5M to +$2M** | Low | Founder-led (Prague, est. 2018); new €2.5k–€7.5k/yr licences lift ARPU; EU costs modest. |
| **Epieos** | $0.5–2M | ~3–8 | **+$0.2M to +$0.8M** | V.Low | Small Paris team; freemium + training/services; upstream-API credit costs thin the margin. |
| **OSINT Industries** | $2–4M | ~11–50 | **−$0.5M to +$1M (≈ break-even)** | V.Low | Founded 2023, **no funding raised** → must roughly self-fund headcount; scaling, so margin is thin/negative now. |
| **UserSearch.org** | $0.5–1.5M | ~2–10 | **+$0.1M to +$0.6M** | V.Low | 500k monthly users; at ~0.5–1.5% premium conversion × ~$12/mo ≈ $0.5–1M; pays partner-data credits. |
| **OathNet** | <$0.3M | ~1–5 | **~$0 to +$0.1M (negligible)** | V.Low | New/small; free 10/day + low-cost paid tiers; tiny paying base. |
| **WiGLE** | negligible (commercial licensing *suspended*) | 2 | **~$0 (passion/community project)** | Med | Volunteer-fed wardriving DB since 2001; clearly **not run for profit**. |
| **SecurityTrails** | ~$2–3M line | ~6–15 | **n/a — absorbed into Recorded Future** | — | Acquired 2022 for $65M; RF itself was bought by **Mastercard (~$2.65B, 2024)**. Profit not separable; the $65M priced the *data*, not standalone profit. |
| **SpiderFoot HX** | <$2M line | small | **n/a — absorbed into Intel 471** | — | Acquired by Intel 471 (2021); a product line, not a standalone P&L. |
| **Maltego** | ~$17M (Latka) / €14.7M FY23 | ~160–174 | **−$5M to +$2M (≈ break-even, leaning negative)** | Low | 160 staff × ~$135k ≈ **$22M people cost > revenue**. PE-owned (Charlesbank, **$100M+ injected, 2023**) and spending for growth → a growth play, *not* a current cash cow. |
| **Censys** | ~$30–50M ARR (est.) | ~163 | **−$15M to −$30M (loss by design)** | Low–Med | VC-funded (**$143M raised**), 130%+ ARR growth, burning the raise to capture the enterprise/federal ASM market. Highest revenue, **deepest losses**. |

---

## 3. The sector's profit story in three points

1. **Revenue and profit are nearly inverted here.** The two *biggest* companies by revenue — Censys
   (~$30–50M) and Maltego (~$17M) — are the *least* profitable: Censys loses tens of millions by
   design, Maltego is a roughly break-even PE growth play. The *most* profitable are tiny: Shodan
   (~10 staff), HIBP (~1–3), Hunter (~34). **In OSINT, lean + bootstrapped + a data/infra moat beats
   big + funded.**

2. **The real profit pool is small and concentrated.** Summing the *profitable* operators gives a
   combined annual profit of very roughly **$10–18M — and Shodan alone is ~half of it.** This is not
   a fat industry; it is a handful of lean cash generators sitting beside several break-even or
   loss-making scale-ups. The "value" headlines (Maltego's $100M raise, Censys's $143M, the $65M
   SecurityTrails and $2.65B Mastercard/Recorded Future deals) price **data and growth**, not current
   earnings.

3. **Margin tracks the business model precisely.** *Data/infra-moat owners* (Shodan, HIBP, DeHashed,
   IntelX) keep 40–70%+ because their marginal cost per query is ~zero. *Aggregators* (Epieos, OSINT
   Industries, UserSearch) are margin-thin because **they pay upstream vendors per lookup**.
   *Orchestration/ASM scale-ups* (Maltego, Censys) spend their revenue on headcount and growth. The
   profit ladder is the same data-vs-tooling axis the gap analysis found.

---

## 4. What this means for HSE

HSE earns **$0** — it is open-source and captures none of this pool. The useful question is *whose
profit it pressures*:

- **It erodes the thin-margin tiers, which barely have profit to take.** HSE's free orchestration and
  username/email/breach-*presence* fan-out most directly substitutes for **Maltego** (≈ break-even),
  **OSINT Industries** (≈ break-even), **Epieos** (~$0.2–0.8M), and **UserSearch** (~$0.1–0.6M).
  Every one of these is a *low- or negative-profit* layer — so HSE compresses an **already-thin
  margin**, it does not knock over a cash cow.
- **It *feeds* the high-profit data-moat tiers.** Shodan, HIBP, DeHashed, and IntelX — the only
  serious profit generators — are exactly the services HSE **drives traffic to** via BYO-key modules
  (`shodan`, `hibp`, `dehashed`, `intelx`, `oathnet_pro`). HSE is a *demand channel* for their paid
  data, not a competitor to it. A user who runs HSE and hits a data moat becomes a paying API
  customer of precisely the profitable players.
- **Net effect:** HSE's existence is roughly *profit-neutral-to-positive* for the cash generators and
  *margin-compressing* for the break-even orchestration/aggregator layer — which mirrors the value
  analysis exactly: it zeroes the platform/aggregator markup (where there's little profit anyway) and
  channels spend to the raw-data owners (where the real profit is, and which HSE can't replicate).

---

## Sources

- Shodan — <https://www.owler.com/company/shodan>, <https://craft.co/shodan>, <https://www.crunchbase.com/organization/shodan>
- Hunter.io — <https://getlatka.com/companies/hunter>, <https://www.konaequity.com/company/hunterio-4393785091/>
- Maltego — <https://getlatka.com/companies/maltego.com>, <https://www.maltego.com/blog/maltego-secures-100m-to-accelerate-growth-of-its-intelligence-platform-to-combat-cybercrime-and-misinformation/>, <https://www.northdata.com/Maltego+Technologies+GmbH,+M%C3%BCnchen/HRB+236523>
- Have I Been Pwned — <https://haveibeenpwned.com/About>, <https://www.troyhunt.com/a-decade-of-have-i-been-pwned/>
- DeHashed — <https://www.konaequity.com/company/dehashed-4862641733/>, <https://www.cbinsights.com/company/dehashed>
- Censys — <https://www.prnewswire.com/news-releases/censys-secures-75m-in-new-funding-301965193.html>, <https://techcrunch.com/2023/10/24/censys-lands-new-cash-to-grow-its-threat-detecting-cybersecurity-service/>, <https://tracxn.com/d/companies/censys/__3GBTZqJCaQp-ZndBecQ520W1m3sHRu0I1EvfHliOlkA>
- Intelligence X — <https://intelx.io/about>, <https://www.zoominfo.com/c/intelligence-x/470382817>, <https://parsers.vc/startup/intelx.io/>
- Epieos — <https://epieos.com/aboutus>, <https://www.crunchbase.com/organization/epieos>
- OSINT Industries — <https://find-and-update.company-information.service.gov.uk/company/14974274>, <https://tracxn.com/d/companies/osint/__95NYop9MyRMgXbaxzWxqfWuttWinvuDwVt00UORYe9E>
- SecurityTrails / Recorded Future — <https://www.securityweek.com/recorded-future-acquires-securitytrails-65m-deal/>, <https://www.prnewswire.com/news-releases/recorded-future-acquires-securitytrails-301453543.html>
- WiGLE — <https://en.wikipedia.org/wiki/WiGLE>, <https://www.zoominfo.com/c/wigle-net/356945277>
- UserSearch — <https://www.similarweb.com/website/usersearch.org/>

*All revenue figures are third-party estimates that frequently disagree; all profit figures are this
document's own modelling from the stated assumptions and should be read as illustrative ranges, not
financial statements. Verify against primary disclosures before relying on any number.*
