# Live investigation (ALL modules + APIs) — "Jordan Leigh Meyer"

> **Full-capability live run, synthetic seed.** `hse scan --kind name --value
> "Jordan Leigh Meyer" --depth 1` with **no `--free-only` filter** — all 86
> modules, real keys active (OathNet, HIBP, WiGLE, SeekNow). Result: **503
> entities, 14 correlations (1 critical, 2 high), 117 s, `complete`.** Raw
> export gitignored (contains live breach PII). This file is the analytical
> product; individual third-party PII is summarised in aggregate, never listed.

## 1. BLUF — turning on every API made attribution *worse*, not better

- The genuine subject signal is unchanged from the free run: one
  high-confidence anchor, **`Jordan Leigh Meyer`** (person, `Ceff 1.00`), plus
  a handful of search-discovered handles. Nothing more was actually confirmed.
- The keyed breach module (**OathNet**) answered the common-name query with a
  **bulk US financial-sector breach dump** — ~100+ unrelated identities
  (banking/credit-union staff) across `abrigo.com` and similar. HSE faithfully
  materialised these as **~341 low-confidence entities** (92 emails, 53 phones,
  53 addresses, 100+ persons), none tied to the subject (corroboration = 1,
  `Ceff` 0.25–0.70, single-source).
- That flood then **triggered false-positive correlations**: the **CRITICAL
  AU-002** ("92 emails + 17 usernames + 53 phones co-located") and **HIGH
  AU-018** are aggregating breach-dump PII that has nothing to do with Jordan
  Leigh Meyer. **Do not report them as subject findings.**
- **Australia: still NOT corroborated.** Multi-source geo is entirely US
  (Hawaii, Virginia, Alaska, Montana, Washington, Minnesota, …) + a Seattle
  coordinate. The lone `country:AU` tag traces to the same incidental Gold
  Coast Bulletin true-crime URL seen in the free run — context, not location.

## 2. What is actually attributable to the subject

| Entity | Kind | Ceff | Why it counts |
|--------|------|-----:|---------------|
| `Jordan Leigh Meyer` | person | 1.00 | Only cross-source anchor: `oathnet_pro` + `search_engines` (140+163 results / 14 queries) + `social_probe` (1 profile on PeekYou) |
| `jordanleigh.meyer.3`, `jordan_leigh_meyer`, `jordanmeyermusic`, `jordancmeyer` | username | 0.55 | Search-discovered handles (single-source — *candidates*, unconfirmed) |
| `name_to_username` variants (`jmeyer`, `jordan.meyer`, …) | username | 0.35 | Combinatorially *generated*, not observed |

The anchor's own OathNet evidence is the tell: its summary is *"100 breach
record(s) — abrigo.com, countries: US"* attached to a query string, with a
roster of ~100 names that are not the subject. The match is the **query**, not
the **person**.

## 3. The noise mechanism (analyst-grade)

OathNet free-text search is **high-recall / low-precision**: a common full name
pulls entire breach corpora whose records merely co-occur with the query
tokens. HSE's pipeline then:

1. promotes every breached email/phone/address/name to an entity;
2. `geo_normalize` geocodes the (US) addresses;
3. the correlator sees 92 emails + 53 phones + 52 locations in one scan and
   fires **AU-002 (CRITICAL)** and **AU-018 (HIGH)** — co-location rules that
   assume the entities belong to *one* subject.

The rules are working as designed; their **precondition is violated** by
low-precision recall. This is the classic common-name breach-search trap.

## 4. Correlation triage

| Rule | Sev | Verdict |
|------|-----|---------|
| AU-002 identity cluster | **critical** | **False positive** — aggregates unrelated breach-dump PII. |
| AU-018 email↔location | **high** | **False positive** — same dump. |
| AU-015 threat-intel | high | **False positive** — `192.0.2.1` (RFC 5737 TEST-NET) from the scanner's own ARP, as in the free run. |
| AU-030 / AU-014 geo convergence | medium | Real but **US**, not AU. |
| AU-003 / AU-010 / AU-013 | low/med | `192.0.2.1` scanner-environment artefacts. |

## 5. Comparison: free vs full-API

| | Free-only (prior) | All modules + APIs |
|--|--|--|
| Entities | 162 | 503 |
| Subject-attributable | anchor + handles | **same** anchor + handles |
| Added by keys | — | ~341 unrelated breach-dump entities |
| Geo on subject | weak US | weak US (no AU) |
| Critical correlations | 0 | 1 (false positive) |

**Net:** the extra APIs tripled the entity count and manufactured a CRITICAL
alert without adding a single attributable fact about the subject. More data ≠
more intelligence.

## 6. Assessment & recommendations

1. **Report the anchor only.** Subject = person `Jordan Leigh Meyer`; location
   **unconfirmed** (no Australia corroboration in two independent live runs;
   only weak US leads). State this plainly rather than inheriting the AU premise.
2. **Suppress the OathNet bulk dump.** Treat single-source, corroboration-1
   breach entities from a common-name query as recall noise; do not attribute
   the 92 emails / 53 phones / 53 addresses to the subject. (Platform follow-up:
   gate OathNet name-queries behind a precision filter or down-weight
   single-source breach entities so they can't alone satisfy AU-002/AU-018.)
3. **Confirm handles before pivoting.** Username scans on
   `jordanleigh.meyer.3` / `jordan_leigh_meyer` (→ hackernews / github_user /
   username_search) to convert candidates into confirmed accounts and seed
   AU-033 behavioural timestamps.
4. **Privacy.** The raw export contains real third-party breach PII unrelated
   to the target; it is gitignored and must not be redistributed.

---
*Run: `hse scan --kind name --value "Jordan Leigh Meyer" --depth 1
--max-wall-time 280 --max-entities 400` (all modules, keyed APIs active).*
