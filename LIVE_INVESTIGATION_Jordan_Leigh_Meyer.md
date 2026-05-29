# Live investigation — "Jordan Leigh Meyer" (AU premise)

> **Live run, synthetic seed.** Executed against the public internet with
> `hse scan --kind name --value "Jordan Leigh Meyer" --free-only --depth 1`
> (free/passive sources only, capped at 250 entities / 150 s). Result:
> **162 entities, 28 modules run (6 errored), 164 s, status `complete`.**
> Raw export held off-repo (`/tmp/jlm_live.json`) as it contains live-scraped
> public-web data; this file is the analytical product. Findings reflect what
> live OSINT actually returned — which differs materially from the previously
> committed *synthetic* corpus.

## 1. BLUF

- **Identity — MEDIUM.** The name resolves to a person entity
  `Jordan Leigh Meyer` (`Ceff 0.91`, search + social-probe) and a cluster of
  plausible social handles. This is a real, if thin, footprint.
- **Australia premise — NOT CORROBORATED (this is the headline).** Live public
  data produced **no** Australian geolocation. The only geocoded location is
  **Colorado Springs, US** (`38.8339,-104.8214`, `country:US`, `Ceff 0.37`).
  Australia surfaced only as incidental web artefacts (a `goldcoastbulletin.
  com.au` true-crime URL, a stray `com.au` token) — context, not location.
- **All HIGH-severity correlations are scanner-environment noise, not subject
  intel.** They trace to `192.0.2.1` — RFC 5737 `TEST-NET-1` — picked up by
  `local_net` (ARP) from the *scanning host*, then mis-enriched. Reject in full.
- **Temporal/behavioural — did not engage.** No confirmed account with an
  activity history, so no behavioural timestamps; AU-033 did not fire.

## 2. Identity core (live)

| Entity | Kind | Ceff | Source | Read |
|--------|------|-----:|--------|------|
| `Jordan Leigh Meyer` | person | 0.91 | search_engines + social_probe | Confirmed footprint |
| `jordanleigh.meyer.3` | username | 0.55 | search_engines | Strongest handle |
| `jordan_leigh_meyer` | username | 0.55 | search_engines | Handle |
| `jordanmeyermusic` / `jordancmeyer` / `jordan.meyer8` | username | 0.55 | search_engines | Plausible variants |
| `jmeyer` / `jordan.meyer` / `meyer.jordan` | username | 0.35 | name_to_username | *Derived* (combinatorial, unconfirmed) |

`name_to_username` handles are **generated**, not observed — do not treat as
discovered accounts until a platform module confirms them. Family-association
candidates `Genres Meyer` / `Lee Meyer` (`Ceff 0.45`) are low-confidence
search co-occurrence only.

## 3. Geospatial assessment (live)

| Signal | Value | Ceff | Verdict |
|--------|-------|-----:|---------|
| Coordinates | `38.8339,-104.8214` (Colorado Springs, US) | 0.37 | Only concrete geo — **weak, US not AU** |
| Address | `Colorado Springs, Colorado` | 0.45 | Same; US |
| Web artefact | `goldcoastbulletin.com.au/truecrimeaust` | — | AU-adjacent **context**, not a location fix; possible name collision with crime reporting |

**Conclusion: the Australia premise is unsupported by live public data.** Where
the earlier *synthetic* corpus had Brisbane/Sydney injected (`Ceff` up to 1.00),
the live web does not reproduce them. The faint real-world lean is US, not AU.
This divergence is itself the most useful result: it cleanly separates the
seeded narrative from ground truth.

## 4. Correlations — triage

| Rule | Sev | ×  | Reality |
|------|-----|---:|---------|
| AU-031 malicious adjacency | medium | 50 | **Noise.** All are `domain derived_from 192.0.2.1` — infra-tooling hosts (`alibabacloud.com`, `dnschecker.org`, `ip2whois.com`) pivoted off the scanner's local IP. |
| AU-015 threat-intel hit | high | 1 | **False positive.** `192.0.2.1` = TEST-NET-1, from local ARP. |
| AU-003 / AU-010 | medium | 1+1 | Same `192.0.2.1` corroboration/consensus — scanner artefact. |
| AU-014 geo cluster | medium | 1 | The Colorado Springs coordinate. Only genuinely subject-relevant correlation. |
| AU-013 local-network | low | 1 | Confirms `192.0.2.1` is local (`local-arp`) — the tell that §4's hits are environmental. |

Root cause of the noise: `local_net` legitimately enumerates the host's own
interfaces/ARP; in this sandbox that surfaced `02:fc:…` MACs and the
`192.0.2.1` gateway, which then flowed through the infra/threat modules. On a
real device this is the operator's own LAN — never the target's.

## 5. Module performance

28 modules ran, 6 errored (transient upstream/HTTP), 0 timed out, in 164 s —
the TLS-trust-store fix held throughout (no `UnknownIssuer`). Yield was
dominated by `search_engines` (155 evidence rows; also the source of 108
mostly-irrelevant scraped domains — the bulk of the entity count is search
noise, not identity signal).

## 6. Assessment & next steps

1. **Do not assert Australia.** State the location as *unconfirmed*; the only
   concrete geo lead is US (Colorado Springs), itself weak. If an Australian
   tie is expected, it must come from a source the free name-scan didn't reach.
2. **Confirm handles before pivoting.** Run username scans on
   `jordanleigh.meyer.3` and `jordan_leigh_meyer` (→ `hackernews`,
   `github_user`, `username_search`) to convert candidates into confirmed
   accounts — and, as a by-product, populate behavioural timestamps so AU-033
   can test a timezone independently.
3. **Suppress the `192.0.2.1` cluster** in any report: it is the scanner's
   own network, and every HIGH finding hangs off it.
4. **Investigate the Gold Coast Bulletin true-crime URL** separately — likely a
   name collision, but it is the one concrete AU-adjacent artefact and should be
   either tied to or excluded from the subject.

---
*Run: `hse scan --kind name --value "Jordan Leigh Meyer" --free-only --depth 1
--max-wall-time 150 --max-entities 250`. Analysis via
`cargo run --example investigate`.*
