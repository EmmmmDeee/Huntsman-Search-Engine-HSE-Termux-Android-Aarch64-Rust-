# Investigation — synthetic seed "Jordan Leigh Meyer" (AU)

> **Synthetic-target notice.** Jordan Leigh Meyer is a fabricated seed used to
> exercise HSE end-to-end. This dossier is an analytical pass over the
> committed scan corpus `scan_jlm_50modules_depth2.json` (50 modules, depth 2,
> 480 entities, 281 correlations, status `complete`). It was produced offline
> by re-hydrating the export into HSE's own types and running the live engine
> via `cargo run --example investigate`. No live collection was performed.

## 1. Bottom line up front (BLUF)

- **Identity anchor — HIGH.** The seed resolves to a tight, mutually
  corroborating handle cluster, not a single string. The strongest real
  identity signal is the person **Jordan Leigh Meyer** (`Ceff 1.00`, ×28
  corroboration) plus the handle family `jordanleigh.meyer`,
  `jordanleigh.meyer.3`, `jordanleighb`, `jordanmeyer`, `meyer`.
- **Geolocation — HIGH for Australia, narrowed to South-East QLD.** Geospatial
  evidence converges on **Brisbane, Queensland** (`-27.4698,153.0251`,
  `Ceff 0.95`; address `Brisbane, Queensland` `Ceff 1.00`), with **Sydney, NSW**
  as a strong secondary (`-33.8688,151.2093`, `Ceff 0.90`). Adelaide is weak.
- **Primary email lead — MEDIUM/HIGH.** `iamjordi.com@gmail.com` —
  breach-present and tagged `password-at-risk`. The single best pivot for
  follow-on collection.
- **Noise is heavy and partly adversarial.** A large fraction of high-`Ceff`
  entities are decoys, co-tenant breach identities, or feed poisoning (see §5).
  Triage before action.

## 2. Identity core

| Tier | Entity | Kind | Ceff | Corrob. | Read |
|------|--------|------|-----:|--------:|------|
| Anchor | `Jordan Leigh Meyer` | person | 1.00 | 28 | Seed, fully corroborated |
| Anchor | `jordanleigh.meyer.3` | username | 1.00 | 22 | Multi-platform, social-probed |
| Anchor | `jordanleigh.meyer` | username | 1.00 | 16 | breach + oathnet-enriched |
| Strong | `jordanleighb` / `jordanmeyer` / `meyer` | username | 1.00 | 13–21 | Handle family |
| Lead | `iamjordi.com@gmail.com` | email | 1.00 | 8 | **breach, password-at-risk** |

**Pivot recommendation.** Run a fresh username scan on `jordanleigh.meyer.3`
and `jordanleighb` and an email scan on `iamjordi.com@gmail.com`. These three
maximise unlock potential while staying inside the anchored cluster.

## 3. Geospatial assessment

| Coordinate | Ceff | Resolves to | Verdict |
|------------|-----:|-------------|---------|
| `-27.4698,153.0251` | 0.95 | **Brisbane, QLD** | Primary — accept |
| `-33.8688,151.2093` | 0.90 | **Sydney, NSW** | Secondary — accept |
| `-34.9285,138.6007` | 0.37 | Adelaide, SA | Weak — hold |
| `38.8339,-104.8214` | 0.45 | Colorado Springs, US | **Decoy / recycled — reject** |

Address evidence agrees: `Brisbane, Queensland` (`Ceff 1.00`) and
`Sydney, Australia` (`0.86`) dominate; US addresses (Colorado, Virginia,
California) are low-confidence recycled artefacts. **Assessed home region:
South-East Queensland (Brisbane), with Sydney activity.** Consistent with the
"in Australia" brief.

## 4. Infrastructure

308 domains / 88 URLs / 20 IPs. The high-`Ceff` IP set is dominated by
Cloudflare (`2606:4700::/…`) and Meta (`2a03:2880:…:face:b00c:…`) ranges —
i.e. the CDNs behind scraped social/platform pages, **not** subject-owned
infrastructure. No subject-attributable hosting was isolated; treat
infrastructure here as context, not attribution.

## 5. Signal-vs-noise triage (analyst caveats)

This corpus is deliberately salted; several "high-severity" findings are
**false positives** and must be down-weighted:

- **AU-015 threat-intel hits are feed poisoning.** The rule fired on
  `facebook.com`, `instagram.com`, `linkedin.com`, `tiktok.com`,
  `wikipedia.org` and `192.0.2.1`. `192.0.2.1` is `TEST-NET-1` (RFC 5737) and
  the rest are mainstream platforms — the synthetic `ip_reputation` stub is
  returning positives for common domains. **Reject all six** as subject risk
  indicators.
- **Co-tenant / collision identities.** Persons `chanprakaisi`, `mercaitis`,
  `steric`, `kiekel`, `amphayvanh` and usernames such as `ljharb`, `_maria`
  carry `Ceff 1.00` but arrive via breach/people-search co-tenancy and handle
  collisions (`ljharb` is a well-known unrelated developer). **Not the
  subject** — exclude from the identity cluster.
- **Service/role emails.** `security@facebookmail.com` (×106),
  `support@fb.com`, `dns@cloudflare.com` are scraped infrastructure contacts,
  not the subject's addresses.

The one **genuine** high-severity correlation is **AU-018** — four emails
co-located with five AU address/coordinate entities: a real
identity↔location linkage that reinforces the Brisbane/Sydney assessment.

## 6. Temporal / behavioural

`core::temporal::analyze` found **insufficient behavioural timestamps** in this
corpus (the scan predates the timestamp-emitting modules), so AU-033 timezone
inference did not fire. **Recommendation:** re-scan with `github_user`,
`hackernews`, and `crtsh`. The new `hackernews` module in particular harvests
per-item `created_at`, which would feed the diurnal histogram and let AU-033
test the Australia hypothesis independently (a genuine UTC+10 subject should
trough ~17:00–19:00 UTC).

## 7. Recommended next actions

1. Email pivot: `iamjordi.com@gmail.com` → breach/credential modules.
2. Username pivot: `jordanleigh.meyer.3`, `jordanleighb` → `hackernews`,
   `github_user`, `username_search` (also populates temporal signal).
3. Geo confirmation: geocode/refine around Brisbane SE-QLD; treat US coords as
   rejected decoys.
4. Suppress AU-015 platform/TEST-NET hits in reporting; carry AU-018 forward as
   the load-bearing identity-location link.

---
*Generated via `cargo run --example investigate -- scan_jlm_50modules_depth2.json "Jordan Leigh Meyer"`.*
