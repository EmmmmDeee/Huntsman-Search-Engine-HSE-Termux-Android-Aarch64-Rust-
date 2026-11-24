# HUNTSMAN — BREACH AND COMPROMISE INTELLIGENCE

**Status:** target-domain operating model and gap register. Existing Rust modules are named where present; proposed features are explicitly not claimed as implemented. Inspired by disciplined investigation and evidence handling, not an FBI affiliation or access to restricted law-enforcement systems.

## Purpose and supported scope

Find and explain **publicly reported breaches, account exposure, infostealer compromise, malicious infrastructure, phishing campaigns, disclosed ransomware incidents, and leaked secrets in operator-authorised repositories**. Preserve original evidence, incident-time boundaries, provider restrictions and independent failure outcomes. Huntsman remains pure Rust, rootless Android AArch64, local Web UI, shared guarded HTTP transport, and no runtime LLM.

No scraped credential-dump acquisition, leaked-password disclosure, live session tokens, unauthorised personal-account searches, private social-account collection, or attribution of a stolen identity to a real person without independent proof.

## Canonical module ownership

| Question | Existing Huntsman owner | Evidentiary scope |
|---|---|---|
| Is a **breach corpus** publicly reported? | `src/hibp/` (public catalogue) | Incident metadata, **not** member-account verification |
| Does an **authorised email** appear in public breaches? | `src/xposedornot.rs`; `src/hibp/` (keyed account) | Provider-specific account exposure statement; subject identity unproven |
| Has a **domain** had infostealer-associated exposure? | `src/hudsonrock.rs` (domain aggregate) | Employees/users/third parties counts; **not individual account identity** |
| Does an **authorised email** appear in infostealer metadata? | `src/hudsonrock.rs` (email) | Infection metadata only; no stolen passwords, session cookies or machines |
| Are licensed commercial breach datasets available? | `src/dehashed.rs`, `src/stolen_tax.rs`, `src/oathnet.rs`, `src/seeknow_collector.rs` | Key/entitlement gated; no operator key means no request |
| Are infrastructure indicators malicious? | `src/threatfox.rs`, `src/urlhaus.rs`, `src/phishstats.rs`, `src/virustotal.rs`, `src/otx.rs` | Provider intelligence **assessment**, not direct proof of incident cause |
| What is the ordered exposure workflow? | `src/breach_hybrid.rs` | Free-then-keyed planning, no automatic paid escalation |
| How are results validated and compared? | `src/source_outcome.rs`, `src/exposure.rs`, evidence graph | Distinct successes, clean zeros, errors, missing keys, conflicting claims |

Additional public incident source families to assess (not yet verified as in-tree adapters): official national breach notifications and privacy regulators, public ransomware disclosure-monitoring feeds, and secret-scanning alerts for **operator-controlled** repositories. A ransomware victim listing is an allegation until independently corroborated; do not treat it as a verified breach or person-location signal.

## P0: Fail-closed negative-result contract

**A clean zero requires a complete, contract-valid response from the expected endpoint.** These conditions are **not** a clean zero:

- HTTP 200 with an explicit provider error, partial results or unknown schema.
- HTTP 401/403/429/5xx, challenge pages, redirects or bounded-body truncation.
- A field saying `Error` or `error` beside an empty XposedOrNot breach list or zero Hudson Rock infection counts.
- A nonempty XposedOrNot breach group containing only unusable names.
- Provider outage or quota exhaustion; a different provider returning no matches does not erase a failed provider.

**Current branch repair**: `src/xposedornot.rs` and `src/hudsonrock.rs` reject contradictory error markers and malformed no-result envelopes, preserving the documented XposedOrNot `{"Error":"Not found","email":null}` response and Hudson Rock `{"stealers":[]}` response as valid zeros.

## P1: Source-semantic correlation

Use a typed `source_coverage` and `record_scope`, distinct from the source's claim state:

- `breach_catalog` — reported incident; no individual account conclusion.
- `email_exposure` — provider asserts an account identifier appeared; not proof the operator controls it.
- `domain_infostealer_aggregate` — an organisation-domain statistic, not a named-person match.
- `email_infostealer_metadata` — credential-theft exposure; no secret material retained.
- `ransomware_claim` — disclosure by a third party, pending independent incident confirmation.
- `repo_secret_alert` — a scanner alert in a repository the operator can access, not proof a key is still live.
- `ioc_reputation` — attributed vendor/community assessment, not proof of compromise.

Keep `source_id`, source URL/record ID, `queried_at`, `published_at`, `event_at`, `last_verified_at`, data scope, schema version, source outcome, source independent lineage, evidence hash, match basis, and any coverage limit. Maintain status `candidate/observed/corroborated/verified` plus `rejected/conflicted/stale`. Treat counts as counts, never as causality.

A data broker, media article and search engine repeating one underlying leak are **one underlying event**, not three independent confirmations.

## P2: External APIs to validate before implementation

| Provider / feed | Path / capability | Access and critical restriction |
|---|---|---|
| HIBP | `https://haveibeenpwned.com/api/v3` | Public catalogue; account lookups use authorisation and paid key; display attribution |
| XposedOrNot | `https://api.xposedornot.com/v1/check-email/{email}` | Free basic email check; respect rate limits and untrusted error bodies |
| Hudson Rock Cavalier | `https://docs.hudsonrock.com/` | Public/entitled infostealer intelligence; store safe metadata only |
| GitHub Secret Scanning REST | `/repos/{owner}/{repo}/secret-scanning/alerts` | Requires repository permissions; redact secret values; never scan arbitrary private repos |
| Ransomware.live and similar open datasets | Public claimed-victim information | Attribution and freshness checks; listings do not establish independently verified intrusion |
| Official breach notices | National authorities, regulators, court records | Distinguish aggregate statistics from named incident notices |
| ThreatFox, URLhaus, VirusTotal, OTX | Malware/network indicators | Retain feed timestamp, confidence and source attribution |

Do not claim API connectivity, purchased entitlements or live coverage without testing the connector. Distinguish configuration, authentication, provider reachability and validated evidence.

## P3: Incident-centric local UI

The existing localhost Web UI should present **six distinct panels**, not mix them into a person dossier:

1. **Breach catalogues** — incident names, dates, affected data categories, sources.
2. **Authorised identifier exposure** — per-provider findings, evidence scope and zero/error states.
3. **Infostealer risk** — aggregate versus identifier-scoped compromise clearly separated.
4. **Ransomware disclosures** — attributed claims, confirmation status, reporting date.
5. **Malware and phishing indicators** — IoCs, reputational assessments and temporal overlap.
6. **Case evidence** — claims, contradictions, timestamps, provenance, exclusions and export.

Use the existing evidence storage and web routes. Do not create a second graph, background credential collector or unsafe third-party UI scripts.

## Deterministic acceptance

```sh
cargo fmt --all -- --check
cargo test --locked xposedornot::tests
cargo test --locked hudsonrock::tests
cargo test --workspace --locked
cargo gate full
huntsman-recon check
```

Add mock transports for 200 error envelopes, malformed body, inconsistent zero, 404, 429, expired auth and body truncation. Verify that no passwords, session cookies, raw URLs containing secrets or account-owner inference are persisted. Run Android-native tests before merging. Do not promote synthetic fixture success into a live-provider coverage claim.

**Priority order:** false-negative elimination > credential/data integrity > source attribution > source-family expansion > UI presentation > measured performance improvements.
