# HSE — Roadmap to Completion & Optimal File Structure

> **This is the single, living source of truth for HSE's optimal file structure,
> the codependencies and pivot pathways between its parts, and the route to a
> permanently superior production state.** It is checked in, survives fresh
> checkout, and is re-read first. It is **maintained continuously**: every
> iteration re-assesses the structure against what is optimal, realigns, and
> records the change here before proceeding. Do not let it drift from reality —
> a claim here that the code does not honour is a defect in this document.
>
> Governing companions (authoritative, not duplicated here): [`CLAUDE.md`](../CLAUDE.md)
> (project memory + jurisdiction), [`RULE.md`](../RULE.md) &
> [`OPERATIONAL_CONSTITUTION.md`](OPERATIONAL_CONSTITUTION.md) (doctrine),
> [`REQUIREMENTS_LEDGER.md`](REQUIREMENTS_LEDGER.md) (the correctness backlog and
> its falsification transcripts), [`GLOSSARY.md`](GLOSSARY.md) (one spelling per
> concept). The per-module catalogue is the **registry itself**
> (`src/modules/mod.rs`) plus each module's `ProviderDescriptor`
> (`src/core/module/provider.rs`) — machine-readable and canonical, so this
> document points at it rather than copying it.

Last realigned: **2026-09-18**.

---

## 1. Mission & success criteria

Build the OSINT/GEOINT/NETINT engine that **supersedes the best of SpiderFoot
and Maltego** — deeper correlation, honest evidence, more reachable capability —
while staying **lightweight, minimalist in its graph, no-root, and entirely
Rust**, at a level of craft worthy of the Rust ecosystem's best (ripgrep /
`burntsushi` discipline: small dependency surface, exact algorithms, relentless
tests, zero fabricated behaviour).

A feature is "done" only when it is **source-authoritative, transitively wired,
regression-locked, reproducible, integrated, remotely verified, and
operationally exercised** — the Permanent-Upgrade Law. The prime directive is
**evidence-gated correctness**: `OBSERVATION > ARGUMENT`, `TEST PASS ≠
PRODUCTION PROOF`, and *no demonstrated capability may silently regress*. A false
finding about a real person (a fabricated sanction, a mis-attributed
credential, a forged "proof of control") is treated as worse than missing
coverage.

**Superseding SpiderFoot/Maltego concretely means:**
- One typed outcome for every provider state (found / clean-negative /
  not-applicable / unavailable / rate-limited / blocked / failed) — never the
  "silence == negative" ambiguity those tools ship with.
- A confidence- and corroboration-graded entity graph with a real correlator
  (the `AU-*` rules), not a flat node/edge canvas.
- Keyless-first coverage: the widest free provider surface reachable with no
  entitlement, with paid/manual providers surfaced as an operator query pack.
- Minimalist graph: the pivot chains matter, not the visual sprawl.

---

## 2. Optimal file structure — layered by dependency order

The build order below is also the **read order** for understanding the system.
Lower layers never depend on higher ones; this acyclicity is the structural
invariant this document exists to protect.

### Layer 0 — `hse-core/` (dependency-free kernel, wasm-shareable)
The pure type kernel. **No `tokio`/`rusqlite`/`reqwest`** — deliberately, so the
same code compiles into the `wasm32` browser UI. `#![forbid(unsafe_code)]`.
- `hse-core/src/lib.rs` — `Entity`, `EntityKind`, `Evidence`, `Classification`,
  confidence clamping, gamma-decay, `demote_to_candidate` quarantine, `scan_id`,
  `unix_now`. The single definition of what a finding *is*.
- `hse-core/src/tags.rs` — the canonical tag vocabulary (`SANCTIONED`,
  `SANCTIONS_LINKED`, `PEP`, `DEBARRED`, `THREAT_INTEL`, `VULNERABLE`,
  `SOCIAL_PROFILE`, `CANDIDATE`, …). Tags are the contract between producers
  (modules) and consumers (correlator rules); adding one is an API change.
- `hse-core/src/coords{,.rs}` — coordinate/geo primitives and plausibility
  bands (`is_valid_coords`, `is_plausible_provider_coord`).

**Codependency:** re-exported by the main crate as `crate::core::entity` /
`crate::core::tags` so existing call sites are unchanged. Everything above
depends on it; it depends on nothing in-repo.

### Layer 1 — `src/util/` (213 files, stateless shared mechanism)
The reusable primitives every module leans on. Key sub-areas:
- `util/http/` — the shared client, `send_tagged`, `read_body_capped_or_fail`
  (fail-closed body reads), `http_status_error` (typed 404/429/BotChallenge/…),
  `json_body_error` (credential-redacting), the DNS-level `SsrfResolver`, url
  encoders. **The single outbound-request authority.**
- `util/preflight/` — the SSRF predicate family (`is_private_ip`,
  `is_private_ip_host`, `url_host_is_private`, `email_host_is_private`,
  `is_local_domain`, `unbracket_host`). Consumed by the engine's dispatch gate.
- `util/key_pool/` — the API-key pool: `KeyEntry`, `is_harvested()`
  (`discovered_by.is_some()`), `next_key_excluding` (the auth chokepoint that
  keeps harvested/breach-sourced credentials out of HSE's own requests),
  `add_and_validate` (provenance-stamped).
- `util/html`, `util/probe`, `util/target_match`, `util/canonical`,
  `util/address_au`, `util/domains`, `util/domain_vn`, `util/geo`,
  `util/extract`, `util/gravatar` — challenge-page detection, presence
  controls, whole-word/boundary matching, canonicalisers (email subaddressing,
  AU/VN address & phone), boundary-aware relevance, geo validation, identity
  splitting.

**Canonicalisation priority lives here.** One canonical form per concept, one
authority per canonicaliser — `to_e164_au`, `canonical_email_mailbox`,
`TargetMatch`, `split_identity_secret` are each single-sourced and shared, never
re-implemented per module.

### Layer 2 — `src/core/` (203 files, the engine and its contracts)
- `core/module/` — the **`Module` trait** (the capability contract: `accepts`,
  `process`, `produces`, `category`, `priority`, `attack_techniques`,
  `max_timeout_ms`) and `provider.rs` (`ProviderDescriptor`: cost/economics,
  keyed-ness, capability descriptor read identically by engine, CLI, API, web).
- `core/confidence.rs` — the confidence tier ladder (`ZERO`…`CERTAIN`) and the
  expansion floor / derivation constants. Every entity's confidence is one of
  these named tiers, never a magic float.
- `core/scan/` — `Target`, `TargetKind`, `ScanOptions`
  (`min_expand_confidence`, depth), the seed contract.
- `core/engine/` — dispatch (`module_skip_reason` — the universal pre-dispatch
  SSRF + applicability gate), expansion (`c_effective` ≥ floor → new targets),
  ranking, history (cross-scan candidacy), the durable event log. **The heart.**
- `core/correlator/` — the `AU-*` rule registry (identity/account/key, org,
  breach, geo, infra, …) and `Severity` (Low/Medium/High/Critical). This is
  HSE's edge over a flat graph: findings derived across entities, each graded
  and framed as "a signal, not a determination".
- `core/resolve/`, `core/validation/`, `core/intelligence/`, `core/coverage/`,
  `core/roi/`, `core/entity_extractor`, `core/diff/` — entity resolution &
  grouping, admission validation (homograph/placeholder gates), provider-outcome
  ledger, coverage verdicts, ROI/budget expansion levers, free-text extraction,
  scan diffing.

**Codependency:** `core` consumes `util` and `hse-core`; `modules` and the app
layer consume `core`. The correlator consumes only entities + tags — so a
module changes what the correlator can conclude *only* through the tags/evidence
it emits (the seam REQ-PGP-001 / REQ-OPENSANCTIONS-001 both turned on).

### Layer 3 — `src/modules/` (516 files, 193 provider modules)
One directory per provider, each an implementation of `Module`. Registered in
`src/modules/mod.rs` (the canonical list). Categories: People, Network, Geo,
Breach/Stealer, Threat-Intel, Registry (AU/VN gov), Crypto, Archive, Presence,
Search. Each module: `accepts` only the kinds its provider indexes; fails
closed on non-2xx; emits entities with graded confidence + contract-checked
tags; ships a falsified unit-test suite pinning found/clean/error paths.

**Synergy is the point.** A module's value is the *pivots it opens*: `pgp`
email→name→alternate-address feeds the identity correlator; `opensanctions`
name→designation feeds AU-114; breach modules feed the multi-source
corroboration rule (AU-001); geo providers feed the location-fusion correlator.
The optimal registry order groups modules by the entity kinds they consume and
produce, so a reader sees the chains. New modules earn their place by the
correlations they unlock, not by count.

### Layer 4 — application surfaces (consume the engine, never each other's guts)
- `src/app/` (45) — orchestration: import (`combolist`, `sql_dump`, `json`
  stealer-log, DeHashed CSV), batch/query-pack generation, export/redaction.
- `src/cli/` (39) — the `hse` command surface (`scan`, `query`, `dorkus`, `sf`
  SpiderFoot-compat, `batch`, `query-pack`, `keys`, `import`, `radar`), one
  spelling per concept (locked against `GLOSSARY.md`).
- `src/api/` (24) — the HTTP surface: scan lifecycle, coverage endpoint,
  operator-only batch download, auth middleware, redaction boundary.
- `src/web/` — the console (server-rendered + `wasm-ui/` browser bundle);
  Engines capability panel, Provider Coverage panel, minimalist graph view.
- `src/storage/` (9) — SQLite (`rusqlite`) persistence: `Store`,
  `integrity_check`, checkpointing (a resumed scan knows what it is owed).
- `src/bin/` (14), `src/selftest/` (3), `src/audit/` (5) — auxiliary binaries,
  in-binary self-test, and the drift/canary audit harness (`CANARY_PROBES`,
  live-drift remote verification).

### Layer 5 — verification & release scaffolding
- `tests/` (integration: `smoke.rs` engine-boundary locks, `api.rs`,
  `install_invariants.rs`), `benches/`, `fuzz/`, `proptest-regressions/`.
- `build.rs`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`,
  `dep-cooldown.toml` — reproducible build & supply-chain policy.
- `install.sh`, `Dockerfile`, `docker-entrypoint.sh`, `railway.json`,
  `scripts/reconcile.sh` — install / deploy / device-reconcile lifecycle.
- `wasm-ui/` — the browser UI crate; kept in lockstep with served exports.

---

## 3. The pivot graph (why the order matters)

```
seed Target ─▶ engine::dispatch (skip_reason: SSRF gate, applicability)
            ─▶ Module::process ──▶ Entities (kind, confidence, tags, evidence)
            ─▶ engine::expansion (c_effective ≥ min_expand) ──▶ new Targets ──┐
            ─▶ core::resolve (group/dedup) ──▶ correlator (AU-* rules) ──▶ Findings (graded)
            ─▶ storage (durable events + checkpoints) ──▶ api/cli/web (redacted) / export
                                                                                └─(loops)
```
Every arrow is a contract. The high-leverage seams — the ones worth the most
future-proofing — are: the **dispatch gate** (one place to refuse a target),
the **tag/evidence emission** (the only channel from module to correlator), the
**expansion floor** (what becomes a new pivot), and the **redaction boundary**
(what leaves the tool).

---

## 4. Roadmap to completion — four concurrent tracks

Progress is ranked by **PERMANENT RETURN = (functional value × production
reachability × defect elimination × dependency unlock × future leverage ×
confidence) ÷ (complexity × regression risk × lifecycle cost)**. The active
ranked queue of concrete items lives in the session task list and the
`REQUIREMENTS_LEDGER.md`; the *tracks* below are stable.

**T1 — Correctness (root-cause elimination).** Drive the fabrication/false-clean
backlog to zero. Each fix is test-first (lock observed failing on the baseline),
falsified (revert reproduces), and recorded in `REQUIREMENTS_LEDGER.md`. Shipped
this wave: the SSRF gate closures (REQ-SSRF-001/002), stolen-credential pool
hygiene (REQ-KEYPOOL-001), the PGP forged-UID correlation (REQ-PGP-001), the
sanctions-linked mis-designation (REQ-OPENSANCTIONS-001), the cert_intel
dead-probe fabricated-certificate finding (REQ-CERTINTEL-001), the au_geo
ArcGIS-error-envelope guard that never failed closed (REQ-AUGEO-001), the intelx
search-start that read an auth/quota failure as a clean "no records"
(REQ-INTELX-002), the chain_intel BTC/LTC/DOGE lookup that minted a confident
"dormant wallet" verdict from a throttled/blocked 200 (REQ-CHAININTEL-001), the
export renderers that leaked the operator's own configured API keys when a
provider echoed them back into entity evidence — the secret redactor was wired
into the raw archive but not the five human-facing/API export paths
(REQ-EXPORT-001), the `TargetMatch` subject-attribution primitive that was
order/position-blind on IP-address targets — a different host sharing the
octet digits was minted as the subject across `dehashed`/`oathnet_pro`/`see_know`,
fixed by canonical `IpAddr` equality (REQ-TARGETMATCH-001), plus the
abuseipdb/phone_au/email-canon fabrication fixes. REQ-AUGEO-001,
REQ-INTELX-002 and REQ-CHAININTEL-001 are the same recurring family — an
all-`default` `#[serde(default)]` response struct decoding an unexpected 200 as a
clean (or, for chain_intel, affirmative "dormant") result; three fixed so far,
and the still-open siblings (REQ-ZOOMEYE-001, REQ-LEAKCHECK-001,
REQ-HUDSONROCK-001) have a proven fix pattern (require a field the real shape
always carries; make the catch-all fail closed). REQ-EXPORT-001 is a distinct
class — a correct sanitizer wired into one serialized copy (the raw archive) but
not the parallel renderings of the same field; its rule is to audit a redactor's
call sites against *all* emitters of the value it guards. REQ-TARGETMATCH-001 is
a canonicalisation debt of a third kind — a structured, ordered identifier (an IP)
compared by an order-blind token set instead of its own canonical type; its rule
is that an identifier with internal order (IP, coordinate pair, version, split
hash) is compared by its canonical type, never tokenised into a bag. Open high-stakes items remain
queued (namesake fabrications, ambiguity-discarded geo, truncation-silent
providers, key-header replay).

**T2 — Universal canonicalisation (priority).** One canonical form and one
authority per concept, everywhere. Every remaining "same bug, sibling module"
finding (a validator ported to one place but not its twin; a weaker
`is_valid_coords` where `is_plausible_provider_coord` is meant) is a
canonicalisation debt: consolidate on the single authority and redirect callers.
Extends to spellings (`GLOSSARY.md`), tags (`hse-core::tags`), and outcome
types (one typed `SkipClass`/error per provider state).

**T3 — Cleanup & consolidation (standing initiative).** See §5. Remove stale
point-in-time artifacts, fold duplicate docs, delete dead code only after
verified migration.

**T4 — Capability (supersede SpiderFoot/Maltego).** Widen keyless coverage, keep
the correlator graph the differentiator, and make every implemented capability
*reachable and exercised* (the Engines/Coverage panels, live-drift canaries).
Nothing dormant: a rule with no producer, a leg that never runs, a declared
error never constructed — each is either wired or removed.

---

## 5. Cleanup & consolidation register (T3 — living)

The tracked tree carries **no** editor/backup/patch/output junk (verified via
`git ls-files`), and build artifacts (`target/`) are correctly gitignored — so
there is no unsafe-to-keep junk to delete. The `docs/` directory accreted
point-in-time autonomous-run reports; their disposition, **after verification**
(2026-09-18), is:

| Path | Verified status | Action |
|---|---|---|
| `docs/*_2026-08-27{,_czrqs1}.md` (AUTONOMOUS_DECISIONS, BENCHMARK_RESULTS, CREDENTIAL_AUDIT, DEPENDENCY_GRAPH, EXCEPTION_LEDGER, FINAL_REPORT, ISSUE_LEDGER, RUST_MIGRATION_AUDIT) | **Referenced** by README, CHANGELOG, PROBLEM_TREE, REQUIREMENTS_LEDGER, gap_register, `.gitleaks.toml`, `.agent/state.json`, and some module source | **Retain.** Not junk — a referenced historical audit trail. Do not delete. |
| `CREDENTIAL_AUDIT_2026-08-27.md` vs `…_czrqs1.md`; `RUST_MIGRATION_AUDIT_2026-08-27.md` vs `…_czrqs1.md` | **Not** identical (182 / 606 differing lines) — two distinct reports, both referenced | **Retain both.** The "duplicate pair" hypothesis was falsified; merging would lose content and break references. |
| `docs/OATHNET_API_GUIDE.txt` | `.txt` amid `.md`; referenced by the `oathnet` provider source | Normalise to `.md` only as part of a reference-updating pass, not a bare rename. |

**Outcome of the reassessment:** there is no safe, high-value doc deletion or
consolidation available right now — the cleanup dividend is small and the
reference-breakage risk real. Effort is therefore directed to the correctness
and canonicalisation tracks (T1/T2), where permanent value is created, and this
register is revisited only if a deliberate doc-index refactor is undertaken with
its references updated atomically.

**Rule for this register:** a doc is removed or moved only after confirming
every reference (build, code, governing docs, tooling config) is updated in the
same change — deletion/renaming is outward-facing and irreversible, so it is
verified first and done in a clearly-scoped commit the user can review.

---

## 6. The maintenance process (how this document stays true)

On **each** iteration, before proceeding:
1. **Sync & re-baseline** against the latest `origin/main`.
2. **Re-map authority** for the target area (source of truth, callers,
   generated outputs, tests).
3. **Re-rank** by PERMANENT RETURN — the optimal next step may have changed.
4. **Execute** test-first, falsify, gate (fmt / clippy `-D warnings` / full
   suite), integrate, verify remotely.
5. **Realign this document**: if the structure, a codependency, a pivot
   pathway, or the cleanup register changed, update §2–§5 here in the same
   change. Update the "Last realigned" date.

A change that improves a pivot pathway or removes a duplicate authority updates
§3 and §2; a shipped fix updates the `REQUIREMENTS_LEDGER.md` (detail) and, if
it changed a contract, §2 here (structure). This file holds the *map*; the
ledger holds the *transcripts*; the registry holds the *catalogue*.
