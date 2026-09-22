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

Last realigned: **2026-09-19**.

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
  encoders. **The single outbound-request authority.** The outage discipline
  lives here too: `breaker_gate` (refuse before dialling a tripped endpoint) and
  `record_breaker_outcome` (the typed `BreakerOutcome::{RateLimited, Failure,
  Success}` decision — a 429 opens on the server's own `Retry-After` window, a
  5xx accumulates, anything else clears). A module that dials by hand and
  re-implements either half is a defect, not a variation: that was exactly
  REQ-HTTP-005 (`util::wigle` kept three hand-rolled copies) and
  REQ-DOHRESOLVER-001 (the primary DNS transport had none).
- `util/circuit_breaker/` — per-endpoint outage state. `endpoint_of` is the
  **key authority**: host plus `port_or_known_default()`, so `https://h` and
  `https://h:443` cannot split into two breakers and two loopback servers cannot
  collide into one. The key's shape is a structural property, not a convention —
  sixteen hand-written cross-test resets existed only because it was wrong
  (REQ-BREAKER-001).
- `util/preflight/` — the SSRF predicate family (`is_private_ip`,
  `is_private_ip_host`, `url_host_is_private`, `email_host_is_private`,
  `is_local_domain`, `unbracket_host`). Consumed by the engine's dispatch gate.
- `util/key_pool/` — the API-key pool: `KeyEntry`, `is_harvested()`
  (`discovered_by.is_some()`), `next_key_excluding` (the auth chokepoint that
  keeps harvested/breach-sourced credentials out of HSE's own requests),
  `add_and_validate` (provenance-stamped).
- `util/namesake/` — whether one provider's own answer proves a name is held by
  more than one party, plus the ceiling and the marking rule for when it does
  (`AMBIGUOUS_CEILING`, `mark_ambiguous`). Keyed on `derive_uid`/`normalise`
  themselves, so it answers "will the engine fuse these rows?" exactly rather
  than by imitation. Consumed by `ahpra` (practitioners), `gleif_lei` and
  `opencorporates` (legal names, and officer names) and `wikidata` (item
  labels). Its shared-ness is demonstrated, not assumed: making
  `NameCollisions::of` keep every name breaks **thirteen controls across all
  four consumers** and none of the locks.

  Two distinct harms answer to the same question, which is why one authority is
  the right shape. In `gleif_lei` / `opencorporates` / `ahpra` a fused composite
  *claims* more than the evidence supports. In `wikidata` the module already had
  the correct safeguard and the engine's merge **erased** it — `absorb` takes
  `f64::max(confidence)`, so a deliberately sub-floor candidate was absorbed
  into the primary and pivoted. A demotion applied to an entity that is about to
  fuse with a higher-confidence twin is not a demotion at all.
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
  and framed as "a signal, not a determination". A rule that emits more than one
  row shape keeps the grade in one place, apart from the shape: AU-031's
  `adjacency_severity`/`adjacency_title` (`rules/infra.rs`) are the worked
  example — `ADJACENCY_BAD_TAGS` are three different claims (`malicious`
  asserts conduct; `threat-intel` is an unadjudicated sighting; `vulnerable`
  marks a VICTIM, usually the target's own asset), and a rule that flattens them
  headlines an exposure as an accusation (REQ-CLOUDSTORAGE-001).
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
  `install_invariants.rs`, `architecture.rs` wiring locks), `benches/`, `fuzz/`,
  `proptest-regressions/`.
- `tests/doc_drift.rs` — the guards that keep **documentation from drifting off
  the code and off itself**. Numeric claims (SeekNow credit costs, the MSRV
  pinned in `ci.yml`) are compared to their source of truth; and the three
  organising documents are locked to each other: this map may not cite a
  `REQ-…` the ledger does not record under a heading of its own, and
  `CHANGELOG.md` must account for every requirement the ledger holds. See §6.
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
the **outbound chokepoint** (`util::http`: one place that types a provider's
answer and records its outage state, so every module inherits the same 429 /
challenge / 5xx discipline instead of re-deriving it), the **tag/evidence
emission** (the only channel from module to correlator), the **expansion
floor** (what becomes a new pivot), and the **redaction boundary** (what leaves
the tool).

A seam has a matching failure mode worth naming, because it is not a missing
guard but a missing *reader*: a value that is captured, carried, persisted and
exported with no consumer anywhere. CONFIGURATION ≠ CONSUMPTION. `geocode` and
`photon` had recorded the grain of every match since they were written, on the
very entity the geo fusion weighs, and the fusion read the source's name instead
— weighing a state centroid as a rooftop (REQ-GEO-002). Auditing for a recorded
value with no reader is cheaper than auditing for a missing guard, and it found
a fix that needed no module change at all.

Its sharpest form so far is a value with a reader *three lines away* that was
never handed to it: `shodan` read Shodan's `city`, composed `"Brisbane,
Australia"`, exported it as the `Address` — and passed the geocoder the bare
`country`, which a gazetteer of cities can never answer (REQ-SHODAN-002). The
capability was not missing; it was one argument away. So the audit question is
not only "does this recorded value have a reader?" but "**is the reader being
handed the whole value, or one field of it?**"

A third reading is sharper still, because the unread field is the source's own
verdict on its data. Every Wikidata statement carries a `rank`, and
`deprecated` means the project has retracted it; all four of `wikidata`'s claim
readers discarded that field and minted retracted statements as current fact
(REQ-WIKIDATA-002). When a provider grades, ranks, flags or supersedes its own
records, that grade is the most load-bearing field in the response — and the
easiest to drop, because the value beside it looks complete on its own.

The tag/evidence seam has the mirror-image failure: a signal **read** by a
consumer that flattens what it means. `ADJACENCY_BAD_TAGS` carries three
distinct claims into AU-031, which graded all three `High` in its common branch;
because the seam is the only channel from module to correlator, the only fix
available at the module end is to stop emitting the tag — which is what
REQ-ABUSEIPDB-001 had to do. Correcting the consumer restored the signal
(REQ-CLOUDSTORAGE-001). When several emitters are being taught to withhold the
same tag, the reader is the thing that is wrong.

And a tag can have **no** reader. `addr-derived` was written so a derived
coordinate would be "distinguishable from a direct geocode", and nothing ever
drew the distinction — while the rules that count geo points quietly treated a
re-geocode of their own input as a third sighting (REQ-CORRELATOR-005). The
cheap tell is the one that found it: a tag with a bare string literal and no
`tags::` const, beside a sibling (`NAME_DERIVED`) that has both a const and
production readers. An emitted signal nobody consumes is not neutral — it is a
distinction the code believes it is drawing and is not.

A module that reaches the network *around* the outbound chokepoint is outside
every one of those disciplines at once — it cannot be rate-limit-aware, cannot
trip or respect the breaker, and reports a wall as a fault. Auditing for that is
now a standing T2 task, not an observation: `doh_resolver`, the engine's primary
DNS transport, was found entirely outside it (REQ-DOHRESOLVER-001).

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
hash) is compared by its canonical type, never tokenised into a bag.

**The fail-open family is now closed.** All five members ship: REQ-AUGEO-001,
REQ-INTELX-002, REQ-CHAININTEL-001, and the last three siblings —
REQ-ZOOMEYE-001, REQ-LEAKCHECK-001, REQ-HUDSONROCK-001. *This paragraph called
those three "still open" for fourteen cycles after they shipped*, which is the
defect this document's own header warns about; §6 now carries the mechanism that
makes the claim checkable rather than remembered.

Open high-stakes items remain queued (namesake fabrications, ambiguity-discarded
geo, truncation-silent providers).

**Five recurring shapes now have names, and finding the next instance starts
by looking for them rather than reading modules at random:**
1. *A guard applied to one consumer but not its neighbour.* Seven instances
   (REQ-AURDAP-001, REQ-EXPORT-001, REQ-BUILTWITH-001, REQ-WEBBANNER-001,
   REQ-HTTP-005, REQ-WIGLE-001, REQ-GLEIF-001). Its rule: a guard's call sites
   are audited against every emitter of the value it protects, not the one that
   motivated it. REQ-GLEIF-001 adds a corollary worth stating separately: when
   the neighbour is *missing* the guard entirely rather than missing one call
   site, the fix is to lift the mechanism into a shared authority both consume
   — `ahpra` held the only copy of the namesake-collision rule, inline, and
   `util::namesake` is now where it lives, with `gleif_lei`,
   `opencorporates` and `wikidata` joined to it (REQ-GLEIF-001,
   REQ-OPENCORPORATES-001, REQ-WIKIDATA-001). The consolidation is only real
   once the *originating* module's copy is deleted too; a shared helper beside
   an untouched inline original is two authorities.

   The cheapest way to find the next instance is to **count the consumers of an
   existing shared helper and look for who is missing**. REQ-KEYBASE-001 was
   found that way and is the shape at its most unambiguous: six sibling profile
   modules called `profile_kit::location_address`/`location_coordinates`, and
   the seventh had an inline copy with no cap at all.

   A consolidation can also drift *internally*. `util::geo::coarse_provider_coords`
   and `coarse_provider_address` were unified emitters for the same pair of
   entities, and disagreed about who stamped `geoint`: the first did it
   centrally, the second left it to eight callers and three forgot
   (REQ-IPGEO-002). **A guard each caller must remember is one every future
   caller can forget** — when two helpers standardise a pair, check they agree
   on who owns each stamp, not merely that both exist.
2. *The rule computes a relation, then discards which side related to which.*
   Five correlator instances (AU-046/REQ-CORRELATOR-002,
   AU-039/REQ-CORRELATOR-004, AU-105/REQ-CORRELATOR-003,
   AU-019/REQ-CORRELATOR-007, AU-016/REQ-CORRELATOR-006). Its rule: **when a
   correlator rule filters one collection using another, the filter's own
   decision IS the finding** — recomputing either side afterwards loses it, and
   loses it silently, because the rule still fires on genuine evidence with the
   wrong entities attached.
3. *A repeated manual procedure standing in for a structural property.* The
   sixteen breaker resets (REQ-BREAKER-001) and the hand-maintained currency of
   this document (§6). Its rule: prefer structural prevention over remembered
   detection — if a discipline is enforced by everyone remembering it, it has
   already drifted somewhere you have not looked.

   A **skipped** check is this shape wearing a disguise, because the skip is
   usually correct. `gate.sh` cannot run the `wasm-ui/pkg` byte-diff without an
   exactly-pinned toolchain and rightly skips instead of guessing — but it
   reported the same bland SKIP on two consecutive branches that changed
   `hse-core/`, which is compiled INTO that bundle, and CI went red both times
   (REQ-CI-009). Its rule: **a skip's cost is not constant, so a skip should
   state what THIS change makes it cost.** Where a check can be skipped, ask
   what input would make the skip load-bearing, and have the skip say so; the
   answer is rarely "fail instead", because the reason it skips is usually that
   failing would be wrong.
   A **missing state in a shared type** is this shape's deepest form, because
   it reproduces itself. `core::coverage::ProviderOutcome` had no "answered, but
   incompletely" variant, so five modules each invented a private evidence
   attribute for it — and a measured **zero** of those keys had a reader outside
   its own file (REQ-COVERAGE-001). Nothing could ask "was this complete?"
   because every module spelled the question differently. Its rule: **when the
   same private helper keeps appearing in module after module, the defect is the
   missing state in the type they all report through, not the modules.** Count
   the spellings before writing a sixth: N ad-hoc implementations of one concept
   is a type that is missing a case. And the reader is the deliverable — a
   canonical spelling with no consumer is the same defect one layer up.

   That fix also surfaced this file's shape 4 at the TYPE level: `is_resolved`
   was answering both "did this provider run?" and "can its silence be trusted?",
   which a truncated provider answers differently. Before adding a case to an
   enum, re-read every predicate over it and ask whether the new case splits one
   of them in two.

   A **promise a module makes about itself** is this shape too. `mnemonic_pdns`
   documents, under the Operational Constitution, that its API returns a
   *sample* and not the exhaustive set — and kept that promise per-entity and
   nowhere a consumer could read it (REQ-MNEMONIC-002). Its rule: **when a
   module's doc comment states a caveat, find the consumer that acts on it; a
   caveat with no reader is a comment, not a contract.** Grep the honesty
   language in a module header and ask what code enforces each claim.

   **Consolidating a guard creates a new gap above it.** When the second module
   needed "was this page returned full?", it moved into one helper — and a
   mutation passing the WRONG cap from a call site then survived every lock,
   because a shared guard cannot check its callers' arguments
   (REQ-ZOOMEYE-002). Its rule: **a helper's own tests never establish that its
   callers pass the right values; each caller needs a lock at its real
   emission path.** Extracting shared logic converts a duplication problem into
   an argument-correctness problem — verify the latter, or the signal can be
   silently dead while everything passes.

   **A dedup key is a claim about identity**, and a partial namespace is this
   shape again. `mnemonic_pdns` keyed IPs under `ip:` so a host and an IP could
   not collide, then let every relationship share one key space — so a host that
   was both MX and NS, or both a forward answer and an inbound alias, silently
   kept one of the two (REQ-MNEMONIC-001). Its rule: **when a key namespaces one
   collision, enumerate the others it does not.** Ask what two DIFFERENT facts
   could produce the same key, and put whatever distinguishes them into it.

   **A test that strains to reach its invariant is telling you the seam is in
   the wrong place.** The config-leak port check spent 103 concurrent sockets
   and a 3-second timeout to assert a property of a URL string, and failed CI
   twice with the code correct (REQ-CI-010). Its rule: **when a test needs
   elaborate machinery to observe a simple property, extract the property
   instead of hardening the machinery** — the previous fix hardened the
   machinery and did not hold. Then, and only then, relax the expensive
   assertion to what its machinery can prove without a race; a deterministic
   lock must exist BEFORE the relaxation, or a flake has been traded for
   weaker coverage.

   **A hidden argument makes tests ordered whether or not anyone chose that.**
   `module_skip_reason` took five arguments and read a sixth — the circuit
   breaker — from a process-global map keyed by module name, so any test that
   tripped a circuit changed what every other test saw (REQ-CI-004). Its rule:
   **a decision function's inputs must all be in its signature; inject the
   global and let the caller read it.** And when the symptom is a flake,
   remember the race is only how the coupling SHOWS — set the global yourself
   and the failing baseline is deterministic, with no scheduler to win.

   **A cache that stores failures turns a transient fault into a permanent
   verdict.** `control_presences` remembered `ProbeResult::Error` beside real
   answers, so one network blip marked every later presence on that site
   unconfirmable for the life of the process (REQ-PROBE-005). Its rule: **ask of
   every cache what happens when the value being stored is a failure** — the
   answer is almost always "re-ask", and the doctrine `ProviderOutcome` states
   for providers applies to any store that will be read as if it held an answer.

   **A declared-but-never-constructed variant is a cap that does not exist.**
   `DocumentParseError::FileTooLarge` carried a `{0} MiB` message and appeared
   exactly once in the tree — its own declaration — while `parse_pdf` read
   unbounded files and copied them again (REQ-DOCPARSE-002). Its rule: **grep
   every error variant for a construction site; one that has none is
   documentation, not a guard.** The same question answers "is this limit
   enforced?" without reading a line of logic.

   **A loop with several exits is several answers wearing one return type.**
   `see_know`'s pivot walk stopped for four different reasons — one meaning the
   chain was exhausted, three meaning it was cut short — and returned the same
   thing for all of them (REQ-SEEKNOW-001). Its rule: **when a loop's doc
   comment lists its exit conditions, ask whether the caller can tell which one
   fired.** If the list has more entries than the return type has cases, the
   difference is being discarded.

   **A guard that stops at one grain leaves the same defect at every finer
   one.** `place_grain::is_bare_country` refuses a country centroid because it
   "is never a subject's location" — and a city table happily returned Manhattan
   for `"New York State"`, the identical failure with a smaller radius and more
   apparent precision (REQ-SOCIALLOC-002). Its rule: **when a predicate rejects
   a value for being too coarse, ask what the next grain down looks like** —
   country, state, region, metro — and whether anything rejects those.

   **A consolidation is not done until the last copy is gone.**
   REQ-COVERAGE-001 found five private truncation vocabularies and wired three,
   leaving `web_crawler` and `netlas` — so the ledger described a consolidation
   the tree did not have (REQ-WEBCRAWLER-003 / REQ-NETLAS-001). Its rule:
   **when a cycle migrates N of M call sites, record the remainder as an open
   contradiction and close it**, because a shared authority standing beside two
   survivors is three authorities, and the next reader cannot tell which is
   canonical.

   **A filter's SHAPE can contradict the thing it filters.**
   `is_plausible_provider_coord` exists to drop a no-fix placeholder that is a
   *point* near `0,0`, and was written as "neither component may be near zero"
   — a cross of two great-circle strips, not a square, so thirteen modules went
   blind along the whole equator and the whole prime meridian while every
   comment and every fixture in the tree described the square
   (REQ-GEOGATE-001). Its rule: **when a guard rejects a region, state the
   region's shape in the same words as the thing it is rejecting, and test a
   real value from the difference between them.** The difference here held
   Greenwich, Pontianak and the Gironde — and two of the three assertions
   pinning the wrong shape used coordinates that are real inhabited places as
   their examples of what must be discarded.

   **`#[serde(default)]` on a struct is a decision about every field, including
   the ones you were not thinking about.** `open_meteo_geo` applied it for a
   dozen optional enrichment fields that were already `Option`, and it silently
   also covered the two bare `f64` coordinates — so an omitted latitude became
   `0.0` and shipped as an equatorial fix (REQ-OPENMETEO-001). Its rule: **when
   a container-level serde attribute is added for one group of fields, list the
   fields it ALSO reaches** — particularly any non-`Option` primitive, where the
   default is indistinguishable from a real value.

   **CORRECTED by applying it.** Swept as a population: nine such structs in the
   tree, each read at its use sites — and **seven are correct by design**
   (REQ-FOFA-001). A rule that fires nine times and is right twice is one the
   next reader learns to ignore. The rule is therefore: **a bare field under a
   container-level `default` is safe iff EITHER a container-level sentinel
   distinguishes "no response" from "a response of zeros", OR every use site
   guards the default before it becomes a claim** — a defect only when neither
   holds. The two are not interchangeable: a sentinel is the only option when
   the zeros are themselves meaningful data (`chain_intel`, where a dormant
   address really does return an object full of zeros, so per-leaf `Option`
   would be actively wrong); guarding at the use site is the only option when
   the struct has no field a real response guarantees.

   **`cargo clippy` and `cargo test` do not cover rustdoc, so renaming a
   documented item can pass every check you ran and still break the build.**
   `uninterpretable` was renamed to `classify` mid-cycle; two `[`…`]` intra-doc
   links still pointed at the old name. Clippy was clean, `doc_drift` was clean,
   all 20 module tests passed — and `cargo doc` failed on
   `rustdoc::broken-intra-doc-links`, which is what CI actually runs
   (REQ-FOFA-001). Its rule: **after renaming or removing any item that has a
   doc comment, run `cargo doc --no-deps --document-private-items` before
   committing** — it is the only check in the set that resolves intra-doc links,
   and a rename is precisely when they rot. The deeper rule is about the gate:
   a gate stopped part-way has verified only the steps that ran, so a commit
   made on "clippy and the tests passed" is a commit made on a subset nobody
   chose deliberately.

   **A fixture built by CONSTRUCTING a struct cannot express an absent key —
   which is the one thing a `#[serde(default)]` defect is about.** `fofa`'s
   eight pre-existing tests all built `FofaResp` with every field set, so none
   of them could reach the missing-`error` case the defect lived in; and the
   first repair repeated the mistake one field over, leaving a mutation that
   read `results` alone alive because no fixture omitted `results` either — the
   body that exposes it is an error envelope, which on the wire carries no
   `results` at all (REQ-FOFA-001). Its rule: **test a serde guard by
   deserializing TEXT, and include the shape each branch actually arrives in.**
   A struct literal can only express presence, so it silently tests the one
   scenario the guard does not care about. Note the cost of missing it here was
   not a wrong entity: an envelope misrouted past `note_keyed_error` stops a
   dead key rotating out of the pool, so every later scan keeps spending on it.

   **A precedent transfers only with the fact that made it safe.** The same
   cycle's obvious fix — copy `chain_intel`'s "require the structural key, fail
   closed without it" — was rejected for `fofa`, because `chain_intel`'s
   sentinel is a field a real response demonstrably echoes and `fofa`'s module
   header documents no response shape at all (REQ-FOFA-001). Its rule: **before
   reusing a fail-closed sentinel, ask what evidence establishes that a SUCCESS
   carries it.** Without that evidence the repair trades a fail-open for a
   fail-shut, which is worse; the weakest condition that still rejects the
   uninterpretable body is the right one, and the assumption it rests on is
   recorded as an assumption.

   **A fix is only as permanent as its least-locked call site.**
   REQ-WIGLE-001 applied the band gate to three sites and locked one; two could
   be reverted with all 52 of the module's tests still green (REQ-GEOGATE-001).
   The same gap appeared in REQ-ZOOMEYE-002, REQ-DOCPARSE-002 and
   REQ-SEEKNOW-001 before it. Its rule: **mutate every call site, not the shared
   helper** — a helper-level lock proves the helper, and says nothing about who
   calls it.

   **A value hoisted out of a loop "for efficiency" freezes every decision the
   loop makes with it.** `target_distinct_sources` was computed once before the
   dispatch loop — the comment calls it "computed once per target, not per
   module" and says nothing about the cost — so a target that crossed the
   cross-correlation threshold during its own round could not re-open the gate,
   and since a target is visited exactly once, that skip was permanent
   (REQ-ENGINE-002). Its rule: **for every loop-invariant hoist, ask what
   changes inside the loop that the hoisted value was measuring.** If the answer
   is "the thing itself", the hoist is a stale read, not an optimisation — and
   the repair is a barrier at the loop's end, not a recompute inside it, because
   a per-iteration recompute makes the answer depend on an order the concurrent
   phases do not fix.

   **A test whose premise is not asserted cannot tell you which half failed.**
   The first version of REQ-ENGINE-002's lock emitted entities with no
   `Evidence` attached — the engine stamps none of its own — so the count never
   moved and the lock went red for a reason that had nothing to do with the gate
   it was written to catch. Its rule: **assert the antecedent before the
   consequent.** A lock of the form "given P, the system must do Q" needs P
   asserted first, in the same test, or its red is ambiguous between "P never
   held" and "Q did not follow" — and the first of those is a broken harness
   reporting a fixed bug or an unfixed one at random.


   **A guard that catches a value incidentally stops catching it the moment the
   value varies.** `is_username_derived_name` rejects `"\N \N"` — but because
   the two tokens are *identical*, not because it knows what `\N` means; the
   predicate contains no absence concept at all. Four sites recorded that
   coincidence in a comment as coverage (*"the `"\N \N"` SQL-null pair
   (identical tokens the doubled-token rule also catches)"*), and the coverage
   evaporated the moment one column was populated: `"\N Smith"` has two
   different tokens, no slug, a space and five characters, so nothing stopped it
   (REQ-NAMEGATE-001). Its rule: **when a comment credits a guard with catching
   a value, check WHICH property of the value it matches.** If the guard's
   reason is not the value's reason, the coverage holds for the exact sample in
   the comment and nothing else — and a comment that names the sample is what
   stops anyone re-deriving it.

   **Two public predicates for one decision, and the call sites converge on the
   weaker.** `is_username_derived_name` and the per-component absence check were
   both available; six name slots called the first and one called both, so the
   rule `breach_rich` documents and regression-locks was enforced at one site in
   six (REQ-NAMEGATE-001). The same pull produced three private copies of
   `is_null_sentinel || is_placeholder_secret`, each doc-commented as mirroring
   one of the others. Its rule: **when one decision has more than one callable
   authority, the weakest is the de-facto rule — so export one gate and make the
   components unreachable.** `validation/mod.rs` already records the converse
   case (Pass 25 deleting zero-caller validators rather than leave *"a
   plausible-looking second authority"*); a second authority that is merely
   WEAKER is worse than one that is unused, because it has users.

   **A no-op guard reads exactly like an enforced one.** `dehashed` called
   `is_null_sentinel` on the composed name for its entire life. The predicate is
   an exact match on `\N`, so the only value it could reject is a bare `"\N"` —
   which the `contains(' ')` test on the line above had already rejected. It
   cost nothing, caught nothing, and made the site look guarded to every later
   reader, including the sweep that first catalogued the six name slots
   (REQ-NAMEGATE-001). Its rule: **for a guard on a composed or filtered value,
   ask what reaches it after the preceding conditions** — an exact-match
   predicate behind a shape test is usually testing a value the shape test made
   impossible, and the sibling that looks unguarded may be in better shape than
   the one that looks guarded.

   **A module's silence has four meanings and only one vocabulary to say them
   in.** Ten modules guarded a query-quality floor, refused to spend a provider
   call, and returned `Ok(empty)` — which dispatch and `core::coverage` turn
   into `CleanNegative`, "the provider was asked and holds nothing". The typed
   `Error::Skipped` existed for exactly this, said so in its own doc, and was
   already used by ten OTHER modules; each of the ten silent sites even carried
   a comment stating why it refused (REQ-SKIPCLASS-001). Its rule: **when a
   module returns early without querying, the reason in the comment belongs in
   the outcome.** A comment explains the code to a reader; only a typed outcome
   explains it to the coverage report the operator actually reads. Ask of every
   early `Ok(empty)`: did the provider ANSWER that, or did we decide it?

   **Do not flatten a per-site judgement into a uniform sweep.** The obvious
   finish to that cycle — one `SkipClass` for all ten — is wrong: nine refuse on
   their own policy (`Scoped`, a coverage gap the operator can close by asking
   better), while `ransomlook`'s own comment says the API would have rejected
   the query, which is `NotApplicable`'s definition almost verbatim and carries
   `is_coverage_gap() == false`. A mutation hardcoding one class is killed by
   that single row (REQ-SKIPCLASS-001). Its rule: **a doctrine sweep decides
   each site from that site's own evidence**, and the sweep has gone wrong when
   every row comes out identical — the differing row is usually documented in a
   comment someone already wrote.

   **A test named for the right behaviour can still assert the wrong one.**
   `asic_persons::single_token_name_makes_no_request` and
   `data_gov_au::short_query_is_skipped_without_a_request` both failed on
   REQ-SKIPCLASS-001's fix. Their names and comments were already correct —
   "makes no request", "must return early ... before any HTTP call is
   attempted" — and only the assertions encoded the defect, one of them via an
   expect message reading `"single-token name is a clean no-op"`. Its rule:
   **when a fix breaks a test, read the test's NAME against its assertion
   before touching either.** A gap between them means the oracle drifted from
   its own intent, and the correction belongs in the assertion (REQ-EMAILCANON-001
   set the same precedent with three oracles).

   **A doctrine comment protects the line it sits on, and nothing else.**
   `breachdirectory` and `c99` each carry "PROVIDER FAILURE != ZERO EVIDENCE ...
   Error::MissingKey is the contract (REQ-KEYSKIP-001)" on their credential
   path, and each violated that exact sentence thirty lines below on their
   response path (REQ-SUCCESSFLAG-001). It is the third instance of the shape on
   this branch — REQ-OATHNET-002 (`is_absent` defined at line 20 of the file
   that never called it on the name slot) and REQ-NAMEGATE-001 (`breach_rich`
   documenting AND locking a rule five siblings ignored) are the others. Its
   rule: **when a cycle applies a doctrine at one path, grep the same FILE for
   the other paths that decide the same thing.** The comment explaining why is
   the best search key available, and finding it already written is evidence the
   site was reached and skipped, not that it was considered and excused.

   **An over-correction passes every rejection test.** REQ-SUCCESSFLAG-001's
   most valuable mutation was not the pre-fix fusion but the fail-shut: refusing
   whenever `success != Some(true)` satisfies every assertion about failures and
   unreadable bodies, and destroys the module's ability to report an honest
   absence. Its rule: **for every guard that converts a quiet outcome into an
   error, write the control that the QUIET outcome still happens** — and mutate
   toward the over-correction, not only away from it. REQ-OPENMETEO-001 and
   REQ-GEOGATE-001 needed the same control for the same reason; a gate that
   rejects everything is indistinguishable from a gate that works, on rejection
   evidence alone.

   **A mutation that dies on the way to the control has tested the path, not the
   control.** REQ-GATE-002's vacuity mutation pointed the workflow walk at a
   missing directory and was duly killed — by the pre-existing
   *directory-not-found* check, which fires long before the new
   "did the walk actually find anything?" guard it was written to exercise.
   Only a directory that EXISTS and yields too few jobs reaches that guard. Its
   rule: **after a mutation is killed, read WHICH assertion killed it.** A green
   matrix row proves something died, not that the thing you were testing did —
   the same failure as the mistyped test path earlier on this branch, where
   `cargo test --exact` on a name matching nothing reported no failure at all.

   **The instruction that relies on being read is not a mechanism.**
   `scripts/gate.sh` has carried "if CI gains a check, add it here in the same
   commit — a gate that has drifted from CI is a defect" since it was written,
   and had drifted from CI anyway: the `gitleaks` secret scan was neither run
   nor skip-listed (REQ-GATE-002). The remedy was not to add the check but to
   add the lint that fails when the two disagree. Its rule: **when a file tells
   a future editor to keep two things in step, ask what fails if they do not.**
   If the answer is "nothing, until someone notices", the comment is a wish;
   convert it into a check that both sides must satisfy, in both directions.

   **Record WHICH assertion killed each mutation, not just that one died.**
   REQ-GATE-003's matrix applied REQ-GATE-002's lesson prospectively and it paid
   off on the first run: the vacuity mutation pointed the path reader at
   `bench-smoke.yml`, was duly KILLED, and had never reached the guard it was
   written for — that workflow has its own `paths:` filter, so the ordinary
   missing-path assertion fired first. Only a workflow with no filter at all
   reaches the vacuity guard. Its rule: **a matrix row that says only KILLED is
   compatible with the guard under test never running.** Assert the expected
   failure MESSAGE, not the exit code.

   **A lint that compares two hand-written lists has relocated the maintenance,
   not removed it.** `gate.sh` carried `**/Cargo.{toml,lock}` hand-expanded into
   eight literal paths — correct on the day it was written, and silently wrong
   the moment a ninth crate appears. The fix computes the expansion against the
   real tree, so a new crate fails the lint instead of quietly narrowing the
   gate (REQ-GATE-003). Its rule: **when enforcing that a derived list matches
   its source, DERIVE it** — otherwise the check is only as fresh as whoever
   last edited both sides, which is the condition it was supposed to end.

   **Fixing WHICH inputs a guard watches is worthless if it asks the wrong
   QUESTION of them.** REQ-GATE-003 corrected the audit gate's path list;
   REQ-GATE-004 found the guard compared `git diff HEAD` — uncommitted edits —
   where CI compares the branch's cumulative diff against its base, so on a
   clean tree it skipped however correct the list was. Its rule: **when
   mirroring a CI filter locally, state the comparison base before the paths.**
   Paths answer *what*; the base answers *since when*, and a local gate run
   before a push has no uncommitted changes to look at. A skip whose stated
   reason is false ("no manifest change" on a branch that changes one) is worse
   than a check that is merely missing: the omission is invisible, the wrong
   reason is believed.

   **A field that may always be absent cannot report its own misspelling.**
   `ScanOptions`' 30 fields are every one absent-tolerant, and rightly so:
   omitting a knob has to mean "no preference". But that makes an unknown key
   and an omitted key the same thing after deserialisation, and for six of those
   fields the "no preference" default is the PERMISSIVE value — so a one-character
   slip in `passive_only` ran the active scan the operator forbade, answered
   `202 Accepted` (REQ-SCANOPTS-001). Its rule: **tolerating absence is a
   decision about the FIELD; rejecting an unknown name is a decision about the
   REQUEST, and the first cannot make the second.** Wherever a permissive
   default means "unconstrained", the key's spelling is part of the control.

   **The same serde strictness is right and wrong on one type, depending on who
   owns the schema.** `deny_unknown_fields` belongs on operator-supplied
   configuration — `dep-cooldown.toml` has it, and says why — and must stay OFF
   provider response structs, where `devto`/`hibp` deliberately lock it out so an
   upstream field addition cannot break a module. `ScanOptions` is BOTH a request
   body and the persisted form (`Scan` is serialised whole into `scans.data_json`
   and read back), so the attribute would have bought input strictness at the
   price of making a stored scan with a legacy key unreadable. Its rule:
   **before tightening a serde contract, ask which of the type's readers you are
   tightening against** — a type with two readers has two contracts, and the
   check belongs at the seam that has only one.

   **Search for the SEAM, not for the type you expect to find there.**
   REQ-SCANOPTS-001 fixed the scan request's option check and claimed the input
   side closed; it had searched for `Json<…ScanRequest>` / `Json<…ScanOptions>`
   by type name, and `LiveRequest` — a different name that *contains*
   `ScanOptions` — matched nothing, so `POST /api/v1/live` stayed open
   (REQ-SCANOPTS-002). Its rule: **a type-name search answers "where is this
   type used", which is never the question.** The question is "where does this
   kind of input enter", and the extractor, handler signature or entry point is
   what answers it — enumerate those and the set is complete by construction.

   **When a check is parameterised by which authority it consults, the wrong
   authority is invisible to every rejection test.** Cross-wiring the live
   request's `live` object to the *scan* key set still rejects every
   misspelling — they are unknown to both sets — so the whole rejection suite
   stays green; only a control supplying a genuinely VALID value fails
   (REQ-SCANOPTS-002). Its rule: **for a parameterised guard, the control is
   the only test that distinguishes "rejects the wrong things" from "rejects
   the right things"** — and the two authorities must be asserted disjoint, or
   a later overlap silently removes even that.

   **A containment question needs a containment test — proximity is not
   containment.** Classifying a `store.…()` call as "inside the blocking hop"
   by looking three lines up reported eight violations, every one false,
   including a handler whose `move ||` sat four lines above the call inside a
   correctly-hopped group (REQ-REACTOR-001). Its rule: **when the question is
   "is X lexically inside Y", match the delimiters** — a line window narrow
   enough to exclude the unrelated is narrow enough to exclude the relevant, and
   widening it only moves the error. Had the heuristic been trusted, the cycle
   would have "repaired" eight already-correct handlers.

   **A green test is evidence about the tree, not about the test.** The hop
   matcher first searched `find("offload_store(").or_else(|| find("spawn_blocking("))`,
   which steps over every `spawn_blocking` that precedes the last
   `offload_store`, under-counts the spans and would invent violations — and it
   passed, because no file happens to order the two keywords that way *today*
   (REQ-REACTOR-001). Its rule: **a checker that passes has only demonstrated
   agreement with the current tree**; whether it would catch the thing it is
   for is a separate question, answered by mutating the tree, and whether it is
   correct at all is answered by reading it.

   **A test at an inner boundary does not cover the artifact that composes
   it.** `render_full` had a lock proving it masks an operator key echoed into
   evidence; the debug bundle, which embeds `render_full`'s output alongside
   four other sections, had none — and a mutation adding a sixth section that
   forgets the redactor leaves the inner test green while leaking the key from
   the outer file (REQ-EXPORT-002). Its rule: **lock the artifact that ships,
   not only the function that builds part of it.** The composition is what the
   reader opens, and a component's guarantee says nothing about what was
   appended after it.

   **A sink with no guard is exactly as good as every producer above it.**
   `render_event_log` prints event text verbatim; the protection is that
   `util::http` redacts at error CONSTRUCTION. That is a sound design, but it
   moves the audit: instead of checking one sink you must check every producer
   (REQ-EXPORT-002). Its rule: **when protection lives upstream, enumerate the
   producers and say so where the sink is** — otherwise the next reader sees a
   bare sink, assumes a hole, and either adds a redundant pass or files a
   defect that is not one.

   **A filed hypothesis is cheaper to observe than to argue.** REQ-SCANSTATUS-001
   sat as INFERRED-from-source with a "needs a product decision" label until the
   running binary was pointed at it: a 30 s throttle gap, `kill -9`, restart,
   and the stale `running` row was OBSERVED in under a minute (REQ-SCANSTATUS-001).
   The observation also dissolved the deferral — the "decision" was only a
   label. Its rule: **when a claim about runtime state can be produced by
   running the thing, run the thing before deferring it**; source reading
   establishes possibility, not occurrence, and a product question often
   evaporates once the behaviour is on the screen.

   **When only the owner can finalise a persisted status, report ownership at
   read time instead of guessing at write time.** A `running` row is finished
   only by the process that started it; if that process is gone the row is
   stuck, and a startup rewrite cannot tell a dead owner from a concurrent one
   (REQ-SCANSTATUS-001). Its rule: **derive "nobody owns this" from the
   process's own live registry and surface it as a non-persisted field** — it
   is exact per process, mutates nothing, needs no migration or new enum
   variant, and an older binary reading the row sees exactly what it saw before.

   **The registry you derive from must be the one every spawn path fills.**
   The first draft read `AppState.cancellations`, which only `spawn_scan`
   populated; the live loop ran the engine itself, so a scan this very process
   was running read `interrupted` — and, probed on the running binary, the same
   gap had left every live iteration deletable mid-run and uncancellable by
   scan id all along (REQ-SCANSTATUS-001). Its rule: **when a reader asks "is
   this in flight?", find every path that puts work in flight and make them
   all write the one map the reader consults** — a second lookup unioned in at
   the read fixes the symptom you noticed and leaves the consumers you did not
   look at exactly as broken.

4. *One judgement with two definitions, in one function.* AU-031 chose between
   a per-neighbour branch and an aggregate branch on a fan-out count, and only
   the aggregate branch derived its severity from the reason — the other
   hardcoded `Severity::High`. The same flagged host therefore graded High with
   five domains resolving to it and Medium with thirty (REQ-CLOUDSTORAGE-001).
   This is shape 1's cousin, and harder to see: there is no sibling module to
   compare against, because both copies live inside the function you are
   reading, and the graded one *looks* like the whole story. Its rule: **when a
   function branches on shape, every branch reads the same authority for every
   judgement that is not about shape.** A count that decides how to PRESENT
   rows must not also decide what they CLAIM.

   Two tells make it findable. A literal severity, confidence or threshold
   sitting in one arm of a branch while another arm computes the same quantity
   is the first. The second is a comment that states the graded rule — AU-031's
   said "weaker reasons (vulnerable/threat-intel on shared infra) are Medium" —
   which is where the judgement was written down once and then applied once.

   It also explains a class of *emitter* fix: REQ-ABUSEIPDB-001 gated a tag at
   its source because AU-031 escalated everything it received. That was right,
   and it was a workaround for this defect. **When several emitters are being
   taught to withhold a signal, suspect the consumer.**

   Its opposite failure is worth naming beside it, because the obvious repair
   invites it: collapsing several judgements into one authority when they were
   never the same judgement. `wikidata`'s statement rank says two different
   things — `deprecated` retracts a statement, `preferred` picks among live ones
   — and a single "filter to preferred, else normal" seam would have traded a
   fabrication for a silent deletion, discarding the true second and third
   occupation of a person who holds several (REQ-WIKIDATA-002). The rule that
   falls out: **one authority per judgement, and count the judgements before
   deciding there is one.** A mutation that over-corrects belongs in the
   falsification set next to the one that under-corrects; without it, "fewer
   wrong values" and "fewer values" are indistinguishable.

   The shape has a third form, and it is the one a maintained codebase reaches
   last: the two definitions have **already been reconciled**, and reconciling
   them was mistaken for grounding them. `Module::is_derivation()` and
   `hse_core::ENRICHMENT_ONLY_SOURCES` are two declarations of one judgement,
   and a bidirectional architecture guard pins them to each other for every
   registered module. That guard passed while `au_business_id` — a pure offline
   decoder of an identifier's own check digits — declared `false` on one side
   and was absent from the other (REQ-AUBUSINESSID-001). Perfectly consistent,
   consistently wrong.

   Its rule: **a consistency guard is blind to an entry missing from every side
   it compares.** Agreement is all such a guard can see, so it keeps copies
   honest but can never originate the judgement. Ask separately, of each
   declaration, *what in the tree would notice if this were simply absent?* —
   and where the answer is "nothing", the finding has to come from reading, not
   from the suite. Here it came from the module's own header naming a sibling
   that was on the list: shape 1's "count the consumers and look for who is
   missing", applied to a shared LIST rather than a shared function.
5. *The workaround went into the test fixture.* `shodan` geocoded a bare
   country name against `util::city_coords`, a gazetteer whose 143 rows are all
   cities, so the branch could not execute on any response Shodan can send. Two
   tests reached it by passing `{"country_name":"Brisbane"}` — an impossible
   response — under comments stating plainly that "no bare country name
   resolves, and this is the only way to reach that branch with a real fixture
   at all" (REQ-SHODAN-002). The diagnosis was complete and correct; the repair
   went into the fixture instead of the module, and the branch stayed dead for
   every real scan while the suite stayed green.

   Its rule: **when a test needs an input the provider cannot produce, the
   branch is the defect, not the fixture.** A fixture is a claim about what the
   world sends; one that no longer makes that claim has stopped testing
   anything. The tell is a comment explaining why a fixture is odd — grep the
   test tree for fixtures whose own comments apologise for them.

   Two corollaries earned the same cycle. A guard written for an unreachable
   path never runs, so it is dormant in the same way a rule with no producer is:
   REQ-IPGEO-001's confidence cap had been correct and idle since it was
   written, and only engaged once the branch it guarded became live. And a
   *vacuous* assertion hides inside a passing test — "the fallback is never also
   planted beside a real fix" could not have failed while the fallback could not
   fire at all. When a branch becomes reachable, re-read every test that
   mentions it: some were proving nothing.

   **Vacuity has more than one shape, and the session has now hit four.** A
   mutation that cannot REACH its control past an early return
   (REQ-WIKIDATA-001). A harness that never BUILT and reported green because it
   only grepped for failures (REQ-TYPOSQUAT-001, and again in
   REQ-AUBUSINESSID-001 where the mutation itself would not compile). A FIXTURE
   that does not survive the transform under test (REQ-KEYBASE-001's
   whitespace), or that asserts an outcome unreachable for an unrelated reason
   (REQ-CORRELATOR-005's control used sources a positive allowlist drops before
   the code under test is reached). And a COMPARISON whose two sides are equal
   because both are empty (REQ-CORRELATOR-005's first AU-053 test, where a
   mutation survived because neither side fired).

   The generalisation: **every check must separately establish that it could
   have failed.** A check that can only report failure must prove it ran; a
   check that compares two runs must prove at least one of them does something;
   a fixture must be shown to reach the code it is aimed at. Put the guard on
   the INPUT SET — "this fixture fires on a genuine fourth observation" — never
   on the quantity under test, which is what the assertion is for.

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

**T5 — Radar (signal situational awareness as a product surface).** The
directive: the mobile signal "Radar" — the oracle app's feature set as the
skeleton (Wi-Fi + BLE + classic BT, tracker detection, scan modes, JSON/CSV
export, history) — grown into the best in its class: an open-source map,
real-time tracking, and the complementary features around them, with HSE and
the HSE BLE Radar app working as one system. The authorities, as they stand:

- **The oracle APK** (`com.huntsman.bleradar` v0.3.0, retained in
  `EmmmmDeee/HSE-BLE-API-`) is the behavioural reference, not a codebase — its
  UI is what the operator has in hand today.
- **`bleradar-core`** (pinned git dependency) owns the radar mathematics —
  RSSI filtering, calibrated distance, proximity bands, identity, geometry.
  HSE consumes it (`signal_radar`: channel and proximity band) and never
  re-derives a distance.
- **The Rust-first app** (`android/app` in that repository, v1.0.0) owns
  native BLE scanning with RSSI, the loopback `ApiHttpServer`
  (`/api/devices`, `/api/status`, `/api/scan/start|stop`) and a
  self-contained dashboard. BLE-only by design: Wi-Fi, classic BT and tracker
  detection are not reproduced there yet. Its default port is 8080 — so is
  `hse serve`'s.
- **HSE** owns persistence and analysis: `core::rf::{RfSighting,
  RfDeviceRow, RfSummary}` + `rf_sightings` (position, level, time; geo
  index) read through `StoragePort`, `radar_track` (cross-sweep recurrence),
  the WiGLE/KML importers, AU-117/AU-122, `hse signal` and
  `/api/v1/radar/signals*` (one presenter, `app::signal`), and the SPA Radar
  view (`js/views/radar.js`, `#/radar`) with `/api/v1/radar*`. From Termux the
  sensors are Wi-Fi (with RSSI), classic-discovery Bluetooth (no RSSI), cell
  and GNSS.

Ordered cycles, each shipped with its own ledger entry and gate:

1. **REQ-RADAR-001 — every reading is a sighting.** The live sweep now writes
   the same `rf_sightings` rows a WiGLE import does, positioned by the
   sweep's own fix. Everything below draws from this table. *Shipped.*
2. **The reader, then the map.** *2a, REQ-RADAR-002, shipped:* the sighting
   readers on the port, `/api/v1/radar/signals` and `…/signals/{network_id}`
   through the CLI's presenters, and the `#/radar` view — sweep and continuous
   radar, a polar plot by level, the device table, per-device tracks, the
   sweep history, JSON/CSV — as the radar's one home. *2b, REQ-RADAR-003,
   shipped:* the loopback tile proxy with its on-disk cache
   (`/api/v1/tiles/{z}/{x}/{y}.png`; `HUNTSMAN_TILE_UPSTREAM`, OSM by default,
   with the User-Agent and attribution the policy requires; `feature.map_tiles`
   kills the fetch, never the cache) and the dependency-free map in the view,
   every positioned device at its position and nothing placed where it was
   not heard.
3. **Real-time tracking.** *3a, REQ-RADAR-004, shipped:* the view follows a
   continuous radar over its SSE stream (`scan_complete` → refresh; a running
   radar is recognised by `allow_live_sensors`), one device's track across
   every sweep (`/api/v1/radar/devices/{id}/track`, a trail on the map and a
   sparkline), and `radar_recurring` on the sighting table — level, place,
   time, with entity-only sweeps disclosed as `legacy_sweeps`. *3b, next:*
   per-row sparklines from one grouped signal-history query, a recurrence
   badge on the device row itself (the oracle's "tracking" chip), and a bound
   on the tile cache.
4. **Synergy with the app.** An HSE sensor module reading the app's loopback
   `/api/devices` — the RSSI/distance axis the Termux Bluetooth path
   structurally lacks — after the 8080 collision is settled (one default
   moves; the operator must not have to know).
5. **The app itself** (in its own repository, on its own gates — host-JVM,
   dashboard, emulator, APK): Wi-Fi scanning, classic BT, tracker
   heuristics, scan modes, export and history on the Rust-first core — the
   oracle's feature set, then past it.

What the first cycle taught, as a rule for the rest of the track: **a table
with readers is not a capability until its production writer exists.**
`rf_sightings` had a geo index, a summary, a trackable-device view and a CLI
reader, and the only writer was the importer; every radar-side comment
described the live sweep as a source it never was. Check the writer before
building the next reader.
The second cycle added the converse: **a reader that only the CLI can reach
is not a product surface.** Every `rf_*` reader was inherent on the SQLite
`Store`; the HTTP layer sees the port and could not call one. Put the reader
on the port first, then build the page.
The map cycle's rule is about the browser: **the console loads nothing from
a third party, ever.** A map wants tiles from somewhere; the answer was a
proxy the operator controls, not a CSP exception — and the same proxy is
what makes the map work offline.
The tracking cycle's rule: **an event is a refresh signal only if the row is
written before the event is sent.** `scan_complete` is emitted after the
engine's own `upsert_scan`, and the end-to-end lock reads the sweep through
the web reader at the moment the event arrives — the property the view
rests on is asserted, not assumed.

**T6 — Resilience (the console and the radar under hostile or failing
networks, the process under Android's own lifecycle).** The directive: the
world's most resilient system against (a) predictable Wi-Fi outages, forced
disconnections, deauthentication and hostile network disruption; (b) DNS
failure, captive portals, IP reassignment, routing changes, gateway
instability and partial upstream connectivity; and (c) Android process
termination, battery optimisation, device sleep, app eviction, unexpected
reboots and loss of runtime state. What that means for HSE, whose console is
a loopback page and whose radar needs no network at all: nothing the
operator is looking at may freeze, lie, or lose what it had when the link
goes; the radar keeps sweeping through an outage; the radar *sees* the
disruption — records it, classifies it, and says what it is; and a session
the OS kills is one tap from resumed, never silently gone. The authorities:
the SPA's one stream opener (`scan_info/log.js`) and one request path
(`api.js`), the live loop (`core::live`), `device_sensors`' connected-AP
read (`termux-wifi-connectioninfo`), `core::link` for the Wi-Fi-link record,
`util::curl_client` (the DNS-resolve exit code and its DoH retry),
`util::egress` (the health-scored proxy pool and its captive-portal probe
URL — the same `generate_204` endpoint Android's own connectivity check
uses), `util::dns` (the resolver pool) and `cert_intel`'s TLS capture for
the outage KIND; and the store — `wifi_links`, `rf_sightings`, and a new
persisted live-session row — for everything that must survive the process
dying.

Ordered cycles:

1. **REQ-RESILIENCE-001 — the console survives its own link dying.** The
   live stream reports its state like the scan-log stream does; the Radar
   view says "reconnecting", polls around the gap, re-reads everything on
   `open` (a broadcast stream replays nothing), and releases a stream the
   server closed for good; every page shares one "console unreachable"
   banner raised by the one request path and lowered by the next answer; the
   stream of a session the server does not know is a 404, not a silent pipe.
   Proven by killing and restarting `hse serve` under an open console.
2. **REQ-RESILIENCE-002 — the disruption record.** The connected-AP read is
   a per-sweep `LinkState` (`core::link`) beside the sightings — connected,
   SSID, canonical BSSID, level, address, link speed, the supplicant's own
   state, the read time; *not connected* is a record, not an absence —
   carried on `ModuleResult.link` like the sightings and persisted by the
   engine's one finalise path into `wifi_links`, never on a cache replay.
   `core::link::review` (pure: no I/O, no clock) reads the sweep history —
   each sweep's link record plus the Wi-Fi access points its sightings heard
   — for a forced disconnection (off the network while the last BSSID is
   still heard at ≥ −75 dBm), deauthentication suspected (three or more
   forced disconnections from one access point within an hour), an evil twin
   (a known SSID from a never-seen BSSID, louder than the known one heard in
   the same sweep), periodic outages (more than three outage starts whose
   gaps all sit within 15 % of their median) and the outage timeline they sit
   on; every finding carries the same advice on the page and in the shell.
   `GET /api/v1/radar/disruptions`, `hse signal --disruptions`, and the Radar
   view's "Network disruption" panel share one assembly and one presenter; a
   sweep from before the record existed is counted as unrecorded, not
   guessed. Proven with the sensor scripted through a drop under a real
   `hse serve`, in the shell and in Chromium.
3. **The radar through an outage, with the outage classified.** (Earns its
   own `REQ-RESILIENCE-0xx` id and ledger entry once built and falsified —
   not cited here in advance of that record.) A live radar with a network-bound module against a dead
   host and hanging sensor shims keeps sweeping, every iteration bounded (no
   change needed if the per-module timeouts the engine already enforces are
   sound — verify, don't assume). A new pure `core::outage` (the `core::link`
   precedent: no I/O, no clock, a `review`-shaped entry point over readings
   the caller supplies) classifies what kind of trouble the path to the
   internet is in, from signals HSE already produces or can cheaply add:
   - **Offline** — DNS resolution fails (`util::curl_client`'s own
     `CURL_EXIT_COULD_NOT_RESOLVE`, already surfaced per-provider) AND a
     probe that never touches DNS (an IP-literal request to a stable anchor)
     also fails: no path exists at all, not just a bad resolver.
   - **Captive portal** — DNS resolves and a TCP connect succeeds, but a
     request to `util::egress`'s existing neutral connectivity-check URL
     (`http://www.gstatic.com/generate_204`, already the pool's own health
     probe, and the identical URL Android's and Chrome's own captive-portal
     detectors use) answers anything other than an empty 204 — a 200 with a
     body, or a redirect, is a login page intercepting the request.
   - **DNS hijacked/filtered** — the system resolver's answer for a small set
     of pinned, stable domains disagrees with (or the system resolver fails
     while) the DoH fallback already wired into `util::curl_client` succeeds
     for the same domain at roughly the same time: the two paths give
     different truths.
   - **TLS interception** — a request to a pinned domain completes but the
     leaf certificate's issuer is not one of a small allow-list of public
     CAs, reusing `cert_intel`'s existing `.tls_info(true)` capture
     (REQ-CERTINTEL-001) rather than a second TLS-parsing path.
   Exposed on `hse doctor`, the radar's disruption review (a new finding
   kind carried beside the Wi-Fi-link findings, not a separate surface), and
   the Radar view. Proven against a real captive-portal-shaped stub server
   (200 + HTML where 204 is expected) and a DNS stub that disagrees with
   itself, not asserted from the classifier's own logic.
4. **A session the OS kills is one tap from resumed.** (Likewise: its own
   id and ledger entry land with the implementation, not before it.)
   `core::live` says plainly: "Sessions are in-memory only. Restart →
   cleared." True today, and REQ-RESILIENCE-001 made that visible rather
   than silent — but visible-and-lost is not resilient against exactly the
   failure mode this cycle's directive names: Android's battery optimiser,
   Doze, an OOM eviction, or a plain reboot killing the Termux process mid
   live-radar with no cooperative shutdown to persist anything. A killed
   ONE-SHOT scan already survives this (REQ-SCANSTATUS-001: the row reads
   `interrupted`, and every sighting up to the kill is on disk) — a live
   SESSION's own configuration (target, `ScanOptions`, `LiveOptions`, the
   live-id, when it started, how many iterations it has completed) does not,
   because nothing ever writes it down. Persist a `live_sessions` row
   (mirroring `wifi_links`: append-only-ish, one authoritative row per
   session, written on start and on each iteration boundary — never on the
   async reactor) with enough to reconstruct the session, not the whole
   engine state; on `hse serve` startup, read every row whose status is
   still "running" (the process that owned it is provably gone, or this
   read would not be happening) and surface them as **resumable**, not
   silently re-started — the operator's `passive_only`/`modules`/`depth`
   scope controls are a deliberate choice this fix must never override by
   guessing. `GET /api/v1/live` already lists sessions; extend it (and the
   Radar view's `adoptRunningRadar`, which already re-attaches a session
   still listed) to also list resumable-but-dead ones with a Resume action,
   so cycle 1's "re-attached if still listed" and this cycle's "listed even
   after the process died" are the same code path, not two. Proven by
   `kill -9` on a live radar mid-run and a restart on the same database: the
   session is offered for resume, not silently absent.
5. **Advice and, where Termux allows and the operator opts in, action:**
   PMF/802.11w, cell-data fallback, re-enabling Wi-Fi after a drop, switching
   egress path on a classified captive portal.

The rule the track starts with: **a stream is a refresh signal, not a source
of truth** — anything a page shows must be re-derivable from the store on
demand, so a dropped link costs a delay and never a fact.

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

### Steps 1–5 are a procedure; these two parts of them are now properties

Step 5 was purely remembered, and it drifted: between 2026-09-18 and 2026-09-19
fourteen requirements shipped while this document stood still, and §4 went on
naming three *fixed* defects as open siblings. A repeated manual procedure
standing in for a structural property is the third recurring shape in §4, and
the answer is the same one applied to the sixteen breaker resets — make the
drift fail the suite.

Two guards in `tests/doc_drift.rs` now hold the organising documents to each
other, with **`REQUIREMENTS_LEDGER.md` as the single authority** for what a
requirement is:

| Guard | What it refuses |
|---|---|
| `the_map_never_cites_a_requirement_the_ledger_does_not_record` | A `REQ-…` cited in this file or `CHANGELOG.md` with no ledger entry of its own — a claim with no transcript behind it. This is what let §4 describe three shipped fixes as open: none of the three had a ledger entry at all. |
| `every_requirement_the_ledger_records_is_accounted_for_in_the_changelog` | A ledger entry `CHANGELOG.md` never mentions. One line per requirement is the whole cost, and it makes the changelog impossible to leave behind. Refuted and measured-only leads count: *"we looked and changed nothing"* is an answer, not an omission. |

A check that can only report failure must separately prove it **ran**. A
falsification helper that grepped for `FAILED` lines reported four mutations
survived when the session disk had filled and `cargo test` never built at all —
absence of failures is indistinguishable from absence of a run
(REQ-TYPOSQUAT-001). The same shape has now appeared three times in one wave:
a mutation that could not reach its control past an early return
(REQ-WIKIDATA-001), a fixture that did not survive `trim()` before the length it
asserted was measured (REQ-KEYBASE-001), and this one in the verification
tooling itself. **Vacuity discipline applies to the harness, not only to the
tests it runs.**

Both are backed by `the_requirement_id_scanner_reads_the_shapes_the_documents_use`,
which pins the identifier shapes the corpus actually contains — without it, a
scanner that silently stopped matching would make both guards pass on any pair
of documents.

What the guards deliberately do **not** check is the part that cannot be
mechanised: whether §2's structure claims, §3's seams and §4's ranking still
describe the code. That judgement stays in step 5 — but it is now the only part
of it that does, and a stale citation can no longer hide underneath it.

They have one further blind spot, stated here rather than discovered later: a
shipped fix that has **no ledger entry and is cited nowhere** is invisible to
both. Guard one only sees what the map cites; guard two only sees what the
ledger defines. `REQ-AURDAP-001` surfaced the moment §4 cited it as a recurring-
shape instance, but its sibling `REQ-AURDAP-002` had shipped equally unrecorded
and was found only by looking — it was entered at the same time. Closing that
gap properly would mean reading commit history, which is not reproducible from a
source tarball and so does not belong in the test suite. It stays a step-2
("re-map authority") obligation: when a module is touched, check that the
requirements it already shipped are recorded.
