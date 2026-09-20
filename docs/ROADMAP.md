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

   **A fix is only as permanent as its least-locked call site.**
   REQ-WIGLE-001 applied the band gate to three sites and locked one; two could
   be reverted with all 52 of the module's tests still green (REQ-GEOGATE-001).
   The same gap appeared in REQ-ZOOMEYE-002, REQ-DOCPARSE-002 and
   REQ-SEEKNOW-001 before it. Its rule: **mutate every call site, not the shared
   helper** — a helper-level lock proves the helper, and says nothing about who
   calls it.

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
