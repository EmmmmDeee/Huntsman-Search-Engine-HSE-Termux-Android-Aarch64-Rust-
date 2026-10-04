# IP Investigation Reconstruction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust-first `huntsman-recon ip <IP> [--json] [--deep] [--evidence]` investigation path that produces temporally explicit, provenance-preserving infrastructure evidence with bounded adaptive execution.

**Architecture:** Preserve the current guarded HTTP/fetch, evidence, ancestry, provider-economics, termination, and Android build foundations. Add one focused `src/ip/` subsystem containing pure IP semantics, a provider boundary, standards/current-source providers, claim aggregation, an adaptive orchestrator, and renderers; wire the current Rust binary to it without restoring the legacy monolith.

**Tech Stack:** Rust 2024, MSRV 1.87, `std`, existing `serde`, `serde_json`, `thiserror`, `ureq`; no runtime LLM and no additional language runtime.

**Spec:** `docs/superpowers/specs/2026-10-04-ip-investigation-reconstruction-design.md`

## Global Constraints

- Implement product logic, orchestration, validation, parsing, rendering, provider adapters, and test harnesses in Rust wherever practical.
- Non-Rust additions are limited to unavoidable static fixtures or CI/configuration glue; prefer Rust fixture constructors over external scripts.
- Keep a single Rust crate and current guarded HTTP/fetch boundary unless evidence proves a change necessary.
- Keep Rust 1.87 compatibility unless a higher MSRV has verified positive net value.
- Treat non-root Termux/Android ARM64 as a first-class platform.
- Use no runtime LLM.
- Never treat an IP address as a person, an empty source result as verified absence, or multiple collectors of one upstream dataset as independent evidence.
- Keep observation/event time separate from retrieval time.
- Make provider failures explicit and preserve useful partial results.
- Do not modify `legacy/` or the pinned legacy zip archives.
- Use TDD: every production behavior begins with a failing Rust test that is observed failing for the intended reason.

## Review Focus

- IPv4-mapped IPv6 and special/documentation addresses must not bypass public-target checks; pin in Task 1.
- Truncated/malformed 200 responses must become parse/schema failures rather than clean empty evidence; pin in Tasks 2-4.
- Historical timestamps must never render as current merely because retrieval is recent; pin in Task 5.
- Two providers that declare the same upstream lineage must not become two independent supports; pin in Task 5.
- Deep mode must terminate deterministically under duplicate/no-value actions and finite budgets; pin in Task 6.

---

### Task 1: Pure IP target and investigation model

**Files:**
- Create: `src/ip/mod.rs`
- Create: `src/ip/model.rs`
- Modify: `src/lib.rs`
- Create: `tests/ip_model.rs`

**Interfaces:**
- Consumes: `validation::is_non_routable_ip`, `validation::is_bogus_ip`, `entity::{Evidence, EvidenceProvenance}`, `source_outcome::SourceOutcomeKind`.
- Produces: `IpTarget::parse(&str) -> Result<IpTarget, IpInputError>`, `IpScope`, `IpObservationKind`, `TemporalState`, `IpObservation`, `IpFailure`, `IpClaimState`, `IpClaim`, `IpInvestigation`.

- [ ] **Step 1: Write failing Rust tests for target parsing and invariants**
  - `public_ipv4_is_canonical_and_public`
  - `public_ipv6_is_canonical_and_public`
  - `ipv4_mapped_ipv6_inherits_ipv4_scope`
  - `private_loopback_documentation_and_reserved_are_not_public`
  - `invalid_input_is_rejected`
  - `ip_claim_model_has_no_person_attribution_variant`

- [ ] **Step 2: Run `cargo test --test ip_model` and verify RED**
  Expected: compile/test failure because `huntsman_recon::ip` does not exist.

- [ ] **Step 3: Implement the minimal pure model**
  - `IpTarget` stores canonical `std::net::IpAddr`, original text, and `IpScope`.
  - `IpScope` distinguishes at least `Public`, `Private`, `Loopback`, `LinkLocal`, `Multicast`, `DocumentationOrReserved`, `Unspecified`.
  - `IpClaimState` is proof-state oriented (`Unknown`, `Supported`, `Contradicted`, `Invalidated`), not a confidence score.
  - `IpObservation` stores provider/source identity, lineage family, observation time `Option<u64>`, retrieval time, kind, summary, attributes, and optional raw digest.
  - `IpInvestigation` owns observations, failures, claims, actions considered, budget counters, and termination reason.

- [ ] **Step 4: Run `cargo test --test ip_model` and full `cargo test`**
  Expected: PASS with no regression.

- [ ] **Step 5: Commit**
  `git commit -m "feat(ip): add pure investigation model and target validation"`

### Task 2: Rust provider boundary and explicit failure mapping

**Files:**
- Create: `src/ip/provider.rs`
- Modify: `src/ip/mod.rs`
- Create: `tests/ip_provider.rs`

**Interfaces:**
- Consumes: Task 1 model, `http::{Request, Response, Transport}`, `fetch::{fetch, FetchOptions}`, `module::ProviderDescriptor`, `source_outcome::SourceOutcomeKind`.
- Produces: `IpCapability`, `IpProviderAction`, `IpProviderResult`, `IpProvider` trait, `execute_provider_action(...) -> IpProviderResult`.

- [ ] **Step 1: Write failing Rust tests for provider execution semantics**
  - 200 + valid parser rows yields observations.
  - 200 + malformed body yields `IpFailure::Parse`/schema failure, never empty evidence.
  - truncated response cannot become verified empty evidence.
  - DNS/connect/timeout cause is preserved.
  - 401/429/source failures remain explicit.
  - provider action contains a lineage family distinct from collector name.

- [ ] **Step 2: Run `cargo test --test ip_provider` and verify RED**

- [ ] **Step 3: Implement provider contract**
  Exact trait surface:
  `trait IpProvider { fn id(&self) -> &'static str; fn descriptor(&self) -> ProviderDescriptor; fn capabilities(&self) -> &'static [IpCapability]; fn lineage_family(&self) -> &'static str; fn plan(&self, target: &IpTarget) -> Vec<IpProviderAction>; fn parse(&self, action: &IpProviderAction, response: &Response, retrieved_at_unix: u64) -> Result<Vec<IpObservation>, IpProviderParseError>; }`

  Route network activity only through existing `fetch`; never let provider code instantiate its own client.

- [ ] **Step 4: Run `cargo test --test ip_provider` and full `cargo test`**

- [ ] **Step 5: Commit**
  `git commit -m "feat(ip): add guarded provider boundary"`

### Task 3: Standards-based RDAP allocation provider

**Files:**
- Create: `src/ip/providers/mod.rs`
- Create: `src/ip/providers/rdap.rs`
- Modify: `src/ip/mod.rs`
- Create: `tests/ip_rdap.rs`

**Interfaces:**
- Consumes: Tasks 1-2; existing guarded fetch.
- Produces: `RdapProvider`, IANA bootstrap selection, allocation/operator observations.

- [ ] **Step 1: Write failing Rust fixture tests**
  - parse IANA IPv4 bootstrap and choose the correct RDAP base URL for a representative prefix.
  - parse IANA IPv6 bootstrap and choose the correct RDAP base URL.
  - RDAP network object emits allocation/range/name/handle/country/events as typed observations where present.
  - missing optional fields remain unknown.
  - notices indicating truncation are preserved as partial-result failure/metadata.
  - malformed/truncated JSON fails closed.

- [ ] **Step 2: Run `cargo test --test ip_rdap` and verify RED**

- [ ] **Step 3: Implement `RdapProvider` entirely in Rust**
  Fetch official IANA `ipv4.json`/`ipv6.json` bootstrap data, select a service by address-prefix containment, then request `<base>/ip/<canonical-ip>` through the guarded fetch layer. Cache bootstrap data only inside the investigation/runtime boundary with explicit freshness; do not hard-code a single RIR as universal truth.

- [ ] **Step 4: Run `cargo test --test ip_rdap` and full `cargo test`**

- [ ] **Step 5: Commit**
  `git commit -m "feat(ip): add IANA-bootstrapped RDAP allocation provider"`

### Task 4: Routing/ASN and reverse-DNS providers

**Files:**
- Create: `src/ip/providers/ripestat.rs`
- Create: `src/ip/providers/doh_ptr.rs`
- Modify: `src/ip/providers/mod.rs`
- Create: `tests/ip_routing_dns.rs`

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: `RipeStatNetworkInfoProvider`, `CloudflarePtrProvider`, ASN/prefix and PTR observations.

- [ ] **Step 1: Write failing Rust fixture tests for RIPEstat network-info**
  - routed IPv4/IPv6 response yields prefix plus every announcing ASN.
  - empty `asns` is not transformed into a negative attribution claim.
  - malformed/schema-drift response is explicit failure.

- [ ] **Step 2: Write failing Rust fixture tests for PTR over DoH**
  - IPv4 reverse name construction.
  - nibble-reversed IPv6 `ip6.arpa` construction.
  - Cloudflare DNS JSON PTR answer parsing.
  - NXDOMAIN/empty answer remains an empty observation outcome, not proof no hostname exists globally.
  - malformed/truncated response is explicit failure.

- [ ] **Step 3: Run `cargo test --test ip_routing_dns` and verify RED**

- [ ] **Step 4: Implement both providers in Rust**
  Use current documented RIPEstat `network-info` endpoint and Cloudflare DoH JSON endpoint via existing guarded HTTP/fetch; keep provider source families distinct (`ripe-ris` and `dns-ptr-cloudflare`).

- [ ] **Step 5: Run `cargo test --test ip_routing_dns` and full `cargo test`**

- [ ] **Step 6: Commit**
  `git commit -m "feat(ip): add routing and PTR enrichment providers"`

### Task 5: Claim aggregation, chronology, contradictions, and independence

**Files:**
- Create: `src/ip/claims.rs`
- Modify: `src/ip/mod.rs`
- Create: `tests/ip_claims.rs`

**Interfaces:**
- Consumes: Task 1 observations, existing `evidence_ancestry`/lineage primitives.
- Produces: `apply_observations(&mut IpInvestigation)`, contradiction sets, lineage-aware support counts, temporal state derivation.

- [ ] **Step 1: Write failing Rust tests**
  - two observations with one upstream lineage count as one independent root.
  - two genuinely distinct lineages remain two roots.
  - conflicting ASN/prefix/operator facts remain explicit contradictions.
  - old observation time + recent retrieval time stays `Historical`/`Stale`, never `Current`.
  - missing observation time yields `UnknownCurrent`, not current.
  - no path can construct person attribution from infrastructure observations alone.

- [ ] **Step 2: Run `cargo test --test ip_claims` and verify RED**

- [ ] **Step 3: Implement minimal deterministic aggregation**
  Do not average contradictions away and do not use provider count as proof. Reuse ancestry/lineage concepts where their contracts fit; otherwise preserve explicit source-family roots in IP state without duplicating identity-resolution policy.

- [ ] **Step 4: Run `cargo test --test ip_claims` and full `cargo test`**

- [ ] **Step 5: Commit**
  `git commit -m "feat(ip): add temporal contradiction-aware claim aggregation"`

### Task 6: Bounded adaptive Rust orchestrator

**Files:**
- Create: `src/ip/orchestrator.rs`
- Modify: `src/ip/mod.rs`
- Create: `tests/ip_orchestrator.rs`

**Interfaces:**
- Consumes: Tasks 1-5, existing `termination` concepts and provider descriptors.
- Produces: `IpBudget`, `IpMode`, `run_investigation(...) -> IpInvestigation`, deterministic action ranking/termination.

- [ ] **Step 1: Write failing Rust tests**
  - base mode executes mandatory RDAP/routing/PTR actions within budget.
  - evidence arrival changes the next action ranking where new unresolved pivots appear.
  - duplicate-upstream/duplicate-target actions are suppressed.
  - `--deep` stops at fixed point when no positive-value action remains.
  - call/depth/action budget exhaustion terminates deterministically and records the bound.
  - provider failure does not stop independent remaining actions.

- [ ] **Step 2: Run `cargo test --test ip_orchestrator` and verify RED**

- [ ] **Step 3: Implement bounded ranking**
  Rank by unresolved objective contribution, evidence independence, provider reliability prior, historical/freshness value, optionality, and cost/resource burden. Keep ranking as action selection only; it must never mutate claim proof state directly.

- [ ] **Step 4: Run `cargo test --test ip_orchestrator` and full `cargo test`**

- [ ] **Step 5: Commit**
  `git commit -m "feat(ip): add bounded adaptive investigation orchestrator"`

### Task 7: Rust CLI, shared renderers, and end-to-end acceptance

**Files:**
- Create: `src/ip/render.rs`
- Modify: `src/main.rs`
- Modify: `README.md`
- Modify: `tests/cli.rs`
- Create: `tests/ip_cli.rs`

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: real binary command `huntsman-recon ip <IP> [--json] [--deep] [--evidence]`, `render_text(&IpInvestigation) -> String`, `render_json(&IpInvestigation) -> Result<String, serde_json::Error>`.

- [ ] **Step 1: Write failing binary acceptance tests**
  - missing/bad IP exits usage/data error without network.
  - private/documentation IP is explicitly classified and does not launch public-provider investigation by default.
  - `--json` parses as JSON and contains target, observations, failures, claims, budgets, termination.
  - human and JSON outputs derive from the same serialized investigation facts.
  - `--evidence` adds provenance detail without changing claim truth state.
  - partial source failure still returns useful investigation output when at least one source succeeds.

- [ ] **Step 2: Run `cargo test --test ip_cli` and verify RED**

- [ ] **Step 3: Implement CLI and renderers in Rust**
  Extend the existing manual CLI parser minimally. Do not introduce a second binary or a new CLI framework unless evidence shows the current approach is unmaintainable.

- [ ] **Step 4: Run complete verification**
  `cargo fmt --check`
  `cargo test`
  `cargo clippy --all-targets -- -D warnings`
  `cargo run -- check`
  Expected: all pass; committed `var/` remains unchanged unless an intentional contract change is separately justified.

- [ ] **Step 5: Perform current live verification where network permits**
  - RDAP via official IANA bootstrap/RIR path.
  - RIPEstat network-info.
  - PTR DoH.
  Record fixture/integration/live status separately; do not promote handset/platform state without a handset run.

- [ ] **Step 6: Commit**
  `git commit -m "feat(ip): expose evidence-gated IP investigation CLI"`

### Task 8: Falsification, platform proof, and final disposition

**Files:**
- Modify as required by findings only.
- Update: `docs/DISPOSITIONS.md` for migrated/reimplemented legacy IP files actually used.
- Update: `docs/superpowers/specs/2026-10-04-ip-investigation-reconstruction-design.md` only if verified implementation forces a design correction.

**Interfaces:**
- Consumes: complete branch.
- Produces: verified final state and explicit residual blockers.

- [ ] **Step 1: Run adversarial regression cases**
  IPv4, IPv6, mapped IPv6, private/reserved, malformed input, contradictory data, duplicate lineage, stale timestamps, empty rows, malformed JSON, HTTP 401/403/429/5xx, transport failure, truncation, and exhausted budget.

- [ ] **Step 2: Run full Rust verification again**
  `cargo fmt --check && cargo test && cargo clippy --all-targets -- -D warnings && cargo run -- check`

- [ ] **Step 3: Verify Android/Termux build path remains intact**
  Run existing Android CI contract tests/build path available in the repository. A cross-build is platform-build verification, not handset operational verification.

- [ ] **Step 4: Update dispositions only from demonstrated evidence**
  Mark legacy IP components PRESERVE/MIGRATE/REIMPLEMENT/REPLACE/REMOVE according to what actually survived implementation and verification.

- [ ] **Step 5: Final commit**
  `git commit -m "docs(ip): record verified reconstruction dispositions"`
