# R1 Evidence Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Huntsman's first-principles canonical domain/evidence kernel without weakening current behavior, while making evidentiary independence fail-closed and explicitly distinct from record identity and deduplication.

**Architecture:** Convert the repository into a Rust workspace while retaining the existing `huntsman-recon` root package/binary. Add two dependency-light crates: `hse-domain` for stable domain vocabulary/canonical IDs and `hse-evidence` for evidence layers, provenance, ancestry, equivalence, and independent-root support. Keep current root types operational as the differential oracle and bridge them conservatively through `src/r1_migration.rs`.

**Tech Stack:** Rust 1.87+/edition 2024, serde/serde_json, thiserror, RustCrypto `sha2` for new versioned IDs, existing root reconstruction as differential oracle, existing Android aarch64 CI path.

**Spec:** `docs/superpowers/specs/2026-10-03-r1-evidence-kernel-design.md`

## Global Constraints

- Deployed engine remains Rust-only with no runtime LLM dependency.
- The root `huntsman-recon` package remains the single primary deployable binary.
- Rust floor remains exactly `1.87`; edition remains `2024`.
- Android remains unprivileged aarch64/Termux-compatible; cross-build is evidence only for cross-build, not handset operation.
- Record identity, equivalence/deduplication, and evidentiary independence MUST be separate types and semantics.
- Content equality may collapse support; content inequality MUST NOT establish independence.
- Provider/source/URL/acquisition/record count MUST NOT establish independent roots.
- Unknown root identity MUST contribute zero proven independent support.
- Derived nodes MUST have parents; missing parents and cycles fail closed.
- New IDs are versioned, domain-separated, length-prefixed SHA-256; historical ledger hashes are unchanged.
- Current behavior is a differential oracle, not the specification; conservative divergence is permitted only when it prevents unsupported evidentiary promotion and is covered by a test.
- No provider, transport, persistence, CLI/UI, or platform dependency enters `hse-domain` or `hse-evidence`.

## Review Focus

1. **Modified mirrors with different bytes** — different digests must never become independent roots; Task 5 pins this.
2. **Two query providers exposing one upstream record** — provider/row IDs must not manufacture two roots; Tasks 3 and 5 pin this.
3. **Legacy inferred evidence without usable ancestry** — migration must preserve payload while refusing to promote it to direct observation; Task 6 pins this.
4. **Very deep or diamond ancestry** — support traversal must remain iterative, bounded, and non-exponential; Task 5 pins this.
5. **Canonicalization drift** — new entity canonical forms must match current proven behavior for supported inputs, while new IDs intentionally differ and preserve legacy IDs as metadata; Tasks 2 and 6 pin this.

---

### Task 1: Establish the workspace without changing runtime behavior

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/hse-domain/Cargo.toml`
- Create: `crates/hse-domain/src/lib.rs`
- Create: `crates/hse-evidence/Cargo.toml`
- Create: `crates/hse-evidence/src/lib.rs`
- Modify: `Cargo.lock`

**Interfaces:**
- Consumes: current root package metadata from `Cargo.toml`.
- Produces: workspace members `.`, `crates/hse-domain`, `crates/hse-evidence`; both new crates compile as empty libraries on Rust 1.87 and stable.

- [ ] **Step 1: Write the failing workspace check**

Add a temporary integration assertion in `tests/r1_workspace.rs` that reads root `Cargo.toml` and requires workspace members `crates/hse-domain` and `crates/hse-evidence` while preserving package name `huntsman-recon`.

- [ ] **Step 2: Run the check to verify RED**

Run: `cargo test --locked --test r1_workspace workspace_declares_r1_crates`

Expected: FAIL because the workspace/crates do not exist.

- [ ] **Step 3: Add the workspace and minimal crate manifests**

Root `Cargo.toml` gains:

```toml
[workspace]
members = [".", "crates/hse-domain", "crates/hse-evidence"]
resolver = "2"
```

`hse-domain` and `hse-evidence` each use version `0.1.0`, edition `2024`, rust-version `1.87`, `publish = false`, `unsafe_code = "deny"`, and pedantic clippy warnings. `hse-evidence` depends on `hse-domain` by path. Do not yet add root path dependencies.

- [ ] **Step 4: Regenerate the lockfile and verify GREEN**

Run: `cargo update -w && cargo test --workspace --locked --test r1_workspace workspace_declares_r1_crates`

Expected: PASS.

- [ ] **Step 5: Verify the existing root binary still builds unchanged**

Run: `cargo build -p huntsman-recon --locked`

Expected: exit 0; binary target remains `huntsman-recon`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/hse-domain crates/hse-evidence tests/r1_workspace.rs
git commit -m "build(r1): establish domain evidence workspace"
```

### Task 2: Implement canonical domain vocabulary and deterministic record IDs

**Files:**
- Create: `crates/hse-domain/src/id.rs`
- Create: `crates/hse-domain/src/canonical.rs`
- Create: `crates/hse-domain/src/entity.rs`
- Create: `crates/hse-domain/src/selector.rs`
- Create: `crates/hse-domain/src/relation.rs`
- Create: `crates/hse-domain/src/value.rs`
- Create: `crates/hse-domain/src/time.rs`
- Modify: `crates/hse-domain/src/lib.rs`
- Modify: `crates/hse-domain/Cargo.toml`
- Create: `crates/hse-domain/tests/domain_contract.rs`
- Create: `tests/r1_domain_differential.rs`

**Interfaces:**
- Consumes: current `src/entity.rs::EntityKind`, `src/entity.rs::normalise`, `src/canonical.rs`, `src/graph.rs::RelationKind` as differential evidence.
- Produces:
  - `stable_id(namespace: &str, version: u16, parts: &[&[u8]]) -> String`
  - `EntityKind`, `EntityId`, `Entity`, `EntityRef`
  - `Selector { kind: EntityKind, raw_value: String, canonical_value: String }`
  - `RelationKind`, `Relation`
  - `Predicate::new(&str) -> Result<Predicate, DomainError>`
  - `EvidenceValue`
  - `TimeValue::{Unknown, Instant, Range}`
  - `canonicalize_entity_value(kind: &EntityKind, raw: &str) -> String`

- [ ] **Step 1: Write failing ID tests**

In `domain_contract.rs`, add tests asserting:
- repeated `stable_id("entity", 1, &[b"email", b"a@example.com"])` is identical;
- `stable_id("x", 1, &[b"ab", b"c"]) != stable_id("x", 1, &[b"a", b"bc"])`;
- changing namespace or version changes the ID;
- output is exactly 64 lowercase hex characters.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p hse-domain --test domain_contract stable_id_`

Expected: FAIL because `stable_id` is absent.

- [ ] **Step 3: Implement the ID preimage contract**

In `id.rs`, implement `stable_id(namespace, version, parts)` using RustCrypto `sha2` with this exact byte layout:

`b"HSEID\0" || u32_be(namespace_len) || namespace || u16_be(version) || u32_be(part_count) || each(u64_be(part_len) || part)`.

Add `sha2 = "0.10"` plus serde/thiserror dependencies needed by the crate. Do not change root `src/sha256.rs` or ledger hashing.

- [ ] **Step 4: Verify ID GREEN**

Run: `cargo test -p hse-domain --test domain_contract stable_id_`

Expected: PASS.

- [ ] **Step 5: Write failing canonical/domain tests**

Add contract tests for:
- `EntityKind` variants matching the current root set;
- email/domain/url/username/coordinates/AU phone canonicalization examples already proven by current tests;
- Unicode/whitespace name normalization matching current supported behavior;
- `Entity::new(kind, raw)` preserving both raw and canonical values and deriving `EntityId` from canonical value;
- `TimeValue::Unknown` surviving serde round-trip;
- `EvidenceValue::Object(BTreeMap<...>)` serializing deterministically independent of insertion order;
- `Predicate::new` rejecting empty/whitespace and accepting stable identifiers such as `identity.email`.

- [ ] **Step 6: Implement focused domain modules**

Use the current reconstruction as a behavior oracle, but reimplement inside `hse-domain` so it has no dependency on the root crate. Preserve current canonical outputs for the supported EntityKind inputs covered by differential tests. Keep the new entity ID algorithm separate from legacy `derive_uid`.

- [ ] **Step 7: Add root-vs-new differential tests**

In `tests/r1_domain_differential.rs`, compare current `crate::entity::normalise`/`RelationKind` behavior against `hse_domain` across representative valid, invalid, Unicode, whitespace, tracking-URL, coordinate, and AU-phone fixtures. Assert canonical-value equivalence; explicitly assert legacy UID and new `EntityId` are different algorithms and both remain available.

- [ ] **Step 8: Verify domain and differential GREEN**

Run: `cargo test -p hse-domain --locked && cargo test -p huntsman-recon --locked --test r1_domain_differential`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/hse-domain tests/r1_domain_differential.rs Cargo.lock
git commit -m "feat(r1): add canonical domain contracts"
```

### Task 3: Implement evidence identity, artifact, equivalence, and root provenance types

**Files:**
- Create: `crates/hse-evidence/src/identity.rs`
- Create: `crates/hse-evidence/src/artifact.rs`
- Create: `crates/hse-evidence/src/root.rs`
- Modify: `crates/hse-evidence/src/lib.rs`
- Modify: `crates/hse-evidence/Cargo.toml`
- Create: `crates/hse-evidence/tests/root_contract.rs`

**Interfaces:**
- Consumes: `hse_domain::{Selector, TimeValue, stable_id}`.
- Produces:
  - `AcquisitionId`, `EvidenceNodeId`
  - validated `Sha256Digest`
  - `ArtifactRef::{Retained, External, MetadataOnly}`
  - `RootIdentity::{Established, Unresolved}`
  - private-construction `IndependentRootKey`, obtainable only through `RootIdentity::independent_key()`
  - `EquivalenceKey::{ContentDigest, UpstreamRecord, SourceArtifact, LegacyFamily}`
  - `EvidenceRoot`

- [ ] **Step 1: Write failing independence-boundary tests**

Assert:
- `RootIdentity::Unresolved.independent_key()` is `None`;
- only `RootIdentity::established(non_empty_namespace, non_empty_id)` can yield an independent key;
- query provider, provider record ID, URL, acquisition ID, and content digest are fields/equivalence evidence but expose no conversion API to `IndependentRootKey`;
- empty/whitespace established root identifiers are rejected.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p hse-evidence --test root_contract root_identity_`

Expected: FAIL because the types do not exist.

- [ ] **Step 3: Implement root/equivalence types**

`IndependentRootKey` keeps its inner value private. `RootIdentity::Established` construction validates non-empty canonical namespace/id and derives a deterministic key with `hse_domain::stable_id("independent-root", 1, ...)`. Equivalence keys are sortable/hashable and can only collapse support later.

`EvidenceRoot` stores: `root_identity`, `equivalence_keys`, `acquisition_id`, optional query/upstream/original-source/provider-record/source-URI fields, `ArtifactRef`, event/publication/ingest/retrieval `TimeValue`s, optional `Selector`, and ordered provenance path.

- [ ] **Step 4: Add artifact/digest tests**

Assert lowercase 64-hex validation, `MetadataOnly` requires a non-empty reason, serde round-trip preserves unknown times, and identical content digests are equivalence keys only.

- [ ] **Step 5: Verify GREEN**

Run: `cargo test -p hse-evidence --test root_contract`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hse-evidence Cargo.lock
git commit -m "feat(r1): model evidence roots and equivalence"
```

### Task 4: Implement distinct evidence layers and provider-neutral propositions

**Files:**
- Create: `crates/hse-evidence/src/proposition.rs`
- Create: `crates/hse-evidence/src/layer.rs`
- Modify: `crates/hse-evidence/src/lib.rs`
- Create: `crates/hse-evidence/tests/layer_contract.rs`

**Interfaces:**
- Consumes: `hse_domain::{EntityRef, EvidenceValue, Predicate, stable_id}` and Task 3 evidence identity/root types.
- Produces:
  - `Proposition { subject: EntityRef, predicate: Predicate, object: EvidenceValue }`
  - `Observation { id, subject, predicate, value, root, summary, attributes }`
  - `Assertion { id, proposition, parents }`
  - `Inference { id, proposition, rule, parents }`
  - `Claim { id, proposition, parents }`
  - `EvidenceRecord` enum with `id()`, `parents()`, and `kind()` accessors.

- [ ] **Step 1: Write failing layer-separation tests**

Assert direct `Observation` has an `EvidenceRoot` and no parents; Assertion/Inference/Claim constructors reject empty parent sets; an `Inference` rule must be non-empty; deterministic IDs are unaffected by BTreeMap insertion order.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p hse-evidence --test layer_contract`

Expected: FAIL because layer types are absent.

- [ ] **Step 3: Implement minimal typed layers**

Use separate structs, not flags. Observation records direct source material. Assertion/Inference/Claim are derived records and therefore require parents at construction. Their stable IDs include record kind, canonical proposition content, ordered parent IDs, and for Inference the rule identifier.

- [ ] **Step 4: Falsify silent directness upgrades**

Add tests proving there is no constructor path from an Inference/Claim to Observation and serde round-trips preserve the enum variant exactly.

- [ ] **Step 5: Verify GREEN**

Run: `cargo test -p hse-evidence --test layer_contract`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hse-evidence/src crates/hse-evidence/tests/layer_contract.rs
git commit -m "feat(r1): separate evidence semantic layers"
```

### Task 5: Implement validated ancestry DAG and independent-support analysis

**Files:**
- Create: `crates/hse-evidence/src/ancestry.rs`
- Create: `crates/hse-evidence/src/support.rs`
- Modify: `crates/hse-evidence/src/lib.rs`
- Create: `crates/hse-evidence/tests/ancestry_contract.rs`

**Interfaces:**
- Consumes: `EvidenceRecord`, `EvidenceNodeId`, `RootIdentity`, `IndependentRootKey`, `EquivalenceKey`.
- Produces:
  - `EvidenceDag::insert(record: EvidenceRecord) -> Result<(), EvidenceError>`
  - `EvidenceDag::validate() -> Result<(), EvidenceError>`
  - `EvidenceDag::support_summary(ids: impl IntoIterator<Item = &EvidenceNodeId>) -> Result<SupportSummary, EvidenceError>`
  - `SupportSummary::proven_independent_count() -> usize`
  - `SupportSummary::meets_threshold(required: usize) -> bool`
  - deterministic `RootGroup { roots, equivalence_keys }`
  - explicit unresolved-support set.

- [ ] **Step 1: Write failing structural tests**

Cover duplicate node IDs, derived-without-parent, missing parent, self-cycle, multi-node cycle, and malformed serialized graphs. Deserialization must revalidate graph invariants rather than bypass constructors.

- [ ] **Step 2: Verify structural RED**

Run: `cargo test -p hse-evidence --test ancestry_contract rejects_`

Expected: FAIL.

- [ ] **Step 3: Implement iterative DAG validation/traversal**

Use an iterative three-colour walk equivalent in safety properties to current `src/evidence_ancestry.rs`; no recursive graph traversal. A root Observation is the only parentless evidence record.

- [ ] **Step 4: Write failing support-semantics tests**

Cover all spec-critical cases:
- one established root -> one;
- diamond/mirrors of one root -> one;
- two established root identities with no known collapse -> two;
- unresolved roots -> zero proven independent support;
- same `IndependentRootKey` through two query providers -> one;
- same `EquivalenceKey::ContentDigest` on two apparent roots -> at most one group;
- different content digests alone -> still zero independent support when root identities are unresolved;
- different provider/reseller record IDs alone -> zero independent support;
- identical content via different providers may collapse, never increase support.

- [ ] **Step 5: Implement support grouping**

Traverse to supporting observations, then conservatively union support atoms that share an `IndependentRootKey` or any `EquivalenceKey`. Only groups containing at least one established `IndependentRootKey` count. Unresolved support never increments the count. Distinct established roots count separately only when no known root/equivalence relation joins them.

- [ ] **Step 6: Add deep/diamond stress tests**

Port the current 200,000-node deep-chain safety case and 60-level diamond case. Add a modified-mirror case with different bytes but unresolved root identity and assert proven count remains zero.

- [ ] **Step 7: Verify GREEN and compare old/new semantics**

Run: `cargo test -p hse-evidence --locked --test ancestry_contract`

Expected: PASS.

Then run: `cargo test -p huntsman-recon --locked evidence_ancestry`

Expected: current oracle tests remain PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/hse-evidence/src crates/hse-evidence/tests/ancestry_contract.rs
git commit -m "feat(r1): enforce fail-closed evidence ancestry"
```

### Task 6: Add conservative migration adapters from the current reconstruction

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/evidence_ancestry.rs`
- Create: `src/r1_migration.rs`
- Modify: `src/lib.rs`
- Create: `tests/r1_migration.rs`
- Modify: `Cargo.lock`

**Interfaces:**
- Consumes: current `Entity`, `Evidence`, `EvidenceProvenance`, `EvidenceAncestryGraph`, plus `hse_domain` and `hse_evidence` contracts.
- Produces:
  - read-only `EvidenceAncestryGraph::iter()` for migration only;
  - `MigrationIssue` enum;
  - `MigratedEntity { entity, legacy_uid, legacy_metadata, records, dag, issues }`;
  - `migrate_entity(entity: &crate::Entity, ancestry: Option<&crate::evidence_ancestry::EvidenceAncestryGraph>) -> MigratedEntity`.

- [ ] **Step 1: Write failing migration-accounting tests**

Construct legacy entities containing every current field: UID, kind, canonical/raw values, confidence, corroboration, observed time, evidence summary/attributes/verification/is_inferred/ancestry, tags, scan ID, generation. Assert migration either preserves each value in a typed destination/legacy metadata or emits a specific `MigrationIssue`; silent loss is forbidden.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p huntsman-recon --locked --test r1_migration migration_accounts_for_every_legacy_field`

Expected: FAIL because the adapter is absent.

- [ ] **Step 3: Add root path dependencies and read-only ancestry iteration**

Root package depends on `hse-domain` and `hse-evidence` by path. Add `EvidenceAncestryGraph::iter(&self) -> impl Iterator<Item = &EvidenceAncestryNode>` without changing insertion/query semantics; cover the new accessor with a unit test.

- [ ] **Step 4: Implement entity/provenance migration**

Map current EntityKind/Relation vocabulary explicitly. Preserve `legacy_uid` separately while deriving the new EntityId from canonical semantics. Store current confidence/corroboration/observed-at/tags/scan/generation in ordered migration metadata until later owning subsystems decide their canonical homes.

For legacy direct evidence, create an Observation with `RootIdentity::Unresolved`; provider/source/family/scan/timestamp/summary/attributes remain traceable. `source_family` may become conservative `EquivalenceKey::LegacyFamily`, but never an independent-root identity.

- [ ] **Step 5: Preserve inferred evidence without upgrading it**

When `Evidence::is_inferred` is true and usable ancestry parents exist, migrate it as an `Inference` with parents mapped deterministically from legacy ancestry node IDs. If usable parents are absent, preserve the full legacy payload in migration metadata and emit `MigrationIssue::InferredWithoutUsableAncestry`; do not emit a direct Observation.

- [ ] **Step 6: Migrate ancestry conservatively**

Map valid current ancestry into the new DAG with deterministic legacy-node IDs. Current root `source_family` labels become equivalence hints/unresolved roots only. A migrated current graph may therefore have a lower proven independent-root count than current `root_families()`; add a differential test documenting this intentional fail-closed divergence.

- [ ] **Step 7: Add adversarial migration tests**

Cover empty family, missing parent, cycles, duplicated legacy evidence, same family through multiple providers, Unicode canonical values, inferred evidence without ancestry, and reordered attribute maps.

- [ ] **Step 8: Verify migration and all old tests**

Run:

```bash
cargo test -p huntsman-recon --locked --test r1_migration
cargo test -p huntsman-recon --locked
```

Expected: PASS with no pre-existing root regressions.

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock src/evidence_ancestry.rs src/r1_migration.rs src/lib.rs tests/r1_migration.rs
git commit -m "feat(r1): migrate legacy evidence conservatively"
```

### Task 7: Make workspace verification and Android cross-build prove the new boundary

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/r1_workspace.rs`
- Modify: `README.md`
- Modify: `docs/RECONSTRUCTION_2026-10-02.md`

**Interfaces:**
- Consumes: completed R1 crates and migration adapters.
- Produces: CI that tests/clippies/formats the entire workspace while still building one Android root binary; repository documentation that bounds R1's verification state accurately.

- [ ] **Step 1: Strengthen workspace dependency-boundary checks**

Extend `tests/r1_workspace.rs` to inspect `crates/hse-domain/Cargo.toml` and `crates/hse-evidence/Cargo.toml`. Assert no dependencies on `ureq`, root package, providers, persistence/database crates, CLI/UI frameworks, Android/Termux APIs, or platform modules. Assert `hse-evidence` depends only on `hse-domain` plus approved pure support crates.

- [ ] **Step 2: Verify the boundary test passes locally**

Run: `cargo test -p huntsman-recon --locked --test r1_workspace`

Expected: PASS.

- [ ] **Step 3: Update CI commands to workspace scope**

Use:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run -p huntsman-recon --locked -- check
cargo build -p huntsman-recon --release --locked --target aarch64-linux-android
```

Keep the existing ELF `AArch64` and `/system/bin/linker64` verification and main-branch artifact staging unchanged in meaning.

- [ ] **Step 4: Update documentation without overclaiming**

Document R1 as IMPLEMENTED/UNIT+INTEGRATION verified only after commands pass. State Android status as cross-compiled/ELF-verified only if CI proves it; do not claim handset/live/operational verification.

- [ ] **Step 5: Run the full local verification gate**

Run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run -p huntsman-recon --locked -- check
git diff --exit-code -- var/
```

Expected: all exit 0 and `var/` unchanged.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml tests/r1_workspace.rs README.md docs/RECONSTRUCTION_2026-10-02.md
git commit -m "ci(r1): verify evidence workspace boundaries"
```

### Task 8: Final falsification, regression, and retirement decision

**Files:**
- Modify only if falsification exposes a defect.
- Do not delete current `Entity`, `Evidence`, `evidence_ancestry`, or ledger implementation in R1.

**Interfaces:**
- Consumes: all R1 outputs.
- Produces: evidence-backed R1 status and explicit surviving/retired paths.

- [ ] **Step 1: Re-run proof-obligation matrix**

Map all 18 R1 acceptance obligations in the spec to exact tests/commands. Any obligation without claim-specific evidence remains unverified and blocks R1 completion.

- [ ] **Step 2: Falsify the strongest rival explanation**

Attempt to make independent support increase using only: duplicate providers, duplicate URLs, duplicate acquisitions, distinct reseller record IDs, different content hashes, transformed mirrors, reordered payloads, or inferred descendants. Every attempt must fail to increase proven independent-root count unless an Established underlying root identity is supplied.

- [ ] **Step 3: Regression-check current behavior**

Run the full Task 7 local gate again from a clean tree. Compare current entity canonicalization fixtures and current ancestry tests against their pre-R1 outputs. Intentional semantic divergences must be limited to documented fail-closed independence behavior.

- [ ] **Step 4: Verify Android CI evidence**

After pushing the implementation branch, inspect the GitHub Actions run for the exact head commit. Require green Rust 1.87/stable workspace tests plus green Android aarch64 build/ELF checks before claiming those states.

- [ ] **Step 5: Apply retirement gate**

Retain current root `Entity`, `Evidence`, `evidence_ancestry`, and ledger paths because later consumers still depend on them. Record them as MIGRATE/PRESERVE-until-R9/R12, not REMOVE. Remove only temporary test scaffolding that has no continuing proof value.

- [ ] **Step 6: Commit any evidence-driven repairs and stop R1 only at verified acceptance**

If no repairs were necessary, no synthetic final commit is required. R1 status must state exactly which levels were demonstrated: unit/integration, Android cross-build, handset, live, operational.
