# Huntsman Search Engine — P0 Foundation Refactor Design

**Date:** 2026-09-29
**Parent program:** `2026-09-29-huntsman-end-to-end-refactor-program-design.md`
**Audited base:** `feef60ab48ffe4be599c2ef0f678600cdaffc2aa`
**Scope:** baseline truth, Rust-native architectural invariants, outstanding-work reconciliation, verification boundaries
**Production semantic change:** none

## 1. Objective

Before changing retrieval, evidence, identity, scheduling, or confidence semantics, make Huntsman capable of proving which repository state is authoritative and mechanically rejecting known architecture drift.

P0 converts recurring maintenance instructions into executable Rust checks and produces the canonical outstanding-work ledger that controls later tranches.

## 2. Why P0 is first

The repository already contains:
- staged evidence machinery stronger than live semantics;
- historical unresolved defects from multiple development passes;
- cross-file “keep in sync” rules;
- CI/device validity distinctions;
- older assistant findings whose current status is unknown.

Beginning semantic refactoring before proving this baseline would make later regressions impossible to attribute confidently.

## 3. Architecture

Extend the existing Rust `architecture-audit` binary rather than creating a new tool.

Proposed internal structure:

```text
src/core/architectural_invariants/
    mod.rs
    model.rs
    registry.rs
    repository.rs
    checks.rs

src/bin/architecture_audit/
    existing audit code
    invariant_command.rs

tests/
    architectural_invariants.rs
```

The exact split may adapt to existing repository conventions, but there is one production Rust invariant engine.

## 4. Model

```rust
pub enum Disposition {
    Invariantized,
    Automated,
    Procedural,
    Blocked,
    Superseded,
    Obsolete,
}

pub enum InvariantStatus {
    Satisfied,
    Violated,
    Blocked,
    NotApplicable,
}

pub struct InvariantReport {
    pub id: String,
    pub protected_property: String,
    pub failure_class: String,
    pub enforcement_boundary: String,
    pub disposition: Disposition,
    pub status: InvariantStatus,
    pub evidence: Vec<String>,
}
```

The production implementation may use stronger typed identifiers or static strings where that improves correctness.

## 5. Command surface

Extend `architecture-audit` with repository invariant inspection while preserving existing runtime-graph audit behavior.

Target interface:

```text
cargo run --bin architecture-audit -- invariants
cargo run --bin architecture-audit -- invariants --json
cargo run --bin architecture-audit -- invariants --repo .
```

No new runtime dependency is introduced into `hse serve` or ordinary scanning.

## 6. Initial invariant conversions

### INV-AUTOUPDATE-001 — auto-update skip policy

Current defect:
- production and tests contain mirrored command-policy predicates;
- the test explicitly says to keep them synchronized.

Conversion:
- one module-level Rust predicate owns the policy;
- runtime consumes it;
- tests call the same predicate;
- the duplicated predicate is deleted.

Acceptance:
- exactly one executable policy authority;
- all current skip/non-skip behavior remains characterized;
- a mutation adding/removing one command from a duplicate location is no longer possible because the duplicate does not exist.

Disposition after acceptance: `Invariantized`.

### INV-RUSTPIN-001 — project Rust version compatibility

Current defect:
- `rust-toolchain.toml` is conceptually authoritative;
- normal workflows contain copied numeric project toolchain values;
- MSRV and nightly fuzzing are legitimate independent toolchains.

Conversion:
- Rust invariant parsing recognizes:
  - authoritative project channel from `rust-toolchain.toml`;
  - declared MSRV from `Cargo.toml`;
  - explicit nightly exception;
- copied normal-workflow project pins are rejected unless the chosen integration mechanism derives them from the authority.

Because GitHub YAML is an external platform format, small YAML glue may remain. The invariant policy itself is Rust-owned.

Disposition:
- `Invariantized` where derivation eliminates duplication;
- `Automated` where an external syntax cannot derive the value and compatibility must be checked.

### INV-DOCKER-RUST-001 — Docker builder compatibility

Docker `FROM` cannot reliably read `rust-toolchain.toml`.

Therefore:
- retain the required Docker literal;
- Rust invariant compares it with the authoritative project channel;
- mismatch is fatal to the architecture audit/gate.

Disposition: `Automated`, not falsely labeled `Invariantized`.

### INV-BINARYEN-001 — byte-reproducible wasm tool identity

Current defect class:
- wasm-opt/Binaryen build identity affects byte-exact committed wasm artifacts;
- version and checksum have been represented across multiple consumers.

Target:
- define one canonical build-tool identity;
- consumers derive or are checked against it;
- Rust audit owns compatibility validation;
- no separate Python/Bash invariant engine.

The exact authority location is selected during implementation after inspecting current build-script and CI capabilities. It must not add a second configuration authority merely to remove the first.

## 7. Outstanding-work ledger

Create one canonical machine-readable ledger owned by Rust-compatible data, with entries for prior ChatGPT findings and repository-native ledgers.

Minimum fields:

```text
id
summary
source
first_observed_at
affected_paths
requirement
original_evidence
current_reproduction
current_disposition
owning_tranche
verification_required
supersedes
superseded_by
```

Allowed current dispositions:

```text
SATISFIED
PARTIAL
IMPLEMENT
SUPERSEDED
REJECTED
BLOCKED
UNVERIFIED
```

Historical assistant output enters as `UNVERIFIED` unless current repository evidence independently confirms it.

## 8. Imported defect families

P0 must import, not blindly fix:
- current CI failures/successes by exact revision;
- scheduled live-drift state;
- benchmark workflow state;
- release-pipeline trust-boundary findings;
- API/provider drift reports;
- parser correctness reports;
- cancellation/concurrency reports;
- identity/phone/name parsing reports;
- pre-push receipt/hook defects;
- installer/key-persistence reports;
- UI/accessibility reports;
- Railway/deployment reports.

Each item is re-derived before implementation in its owning tranche.

## 9. Non-vacuity

Every repository scanner proves it still sees what it claims to protect.

Examples:
- workflow scanner asserts workflow count above an explicit structural minimum derived from the repository fixture used by the test;
- toolchain parser has a known stale-pin negative fixture;
- mirrored-policy detector has a deliberately duplicated fixture;
- missing protected files are failures, not silent success;
- parse failures are failures, not “no violations.”

## 10. Testing

TDD sequence:

1. Write failing test that reproduces each current architecture defect.
2. Observe the expected failure.
3. Implement the smallest canonicalization.
4. Observe the targeted test pass.
5. Inject a new violation and verify failure.
6. Test legitimate exceptions.
7. Run full relevant regression.

Minimum gates:
- `cargo fmt --all -- --check`
- targeted P0 tests;
- root locked tests;
- sibling-crate tests where affected;
- clippy according to repository gate;
- architecture-audit command smoke;
- workflow validation;
- Android cross-build if Cargo/build graph is touched.

P0 itself does not claim real Termux runtime verification unless it is actually executed on device.

## 11. Error handling

Architecture audit errors are explicit:
- protected file missing;
- protected syntax unparseable;
- invariant violated;
- invariant blocked by unavailable information;
- internal audit failure.

“Could not inspect” must never be rendered as “satisfied.”

## 12. Rollback

P0 must not change scan semantics or persistent DB state.

Rollback is therefore repository-local:
- revert the P0 commit series;
- existing runtime behavior remains intact.

This low semantic risk is why P0 precedes the intelligence cutover.

## 13. Acceptance criteria

P0 is accepted only when:

1. the existing mirrored auto-update policy fails a pre-change test;
2. one Rust authority replaces the mirror and preserves current behavior;
3. the repository invariant engine detects a deliberately stale project toolchain;
4. legitimate MSRV/nightly exceptions remain valid;
5. Docker/project toolchain mismatch is automatically detected;
6. Binaryen build-identity duplication is either removed or automatically rejected;
7. scanners demonstrate non-vacuity;
8. historical ChatGPT findings are represented with explicit current disposition rather than assumed true;
9. all relevant host-side regression gates pass;
10. the exact tested revision is recorded;
11. no production intelligence semantics changed.

## 14. Implementation boundary

P0 ends before modifying:
- claim promotion semantics;
- source-health outcome taxonomy;
- entity merge semantics;
- scheduler behavior;
- provider parsing;
- geo weighting;
- persistence schema for intelligence;
- evaluation execution.

Those changes belong to later approved subprojects.

## 15. Decision

Implement P0 first.

Its purpose is not to add user-facing capability. Its purpose is to make every subsequent end-to-end refactor more falsifiable, less memory-dependent, and safer to attribute.
