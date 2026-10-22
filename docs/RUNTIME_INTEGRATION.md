# Runtime Integration Spine

The reconstructed Huntsman runtime now has one bounded composition path for offline investigations. The path is designed for Termux/Android AArch64 constraints and preserves evidence provenance rather than treating provider count as corroboration.

## Offline command

```text
huntsman-recon plan [--session-dir DIR] SEED [SEED ...]
huntsman-recon plan --load-session DIR ID
```

The command normalizes and deduplicates selectors, constructs a deterministic dispatch plan, converts explicit operator seeds into non-verifying observations, builds one provenance-aware analysis snapshot, runs graph/intelligence analysis, and renders bounded artifacts.

`--session-dir DIR` saves the run as a session through the bounded atomic session store, and `--load-session DIR ID` prints a saved one. It does **not** execute the planned external source routes. Its output therefore proves the integration/runtime path, not live provider coverage.

## Composition

```text
raw seeds
  -> classifier/canonical entity model
  -> bounded normalization
  -> dependency graph + provider metadata + ROI planner
  -> collection event / observation envelope
  -> upstream-root ancestry + evidence normalization
  -> relation derivation
  -> immutable analysis snapshot
  -> graph / intelligence / metrics / gaps / pivots
  -> coreference / deterministic correlation
  -> cross-scan history and optional bounded cross-scan lookup
  -> termination semantics
  -> bounded JSON / GEXF / snake graph / STIX / Navigator artifacts
```

## Provenance invariants

- Collector identity is not upstream-origin identity.
- Multiple relays of one upstream dataset count as one ancestry root.
- Unknown upstream origins remain unknown and cannot manufacture independent corroboration.
- Discovery routes from `source_registry` are leads only.
- A failed, unavailable, rate-limited, WAF-blocked, auth-blocked, inconclusive, or truncated provider execution is not a clean negative.
- Generic zero-result coverage is clean only when the provider contract produced `ValidZero` and the execution was not truncated.
- STIX and Navigator continue to consume admitted ledger claims; graph observations do not silently become verified ATT&CK evidence.

## Resource bounds

`PipelineLimits` centrally bounds targets, entities, relations, provider dispatches, response bytes, cross-scan frontier/visited state, generation depth, and export bytes. Reaching a bound is surfaced as truncation/resource termination rather than being mislabeled as completeness or a fixed point.

Oversize structured artifacts are omitted atomically with their required size recorded. JSON/XML is never byte-truncated into invalid output.

## Runtime module policy

`tests/fixtures/runtime_module_dispositions.tsv` assigns every compiled library module exactly one role:

- `runtime`
- `adapter`
- `exporter`
- `leaf`
- `diagnostic`

`tests/runtime_reachability.rs` verifies complete classification, pins the core integration modules to `runtime`, and requires every other module to be named, through a `crate::` or `huntsman_recon::` path, by the binary, `src/lib.rs`, xtask, a runtime module or a module one of those reaches. `#[cfg(test)]` code and a `pub use` that re-exports a whole module do not count as callers. A module that only integration tests or examples reach must be `diagnostic`, or be listed with its owner and reason in the test's `PENDING_OWNER_DECISION`. `tests/architecture_doc.rs` independently enforces the repository layer map and direct dependency rules.

## Verification scope

Completion of this tranche requires the exact branch head to pass formatting, strict Clippy, Rust 1.87 and stable tests, architecture/reachability tests, artifact stability, and Android AArch64 release/ELF verification.

A real live provider collection receipt is intentionally separate. Without legitimate provider credentials/network execution in the verification environment, live collection remains unverified rather than simulated or inferred from mocks.
