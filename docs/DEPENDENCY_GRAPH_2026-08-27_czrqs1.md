# Dependency Graph — 2026-08-27 (branch `claude/huntsman-consolidation-czrqs1`)

Phase 0 of the run's mandate calls for a dependency graph as part of the
migration-planning inventory. Since Phase 0 also found the codebase already
100% Rust (see `RUST_MIGRATION_AUDIT_2026-08-27_czrqs1.md`), there is no
legacy-vs-ported module graph to plan batching over. What follows instead is
the graph that actually matters for this codebase's own stated architecture
rules and for the external supply-chain surface `cargo audit`/`cargo deny`
evaluate.

## Internal layering (enforced by `tests/architecture.rs`)

```
src/modules/*  (182 provider modules, one per external OSINT/GEOINT source)
      │  implement Module trait, dispatched via modules::registry()
      ▼
src/core/*     (engine, scan orchestration, entity model, correlator,
                storage port trait, error types)
      │  depends on util only, never the reverse
      ▼
src/util/*     (shared primitives: http client, key resolution/pooling,
                geo, canonicalisation, str utilities, egress, ...)
```

Two architecture tests make this a checked invariant, not just a convention:

- `modules_do_not_import_engine_or_storage` — no `src/modules/**` file may
  `use crate::core::engine` or the concrete storage backend directly; modules
  only see `ModuleContext`/`ModuleResult`/the `Module` trait.
- `util_does_not_import_upper_layers` — no `src/util/**` file may import
  from `core` or `modules`, keeping `util` a true leaf layer.

`src/app/*` sits above all three as the only composition root: it is the one
place that constructs the concrete `storage::Store` and wires the CLI/API
surfaces to the engine.

## External dependency graph (supply-chain surface)

Generated directly from this tree with `cargo tree`, not hand-maintained —
re-run the same commands to regenerate:

- Default features: `cargo tree --edges normal` — 547 lines, committed
  alongside this doc as `dep_tree_normal.txt` in the deliverable's
  `audit-data/` directory.
- `--all-features` (the same feature superset `deny.toml`'s
  `[graph] all-features = true` evaluates): `cargo tree --all-features` —
  640 lines, `dep_tree_all_features.txt`.

Headline facts drawn from these trees, cross-referenced against
`deny.toml`'s own documented exceptions:

- 369 crate dependencies at default features; the `--all-features` graph
  additionally pulls in `image`'s `ravif`/AV1 encode path
  (`ravif → rav1e → paste`), which is where the one pre-existing waived
  `RUSTSEC-2024-0436` (`paste`, unmaintained) advisory originates — see
  `deny.toml`'s own comment and `ISSUE_LEDGER_2026-08-27_czrqs1.md`.
- No dependency cycles (Cargo's resolver forbids them structurally; nothing
  to verify here beyond what `cargo tree` would already fail to render).
- No banned/duplicate-version crates flagged by `cargo deny check`
  (`bans ok`).

## Re-verification note (this run)

Re-running `cargo tree -i paste --all-features` on the post-merge tree
prints nothing (not an error — the crate genuinely isn't part of the graph
`cargo tree` resolves for this host target), while `cargo audit` still lists
it because `cargo audit` scans every entry physically present in
`Cargo.lock` regardless of target/feature reachability, and `pulp`/`rav1e`
remain locked entries (confirmed via `cargo metadata --all-features`). This
is consistent with `deny.toml`'s own note that the `rav1e[fuzzing]` path
"is never linked into the shipped binary" — the two tools apply different
reachability strictness, not a disagreement about the underlying fact.
Recorded here rather than treated as a new finding, since both tools agree
the advisory is already covered by the existing waiver.
