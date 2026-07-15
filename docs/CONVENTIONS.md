# Source-Tree Conventions

The standing rules for how this tree is organised and why. Several are
mechanically enforced (the enforcing test is cited); the rest are conventions a
review should hold the line on. The unifying principle: **every fact lives in
exactly one place, and where drift between two places is possible, a test makes
drift a CI failure.**

## 1. Layering

The dependency direction is `cli`/`api` → `core` → `util`, with `modules`
depending only on `core` types: **core is module-agnostic** — the engine drives
modules through the registry, never the reverse. Core reaches `util` only through
the deliberate exceptions listed in the test. Persistence is consumed through the
`core::port::StoragePort` trait; `core/` and `api/` never name `storage::Store`
directly — the only `Store::open` sites are the CLI composition roots.

*Enforced:* `tests/architecture.rs` guards `core → util`
(`core_does_not_import_util_directly`), `core → storage`
(`core_does_not_import_storage_directly`), `core → modules`
(`core_does_not_import_modules`), and `modules → engine/storage`
(`modules_do_not_import_engine_or_storage`). The `core → modules` edge was
inverted in **T1.4** (`docs/PROBLEM_TREE.md` §3.1): `core` calls a
function-pointer registry (`core::hooks`) that the module layer installs at
startup, so `core` never names `crate::modules` — and no laundering allowlist
remains.

## 2. One module per file; hubs declare, never house

A `mod.rs` is a declaration + re-export surface, not a place where code lives.
There are no size-based exceptions (even 17-line utilities get their own file —
`util/uid.rs`). The current end-state, hold it:

- `core/mod.rs`, `util/mod.rs` — pure alphabetical declaration hubs.
- `core/engine/` — orchestration in `mod.rs`; mechanism in satellites
  (`dispatch`, `expansion`, `circuit`, `timeout`, `enrich`, `ledger`). A helper
  belongs in the satellite whose charter (`//!` header) describes it.
- `cli/` — one file per subcommand, `run()` dispatches to
  `<file>::cmd_<name>`; cross-cutting glue (`cost_label`, `build_runtime`,
  colour helpers) stays `pub(super)` in `cli/mod.rs`.
- `api/` — handlers split by domain (`handlers` = system/read/SSE,
  `scan_handlers` = scan data, `settings_handlers` = keys/settings/toggles).

Inline modules are permitted only for trivial wrappers (a build-script
`include!`, a ≤5-line constants shim) and `#[cfg(test)] mod tests`. Each
non-test exception is allow-listed by `(path, module-name)`, so adding one is
a reviewed decision rather than a silent drift.
*Enforced:* `no_inline_module_bodies_outside_allowed_exceptions` in
`tests/architecture.rs`.

## 3. Single-source vocabularies

When a type has a canonical string form, the **type owns it** (`as_str` /
`as_canonical` / `canonical_str`) and a test pins it to the serde wire format
so the two cannot drift. Never re-state a mapping at a call site. Pinned
instances: `ModuleCost`, `ModuleCategory`, `Classification`, `RelationKind`,
`ExpansionStrategy`, `Severity::as_canonical`, `TargetKind::canonical_str`,
and `ScanStatus::as_str`. Several are extra load-bearing because the same
string is *also* hard-coded in SQL: `Severity` in the `correlations_for_scan`
`ORDER BY CASE`, `ScanStatus` in `latest_completed_scan`'s `= 'complete'`
probe — there a drift wouldn't just mislabel, it would break the query.
`core::tags` is a constants module (the strings *are* the source). The
classification ladder is likewise single-sourced
(`Classification::{VERIFIED_MIN, PROBABLE_MIN, from_c_eff}` — a tier threshold
literal outside `entity.rs` is a bug).

**Display variants** are allowed but must be documented as presentation and
*not* serde-pinned: the CLI's hyphenated `key-gated` (vs canonical
`key_gated`), and `TimelineEventKind::as_str`, whose `Generic => "event"`
deliberately differs from serde's `"generic"`. Each carries a doc comment
saying so, so the absence of a pin is a recorded decision, not an oversight.

## 4. Normalisation defines identity — delegate, never copy

`uid = SHA-256(kind:normalised_value)`, so `core::entity::normalise` is the
identity function of the whole system. Anything that needs "the same
normalisation as entities" calls it (`relation::domain_key`,
`expansion::visit_key`, `dispatch_key`) — a hand-rolled copy is how the
`www.`-fixed-point drift happened. The same rule generalises: shared predicates
(`is_noncentral_domain`, `is_plausible_provider_coord`, the crypto classifier)
have one definition that modules delegate to.
*Partially enforced:* the coarse-geo-provider gate in `tests/architecture.rs`.

## 5. Determinism

Identical inputs produce identical outputs, independent of `HashMap` iteration
or task-completion order. Concretely: sort by UID before any order-sensitive
fold (clustering, collision resolution), use deterministic tie-breaks in every
ranking comparator (NaN handled explicitly), canonicalise evidence/tag order
before persistence, and derive ids by hashing canonical inputs. New
order-sensitive code gets a permutation test (see
`canonicalize_order_is_merge_order_independent` and
`correlation_key_is_order_independent_over_uids`).

## 6. Drift-guards for hand-maintained facts

Any number or list that exists in prose AND in code gets a test tying the prose
to the live value: README module counts sweep against `registry()`
(`tests/architecture.rs`), `docs/MODULES.md` lists every registered module,
tier thresholds and ladder boundaries are pinned, serde defaults that mirror
product defaults share one function (`default_scan_options`) so
"omitted" and "empty object" cannot mean different things.

## 7. Tests

- Unit tests live beside the type (`mod tests` in-file, or a sibling
  `tests.rs` reached via `use super::*` for private access).
- Integration crates share `tests/common/` (`tmp_db` owns the full
  db/`-wal`/`-shm` cleanup; callers never hand-roll temp paths).
- Every bug fix lands with a regression test that fails against the unfixed
  code; fixes to a *class* of bug get a guard for the class (property tests
  over `NORM_CORPUS`, the README count sweep), not just the instance.

## 8. Documentation

Every file opens with a `//!` stating its charter — that header is what decides
where new code belongs (rule 2). Doc comments are contracts: keep them attached
to the item they describe (CI denies `rustdoc::broken_intra_doc_links`;
misattached doc blocks have shipped wrong contracts three times). Comments
explain constraints the code can't show — calibration provenance, RFC
citations, why a trade-off was taken — never what the next line does.

## 9. The gate

A change is done when **all** of: `cargo fmt --check`, `cargo clippy
--all-targets` (zero warnings), `RUSTDOCFLAGS="-D
rustdoc::broken_intra_doc_links" cargo doc`, and `cargo test` pass — plus, for
behaviour-touching changes, running the affected surface for real (`hse
diagnostics`, or the command itself).
