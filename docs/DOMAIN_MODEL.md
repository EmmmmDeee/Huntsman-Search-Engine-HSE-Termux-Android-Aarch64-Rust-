# Huntsman Search Engine — Domain Model

This document describes the core domain concepts and invariants that govern HSE's
entity graph. It is intended as a maintainable reference for contributors and
reviewers.

## Entity

An [`Entity`](crate::core::entity::Entity) is a typed, confidence-scored
observation in the dossier graph. Every entity has:

- A deterministic SHA-256 `uid` derived from `(kind, normalised_value)`.
- A `kind` drawn from the closed [`EntityKind`](crate::core::entity::EntityKind)
  taxonomy.
- A `value` (normalised, canonical form) and a `raw_value` (first-seen spelling).
- A base `confidence` ∈ `[0, 1]`.
- A `corroboration` magnitude (≥ 1) representing summed observation weight.
- An `evidence` chain of `(source, summary, attributes)` records.
- A set of `tags`.
- Timestamps and scan lineage.

## GREATEST-semantics merge

When two entities share the same `uid` (same kind + normalised value), they are
folded with **GREATEST** semantics in [`Entity::merge`](crate::core::entity::Entity::merge).
This is a foundational architecture invariant: replaying a finding must never
regress confidence or drop evidence.

### Rules

| Field | Merge rule | Rationale |
|-------|------------|-----------|
| `uid` | Must match; merge is a no-op (release) / `debug_assert` panic (debug) otherwise | Identity is immutable |
| `value` | Already identical (same UID) | Normalised value is the identity key |
| `raw_value` | Lexicographically smaller spelling wins | Determinism Requirement: output must not depend on merge order |
| `confidence` | `max(self.confidence, other.confidence)` | Confidence never decreases |
| `corroboration` | `saturating_add(self.corroboration, other.corroboration).max(1)` | Observation magnitude accumulates |
| `observed_at` | `max(self.observed_at, other.observed_at)` | Recency only increases |
| `generation` | `min(self.generation, other.generation)` | Preserves the earliest expansion round the entity actually entered the graph |
| `tags` | Set union | Both tag sets are retained, duplicates removed |
| `evidence` | Union by `(source, summary)`; attributes merged on conflict | Repeated observations by the same source with the same summary are one record, but new attributes are folded in deterministically |

### Effective confidence

The tier displayed to users and used by expansion gates is not the base
`confidence` but [`Entity::c_effective()`](crate::core::entity::Entity::c_effective),
which boosts the base confidence by the number of *distinct corroborating
sources* `n` (not the raw `corroboration` magnitude):

```text
multiplicative = confidence * (1 + 0.15 * ln(n))
agreement      = 1 - (1 - confidence) * 0.65^(n-1)
c_effective    = clamp(max(multiplicative, agreement), 0.0, 1.0)
```

At `n = 1` both terms equal `confidence`. Additional independent sources can only
increase `c_effective`; they can never decrease it.

### Classification tiers

[`Classification`](crate::core::entity::Classification) is derived from
`c_effective` at query time:

- `Verified`   : `c_effective >= 0.75`
- `Probable`   : `c_effective >= 0.40`
- `Candidate`  : otherwise

Because `c_effective` is monotonic in `confidence` and `n`, tiers only ever rise
as corroboration is added.

## Evidence

An [`Evidence`](crate::core::entity::Evidence) record carries:

- `source`: the module or origin that produced the observation (e.g. `hibp`).
- `summary`: a short human-readable description.
- `attributes`: a sorted map of machine-readable key/value pairs.
- `recorded_at`: ingestion timestamp.

Evidence is deduplicated by `(source, summary)` during merge. When two records
share the same key but differ in value, the smaller value is kept deterministically.

## Determinism Requirement

Any operation that folds multiple module results must yield the same persisted
output regardless of module completion order. `Entity::merge` satisfies this by:

- Using commutative operators (`max`, `sum`, `union`).
- Choosing a canonical `raw_value` (lexicographic `min`).
- Sorting evidence and tags at finalisation.

Tests enforcing these invariants live in
[`tests/entity_merge_greatest.rs`](../../tests/entity_merge_greatest.rs).
