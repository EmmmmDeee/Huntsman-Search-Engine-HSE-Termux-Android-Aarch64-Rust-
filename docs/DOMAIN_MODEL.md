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

## Relation

A [`Relation`](crate::core::relation::Relation) is a directed, typed edge between
two entities (referenced by `uid`). Entities are *what was found*; relations are
*how the findings attach to each other* — the layer path-finding, clustering, the
subject-network synthesis and the dossier's CONNECTIONS section all read.

- `id` is deterministic: `hex(SHA-256("from|kind|to|scan"))`, so storage upserts
  idempotently and a re-scan never duplicates an edge. Note it **excludes**
  confidence — see the collapse rule below.
- `kind` is drawn from the closed
  [`RelationKind`](crate::core::relation::RelationKind) taxonomy.
- `confidence` carries the trust of the endpoints it connects (the weaker of the
  two, clamped to `[0, 1]`), damped where the *binding* is inferred rather than
  read off a source.

### Edge families

| Family | Kinds | What the edge asserts |
|--------|-------|-----------------------|
| Infrastructure | `subdomain_of`, `belongs_to_domain`, `hosted_on`, `resolves_to`, `registered_by`, `same_operator` | Estate structure: what an operator's assets are and how they hang together |
| Identity | `identified_by`, `alias_of`, `same_as`, `same_identity`, `shares_secret_with` | Which identifiers belong to one holder, and which are one holder in two spellings |
| Place | `located_at`, `co_located_with` | A person or organisation at an address / coordinate |
| People | `associated_with` | A kinship, household, co-mention or declared-associate tie between two people |
| Affiliation | `officer_of`, `employed_by`, `member_of`, `controlled_by`, `operated_by` | A person's or asset's tie to an organisation, and one organisation's tie to another |
| Lineage | `derived_from` | Which entity's expansion surfaced this one |

The affiliation kinds are deliberately **not** collapsed into a single
"affiliated with": an investigation treats a filed directorship
(`officer_of` — a regulator is the source, and the role carries legal control)
differently from a self-reported job (`employed_by`), and `controlled_by` is
oriented `child → controller` specifically so a chain of edges walks *up* an
ownership tree. See [`core::relation::affiliation`](crate::core::relation::affiliation)
for which source grounds each one.

### Determinism

Relation derivation holds the same bar as `Entity::merge`. A builder:

- depends only on the entity slice passed in, never on iteration order (outputs
  are sorted by endpoint pair, and `HashMap`s are used as membership indexes
  only);
- emits symmetric edges in one canonical direction (smaller `uid` → larger), so a
  pair yields exactly one edge;
- links only entities **present in the set** — a name matching nothing links
  nothing, because inventing the missing endpoint would be fabrication.

Because `id` excludes confidence, several builders can emit the same
`(from, kind, to)` at different strengths (a surname guess, then an
evidence-grounded household tie, then a declared relationship). `derive_all`
therefore ends by collapsing duplicate ids to their **maximum** confidence, so
the strongest grounding wins regardless of emit order or the persistence
layer's conflict policy.

## Determinism Requirement

Any operation that folds multiple module results must yield the same persisted
output regardless of module completion order. `Entity::merge` satisfies this by:

- Using commutative operators (`max`, `sum`, `union`).
- Choosing a canonical `raw_value` (lexicographic `min`).
- Sorting evidence and tags at finalisation.

Tests enforcing these invariants live in
[`tests/entity_merge_greatest.rs`](../../tests/entity_merge_greatest.rs).
