# Corroboration pathway precision

`relation::disjoint_pathways(start_uid, end_uid, relations)` remains a numeric compatibility API. The newly exported `relation::assess_disjoint_pathways(start_uid, end_uid, relations)` returns `PathwayAssessment { count, precision }`, serializable as JSON.

`precision=exact` means the bounded (maximum eight-edge) basis-disjoint enumeration completed or a missing/identical selector proves no route. `precision=conservative_lower_bound` means an exact-search resource ceiling was hit and the count is the number of independently supported paths selected by the existing greedy fallback. Additional paths may exist. Neither value establishes complete external-source discovery.

Every named evidence basis may support at most one independent pathway; multiple edges using the same basis are not independent corroboration. Neither `exact` nor `conservative_lower_bound` proves identity. A counted route is a structural relationship, not a source-trust, time-validity or consent assessment.

Example serialized responses:

```json
{"count":2,"precision":"exact"}
{"count":1,"precision":"conservative_lower_bound"}
```

The original numeric API and pairwise API remain unchanged. Consumers requiring a statement about certainty should migrate to `assess_disjoint_pathways`; the pairwise API does not yet expose per-pair precision. This is an in-process Rust API improvement, **not** a new CLI or web endpoint.

Resource bounds and exact algorithms remain internal to `src/relation/graph.rs`; do not present values as globally maximal independent pathways when fallback was used. No provider I/O, new credentials, database mutation or LLM runtime is involved.
