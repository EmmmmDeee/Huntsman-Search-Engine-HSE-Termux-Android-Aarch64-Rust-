- Unused library items from the key-probe registry and the module graph are gone, and no
  output changes:
  - the probe rows for Intelligence X, ONYPHE, Criminal IP, HLR Lookups, OpenCNAM, Trove,
    FullContact, DomainsDB, NiamonX and OSINTCat, which `credential-status --probe` could never
    reach because no provider in the catalogue reads their slots, with the Criminal IP body
    check and the Intelligence X evidence fields only those rows used;
  - `service_defs::service_defs()`, `is_poolable_service`, `rate_limit_reset`,
    `ProbeVerdict::as_str`, the never-built `HeaderPrefixed` key placement, the `category` and
    `rate_limit_reset_secs` fields of `ServiceDef` and the `response` field of `ProbeResult`;
    `service_defs::KeyPlacement` is replaced by `api_leg::KeyPlace`, the placement every
    keyed lookup declares, `probe_service` takes the key as a `keys::Secret`, and
    `build_probe_request` no longer takes the key;
  - `ModuleGraph::module_count_for`, `richness_for`, `produced_kinds` and `to_summary`, the
    `ModuleGraphSummary`, `KindNode` and `dependency::PivotEdge` types, the reachability
    helpers `reachable_target_kinds`, `dependency::reachable_modules`, `unreachable_modules`,
    `coverage_from`, `seed_universe`, `human_seed_kinds` and `fully_wired`, the `ModuleMeta`
    trait, and `ModuleCost::as_str` and `ModuleCategory::as_str`, which only repeated the
    serde names.
- `doctor serve` checks the page's script hash with the same block reader and hash format the
  server uses to build its policy, instead of a copy of them.
