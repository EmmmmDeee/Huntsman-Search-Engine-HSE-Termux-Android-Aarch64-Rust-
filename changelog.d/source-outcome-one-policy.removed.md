- Unused library items are removed. Each was referenced only by its own unit test or restated
  another item, so no command loses anything:
  - `SourceOutcomeKind::is_auth`, `is_contract_drift` and `normally_retryable`, which each
    restated part of `recommended_action`; that remains the only outcome policy.
  - `Entity::c_effective_from_ancestry` and `c_effective_depth_decayed`.
  - The graph node builders `with_label` and `with_evidence`.
  - `ResponseCache::clear_prefix`.
  - The textnorm helpers `pipe_delimited`, `is_handle`, `truncate_safe`, `char_window` and
    `slugify`.
  - `validation::strip_invisible`, `atproto::is_bluesky_operated_pds`, `au_id::company_names`,
    `address_au::is_business_service`, and the `search-discovered` tag that no entity carried.
