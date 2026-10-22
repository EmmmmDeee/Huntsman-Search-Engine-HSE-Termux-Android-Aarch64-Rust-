- The `event` and `scraper_health` library modules (about 440 lines): a second module-outcome
  event model with a `type` serde tag, its own `SkipClass` and a third `ScanStatus`, and the source
  drift and quarantine aggregation over it. Nothing wrote those events, so the aggregation never
  ran. Module outcomes are `coverage::Event`, tagged by `kind`, and a test now pins that wire form.
- The `archive` and `archive_bridge` modules and `PipelineLimits::max_archive_captures`. No
  collector fetches the Wayback CDX or Common Crawl index or builds an archive capture, so the
  model, its bridge into collection observations and its bound described a path the engine does
  not have, and `docs/RUNTIME_INTEGRATION.md` no longer says archive records enter the pipeline.
  Limits JSON that still carries the field still reads; the old field is ignored. The `wayback` search route that `plan`
  and `source-registry` list is unchanged. `canonical::canonical_authority` is private now that
  `canonical_url` is its only caller.
- `benchmark`'s scan report (`report`, `BenchmarkReport`, `Scorecard` and its own `ScanStatus` and
  `ScanRecord`) and the uncalled `score_person_resolution` wrapper. `analysis::InvestigationReport`
  carries a scan's metrics, coverage and pivots; the person-resolution scorer stays.
- The re-exports of `radar` from `geoint` and of `address_au` and `postcode_au` from `au_id`, which
  nothing used. `tests/runtime_reachability.rs` no longer counts an integration test, an example,
  `#[cfg(test)]` code or a whole-module `pub use` as a caller: a module that only tests reach must
  be `diagnostic` or wait, with its owner and reason, in `PENDING_OWNER_DECISION`.
