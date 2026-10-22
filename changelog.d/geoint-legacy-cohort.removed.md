- The `geo`, `geometry` and `place` library modules (about 1,860 lines), which nothing called
  outside their own tests except `rf`'s use of `geo::is_valid_coords`, and
  `address_au::single_state_code`, which only `geo` called: address parsing, country and timezone
  lookup by coordinate, AU locality and postcode lookups, enclosing circles, geometric medians,
  convex hulls and namesake distance checks. The `geo`, `geohash` and `coarsen` commands are
  unchanged; they run on `geohash`, `geoint` and `redact`, and a test now pins `geo`'s Brisbane to
  Sydney answer at 732379 m. `rf` keeps the one predicate it used from `geo`, `is_valid_coords`,
  as a private function.
- `postcode_au::localities_with`, a request to `api.zippopotam.us` that called `Transport::send`
  directly instead of going through `fetch`, with its response parser and `is_in_au_range`. Only
  `geo` called it. The offline centroids `asic_director` and `asic_persons` use are unchanged.
- `geoint::{Fix, CoLocation, colocated}`, the legacy `geohash::geohash` wrapper that turned invalid
  input into an empty string, and the re-exports of `geo`, `geometry`, `oui`, `postcode_au` and
  `rf` from `geoint` and of `place` items from `geohash`. `tests/runtime_reachability.rs` counts a
  re-export as a caller, so these let `geometry` and `place`, which nothing called, pass it.
