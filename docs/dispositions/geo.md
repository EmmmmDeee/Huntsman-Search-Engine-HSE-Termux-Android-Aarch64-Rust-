| legacy path | lines | decision | new module | defect found/evidence or reason |
| --- | ---: | --- | --- | --- |
| `src/util/geo/mod.rs` | 650 | MERGED | `src/geoint.rs`, `src/geo.rs` | Rebuilt pure parsing/validation, AU-state partition, locality/postcode lookups, confidence ladder, and family-distance helpers. Legacy mixed in monolith `Entity` birth/tag helpers; those are left out here. |
| `src/util/geo/tests.rs` | 271 | MERGED | `src/geoint.rs`, `src/geo.rs` | Ported the pure-oracle cases that fit this crate: coordinate parsing, AU box/state, locality lookup, postcode fallback, provider plausibility, namesake distance. |
| `src/util/geometry/circle.rs` | 135 | REBUILT | `src/geometry.rs` | Minimum enclosing circle rebuilt with equirectangular lon scaling and great-circle output radius. |
| `src/util/geometry/coherence.rs` | 162 | REBUILT | `src/geometry.rs` | Single-linkage coherence clustering rebuilt without monolith `union_find` dependency. |
| `src/util/geometry/fix.rs` | 107 | REBUILT | `src/geometry.rs` | Consolidated `LocationFix` rebuilt; deterministic bundle of centroid/median/circle outputs. |
| `src/util/geometry/footprint.rs` | 182 | REBUILT | `src/geometry.rs` | Convex hull + polygon-area centroid rebuilt; preserved the legacy defect fix away from naive vertex means. |
| `src/util/geometry/median.rs` | 192 | REBUILT | `src/geometry.rs` | Geometric median, weighted median, weighted centroid, and robust radius rebuilt. |
| `src/util/geometry/mod.rs` | 37 | MERGED | `src/geometry.rs` | Legacy split modules intentionally collapsed into one pure offline module for this crate. |
| `src/util/geometry/tests.rs` | 649 | MERGED | `src/geometry.rs` | Ported representative differential/property tests for hull, centroid, median, enclosing circle, coherence, and summary text. |
| `src/util/geohash/address.rs` | 117 | MERGED | `src/geohash.rs`, `src/place.rs` | Address parsing merged into the existing geohash module surface. |
| `src/util/geohash/country.rs` | 250 | MERGED | `src/geohash.rs`, `src/place.rs` | Reverse country boxes and ISO/name helpers merged into `src/geohash.rs`; HK/TW/SG ordering preserved. |
| `src/util/geohash/distance.rs` | 33 | MERGED | `src/geohash.rs` | Great-circle distance merged; kept the numerically-stable `atan2` form. |
| `src/util/geohash/encode.rs` | 94 | MERGED | `src/geohash.rs` | Existing geohash encoder extended with legacy-compatible wrapper and coordinate parser. |
| `src/util/geohash/mod.rs` | 36 | MERGED | `src/geohash.rs`, `src/place.rs` | Pure helpers consolidated into the existing geohash module rather than duplicated. |
| `src/util/geohash/tests.rs` | 298 | MERGED | `src/geohash.rs`, `src/place.rs` | Ported reference-vector, parser, metric, timezone, country-box, and address tests. |
| `src/util/geohash/timezone.rs` | 85 | MERGED | `src/geohash.rs`, `src/place.rs` | Coarse timezone inference merged into the existing geohash surface. |
| `src/util/city_coords/mod.rs` | 726 | REBUILT (subset) | `src/geo.rs` | Rebuilt whole-token/longest-match/foreign-gate/postcode fallback logic. Retained only a minimal verified row set used by tests; bulk gazetteer remains `PENDING-PROVENANCE`. |
| `src/util/city_coords/tests.rs` | 389 | MERGED | `src/geo.rs` | Ported the logic-oracle cases (postcode fallback, foreign-address rejection, AU-vs-foreign homonym gating) against the verified subset. |
| `src/util/place_grain.rs` | 276 | MERGED | `src/geohash.rs`, `src/place.rs` | `is_bare_country` merged into geohash/place helpers. |
| `src/util/cell.rs` | 112 | REBUILT | `src/rf.rs` | Canonical tower id, MCC/MNC normalisation, and LAC/TAC fallback rebuilt. |
| `src/util/wifi/mod.rs` | 121 | REBUILT | `src/rf.rs` | SSID generic/default classifier and Wi-Fi band boundaries rebuilt. |
| `src/util/wifi/tests.rs` | 91 | MERGED | `src/rf.rs` | Ported the whole-token vs substring regressions and band-boundary cases. |
| `src/util/oui/mod.rs` | 371 | REBUILT | `src/oui.rs` | Curated MAC/OUI classifier rebuilt; preserved randomized-address and multicast-bit handling. |
| `src/util/oui/ieee.rs` | 144 | REBUILT | `src/oui_ieee.rs`, `src/oui_ieee.bin` | Packed IEEE MA-L registry loader rebuilt and pointed at a copied blob. |
| `src/util/oui/ieee_tests.rs` | 135 | MERGED | `src/oui_ieee.rs` | Ported blob/lookup spot checks into the new IEEE helper. |
| `src/util/oui/tests.rs` | 252 | MERGED | `src/oui.rs` | Ported curated, registry-tier, randomized/private, and table-shape tests. |
| `src/core/geo_family/mod.rs` | 290 | MERGED (subset) | `src/geo.rs` | Rebuilt the pure postcode/distance/namesake subset (`extract_au_postcode`, coarse centroids, distance bands). The monolith `Entity` graph integration remains outside this slice. |
| `src/core/geo_family/tests.rs` | 400 | MERGED (subset) | `src/geo.rs` | Ported postcode extraction, foreign-address rejection, and near/far family-distance cases that fit the pure subset. |
| `src/core/rf.rs` | 383 | REBUILT | `src/rf.rs` | RF sighting model rebuilt with canonical network ids, OUI classification, position/timestamp guards, and WiGLE type parsing. |
| `src/core/rf_tests.rs` | 241 | MERGED | `src/rf.rs` | Ported RF sighting, timestamp, address-bit, and enum-roundtrip tests. |
| `src/core/radar_live.rs` | 434 | REBUILT | `src/radar.rs` | Live Bluetooth presence reducer rebuilt with not-read handling, randomized/bonded aggregates, and capacity eviction reporting. |
| `src/core/radar_live/tests.rs` | 377 | MERGED | `src/radar.rs` | Ported the reducer state-machine regressions (`new/present/missing/departed`, not-read, eviction, metadata). |
| `src/core/radar_track.rs` | 278 | REBUILT | `src/radar.rs` | Cross-sweep recurring-device review rebuilt and ranked deterministically. |
| `src/util/postcode_au/mod.rs` | 265 | REBUILT (subset) | `src/postcode_au.rs`, `src/geo.rs` | Rebuilt JSON parsing, offline centroid fallback, and the newly in-scope online postcode-locality lookup behind the shared `crate::http::{Request, Response, Transport}` boundary. Bulk gazetteer breadth still remains `PENDING-PROVENANCE`. |
| `src/util/postcode_au/tests.rs` | 147 | MERGED (subset) | `src/postcode_au.rs`, `src/geo.rs` | Ported postcode shape/range/fallback cases and added fake-transport tests implementing the shared `Transport` trait for the restored online lookup boundary. |
