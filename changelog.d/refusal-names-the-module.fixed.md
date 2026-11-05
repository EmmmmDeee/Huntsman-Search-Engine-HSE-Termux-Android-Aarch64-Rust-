- A refusal or an unanswered lookup now names its source in every lookup, as `ip`, `domain`,
  `email`, `username` and the other `SourceReach` lookups already did. This now also covers
  `people`, `crypto`, `geocode` (place), `company`, `gleif`, `itunes` and `wikidata`.
  - **Before:** these seven ended a refused lookup (exit 77) with the bare egress reason, so
    the operator could not tell which source was refused. `people` and `geocode` also ended an
    unanswered lookup (exit 69) with no source or reason ("nothing collected", or
    `no source answered for "…"`).
  - **Now:** each records a failed leg as a row naming its module. A request the guarded fetch
    refused becomes `refused_before_sending` (`people` recorded it as `connect_failure`); any
    other error becomes `inconclusive`. Each lookup ends from those rows through `SourceReach`.
    A refusal reads `gleif_lei: egress-policy: …`, and an unanswered lookup reads
    `no source answered for …: <module>: <reason>`.
  - **`company`** now runs GLEIF and ABN Lookup even when its registers are refused, instead
    of stopping at the first refusal. A refusal ABN Lookup records as a row now exits 77
    instead of 69. No other exit code changes.
  - `source_outcome::none_accepted`, the second rule for "no source answered", is removed. Its
    tests now hold `SourceReach::unanswered` to the same answers.
  - The refusal-contract harness now holds these seven lookups with no exceptions. The 17
    breakages Phase 0 recorded are gone, and the seven join the guard against
    side-channel reasons.
