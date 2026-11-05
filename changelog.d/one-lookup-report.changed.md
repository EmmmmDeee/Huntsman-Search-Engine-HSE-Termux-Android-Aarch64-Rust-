- The lookup front-ends share one report type and one ending. No output changes.
  - **One report type.** Fourteen front-ends (`asn`, `company`, `crypto`, `domain`, `email`,
    `gleif`, `ip`, `itunes`, `netblock`, `geocode`, `people`, `phone`, `username`, `wikidata`)
    each declared the same two-field `Report`. Each `Report` is now an alias of one
    `lookup_report::LookupReport`, so every path still resolves.
  - **One ending.** Six front-ends with identical endings (`company`, `crypto`, `gleif`,
    `itunes`, `wikidata`, `geocode`) now end through `lookup_report::finish`. It merges the
    entities by UID, ends an unanswered lookup through `SourceReach::unanswered`, and
    renders the report.
