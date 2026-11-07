- Names ending in `Limited`, `Ltd`, `PLC` or `LLP` are read as organisations, not people.
  "Telstra Group Limited" was classified as a person, so `sources` gave it person search routes.
  `sources` also gives a one-word query (`sources Telstra`) its organisation search routes, at
  low confidence, instead of refusing it.
