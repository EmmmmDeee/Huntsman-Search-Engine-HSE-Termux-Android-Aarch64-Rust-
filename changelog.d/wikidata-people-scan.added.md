- A `people NAME` scan (and `scan -k people`, the Web UI people scan and saved people scans) now
  also queries the keyless **Wikidata** source beside the ASIC people and director registers, so a
  people lookup is no longer Australia-only. Wikidata resolves the name to its top public item and
  keeps it as a `Person` candidate when the item is a human — a lead to review, never a confirmed
  identity, and a 200 that is not the requested item is schema drift rather than a fabricated
  entity. This reuses the existing `wikidata` client (previously reachable only through the
  explicit `wikidata` command) with no new source: it is added to the People module list, run by
  `people_cli` beside the registers, its saved-ledger provenance is attributed to `src/wikidata.rs`,
  and the `/api/scans` people-source coverage now accounts for it as the sixth concrete people leg.
