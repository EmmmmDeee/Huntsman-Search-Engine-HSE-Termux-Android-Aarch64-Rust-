- A people scan's Wikidata name-only leads (the website, coordinate and external-profile pivots
  of an item found by name) now carry the shared `name-search-lead` tag, the one the ACNC and SEC
  EDGAR legs already use, instead of their own `wikidata-name-lead` tag, so filtering a report,
  the Web UI or an export on `name-search-lead` finds every name-only lead. Recursion checks the
  one tag, and the Wikidata-only constant is gone.
