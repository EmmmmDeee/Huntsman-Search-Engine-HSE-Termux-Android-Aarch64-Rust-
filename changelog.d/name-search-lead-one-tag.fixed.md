- A people scan's Wikidata name-only leads (the website, coordinate and external-profile pivots
  of an item found by name) now carry the shared `name-search-lead` tag, the one the ACNC and SEC
  EDGAR legs already use, instead of their own `wikidata-name-lead` tag, so filtering a report,
  the Web UI or an export on `name-search-lead` finds every name-only lead. No producer emits the
  old tag any more and the Wikidata-only constant is gone; recursion still refuses to dispatch an
  entity carrying it, as a scan saved before this change may.
