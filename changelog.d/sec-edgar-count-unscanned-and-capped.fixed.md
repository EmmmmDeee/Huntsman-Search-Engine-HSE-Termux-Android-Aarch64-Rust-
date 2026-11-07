- The SEC EDGAR people leg no longer reads a page cap as a complete answer. EDGAR returns one page
  of search hits while reporting its full match total; filings past that page, and matched filers
  past the per-query cap, were silently dropped, so a subject whose filing ranked beyond the first
  page was reported as a clean "no SEC presence". Now, when no scanned filing names the query but
  EDGAR reported more matching filings than were scanned, the leg is `inconclusive`, not
  `valid_zero`; a match reports the shortfall (filers beyond the cap not fetched, filings not
  scanned, and filers that named other people) in its outcome detail. Attribution is unchanged —
  only a filing that names every word of the query, keyed by its own CIK, is ever attached.
