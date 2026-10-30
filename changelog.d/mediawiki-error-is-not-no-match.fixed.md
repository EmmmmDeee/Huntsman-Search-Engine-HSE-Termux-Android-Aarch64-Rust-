- A Wikidata search the `MediaWiki` Action API did not run is no longer recorded as "no Wikidata
  item". The API answers an error (`maxlag` while its databases lag, `ratelimited`, or an internal
  error) with HTTP 200 and an `error` envelope instead of a hit list, and the search read a
  missing list as an empty one, so `wikidata QUERY` and a people scan (on the command line or in
  the Web UI) reported a verified clean negative for a query nobody answered. `maxlag` and
  `ratelimited` are now rate-limited, any other error is inconclusive, and a reply with no hit
  list at all is parser drift. Wikipedia's user-contributions leg reads the envelope by the same
  rule (`fetch::mediawiki_api_error`), its `baduser_ucuser` still the clean "no such account", and
  neither carries an error code into its diagnostic unless it is shaped like one.
