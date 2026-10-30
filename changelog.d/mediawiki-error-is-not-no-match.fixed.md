- A Wikidata search the `MediaWiki` Action API did not run is no longer recorded as "no Wikidata
  item". The API answers an error with HTTP 200 and an `error` envelope instead of a hit list: its
  search backend too busy (`cirrussearch-too-busy-error`) or failing
  (`cirrussearch-backend-error`), or an internal error. The search read the missing list as an
  empty one, so `wikidata QUERY` and a people scan (on the command line or in the Web UI) reported
  a verified clean negative for a query nobody answered. A busy backend or a throttle is now
  rate-limited, any other error is inconclusive, a reply with no hit list at all is parser drift,
  and hits that name no item are schema drift. Wikipedia's user-contributions leg reads the
  envelope by the same rule (`fetch::mediawiki_api_error`). Its clean "no such account" now also
  fires on current `MediaWiki`, which says `baduser` for a name that can be no account where
  releases before 1.35 said `baduser_ucuser`; before, such a name was inconclusive. Neither leg
  carries an error code into its diagnostic unless it is shaped like one (letters, digits, `_`,
  `-` and the `\` of a namespaced internal error, at most 128 of them).
