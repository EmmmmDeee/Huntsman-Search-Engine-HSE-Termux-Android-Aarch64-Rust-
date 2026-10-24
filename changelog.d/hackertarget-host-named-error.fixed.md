- A `domain` or `ip` lookup no longer refuses a HackerTarget host list whose first host begins
  with "error". `domain errorception.com` got the list back (HackerTarget names the domain
  itself first), but read that first line as HackerTarget's error text, so the `hackertarget`
  row was a schema-drift failure reading `HackerTarget: errorception.com,...` and none of the
  hosts or addresses were kept; an address whose first hosted domain began with "error" failed
  the same way. Only a line that is "error" followed by a space, as every HackerTarget error
  text is, is read as an error now, so the row succeeds with `HackerTarget: 1 host` and the
  hosts, addresses and their pivots are kept.
