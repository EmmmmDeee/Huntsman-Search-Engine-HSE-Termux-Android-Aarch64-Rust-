- In the Web UI, "New Scan of this" on an element now runs the lookup the server names for it,
  instead of guessing one from the value, and is offered only when one takes the value. Every
  element row the API serves (`/elements`, search, compare) carries `scan_kind`. That is the
  lookup the element's type names, when that lookup takes the value: `sf.py -t`'s lookup for a
  target type, and the same lookup for the types Spiderfoot gives such values found beside a
  target (a parent, affiliate, co-hosted, look-alike or unresolved domain, an affiliate's
  address, a member block or AS, a role or affiliate e-mail address, a BSSID). A value its type's
  lookup refuses runs the lookup its own form names: a breach record's `username` that is an
  e-mail address runs the e-mail lookup, and a host name that is an IP address runs the IP
  lookup. It is null when nothing takes the value as what it is, never a people search of its
  words. The page used the type only for addresses and crypto addresses and kept its own list of
  the types it offered New Scan for. A `USERNAME` element left to detection was refused
  (`janedoe`) or run as another kind of scan: a domain scan of `jane.doe`, or of someone else's
  real domain for a handle such as `ada.dev`, an AS scan of `1337`, or a people search of
  `john_smith`. A co-hosted site such as `0412345678.com.au` ran a phone scan, and a domain with
  an `_` label ran a people search.
- A dotted IPv4 address is no longer a domain: no top-level label is all digits. A website on an
  address (`http://93.184.216.34/`) no longer gives a domain that a domain scan asks
  certificate logs, archives and DNS about while the address's own lookup never runs.
- A saved breach (`exposure`) scan of a handle types its target `USERNAME`, not `EMAILADDR`, so
  New Scan of it runs the username lookup instead of an e-mail scan the server refuses.
