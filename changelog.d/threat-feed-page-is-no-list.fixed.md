- A threat feed's publisher serving a page in place of its list (an HTML landing, terms, "feed has
  moved" or challenge page) no longer replaces the list kept on the device or reads as the list.
  Any 200 body was kept as the feed's copy, so such a page replaced the last good copy and every
  lookup read the page until the copy was due again (18 hours; Steven Black's 24, Tor's one). On a
  URL list, every URL inside the page's markup (`<link href="https://…">`) read as an entry, so
  the page passed as a list: the hosts its markup named (the publisher's own, a font or script
  host) were listed as malicious, and every other address and host a domain, IP or netblock lookup
  checked read as "not listed". A download that is an HTML document is now a failed download: it
  is not kept, a feed with a copy keeps answering from it and says the list could not be
  downloaded again, and one with none says it was an HTML page in place of the list. A page an
  earlier version kept is downloaded again, and a `://` makes a URL only after a URI scheme. Any
  other body is read as before: a list wrapped in markup that is no document (VX Vault's `<pre>`)
  is the list whatever its entries spell, and a list that empties replaces its copy.
