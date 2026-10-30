- A threat feed's publisher serving a page in place of its list (an HTML landing, terms, "feed has
  moved" or challenge page) no longer replaces the list kept on the device or reads as the list.
  Any 200 body was kept as the feed's copy, so such a page replaced the last good copy and every
  lookup read the page until the copy was due again (18 hours; Steven Black's 24, Tor's one). On a
  URL list, a line of the page's markup linking to another site (`<link href="https://…/…">`) read
  as an entry, so the page could pass as a list: the hosts it linked to (the publisher's own, a
  font or script host) were listed as malicious, and every other address and host a domain, IP or
  netblock lookup checked read as "not listed". A body that opens with a tag (a doctype, `<html>`,
  a `<meta>` refresh, a `<script>`, after any byte-order mark, white space, XML declaration and
  comments) is now a failed download: it is not kept, a feed with a copy keeps answering from it
  and says the list could not be downloaded again, and one with none says it was an HTML page in
  place of the list, a challenge page as a challenge. A page an earlier version kept is downloaded
  again. VX Vault's list, which opens with `<pre>`, is still the list whatever its entries spell,
  as is Tor's JSON relay list, and a list that empties still replaces its copy. A URL list's entry
  is read by its host after a URI scheme's `://`, and without a scheme when a `://` falls inside it
  (a URL in its query), and a byte-order mark no longer hides a list's first entry.
