- A blocklist listing marks an address malicious only when it records the address's own abuse.
  Spamhaus's PBL (`127.0.0.10`/`.11`) lists end-user ranges by policy, and UCEPROTECT's levels 2
  and 3 list the address's network and AS, yet each tagged the address `malicious` at 0.90 and a
  saved scan held `MALICIOUS_IPADDR` for it. Each listing now keeps its class (`dnsbl_class`:
  `abuse`, `policy` or `neighbourhood`) with its list, zone, answer and reason; a policy or
  neighbourhood listing is still `BLACKLISTED_IPADDR`, as Spiderfoot types a listing, but marks
  nothing malicious (Spiderfoot's `multiple_malicious` rule, run unchanged, still counts any two
  blacklistings of one address). SURBL's DM and CT bits (disposable-mail providers and mail click
  trackers) are named and are policy listings, where they read as "undocumented answer" abuse. A
  scan saved before listings carried a class reads as it did.
- Spamhaus's DBL answer `127.0.1.255` ("IP queries prohibited") is the refusal it is, not a
  listing of the "domain" at 0.90.
- SORBS has shut down: `sorbs.net` no longer resolves (NXDOMAIN at the `.net` servers), so every
  lookup asked a list that could never answer. It is no longer asked, and its row is
  `confirmed_dead` saying why.
- A blocklist that failed is no longer "not listed": `EAI_FAIL` ("non-recoverable failure in name
  resolution", glibc's and bionic's words for a server that refused or could not answer the
  query) was read as "no such name". A name DNS cannot carry (over 253 bytes, or a label over 63) is never asked, and its
  row says it could not be.
- A filtering resolver's block address that the zone publishes itself (a parked or sinkholed name
  answering `0.0.0.0` everywhere) is the zone's own record, not a block: CloudFlare's malware
  filter no longer marks such a name malicious because every resolver gives the same answer.
