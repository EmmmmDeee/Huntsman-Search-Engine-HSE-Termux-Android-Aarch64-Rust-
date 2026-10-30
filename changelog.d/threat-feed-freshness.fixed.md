- A threat feed whose publisher stopped updating it no longer answers "not listed" or marks what
  it lists as a current threat. The date a feed was last updated (`Last-Modified`) is now kept
  with its copy, bound to the copy's length and CRC-32, and named on its row. A list published
  without one answers for when its copy was downloaded, and a copy whose date is unknown answers
  for nothing. A list older than its window (30 days; blocklist.de's 48 hours, CleanTalk's seven
  days, Tor's relay list three days) cannot say a subject is absent, so its row is inconclusive
  instead of a validated zero. A subject it lists keeps its whole entry, marked stale with the
  list's date, but is neither `BLACKLISTED_*` nor `MALICIOUS_*` in a saved scan, which
  Spiderfoot's "considered malicious by multiple sources" correlation would read as a current
  verdict, and no `TOR_EXIT_NODE`. On 30 October 2026 four lists were older than that and had
  read as live threat lists: AlienVault IP Reputation (last updated November 2021), botvrij.eu
  (October 2021), CleanTalk's list (July 2025) and abuse.ch's Feodo Tracker (June 2026). Lists
  published without a date (CyberCrime-Tracker, OpenPhish, Steven Black, VoIPBL, VXVault) answer
  for when they are downloaded, so one that stops changing without saying so still reads as
  current. A copy
  kept by an earlier version, or rewritten since its date was kept, is downloaded again, and if
  that fails it answers for nothing. A source with more than one list says "not listed" only
  when every list under it was read and is current.
- URLhaus's downloads, which answer `410 Gone`, and CoinBlocker's list, no longer public, are no
  longer downloaded. Every lookup that ran them asked both: CoinBlocker's row failed, and
  URLhaus's failure was folded into the `abusech` row, which said "not listed" whenever Feodo
  Tracker answered without listing the subject. URLhaus is still asked through its keyed API
  (`HUNTSMAN_ABUSECH_KEY`) about an IPv4 address or a domain a lookup targets; the other
  addresses and hosts a lookup finds, address blocks and IPv6 addresses are no longer checked
  against URLhaus. A saved scan or
  Spiderfoot module list that names `coinblocker` or `sfp_coinblocker` still runs, without it.
