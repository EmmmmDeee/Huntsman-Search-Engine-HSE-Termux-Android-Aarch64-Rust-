- An IP address is one value however it is written. An IPv4 address written IPv4-mapped
  (`::ffff:1.1.1.1`) was kept in that form, so `ip ::ffff:1.1.1.1` (and `scan` routing it) asked
  Shodan InternetDB, RIPEstat, mnemonic, Pulsedive, urlscan.io, IPinfo, Robtex, StopForumSpam,
  Maltiverse and PhishStats about `::ffff:1.1.1.1`, OTX as an IPv6 indicator, the reverse zone under
  `ip6.arpa`, and RDAP's IPv6 bootstrap, which names no registry for it, so the regional registry
  was never asked; GreyNoise, Netlas, HackerTarget and the SANS ISC, asked about IPv4 addresses
  only, were not asked at all.
  It is now looked up as `1.1.1.1`, request for request, and a mapped private address is refused
  as its IPv4 address is. An address a source reports is one entity in every spelling it is written
  in (`2001:DB8::1`, `2001:db8:0:0::1`, `[2001:db8::1]`), keyed by its compressed lower-case form,
  where each spelling was its own entity and the sources that reported it never corroborated each
  other; what the source wrote stays the entity's raw value. A provider that echoes the asked IPv4
  address in its mapped form is read as answering about it.
