- A source row for a request Huntsman's guarded path refused before sending — the egress policy
  dropped the destination's address, or a URL, redirect target or credential binding could not be
  sent safely — now carries the `refused_before_sending` outcome kind instead of `inconclusive`,
  `connect_failure` or `entitlement_denied`. This covers the keyed and keyless JSON legs
  (internetdb, ripestat, greynoise, abuseipdb, virustotal, hunter, mnemonic, certspotter, the
  indicator sources and numverify), RDAP, WiGLE and OathNet, the threat-feed sources, the DoH and
  UDP DNS filters, the DNS resolver pool (an `ip` PTR sweep, a `netblock` sweep and a `domain` dns
  or dnsresolve row refused only when every server asked refused), crt.sh, stolen.tax, the
  username profile legs and the SeekNow lookup row. For these rows the recommended action becomes
  `investigate` and a scan's uncertainty register lists them under `refused_before_sending`.
- An aggregated row that joins several requests (the DoH pool, the `asn` holder/prefixes/neighbours
  calls, a threat-feed source with several feeds, a DNS filter with two servers) is refused only
  when every request it made was refused; if one request reached a server and then failed, the row
  keeps that reached-server failure.
- No lookup's exit status or stderr changes yet: the front ends still end from their own channels,
  so this release only relabels the rows. crt.sh's refused row detail now reads
  `crtsh: request refused: <reason>` instead of the bare reason.
