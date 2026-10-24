- An `ip` lookup of an IPv6 address no longer asks URLhaus, which cannot answer for one. With
  `HUNTSMAN_ABUSECH_KEY` set, the address was sent to URLhaus's host endpoint, which takes an IPv4
  address, host name or domain name only, so every IPv6 lookup reported a failed `urlhaus` row
  (`schema_drift`). URLhaus now runs for IPv4 addresses and domains only, as HackerTarget, Netlas
  and the Internet Storm Center do, and leaves no outcome row for an IPv6 address.
