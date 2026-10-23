- `ip` no longer asks the Internet Storm Center about an IPv6 address. ISC answers every IPv6
  query with the same unrelated record (`"number": false`), so
  `huntsman-recon ip 2001:4860:4860::8888`, and the same address in `scan` or the web UI's
  lookup, sent the address to isc.sans.edu and always ended with a failed `isc` row,
  `schema_drift` with `isc: answer names another address`. An IPv6 lookup now sends nothing to
  ISC and has no `isc` row, as it already had none for Netlas and HackerTarget; IPv4 lookups are
  unchanged, and `modules` and the README say ISC is IPv4 only.
- An Internet Storm Center answer whose only activity is web-honeypot requests now marks the
  address malicious. For an answer on `45.148.10.99` holding
  `"weblogs":{"count":5,"firstseen":"2026-02-04","lastseen":"2026-02-04"}` and no reports,
  network, threat feed or SSH record, the `isc` row read `valid_zero` and the address got no ISC
  evidence, although the same answer with an SSH record was malicious. It is now an `isc` success
  row whose evidence is tagged `malicious`, with `malicious=5` and the `weblogs` attribute.
