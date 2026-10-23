- `asn AS13335` (and the AS arm of `scan`) starts its three `RIPEstat` calls as the `email`,
  `exposure` and scan lookups start their legs. On a phone that could not start another thread
  it panicked; a call whose thread cannot start now runs on a thread the lookup already has,
  only later, and each thread it starts has the 4 MiB stack `serve` gives a lookup. Its report
  does not change.
