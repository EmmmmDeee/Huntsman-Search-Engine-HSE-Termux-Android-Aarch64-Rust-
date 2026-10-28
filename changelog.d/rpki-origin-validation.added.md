- `ip ADDRESS` (and `scan -k ip`, saved scans and `/api/lookup`) now asks RIPEstat's keyless
  `rpki-validation` for the RPKI route-origin validation state of the announced prefix covering
  the address, for each of its first four public origin AS numbers. Each origin AS carries
  `rpki_state` (`valid`, `invalid_asn`, `invalid_length` or `unknown`), what that state means
  and does not, the validator and the ROAs it was judged against. An invalid state also puts a
  record tagged `rpki_invalid_origin` on the address: a misconfiguration, a stale ROA or a
  hijack, never stated as proof of any. An unannounced address sends no RPKI request, and a
  check that failed is recorded as failed, never as an unknown state.
