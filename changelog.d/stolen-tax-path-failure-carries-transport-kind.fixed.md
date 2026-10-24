- An `exposure` lookup whose stolen.tax paths all got no response (no route, no connection, a
  timeout) ends as no usable response (exit 69) naming `stolen_tax`, where before it printed an
  empty report and exited 0. Each stolen.tax path failure now carries the outcome kind the fetch
  saw (`PathFailure::kind`) beside its text: a transport failure for a path that got no response,
  the status's kind (`upstream5xx`, `rate_limited`, ...) for one the source answered with an
  error, `inconclusive` for a 2xx that was no usable envelope. The exposure row keeps that kind
  instead of reading every stolen.tax failure as `inconclusive`, and a lookup budget spent after a
  path failed keeps the failed path's kind rather than always `body_timeout`. This closes the last
  refusal-contract gap: the contract test's second allowlist, `KNOWN_GAPS`, is gone and `BROKEN`
  is the one exact-set list, empty.
