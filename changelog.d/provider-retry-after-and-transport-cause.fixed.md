- Every keyed leg now reads a rate limit's `Retry-After` the way the fetch does. The free-tier
  API legs, OathNet, WiGLE and DeHashed read only a count of seconds, so they dropped a pause
  sent as an HTTP-date and kept a pause of more than an hour as sent. They now take the value
  the fetch reads, which honours a date and caps the pause at an hour, as the circuit breaker
  already does.
- HIBP and DeHashed now record why a request got no response. `exposure` recorded each such
  failure as `connect_failure` for HIBP and `inconclusive` for DeHashed, while OathNet kept the
  cause. A DNS, TLS or timeout failure is now `dns_failure`, `tls_failure` or `ttfb_timeout` on
  all three. A challenge page served with 200 is now `bot_waf` rather than `schema_drift`, and
  the HIBP leg records the HTTP status and retry hint of a refusal, as the other keyed legs do.
