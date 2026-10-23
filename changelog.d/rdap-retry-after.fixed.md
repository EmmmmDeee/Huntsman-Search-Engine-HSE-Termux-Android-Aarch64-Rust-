- An RDAP registry or the IANA bootstrap that answers 429 or 503 with `Retry-After: 120` used to
  leave the rdap outcome row with `retry_after_secs` null in the web scan JSON and no
  `retry_after_s=` in the scan log. The row now carries the delay (capped at 3600 seconds), in the
  domain, ip, netblock and asn lookups alike, and a `Retry-After` given as an HTTP date is counted
  from the scan's own clock.
