- PhishStats keeps the reports it read when a later page fails. For an address with 100 or more
  reports, a rate limit (HTTP 429) or any other failure on the second page made the `phishstats`
  row a failure (`rate_limited`) and dropped the 100 reports already read, so the address got no
  PhishStats evidence and no `malicious` or `phishing` tag. The row is now a success with those
  reports (`malicious=100`, `phishing_urls`, `more_reports=true`) and a `cut_short` attribute,
  `page 2 could not be read: rate or quota limit reached (HTTP 429)`. A failure on the first page
  still fails the row, as does a later failure when the pages read held no report.
