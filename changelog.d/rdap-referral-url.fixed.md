- When a registry refers an RDAP lookup to another one (for example `huntsman ip` on an address
  where ARIN answers with a 301 to RIPE's record), the `rdap_url` attribute and the rdap
  outcome detail (`record <url>`) used to name ARIN's URL, next to RIPE's record in `whois`.
  They now name the URL that served the record, the last hop. Lookups without a redirect do not
  change.
