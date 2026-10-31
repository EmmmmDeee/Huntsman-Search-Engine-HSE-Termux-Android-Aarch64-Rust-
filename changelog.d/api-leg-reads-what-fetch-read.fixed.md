- A source that never answered is no longer recorded as "checked, nothing known". The free and
  free-tier API legs read a `404` before anything else, so a CDN's block page, a proxy's or a moved
  endpoint's 404 page reached ISC, Maltiverse, sub.md, Hudson Rock's domain leg, Cert Spotter,
  LeakIX, Censys and SecurityTrails as the provider's "nothing known", and the row read
  `valid_zero` (Cert Spotter's at HTTP 200). What the fetch read the response as now decides first:
  a challenge or block page is `bot_waf` and a rate limit is `rate_limited` at any status, and a
  `404` reaches a provider module only when it was read whole and is not a page. ISC, Maltiverse
  and Cert Spotter answer a selector they know nothing of with a `200` (null fields, a neutral
  record, `[]`), and Spiderfoot's `sfp_isc`, `sfp_maltiverse` ("API endpoint not found") and
  `sfp_certspotter` read their `404` as an error, so it is one here too.
- A `403` rate limit (with `Retry-After`, an exhausted `x-ratelimit-remaining`, or GitHub's
  secondary-limit message, which carries neither) is `rate_limited` with its pause, where the API
  legs read it as `entitlement_denied` with none and told the operator to check an account, and
  GitHub's message-only limit read as a rejected credential that never paced the host. A rate
  limit's row keeps the status it came with instead of always saying `HTTP 429`.
- Only a sent credential can be rejected: a `403` to a request that carried none (a geo-block, an
  address ban, a proxy's policy, such as an egress proxy refusing a path) is `upstream4xx`, never
  `auth_rejected` asking for a credential that does not exist, and an API leg's keyless `401` asks
  for authentication rather than reporting a rejected key. The reading is made once, where the
  response is classified, so the keyless sources that classify a response themselves (ACNC, the
  ASIC registers, Nominatim and the web query engines) and `huntsman-recon classify` read a `403`
  the same way.
