- `credential-status --probe` and `doctor --probe` send each key the way the lookups do: as a
  credential bound to the origin of the provider's probe URL, with redirects not followed, so
  the key goes nowhere else. The probe used to follow up to five redirects and judge the key on
  whatever the last one returned, so a probe answered with a 302 to a page that answered 200
  printed `probe=valid`; the redirect is now the answer and prints `probe=indeterminate`.
  Answers that are not redirects print as before.
- The Hunter.io probe sends the key in the `X-API-KEY` header, where the Hunter lookup sends
  it, instead of in the probe URL's `api_key` query parameter.
