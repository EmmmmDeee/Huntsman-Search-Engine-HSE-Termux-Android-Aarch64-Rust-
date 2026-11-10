- Added a BreachDirectory RapidAPI `sources` provider for exact email and username
  lookups, including New Scan module selection, module catalogue, credential
  status, and preserved provenance through the existing evidence pipeline.
- Credential `HUNTSMAN_BREACHDIRECTORY_KEY` is sent only through the existing
  origin-bound credential mechanism; API host header is fixed, redirects are
  disabled, and missing keys make no request. Only breach-source names and
  counts enter evidence; never credential values.
- Unknown and failed responses are reported as errors rather than clean
  negatives. Added synthetic decoding and request tests. Real API schema,
  paid-plan entitlement, CI tests and Android validation are still required
  before release.
