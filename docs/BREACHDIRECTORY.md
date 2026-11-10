# BreachDirectory — RapidAPI source-only collector

BreachDirectory is optional and **disabled without an operator-provided RapidAPI key**.
The integration uses the supported RapidAPI gateway only; it does not scrape the
website, bypass access controls, reuse browser cookies, or call undocumented
direct-backend endpoints.

## Supported contract

| Item | Value |
| --- | --- |
| Module | \`breachdirectory\` |
| Credential slot | \`HUNTSMAN_BREACHDIRECTORY_KEY\` |
| Endpoint | \`GET https://breachdirectory.p.rapidapi.com/\` |
| Query | \`func=sources&term=<percent-encoded exact email or username>\` |
| Required headers | \`X-RapidAPI-Key\`, \`X-RapidAPI-Host: breachdirectory.p.rapidapi.com\` |
| Pin | \`https://breachdirectory.p.rapidapi.com:443\` |
| Redirects | None |
| Request timeout | 20 seconds |
| Client pacing | Conservative shared 60/minute |
| Parsing | \`sources\` must be a JSON array of nonempty source-name strings |
| Max names | 256, each at most 256 bytes |
| Output | One provider evidence source, not independent corroboration per named breach |

Sources:
- https://rapidapi.com/rohan-patra/api/breachdirectory
- https://docs.rapidapi.com/v2/docs/configuring-api-authentication
- https://stackoverflow.com/questions/69969361/loop-through-axios-data-and-perform-another-axios-request-and-concat-the-two-res

The actual provider response schema has **not** been confirmed using an
authenticated request. \`sources: []\` is treated as a valid zero; null, omitted,
oversized or malformed \`sources\` are **inconclusive** until a real, authorised
provider response demonstrates a different zero contract. A 200 response with
\`success: false\` or a non-null error is likewise inconclusive.

The provider has modes that return passwords or hashes (\`auto\`, \`dehash\`).
This collector intentionally does **not** implement them. It does not retrieve,
cache, print or save such values. Source names are saved as leads under a single
\`breachdirectory\` provenance key, without claiming independent corroboration.

## Command and Web UI

After installing a build that contains this module:

1. Create/reuse a RapidAPI account and subscribe to the official API. Verify
   the provider and current plan, quota and overage terms on RapidAPI.
2. Store a valid operator-owned RapidAPI key privately in
   \`$HOME/.huntsman.env\`:
   \`HUNTSMAN_BREACHDIRECTORY_KEY=YOUR_REAL_RAPIDAPI_KEY\`
   and \`chmod 600 "$HOME/.huntsman.env"\`.
3. Run \`huntsman-recon exposure YOUR_AUTHORISED_EMAIL\`, or choose
   \`breachdirectory\` on the New Scan page for email, username or exposure.
4. Look for \`breachdirectory\` in the Sources table. For a positive response,
   a named breach source is stored in the seed entity's \`breach_source\`
   evidence attribute, with \`verification=provider_reported_only\`.

A standalone \`breachdirectory\` subcommand and a spending-key validation probe
are **not** implemented. That is deliberate: probing through search would
consume paid quota. A configured slot is not proof of a working subscription.

## Verification and deployment gate

- Unit tests cover strict parsing, empty versus malformed responses,
  errors and 429, no-key zero network sends, encoded selectors, RapidAPI
  headers, and discarding surplus non-sources response content.
- Build/test on the repository's supported Rust toolchain; run its architecture,
  module-registration, lookup-selection, and exposure tests.
- Complete an opt-in live acceptance test with a **consented** test address and
  a valid key. Save only response schema and a non-sensitive receipt; do not
  log the selector or key.
- The exact plan quotas, live API response semantics, and Android binary
  compatibility remain unverified until that gate is executed.
- No change to existing HIBP, DeHashed, OathNet or stolen.tax credential
  semantics is intended; every existing leg remains independently selectable.
