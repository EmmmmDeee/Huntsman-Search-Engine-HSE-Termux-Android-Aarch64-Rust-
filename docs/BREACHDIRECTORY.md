# BreachDirectory — source-only email and username lookup

BreachDirectory is an **optional**, operator-keyed breach-source provider. The
integration sends a single selector (email address or username) to the RapidAPI
gateway using the documented `func=sources` query. It does not query the
password, dehash or bulk-search functions.

## External API

- Provider homepage: https://breachdirectory.org/
- API listing: https://rapidapi.com/rohan-patra/api/breachdirectory
- Origin: `https://breachdirectory.p.rapidapi.com:443`
- One request: `GET /?func=sources&term=<percent-encoded-selector>`
- Gateway headers: `X-RapidAPI-Host: breachdirectory.p.rapidapi.com` and
  `X-RapidAPI-Key` (resolved by HUNTSMAN's credential mechanism)
- Redirects: not followed
- Client: the shared `api_leg` / `fetch` / `http::Transport` stack;
  no extra HTTP client or third-party runtime dependency

Only configure a RapidAPI key with an account/plan entitled to use this API.
An API key by itself **does not** guarantee subscription or quota access.
RapidAPI plans and overage pricing can change, so confirm them on the live
marketplace before enabling. HUNTSMAN does not purchase a plan.

## Configuration (Termux or other supported host)

Store the operator's key in HUNTSMAN's existing private keys file
(`~/.huntsman.env`; **do not commit the key**):

```text
HUNTSMAN_BREACHDIRECTORY_KEY=<your-RapidAPI-key>
```

Ensure the file is accessible only to its owner (`chmod 600 ~/.huntsman.env`).
Or set the variable in the process environment; normal HUNTSMAN key resolution
and precedence apply. Do not put the key into a query URL, scan identifier,
GitHub issue, screenshot, log or response body.

With a configured key, these existing entry points request the source:

```sh
huntsman-recon credential-status
huntsman-recon email your-address@example.com
huntsman-recon username your-own-handle
```

Use the Web UI's **New Scan → By Module → breachdirectory** selection for
an email or username scan. The provider is not run in passive mode.
When selected but not configured it emits a `not_configured` source outcome,
not an assertion that the target has no breaches.

A configured key enables this provider on applicable normal email/username
lookups. **Such lookups may count against RapidAPI credits or incur overages**
depending on the selected plan. Budget and module selection must be set by
the operator; no API calls are made merely by configuring the key.

## Evidence and failure behaviour

The source processes a reported breach-source name/list and optional
`found` record count. Source names are de-duplicated case-insensitively,
kept as reported in the first spelling, and stored as source-attributed
evidence on the queried email or username. The `breach` tag is applied
only when at least one source name or positive count is reported.

The decoder does **not** retain password, hash, SHA-1, salt, dehash results,
or arbitrary returned account values, even if the gateway includes them
in a response. Credentials are never used as pivots.

A transport error, challenge page, API refusal, rate limit, bad JSON,
unexpected schema or missing key is **not a negative result**. HTTP and
credential failures retain their typed source outcomes, while an explicit
empty source list or `found: 0` is a valid zero.

A positive result is a provider claim that a selector appears in a breach
source, **not independent confirmation of identity or of current account
control**. Corroborate any investigative conclusion with independent evidence.

## Known verification boundaries

The request format and gateway headers are described by API listings and
third-party client references. The response decoder supports conservative,
**synthetic** fixtures for `sources` and `result[].sources` and a numeric
`found`. These shapes must be validated against an **actual successful
response from the operator's subscribed RapidAPI account** before a
production-ready release. In particular, a real response may use different
envelopes or source-name fields.

Required release checks:

```sh
cargo fmt --all -- --check
cargo test breachdirectory
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

For a live acceptance test, run a lookup for a consented test identifier,
inspect the source outcome and saved evidence and compare it to the raw
provider response **without publishing that response**. Verify the same
provider is reached through the Web UI, and verify a configured key and
a missing key produce the expected different outcomes. Check RapidAPI
quota/charges before and after. Perform Termux AArch64 acceptance.

This module intentionally does **not** change HUNTSMAN's separate
`exposure` command or DeHashed/OathNet pipelines. It is reachable via
email and username lookups and their corresponding Web UI scans.
