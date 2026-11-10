# DeHashed

DeHashed is a keyed breach-search provider. Huntsman searches it for one exact value, under a
declared purpose, and reports what each breach record holds except its credentials. The client is
`src/dehashed/`; the record rule it shares with OathNet is `src/breach_record.rs`.

## Entry points

| Path | What it does |
|---|---|
| `huntsman-recon dehashed search (--email ADDR \| --username NAME \| --domain DOMAIN) --purpose PURPOSE [--size N] [--page N]` | One search; prints every record. |
| `... --save-artifact FILE` | Keeps the records as a scan artifact `correlate` can rerun on. |
| `exposure ADDR`, `email ADDR`, `scan -k exposure`, the web UI | Run the DeHashed leg beside HIBP, stolen.tax and OathNet, for addresses only. |
| `credential-status --probe` | Checks the key without spending a search credit (see **Credential probe**). |

**Key resolution.** Every path reads the key by one rule, the slot rule
`provider_credentials::secret_for_slot`. That covers `dehashed search`, the lookup legs,
`credential-status` and its probe, and the web UI's key settings and module list. It reads:

1. the `HUNTSMAN_DEHASHED_KEY` slot of `~/.huntsman.env`;
2. the process environment;
3. DeHashed's legacy private file `~/.config/dehashed/api_key` (`keys::PROVIDER_KEY_FILES`).

The file is read only while it is a regular file, owned by the user, and not readable by group or
others: the gate `~/.huntsman.env` passes. A refused file is named with its fix in the keys'
warning, on stderr and on the web UI's settings page, and its key is not used. The web UI shows a
key it did not save as set, and where it is.

The key is sent only to `https://api.dehashed.com:443`, and redirects are not followed.

## The API, as verified

Facts come from DeHashed's v2 API documentation (updated 2025-04-23), live unauthenticated
probes on 2026-11-06, live authenticated acceptance tests reported in commits
`44a1b57af55b18032e6e5e97104ce0ef0ee48a75` and
`40c4802776c154cb1e7e68054797c960f0d8209d` on 2026-11-07, and third-party clients.
- **Documentation provenance.** DeHashed's documentation was read from a published copy
  because its own pages presented a bot challenge.
- **Authenticated verification boundary.** Those commits report successful live exact
  domain/email searches and raw-response comparison. No usable key was found in the inspected
  source files or three sampled CI job logs; that limited inspection cannot establish that a
  current key exists in GitHub Actions.

| Fact | Source | What Huntsman does |
|---|---|---|
| `POST https://api.dehashed.com/v2/search`, key in the `Dehashed-Api-Key` header; v1 retired | Documentation, live | The only request a search sends |
| Body `query`, `page` (1-based), `size` (at most 10,000), `regex`, `wildcard`, `de_dupe` | Documentation | Sends `de_dupe: true`, `regex: false`, `wildcard: false` |
| "Maximum pagination depth is 10,000": page × size at most 10,000 | Documentation | Refused before sending (`BeyondDepth`, exit 65) |
| "1 search = 1 credit" | Documentation | The exposure leg reads 1,000 records per search |
| Response `{balance, entries, took, total}`; empty attributes omitted | Documentation | `balance` shown as credits left; all four read leniently |
| Entry: `id`, `database_name`, `raw_record {le_only, unstructured}`, and string arrays `email`, `ip_address`, `username`, `password`, `hashed_password`, `name`, `dob`, `license_plate`, `address`, `phone`, `company`, `url`, `social`, `cryptocurrency_address` | Documentation | Every non-credential value kept (see **What is kept**) |
| `vin`, `hash_type`, `obtained_date` | Third-party only | Kept by the same rule if sent; `hash_type` is held back as a credential |
| "10 requests per second from a single IP and API credential", sliding window, 429 past it | Documentation | One process-wide budget of 10 per second |
| Error bodies are JSON sent as `text/plain` | Live | Read as JSON whatever their type |
| `POST /v2/search-password {"sha256_hashed_password": ...}` "does not require credits or a subscription" | Documentation (two third-party clients send `hash` instead) | The credential probe |

**Query syntax.** Exact email and username values are quoted, for example
`email:"a@example.com"` and `username:"ada"`; domain values are **unquoted**,
for example `domain:example.com`. Live v2 testing on 2026-11-07 found that the
quoted domain form fails with HTTP 400, whereas unquoted domains match exactly.
- **Refused before any request.** Wildcards, regex, lists, quotes, backslashes, whitespace and
  non-ASCII input (`src/dehashed/query.rs`), so no search widens into a sweep.

## What is kept

A record is read as the JSON object it is (`Entry::from_record`):

- **Metadata.** `id`, `database_name` and `raw_record` describe the record. `raw_record`'s flags are
  shown as `unstructured` and `le_only`.
- **Every other field is an exposed field**, kept by name, with its values kept as written: one per
  list element, as DeHashed writes every field as a list. This is `breach_record::expose`, the rule
  OathNet follows.
- **Bounds.** At most 64 field names and 64 values per field; a value over 1,024 bytes is dropped
  whole, never cut.
- **Credentials.** A password, hash or salt, and any field the credential rule names (`hash_type`
  included, since the rule fails closed), is kept by name and as the fact that it was exposed.
  Its value is read only while decoding and never reaches a record, a report, an entity, evidence,
  `Debug` output or a saved file.

Where it shows:

- **`dehashed search`** prints, as `key=value` lines:
  - `balance=` and `took=`;
  - for each record, its database, emails, usernames and every other value as `FIELD=VALUE`;
  - `exposed_fields=`, `has_password=`, `has_hashed_password=` and `password_exposed=`;
  - the `unstructured` and `le_only` flags.
- **`exposure`** gives one row per breach database:
  - `dehashed_breach` with its records, `password_exposed` and `fields=`;
  - then one `dehashed_value` row per value, as OathNet's section has them;
  - the address's evidence carries `exposed_fields` and `value_<field>`;
  - the leg's outcome notes the credits left.
- **`--save-artifact`** evidence carries the values; the receipt's quota carries the credits left.

## Failures

| DeHashed answers | Huntsman reads it as | Outcome | Exit (CLI) |
|---|---|---|---|
| 400 `issue with authentication` | key rejected | `AuthRejected` | 77 |
| 400, other | bad request | `Upstream4xx` | 69 |
| 401 `You need a search subscription and API credits …` | no subscription or credits | `EntitlementDenied` | 77 |
| 401, other (`No Authorization header present`) | unauthorised | `AuthRejected` | 77 |
| 403 `Insufficient Credits` | out of credits | `EntitlementDenied` | 77 |
| 403 `Issue with API Key` | key rejected | `AuthRejected` | 77 |
| 403, other | forbidden | `EntitlementDenied` | 77 |
| 429 | rate limited; pauses DeHashed for its `Retry-After` | `RateLimited` | 69 |
| 5xx | server error | `Upstream5xx` | 69 |
| 200 challenge page | not an answer | `BotWaf` | 69 |
| 200 without `entries` | schema drift, never a zero | `SchemaDrift` | 69 |

**Error text.** The provider's words are matched, never echoed, and no error names the searched
value.

**Pacing.** Searches go through `fetch`'s per-host breaker:
- **What opens it.** A 429 opens it for its `Retry-After` (or the cool-down), and five failures in
  a row open it too.
- **What a held-back search reports.** `Paused`, with nothing sent: `Inconclusive`, exit 69.
- **Retries.** None: DeHashed is never retried automatically.

## Credential probe

`credential-status --probe` posts to `/v2/search-password` the SHA-256 of the fixed string
`huntsman-credential-probe`, never a password.
- **Cost.** DeHashed documents the endpoint as free, so the probe spends no search credit.
- **Structurally valid response.** A 200 is accepted only when it carries a numeric
  `results_found` field. This is evidence that the endpoint responded in the expected shape,
  **not independent proof** that the supplied key was authenticated: the repository does not
  test whether the same endpoint accepts a request without a key.
- **Rejected response.** A 401 or 403 is classified rejected (subject to the WAF check).
- **Indeterminate.** Anything else, including a 400 from a body field DeHashed reads differently.

## Not verified

- Historical live-key tests covered exact domain and email searches, record decoding and
  collector evidence. They did **not** establish current key availability in GitHub Actions.
- Remaining uncertainties include some 5xx bodies, live `Retry-After` behaviour,
  plan-specific credit accounting, and the success `Content-Type`.
- The current Search Guide's full field list, and any change after 2025-04-23.
- The live headers `x-ratelimit-limit: 20` and `x-ratelimit-reset: 1` disagree with the documented
  10 per second. Huntsman keeps the documented, lower rate.

## Test plan

Each risk has a test that fails when the behaviour it guards breaks. Test names are in
`src/dehashed/tests.rs` unless another file is named.

| Risk | Test |
|---|---|
| A credential reaches output, evidence or `Debug` | `types::a_documented_v2_record_keeps_every_value_but_its_credentials`, `the_cli_prints_the_credits_left_and_every_value_but_no_credential`, `collector_tests::evidence_keeps_every_value_and_the_receipt_the_credits_left`, `exposure::no_credential_survives_the_search_and_every_other_value_does`, `exposure_cli::tests::dehashed_breaches_show_every_value_on_the_email_but_never_a_credential` |
| A documented field is dropped | the same five |
| One record floods a report | `types::values_are_bounded_per_field_and_an_oversized_value_is_dropped_whole` |
| An odd metadata type loses the answer | `types::response_metadata_is_read_leniently_and_never_voids_the_answer` |
| A refusal names the wrong fix | `each_documented_refusal_reads_as_what_dehashed_meant`, `every_error_names_one_outcome` |
| Callers multiply DeHashed's rate | `every_production_client_shares_one_process_wide_budget` |
| A 429 is followed by another request | `a_rate_limit_pauses_the_next_search_without_sending_it` |
| A failing API is hammered | `repeated_server_failures_hold_back_the_next_search` |
| A request is spent past the depth | `a_page_past_dehashed_s_depth_is_refused_before_it_is_sent`, `cli_refuses_a_page_past_the_depth_without_sending` |
| A complete later page reads partial | `collector_tests::a_complete_later_page_is_not_partial` |
| The exposure leg under-reads per credit | `exposure::the_leg_reads_a_thousand_records_for_one_credit` |
| A key one path finds is missed by another | `every_path_reads_the_key_by_the_slot_rule`, `a_lookup_client_searches_with_the_resolved_key`, `provider_credentials::tests::the_slot_rule_reads_a_provider_key_file_last_and_names_every_source`, `web_server::tests::the_key_settings_show_every_key_a_lookup_would_use_and_where_it_is`, `credential_status_reports_the_key_dehashed_s_own_file_gives_every_search` (`tests/provider_credentials_cli.rs`) |
| The key file is read past its gate, or its refusal is silent | `keys::tests::a_provider_key_file_sets_its_slot_beside_the_keys_file`, `keys::tests::a_refused_provider_key_file_is_named_with_its_own_fix_and_never_read`, `keys::tests::a_provider_key_file_is_read_when_the_keys_file_cannot_be` |
| The probe spends a credit or misreads an answer | `service_defs::tests::the_dehashed_probe_spends_no_search_credit_and_reads_only_its_own_answer` |
| The key leaks into a request's `Debug` or the output | `debug_output_of_the_request_redacts_the_key`, `dehashed_uses_configured_shared_key_without_leaking_it` |

**Mutation check.** The record tests were run with `breach_record::expose` stubbed out and the
balance dropped: all six failed. They pass on the real code.


## GitHub Actions probe-response diagnostic

The repository workflow `.github/workflows/dehashed-auth-diagnostic.yml` uses the
production `huntsman-recon credential-status --probe` command. It has **manual dispatch
only**, and the job explicitly requires `refs/heads/main`. Development-branch pushes
and pull requests cannot invoke a secret-bearing probe.

- The workflow reads the GitHub Actions secret `HUNTSMAN_DEHASHED_KEY`, with
  `DEHASHED_API_KEY` as a fallback. GitHub **does not** make a historical secret
  recoverable from Actions logs, and the presence of earlier live-test commits
  does not imply a currently configured repository secret. The workflow is not
  available for manual dispatch on `main` until it is reviewed and merged.
- The binary is compiled **without** any secret in its build environment.
  The secret is supplied only to the probe step as an environment variable.
  The probe uses a fresh temporary HOME, strips unrelated configured-provider
  environment slots (including the HIBP alias), and does not search for leaked accounts.
  This matters because the existing `credential-status --probe` command otherwise
  checks **all** configured providers, not just DeHashed.
- The wrapper `.github/scripts/dehashed-auth-diagnostic.sh` prints only a
  fixed `dehashed_probe=` verdict, never the key, provider response or records.
  `valid_response` means only that the existing HUNTSMAN probe classified the
  API response as structurally valid. It does not prove key authentication,
  paid-search entitlement, current credit balance or an individual's exposure.
- `not_configured` means no key reached the job; `rejected` is the provider
  response classification; `inconclusive` covers indeterminate/unavailable
  responses. Missing, duplicate or contradictory provider state, verdict, or
  DeHashed key-slot fields are rejected. In free-probe mode the job fails
  on anything other than `valid_response`; paid real-domain mode runs
  independently and reports its own API outcome.
- Run the offline diagnostic contract checks with
  `bash tests/dehashed-auth-diagnostic.sh`. These use only synthetic outputs
  and do not require a provider key or network access.

To configure a repository secret, use the GitHub repository's
**Settings → Secrets and variables → Actions → New repository secret**.
Set `HUNTSMAN_DEHASHED_KEY` (preferred) or `DEHASHED_API_KEY`. Do not commit
a secret to source, a workflow YAML file, an issue, or a log.

## One-credit live acceptance against a real entity

An explicit live acceptance command uses the real DeHashed v2 client against
the public Australian company domain `telstra.com.au`:

```bash
bash scripts/dehashed-live-domain-acceptance.sh --allow-one-paid-search ./target/debug/huntsman-recon
```

It submits exactly one `dehashed search --domain telstra.com.au
--purpose security-research --size 1 --page 1` request, costing up to one
search credit when actually executed with a usable key. The script is intended
for a real authenticated API request, not the simulated offline contract.
It accepts a successful, structurally valid API response and reports only
`api_success_with_record` or `api_success_no_records`; any error, nonzero CLI exit, malformed header, stray record fields in an
empty result or mismatched entry count is a failure. The CLI's original
exit classification (missing key, denied entitlement, upstream failure)
is preserved even when the provider emits no stdout. It filters output in memory
and never prints or stores breach entries, email addresses, credential
values, or the provider's raw error response.

The manual, main-only workflow
`.github/workflows/dehashed-auth-diagnostic.yml` has an optional
`run_real_domain_search` input, default **false**, which runs that paid
acceptance **instead of** the no-credit probe, since an inconclusive free
endpoint response must not block an explicitly requested paid validation.
Automated CI runs only
`bash tests/dehashed-live-domain-acceptance.sh`, which uses synthetic
fake-binary output and spends no credits.

**Verification limits:** The offline contract verifies safe formatting,
argument selection and failure propagation, not an authenticated API
result. At the time of writing, GitHub-hosted runners did not start on
PR #1811; no current DeHashed key was accessible in the chat execution
environment. Accordingly, this live acceptance path remains **untested**
until explicitly executed with an available key and a working runner.
