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

**Key resolution.** Every path resolves the key one way, `dehashed::client::key_from_sources`:

1. the `HUNTSMAN_DEHASHED_KEY` slot of `~/.huntsman.env`;
2. the process environment;
3. the legacy private file `~/.config/dehashed/api_key`, used only while it is a regular file,
   owned by the user, and not readable by group or others.

The key is sent only to `https://api.dehashed.com:443`, and redirects are not followed.

## The API, as verified

Facts come from DeHashed's API documentation (v2, "Updated April 23, 2025"), live unauthenticated
probes of `api.dehashed.com` on 2026-11-06, and third-party clients.
- **Where the documentation was read.** DeHashed's own pages sit behind a bot challenge, so it
  was read from a published copy.
- **What is not verified.** Nothing here has been checked against a live key.

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

**Query syntax.** A search is one field-scoped, quoted, exact value: `email:"a@example.com"`,
`username:"ada"` or `domain:"example.com"`.
- **Refused before any request.** Wildcards, regex, lists, quotes, backslashes, whitespace and
  non-ASCII input (`src/dehashed/query.rs`), so no search widens into a sweep.
- **Unverified.** One third-party client says domains reject quotes.

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
- **Valid key.** A 200 proves the key only when it carries that endpoint's answer, `results_found`.
- **Rejected key.** A 401 or 403 is a rejected key.
- **Indeterminate.** Anything else, including a 400 from a body field DeHashed reads differently.

## Not verified

- Behaviour with a live key: an invalid query's answer, 5xx bodies, whether `Retry-After` is sent,
  whether a page costs one credit or each record does, and the success `Content-Type`.
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
| A key one path finds is missed by another | `every_path_resolves_the_key_one_way`, `a_lookup_client_searches_with_the_resolved_key` |
| The probe spends a credit or misreads an answer | `service_defs::tests::the_dehashed_probe_spends_no_search_credit_and_reads_only_its_own_answer` |
| The key leaks into a request's `Debug` or the output | `debug_output_of_the_request_redacts_the_key`, `dehashed_uses_configured_shared_key_without_leaking_it` |

**Mutation check.** The record tests were run with `breach_record::expose` stubbed out and the
balance dropped: all six failed. They pass on the real code.
