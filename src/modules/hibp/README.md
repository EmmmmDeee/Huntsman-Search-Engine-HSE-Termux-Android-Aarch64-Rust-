# HIBP (Have I Been Pwned) integration

`src/modules/hibp` has two parts:

* the `hibp` scan module (`mod.rs`): email → breaches + pastes, domain →
  breaches, wired into the HSE engine as before;
* a library client (`client.rs`, `passwords.rs`, `oauth.rs`, `key.rs`,
  `rate_limit.rs`, `types.rs`, `error.rs`) covering the HIBP API v3 read
  endpoints and the Pwned Passwords range API.

The endpoint list, parameters and response shapes follow
<https://haveibeenpwned.com/API/v3>. The OAuth flow follows
<https://haveibeenpwned.com/auth.md> and the metadata at
`/.well-known/oauth-authorization-server`, both read on 2026-10-02.

## Endpoints

| Client method | Request | Needs |
| --- | --- | --- |
| `breaches(filter)` | `GET /breaches?Domain=&IsSpamList=` | nothing |
| `breach(name)` | `GET /breach/{name}` | nothing |
| `latest_breach()` | `GET /latestbreach` | nothing |
| `data_classes()` | `GET /dataclasses` | nothing |
| `breached_account(email, opts)` | `GET /breachedaccount/{email}?truncateResponse=&domain=&IncludeUnverified=` | key |
| `breached_account_range(prefix)` / `breached_account_by_hash(email)` | `GET /breachedaccount/range/{6 hex}` | key + `IncludesKAnon` |
| `paste_account(email)` | `GET /pasteaccount/{email}` | key |
| `breached_domain(domain)` | `GET /breacheddomain/{domain}` | key, verified domain |
| `subscribed_domains()` | `GET /subscribeddomains` | key |
| `subscription_status()` | `GET /subscription/status` | key |
| `stealer_logs_by_email(email)` | `GET /stealerlogsbyemail/{email}` | key + `IncludesStealerLogs` |
| `stealer_logs_by_website_domain(domain)` | `GET /stealerlogsbywebsitedomain/{domain}` | key + `IncludesStealerLogs` |
| `stealer_logs_by_email_domain(domain)` | `GET /stealerlogsbyemaildomain/{domain}` | key + `IncludesStealerLogs` |
| `pwned_passwords_range(prefix, mode, pad)` | `GET https://api.pwnedpasswords.com/range/{5 hex}[?mode=ntlm]` | nothing |
| `check_password(pw, mode)` | hashes locally, then the range call above | nothing |

A 404 from a search endpoint means "not found" and returns an empty result.
The domain-verification endpoints (`/domainverification/*`) and the
verification-email endpoint are deliberately not implemented.

## API key: sources and precedence

The first source that has a non-blank value wins (`key::KeyLoader::default_chain`):

1. `HIBP_API_KEY` environment variable.
2. `HUNTSMAN_HIBP_KEY`, the existing HSE slot (process env or `~/.huntsman.env`).
3. `~/.config/hibp/api_key`, whole file, trimmed. Keep it `chmod 600`; a
   warning is logged if group or others can read it.
4. The key embedded at build time (below).

So a runtime key always overrides the embedded one. Blank values and
`insert_..._here` placeholders count as "not set". The key is sent only as the
`hibp-api-key` header, and only to haveibeenpwned.com (never to Pwned
Passwords). `ApiKey`'s `Debug`/`Display` print `<redacted>`, and upstream error
bodies are redacted before they reach an error or a log line.

### Build-time embedding

`build.rs` reads `HIBP_API_KEY`, then `~/.config/hibp/api_key`, on the build
machine and writes it to `$OUT_DIR/hibp_embedded_key.txt`, which `key.rs`
pulls in with `include_str!`. The file is never in the source tree, and the
build prints nothing about the value. **A binary built this way contains the
key.** Anyone who has the binary can extract it.

The embed is skipped (an empty key is compiled in) when any of these is set to
a truthy value:

* `HUNTSMAN_HIBP_NO_EMBED=1`: explicit opt-out;
* `CI`: set by GitHub Actions, so CI and `release.yml` builds never carry a key;
* `HSE_RELEASE`: for any other publishing pipeline.

A binary without an embedded key loads its key at runtime from sources 1–3.
Use `HUNTSMAN_HIBP_NO_EMBED=1` for any build you will share.

**Any build made outside GitHub Actions for publishing must set `HSE_RELEASE=1`
(or `HUNTSMAN_HIBP_NO_EMBED=1`)**: a build on a box where `HIBP_API_KEY` is set
or `~/.config/hibp/api_key` exists embeds that key.

## Plan gating

The stealer-log endpoints and the k-anonymity account range first read
`/subscription/status` (once per client) and return
`HibpError::PlanNotEntitled { plan, feature }` **without calling the gated
endpoint** when `IncludesStealerLogs` / `IncludesKAnon` is not `true`. On a
Core 1 plan both are off. Pwned Passwords is free and never gated.

## Rate limits

* Client-side: a shared sliding-window limiter, 10 requests/minute by default
  (the lowest plan's rate). Set `HIBP_RATE_LIMIT_PER_MINUTE` to change it
  (`0` turns client-side limiting off). Keyed requests and the scan module's
  requests go through it.
* Server-side: a 429 pauses the limiter for the `retry-after` seconds and is
  retried up to 3 times, then `HibpError::RateLimited { retry_after }` (mapped
  to HSE's `Error::RateLimited`).
* Other statuses: 400 `BadRequest`, 401 `Unauthorized`, 403 `Forbidden`,
  5xx `Server`.
* Pwned Passwords has no rate limit and skips the limiter.
* Every request sends `user-agent: huntsman-search-engine/<version> (+repo URL)`;
  HIBP answers 403 without one.

## Pwned Passwords

`pwned_passwords_range` takes a 5-hex prefix and `PasswordHashMode::Sha1` or
`::Ntlm` (`?mode=ntlm`). With padding on it sends `Add-Padding: true` and drops
the zero-count padding entries. `check_password` hashes locally (SHA-1 of the
UTF-8 password, or NTLM = MD4 of UTF-16LE) and only sends the prefix.

## OAuth 2.0 (authorization code + PKCE)

`oauth.rs` is a library flow, no secret, no browser automation:

1. `discover(http, METADATA_URL)` reads the authorization-server metadata.
2. `register_client(http, registration_endpoint, name, redirect_uris)` does
   dynamic client registration at `https://haveibeenpwned.com/connect/register`
   as a public client (`token_endpoint_auth_method: "none"`).
3. `Pkce::generate()` makes an S256 verifier/challenge; `random_state()` a state.
4. `authorization_url(...)` builds the URL with
   `scope=openid offline_access hibp.mcp` and
   `resource=https://haveibeenpwned.com/mcp`. The user opens it and consents.
5. `exchange_code(...)` and `refresh(...)` call the token endpoint.
6. `FileTokenStore` keeps tokens in `~/.config/hibp/oauth_tokens.json` (mode 600).

HIBP documents this token as a bearer token for its MCP server
(`https://haveibeenpwned.com/mcp`). The REST v3 docs only describe the
`hibp-api-key` header, so the REST client keeps using the API key. Whether the
REST API accepts the OAuth token is not verified.

## Tests

`tests/lib.rs` and `tests.rs` run offline against a loopback HTTP server
(`util::http::test_server`) with JSON fixtures shaped on the documented samples.
They cover every endpoint, both auth paths (API key, OAuth/PKCE), plan gating,
padding, 429 handling, the limiter, key precedence and redaction. No test
calls HIBP.
