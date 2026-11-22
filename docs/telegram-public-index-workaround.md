# Huntsman Telegram public-index discovery

**Scope:** Keyless, permission-conscious discovery of *publicly indexed* Telegram links and related public catalogues, through Huntsman's existing `public-osint web` Rust transport. No Telegram login, bot token, MTProto session, private-group enumeration, or access-control bypass. Search-engine results are **unverified leads**, never evidence of account ownership, group membership, or identity.

## Run

From the canonical Huntsman repository with `huntsman-recon` installed:

```sh
# Four default site-filtered search cohorts, 3 built-in engines per cohort.
bash scripts/telegram-public-discovery.sh --output "$HOME/telegram-case-1" example topic

# Eight opt-in cohorts: four default + Telegraph, TelegramChannels, search-t.me and TgramSearch catalogues.
bash scripts/telegram-public-discovery.sh --expanded --output "$HOME/telegram-case-2" example topic

# Offline verification first; live search is explicitly opt-in.
bash scripts/telegram-termux-acceptance.sh
bash scripts/telegram-termux-acceptance.sh --live example topic
```

Default source filters are `site:t.me/s`, `site:t.me`, `site:tgstat.com`, and `site:telemetr.io`. `--expanded` adds `site:telegra.ph`, `site:telegramchannels.me`, `site:search-t.me`, and `site:tgramsearch.com`. An index may ignore the `site:` operator; *neither the domain nor content of returned URLs is independently validated by this wrapper*. Cross-engine overlap is not independent corroboration.

## Resource and data integrity limits

- **Per-cohort timeout:** 65 seconds by default; `HUNTSMAN_TELEGRAM_TIMEOUT_SECS` accepts 1–120 seconds.
- **Whole-run budget:** 240 seconds by default; `HUNTSMAN_TELEGRAM_TOTAL_TIMEOUT_SECS` accepts 1–600 seconds. Unexecuted cohorts are recorded as `not_run_budget_exhausted` with exit 75, not misreported as empty results.
- **Input bound:** 120 UTF-8 bytes, with control characters, quotes and backslashes rejected before network I/O. This preserves the underlying 160-byte Huntsman request ceiling even for the longest expanded site filter.
- **Private outputs:** creates a *new* mode-700 directory, mode-600 files under `umask 077`, and rejects pre-existing case directories. Avoid storing sensitive selectors unless needed and authorised.
- **Raw evidence:** each `*.json` is kept byte-for-byte, with separate `*.stderr`. `manifest.tsv` contains the search cohort, exit status, effective query, filename, response state, byte size, SHA-256 digest and elapsed seconds.
- **Exit semantics:** 0 means at least one underlying web-search cohort reported an answer, **not** that there was a finding. Exit 65 indicates an empty report despite process exit 0; 69 means no cohort answered; 124 indicates an actual cohort timeout; 75 marks skipped cohorts after total budget exhaustion. Individual source failures remain visible even if the wrapper exits 0.
- **Dependencies:** GNU coreutils (`timeout`, `sha256sum`, `wc`) and the canonical Huntsman binary. No new paid API, scraped Telegram session or Rust runtime crate.

Verify one raw report's integrity:

```sh
sha256sum "$HOME/telegram-case-1/telegram_public_channels.json"
# Compare its digest with the same row in manifest.tsv.
```

## Current constraints

This wrapper does not parse URLs into verified Telegram channels, inspect posts, identify account owners, or reconcile channel IDs. A subsequent native Rust ingestion stage should classify canonical Telegram hosts and public message links, reject userinfo/host-spoofing and redirect ambiguity, deduplicate per post/channel, and attach independent source timestamps and source-level outcomes before promoting any claim beyond *candidate*.

For authorised direct Telegram interaction, prefer official API methods and explicit, secure credential storage. The Bot API token is part of its HTTPS URL path: do **not** add it to generic URLs or logs without guaranteed path-based credential redaction. Telegram's global public search may require paid Stars; the zero-cost flow must never automatically authorise charges. Review official API terms and applicable privacy constraints before collecting data.

See https://core.telegram.org/api , https://core.telegram.org/method/channels.searchPosts and https://core.telegram.org/api/terms .

## Verification and release gates

```sh
bash -n scripts/telegram-public-discovery.sh scripts/test-telegram-public-discovery.sh scripts/telegram-termux-acceptance.sh
bash scripts/test-telegram-public-discovery.sh
bash scripts/telegram-termux-acceptance.sh
```

The above are **offline shell tests**; they do not establish that public providers are reachable. Physical Termux acceptance (`--live`), strict Rust workspace gates and GitHub Actions exact-head checks must be run separately before integration. Current draft PR #1845 is not cleared to merge. CI failures at multiple unrelated heads are pre-runner (`runner_id=0`, no executed steps), with exact account cause unresolved; do not bypass branch protection.

## Exact-name searches and native Telegram search

For precise name searches, preserve the quotation marks:

```sh
bash scripts/telegram-public-discovery.sh --expanded --output "$HOME/telegram-kylie-case" '"Kylie Truong"'
```

The guarded Rust `public-osint web` path permits quotation marks for web-only search, but the news, notice, and mixed dossier modes retain their stricter query grammar. These public search-engine results remain unverified indexed leads.

For substantially deeper Telegram searching, an operator-authenticated user session is needed for official `contacts.search`, `messages.searchGlobal` and `channels.searchPosts`. The last method may use limited free search slots or require Telegram Stars; no payment may occur without explicit approval. TGStat's `posts/search` is a separately entitled API, and defaults to the most recent 10 days when `startDate` is omitted. Neither capability is performed by this fallback script.

Official reference: https://core.telegram.org/api/search and https://api.tgstat.ru/docs/ru/posts/search.html


## Native Rust public-index mode (review branch)

The native Rust collector now lives in `src/telegram_index.rs`, with a compatibility adapter in `src/public_osint.rs`; it is exposed through
`huntsman-recon public-osint telegram QUERY...` and the localhost `/api/lookup`
request's `kind=telegram` route. This collector **does not** log in to Telegram
or access its native message-search API. It asks the existing guarded web search
engines for four bounded scope queries:

- `site:t.me/s QUERY`
- `site:t.me QUERY`
- `site:tgstat.com QUERY`
- `site:telemetr.io QUERY`

Results are accepted only for exactly recognised HTTPS hostnames and safe,
public paths. A direct `t.me/HANDLE` is classified as an *indexed handle link*
and not as a verified user or family member. A `t.me/HANDLE/123` is an *indexed
post URL*. A `t.me/s/HANDLE` is an *indexed public preview*. TGStat and Telemetr
links are tagged as *third-party directory* entries. Private invite/forwarding
paths and host-suffix, userinfo or non-HTTPS lookalikes are rejected.

Each retained URL carries original index engine, exact query, URL, scan ID and
`indexed_url_only` evidence role. All index sightings remain in a single
`telegram_web_index` provenance family, so duplicate Bing/Brave/Mojeek
sightings cannot masquerade as primary-source corroboration.

```sh
huntsman-recon public-osint telegram '"Truong"'
huntsman-recon public-osint telegram '"Kylie Truong"'
huntsman-recon public-osint telegram 'Trương'
```

For full authenticated Telegram search, official MTProto API calls
(`contacts.search`, `messages.searchGlobal`, `channels.searchPosts`)
still require their own separately reviewed implementation, user account
authorisation and explicit paid-Star consent if a charge would apply.

### Acceptance checklist

- `cargo test --locked telegram_index` must pass on a real Rust toolchain
- Full CI and static/security jobs must pass on the *exact PR head*
- Run the native command with a non-sensitive public test selector in Termux
- Verify strict hostname filters using the offline unit regressions
- Verify the local web API's `kind=telegram` routing in the phone browser
- Verify the command never reports an identity or relationship as established
- Preserve original raw search-index URL and diagnostic outcomes

This capability is **implemented on the draft branch only**, not yet accepted
or merged into canonical main. In the current environment there is no
`cargo`/`rustc`; the GitHub Actions jobs are failing before any runner steps,
so the exact-head compile/Android gates have not been executed.

## URL canonicalisation and false-positive controls

The native Rust collector now makes **four** separately logged index queries:
`site:t.me/s`, `site:t.me`, `site:tgstat.com`, and `site:telemetr.io`.
These are public-web search scopes, not calls to Telegram's authenticated API.

After exact-host HTTPS validation, it recognises `t.me`, `telegram.me`,
and the documented `telegram.dog` link host. It canonicalises case-insensitive
usernames and public post IDs to a stable `https://t.me/<handle>/<id>` URL
so that different browser-preview and alias links do **not** create separate
post entities. The original URL and discovery engine are retained in evidence
attributes. Handle links and public-preview pages remain different URL surfaces
because a public handle can belong to a person, bot or channel; its category
and owner have not been established.

Third-party pages from TGStat and Telemetr are marked directory leads.
Generic landing/search/ranking/catalogue pages and dot-segment paths are
filtered rather than counted as entity leads. Invite-only link patterns,
private `/c/` references, malicious lookalike domains, and URL userinfo or
port tricks are refused. A valid URL shape is only an **indexed URL lead**:
it is not proof of channel content, identity, timestamp, group membership,
or personal association.

Offline Rust regressions were added for canonical URL equivalence, direct
and preview public posts, meaningful directory records, generic directory
rejections, URL spoofing, private-invite rejection, and pre-network input
validation. Those regressions still require a real `cargo test` run. The
branch remains a **draft** until actual CI and rootless Android acceptance
are available.


### Duplicate evidence cannot increase corroboration

The native collector now keeps a `BTreeMap` of canonical URL entity UIDs
within each bounded run. An additional index sighting adds an evidence record
directly to the existing URL entity; it **does not merge a second Entity**
with a new corroboration counter. This avoids the normal entity merge
incrementing `corroboration` for Bing/Brave/Mojeek duplicate sightings.

Regression fixtures use distinct `telegram.me/<handle>/<id>` and
`t.me/s/<handle>/<id>` URLs referencing the same post, and require a
single canonical entity, `corroboration = 1`, `source_count = 1`, and
both original source URLs preserved in the separate evidence records.
These Rust assertions are authored but **not executed** until a runner or
the operator's Termux toolchain can run `cargo test --locked telegram_index`.

The query still returns only indexed-link candidates, never a verified
Telegram message, account owner, group membership, or identity relation.


## End-to-end native pipeline

The reviewed implementation is split by ownership:

| Component | Role |
| --- | --- |
| `src/telegram_index.rs` | Input policy, 4 bounded web-index cohorts, strict URL parsing, canonicalisation, indexed-lead provenance, non-inflating duplicates, typed outcomes |
| `src/public_osint.rs` | Compatibility delegation to the Telegram module; news/notices/web semantics unchanged |
| `src/cli/public_osint.rs` | CLI and local HTTP lookup dispatch; Telegram uses the shared HTTP transport with 5-second per-attempt timeout |
| `src/web_server/lookup.rs` | Routes Telegram and other special public-OSINT kinds to the guarded lookup handler rather than the incompatible saved-scan `ScanKind` router |
| `src/web_ui.html` | Mobile-facing Telegram public-index search action and safe HTTPS URL rendering |
| `tools/web-ui-check/check.cjs` | Mocked browser test asserting exact quoted query, safe link rendering, and no identity attribution |

**Persistence contract:** Special public-OSINT lookups use the direct HTTP
lookup handler, even on a server with normal saved scans enabled. Results
are **not automatically saved as scans**; record or export the returned report
yourself if long-term persistence is required. Do not infer that a Telegram
public-index lookup has a durable scan ID.

**Outcome contract:** A web engine that returns only unrelated or untrusted
URLs is classified as `inconclusive`, rather than successful Telegram
discovery. Positive search-engine results remain unverified URL leads.
Index overlap is never evidence of account ownership or independent
corroboration. Searches do not access private Telegram messages, APIs,
credentials or Telegram Stars.

**Resource envelope:** 4 scopes × 3 web engines × at most 2 requests per
engine = at most 24 transport attempts. With 5 seconds per attempt, the
configured request-timeout component is at most 120 seconds; circuit
pacing, scheduling and parsing add overhead, so a strict end-to-end
150-second completion guarantee has **not been measured**.

**Tests added:** Pure URL-parser tests, duplicate-evidence tests, two
full collector tests using scripted HTTP responses, server saved-scan
dispatch tests and a mocked mobile browser regression. These newly
authored Rust and browser tests require execution on a working CI runner
and Android acceptance; previously passed local Bash wrapper tests
remain separate.

### Native CLI

```sh
huntsman-recon public-osint telegram '"Truong"'
huntsman-recon public-osint telegram '"Kylie Truong"'
```

### Local Web UI

Open `http://127.0.0.1:8080/#/newscan`, enter a public search term under
Universal Research and press **Telegram public index**. The Web UI uses
`GET /api/lookup?kind=telegram&q=...` with Huntsman's existing same-origin
lookup header; it does not route this request through saved scans.

## Termux acceptance modes

The review branch's acceptance wrapper keeps offline Bash tests separate from
actual Rust acceptance:

```sh
# No network, no Rust compilation:
bash scripts/telegram-termux-acceptance.sh

# Requires a working Rust toolchain; runs native Telegram unit/integration tests:
CARGO_BUILD_JOBS=1 bash scripts/telegram-termux-acceptance.sh --native-check

# Tests native Rust first, then builds/runs the exact checkout on a live public query:
CARGO_BUILD_JOBS=1 bash scripts/telegram-termux-acceptance.sh --native-live '"Truong"'

# The original keyless Bash web-index fallback, still supported:
bash scripts/telegram-termux-acceptance.sh --live '"Truong"'
```

Without Cargo, `--native-check` refuses with exit 69 and
`native_rust_tests=unavailable`; it never reports a Rust pass based on
Bash mocks. A native live probe requires the operator to request it explicitly.

Note that neither the native nor the fallback search is an authenticated
Telegram global-search session; both query public web indexes.
