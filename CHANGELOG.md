# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The crate (`huntsman-recon`, version `0.2.0` in `Cargo.toml`) has no stable
release yet; relevant pushes to `main` are built and verified, and a current-head build publishes a `main-<sha7>` pre-release (#672). Superseded builds remain Actions artifacts for their retention window. Release policy: only pre-releases (`main-<sha7>` plus a rolling
`latest`); a stable release needs the owner's explicit approval.

Versions and tags. The `v1.x` tags belong to the legacy `hse` monolith (`v1.41.0` is its latest),
so they say nothing about this crate. `huntsman-recon` is not tagged: a build is identified by its
commit, which `build-sha` and `diagnostics` print, and by its `main-<sha7>` pre-release. The
`0.2.0` in `Cargo.toml` is the development version that `--version` and the HTTP `User-Agent`
report. A stable release needs its own version heading in this file, cut when the owner approves it.

## [Unreleased]
- Fix the main-channel release race where a queued build could become historical before `gh release create --target <sha>` and fail with GitHub's built-in workflow token. Publication now uses a draft created from the live main head, verifies its tag exactly, and discards a raced draft rather than failing or publishing the wrong commit.

### Changed

- `search` treats a saved file as a challenge page only when it is an HTML document of at most 32 KiB that carries a challenge signature. Markdown, prose and longer pages that quote a vendor or phrase are now searched. The fetch path keeps its stricter rule.
- `search` matches a query that is one email address or one domain as a whole name. `ada@example.com` no longer matches a document that holds "ada", "example" and "com" apart. A domain still matches its subdomains and the addresses at it.
- Engineering-command role names are neutral titles (for example `CHIEF VISIONARY` and `ECONOMIC OPTIMIZATION LEAD`) instead of the earlier named-figure roles, and the command invariant is `CHIEF VISIONARY -> CHIEF SYSTEMS ARCHITECT -> ALL OTHER SYSTEMS`. Any consumer that keys on the old role `name` values in the JSON output must switch to the new names.
- `search` folds Latin diacritics and keeps combining marks and soft hyphens inside a word (Unicode word rule WB4), so `zurich` finds `Zürich`, `jose` finds `José` and `istanbul` finds `İstanbul`, and decomposed text is no longer split at its marks. The folding is accent-insensitive by design: `schon` and `schön` find each other. It also counts only the query terms, which about halves the time of a search with the same hits and scores (`examples/search_bench.rs`).
- The classifier behind `investigate`, `scan` and the `search` query matches company and street markers as whole words, and only in a value of two or more words; a single word is residual. `Vincent Smith` and `Lincoln Hill` are no longer organisations, and `Broadbent Lee` is no longer an address.
- `investigate` scans spans, not single tokens. A phone number, or an ABN or ACN written as two to four digit groups, is one entity (`+61 412 345 678` used to give four address entities). A street address begins at its street number and ends on its last street word, a capitalised connector such as "The" ends it, and bare digits and digit pairs are no longer addresses or people.
- The name matchers (the ASIC director and person lookups, `au_people` and `people`) ignore case for accented letters and count an initial by letters, not bytes: `Émile` matches `émile`, and `É Lovelace` has no name token. Matching lowercases letter by letter; it does not fold accents or `ß`.
- Exit statuses follow `src/exit.rs` and the README. `serve` exits 66, not 65, when `HSE_AUTH_TOKEN` is blank, or absent on a non-loopback bind (an invalid bind address still exits 65). `seeknow` exits 66, not 77, when its key is not configured (a key that is present but refused still exits 77). `verify` exits 66, not 65, for a missing or unreadable ledger (a malformed ledger or a broken chain still exits 65). A script that keys on these statuses must follow.
- `sources` strips every leading `@` from a username and refuses a value made only of `@` signs or only of dots (exit 65, empty stdout).

### Fixed

- The lookup reports write text that a third party controls escaped (`\u{1b}`, `\n`, `\t`), so a profile name, a register entry, a dataset name or a status field cannot drive the terminal or start a row or a column of its own. This covers the `email`, `username`, `people`, `phone` and `investigate` reports, the entity rows of `recon crtsh` and `recon stolen-tax`, the `seeknow` status and search reports, and the lineage rows. Ordinary text prints unchanged. One formatter (`lookup_report::entity_row` and `evidence_row`) now writes the entity and evidence rows that five printers wrote on their own, and `tests/architecture_boundaries.rs` fails if a second one appears.
- `scripts/lifecycle.sh sync` refuses a secret-looking path wherever git would take it from. It read `git status --porcelain`, which lists an untracked directory as one entry and quotes a name with a space or a non-ASCII character, so `deploy/.env` and `my key.pem` were committed and pushed to `main` although `CANONICAL.md` says such paths are refused. It now checks every untracked, changed, deleted and staged file by name, stops when it cannot list them, and also refuses a top-level `keys/` directory. `tests/lifecycle_sync.rs` runs the script against a local bare remote.
- The Railway entrypoint no longer prints the token it generates. The value is stored in the data directory and the log names the file. A token that an earlier build printed is in the platform log and must be treated as exposed: rotate it as `docs/RAILWAY.md` describes.
- `serve` no longer stalls behind one silent connection. Each connection has its own thread, at most 32 at a time, and a connection past that is answered `503` with `Retry-After: 1`; a request must finish within a 10 s deadline or it is answered `408 Request Timeout`. A client that sent one byte at a time used to hold the single-threaded listener, before authentication. On a build of 58a8da94 a page load behind two idle sockets took 10.2 s, and it now takes 3 ms.
- `recon dns` reports only the answers of the queried record type. A CNAME that came ahead of a TXT or an address answer is no longer shown as one.
- A keys-file value in quotes that is followed by a comment (`KEY="abc" # prod`) is read as `abc`. The quote characters were kept, so the key sent to the provider differed from the key in the file: the fingerprints differed, reproduced with `huntsman-recon keys`.
- `geo::extract_au_postcode` and `city_coords` no longer panic on a postcode that follows non-ASCII text such as `Zürich 2000`.
- The `people` lookup reads a page in linear time. Decoding HTML references searched the rest of the page for a `;` from every `&`, and the scan for relatives phrases searched the rest of the page again for every phrase at every hit; a page of 82 KB that repeats `relatives` took 412 s in a debug build. A reference now ends at the first byte it cannot contain, and the relatives scan reads the page once per phrase and yields its windows one at a time. Output is unchanged: both were compared with the previous code on generated texts.
- Other output that carries text from a file, a page or a service is escaped too: `search DIR` prints file names, `query` prints hit addresses, error messages escape what they echo (serde names an unknown field as the file wrote it), `sf` cells and `sf -o json`, HIBP `key=value` lines and paste titles, and `run-history show` prints the commit and suite of each record. `escape_controls` now also escapes U+2028 and U+2029, which split a row for some readers, and the bidirectional embedding, override and isolate controls, which reorder text; the marks and joiners that right-to-left, Persian and Indic text uses are left alone. `fetch --body` still prints the body as received, as documented.
- A guess made from one input counts as one source. `jane.doe@acme.example` yields the username guesses `janedoe`, `jane_doe` and `jane-doe`, which share a uid and merge; the merge read as four sources agreeing, so `janedoe` reached an effective confidence of 0.918 and the class Verified with no source that corroborates it. Evidence that is only enrichment or recall now counts once, so `janedoe` is 0.70 (Probable). An entity with no evidence keeps the number of times it was seen.
- A timestamp with an RFC 3339 numeric offset (`+10:00`) or fractional seconds (`.000Z`) parses, where it was rejected and its evidence dropped from timelines. A malformed offset, an impossible date such as 2024-02-30, trailing fields and an empty time are refused, where they were read as UTC, moved to March 1 or ignored, and a non-ASCII offset no longer panics. Distances use one Earth radius (6371 km): a near-antipodal pair no longer gives NaN, and coordinates that cannot be compared are reported as a conflict, not as agreement. The percentile bootstrap refuses fewer than 30 values.

### Added

- `username` (and `scan -k username`, `sf` USERNAME) sends `HUNTSMAN_GITHUB_TOKEN` to the GitHub API as a Bearer credential pinned to `https://api.github.com:443` when the operator configures it. Before, `credential-status` reported the slot and probed the token, but the lookup never sent it, so a configured operator still hit the 60-request unauthenticated limit. A rate-limit outcome now says whether a token was used and, when none was, names the slot.
- Lookup reports (`email`, `exposure`, `username`, `people`, `scan`) and their saved ledgers show why a source ended as it did: an outcome line ends in `detail=` when the source gave a reason, escaped and capped at 200 characters. Before, the reason was recorded and then dropped, so `people` printed `inconclusive` alike for a challenge page, an unresolvable host and three unanswered electoral rolls.
- `HUNTSMAN_CA_BUNDLE` names a PEM bundle whose certificates replace the built-in Mozilla roots for every outbound TLS connection, so lookups work on networks that intercept TLS with their own CA. Before, every networked lookup on such a network failed with an unknown-issuer TLS error and no way to trust the network's CA. Verification stays on, and an unreadable or certificate-free bundle fails every request closed with `tls_failure` naming the variable instead of falling back to the built-in roots.
- `exposure` shows the public context of each HIBP breach the address is listed in. The report ends with `incidents=N` (`none` when HIBP gave no answer) and, per breach sorted by name (a name the source repeats is merged into one incident that keeps every flag any of its records sets, and the evidence and found count follow the same merged incidents), an `incident` row (title, breach and added dates, domain, account count, verified, flags), a `caution` row for a fabricated or spam-list breach, the description as a plain-text `summary` of at most 600 characters, `data_classes`, `attribution`, and one `reference` row for each http(s) link the description itself gives (at most 8, canonicalised, without repeats; `javascript:`, `data:`, `mailto:` and relative links are dropped, and no link is built from the domain). Every value is escaped. The evidence keeps the summary, links, added and modified dates, attribution and each status flag the source sends, and a fabricated or spam-list breach tags the address `fabricated-breach` or `spam-list`. Before, the description, attribution, dates and flags were fetched and discarded, so a fabricated breach read like a genuine one. This is context about a public incident, not a finding about the person.
- Provider credential health automation: `credential-status [--probe] [FILE]` keeps ordinary status offline, resolves existing private runtime key sources without rendering values, and can run canonical live probes for configured single-slot providers. HIBP uses `/subscription/status` with the required `User-Agent` and reports non-secret plan/RPM/entitlement metadata.
- `seeknow` command: opt-in SeekNow/See-Know lookups through guarded `fetch`,
  with typed entitlement/quota outcomes, a generic collector boundary, and
  lineage-safe L5 collection. Fast/deep duplicates do not manufacture
  corroboration. Offline fake-transport tests; live keyed receipts remain
  operator-gated.
- Wayback CDX client (`wayback`) over guarded `fetch`; captures are archive
  observations and original URLs are never dereferenced.
- Shadow-mode provenance-rooted claim verification kernel (`claim_policy`,
  `claim_coverage`, `proof`, `shadow_assessment`): unknown ancestry cannot
  create independent corroboration, and legacy recomputation cannot manufacture
  `Verified` from caller confidence.
- `recon dns TARGET`: DNS-over-HTTPS lookup of A/AAAA/MX/NS/TXT plus `_dmarc`
  and `_smtp._tls`, through `fetch` (no redirects), parsing SPF/DMARC/TLSRPT
  from TXT. A challenge page is `BotWaf`, not invalid JSON (offline
  fake-transport tests; no live receipt).
- `sources` command: classifies an input and prints curated public search
  routes from `source_registry`, offline and `LeadOnly`; the classifier also
  recognises decimal-degree coordinates (#671).
- Android aarch64 cross-build in CI (`android-aarch64` job, API level 24),
  with ELF machine and `/system/bin/linker64` interpreter checks, a SHA-256
  sidecar, and a 14-day `huntsman-recon-aarch64-linux-android` artifact on
  pushes to `main`. HIBP key embedding is disabled for that artifact
  (`HUNTSMAN_HIBP_NO_EMBED=1`). Contract tests in `tests/android_ci.rs` (#670).
- Opt-in HIBP library (`huntsman_recon::hibp`): REST v3 read endpoints,
  Pwned Passwords SHA-1/NTLM ranges, entitlement checks, a shared 10/minute
  rate limit (`HIBP_RATE_LIMIT_PER_MINUTE`), bounded 429 retries, OAuth PKCE
  for the MCP resource, and optional build-time key embedding for personal
  builds (`tests/hibp_build.rs`) (#662).
- `tests/readme.rs` and `tests/dispositions.rs`, which check the README
  examples, exit codes and gate range, and the legacy disposition counts,
  against the binary and `legacy/` (#669).
- Guarded network layer (`egress`, `http`, `fetch`, `keys`) with `fetch` and
  `keys` commands and `check` gate 11; both legacy archives kept in the
  repository root and extracted into `legacy/`, pinned by
  `tests/legacy_reference.rs`; per-file accounting in `docs/DISPOSITIONS.md`
  (#667, #668).
- `id`, `geohash` and `coarsen` commands, and the rebuilt `au_id`, `geohash`,
  `confidence` and `redact` modules (`check` gate 10).
- Refactor-overlay foundations as library modules: `source_outcome`,
  `evidence_ancestry`, `identity_resolution`, `termination`,
  `credential_origin` and `eval` (`check` gate 5).
- Offline `huntsman-recon` core: RCVF session recorder, hash-chained ledger
  (`verify` command), local document search (`search QUERY [DIR]`), challenge
  page classification (`classify`), GEOINT distance (`geo`), and STIX and
  ATT&CK Navigator export gated on implemented techniques (`check`)
  (7dca720b to dcc60bcb, #666).
- ATT&CK capability ledger v0 with flag-based status (#660; superseded by the
  reconstruction).
- `CHANGELOG.md`.

### Changed

- HIBP's process-wide sliding-window limiter now adopts a positive `Rpm` from successful subscription-status responses while preserving already-consumed capacity; the configured/default budget remains the bootstrap and 429 backoff remains authoritative.
- `huntsman-recon` is the only current tree. The HSE v1.41.0 monolith and the
  refactor overlay are read-only reference under `legacy/` (f0a1c64c, #668).
- `search` is local retrieval over operator-supplied documents; a challenge
  page or a 429 is not a hit (c03e78a2 to dcc60bcb).
- CI test matrix is Rust 1.87 (MSRV) and stable; tests fixed for Rust 1.99
  clippy (`assert_is_empty`) (#669).
- README has a "Which binary to use" section. The legacy `hse` (pre-release
  `main-7dca720`) has the original person-lookup providers. `huntsman-recon`
  provides a subset through `people` and ships only as `main-<sha7>` pre-releases.
- README documents build and install steps, the `fetch` options, how keys are
  supplied, the CI artifact download, and the release state.

### Removed

- The monolith's release, audit, bench-smoke, copilot-setup-steps, fuzz,
  live-drift, rust-clippy and secret-scan workflows, `rust-toolchain.toml`, `docs/INSTALL.md` and the previous
  `CHANGELOG.md` (f0a1c64c). A release workflow for `huntsman-recon` was
  restored in #672.

### Fixed

- `sources` / `source_registry::routes_for` input hardening (#671 review
  follow-up): every leading `@` of a username is stripped (`@@x` routes `x`,
  not `@x`), a handle made only of `@` is refused like an empty value, and a
  value made only of dots (`.`, `..`, `@..`) is refused instead of rendering a
  path-traversal-looking URL. Refused values give no routes, so `sources`
  exits 65 with empty stdout.
- Legacy snapshot restored to its pinned bytes after #665 edited files under
  `legacy/` (78ce7723). #665 therefore has no effect on the current tree, and
  #663 merged no changes.
- SeekNow bulk import build on the pre-reconstruction tree (#661).
- `src/hibp/key.rs` documentation no longer refers to a `ModuleContext`, which
  this crate does not have, or says the HIBP key chain reads `~/.huntsman.env`;
  it does not (the binary's `~/.huntsman.env` auto-load, #674, supplies `fetch`
  credential slots).
- README said `check` gate 5 exercises `credential_origin` and `eval`; it
  exercises `source_outcome`, `evidence_ancestry`, `identity_resolution` and
  `termination` of the overlay modules.
- `docs/RECONSTRUCTION_2026-10-02.md` names the archives as committed and
  gives the monolith archive's file count (1314 files, 1727 zip entries).
