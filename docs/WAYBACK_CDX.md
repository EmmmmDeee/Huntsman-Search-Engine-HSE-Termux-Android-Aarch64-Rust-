# Historical website OSINT: Wayback CDX

`wayback_cdx` is an independent, keyless Rust collector. It turns the Internet Archive's
published CDX index into **actual evidence-bearing historical URL observations**, rather
than a search-engine link. It uses the existing Huntsman request and evidence contracts,
with no new runtime crates, credentials, mandatory cloud integrations or private APIs.

## Entry points

- `huntsman-recon domain example.org`
- `huntsman-recon scan -k domain example.org`
- `huntsman-recon scan --recurse example.org --max-generations 1`
- `huntsman-recon sf -s example.org -m wayback_cdx` (existing SpiderFoot module selection)

The same domain lookup feeds saved scans and the existing local web UI/API. The
`wayback_cdx` selection is listed in the shared module catalogue and browser source list.

## Exact method

One GET to `https://web.archive.org/cdx/search/cdx` with `url`, `matchType=domain`,
`output=json`, `fl=timestamp,original,statuscode,digest`,
`filter=statuscode:200`, `collapse=urlkey` and `limit=32`.

The collector validates the CDX field header, complete JSON, domain boundary,
HTTP(S) URL syntax, timestamp, row limit and source HTTP status before emitting
any findings. The shared guarded transport enforces SSRF restrictions, TLS,
timeouts and a per-host rate-limit circuit breaker. No archive replay,
captured-page download, JavaScript or arbitrary discovered URL is executed.

Each retained record produces an `url` entity tagged `historical_capture`;
an archived subdomain also produces a conservative `domain` pivot tagged
`historical_subdomain`. Evidence records contain the canonical original URL,
archive replay reference, 14-digit UTC capture timestamp, CDX digest when present,
source identifier and local observation metadata. Multiple captures of the same
URL combine through Huntsman's canonical entity merge; they do not become
independent corroborating sources.

The source **does not** prove a page's contents, present-day DNS ownership,
human identity, website authorization, completeness of an archive, or the actual
existence/absence of all older captures. An empty valid CDX query means only that
the particular bounded index query returned no matches.

## Deliberate limits

- At most 32 CDX capture records; at most 128 KiB of CDX JSON parsed.
- Historical URLs containing query parameters, fragments or user information are
  *not persisted*, to prevent leaking accidentally archived session tokens.
- The index is not a complete history; adjacent-key collapse and the small limit
  favor a bounded variety of captured URL paths.
- Malformed, redirected, challenged, over-limit and foreign-domain results are
  classified as non-success, not treated as negative findings.
- Service unavailability and throttling are surfaced through typed source outcomes.
- No source fees, no account credentials and no new Android/Termux dependencies.

## Verification

`cargo test --locked wayback_cdx` exercises offline fixtures for ordinary captures,
historic subdomains, empty results, schema/semantic drift, sensitive query suppression,
and source-bound request construction. Full acceptance requires the existing
`cargo run --locked -p xtask -- gate full`, Android aarch64 CI, Web UI/browser
checks, and exact-head GitHub-hosted results. Live Internet Archive reachability
varies and has not been claimed from deterministic fixtures.

Source contract: https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
