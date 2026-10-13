# headless-fetch (optional operator tool)

`fetch.cjs` drives a headless Chromium to fetch pages that a plain HTTP client
cannot: pages behind a JavaScript challenge. It prints one JSON object per URL
(`{url, status, title, text, error}`), designed to pipe into
`huntsman-recon investigate`.

**This is not part of `huntsman-recon`, by design.** The engine is a single
static `ureq` binary with no browser and no JavaScript runtime, built for Termux
aarch64 no-root; a ~400 MB headless Chromium cannot ship inside it, and would
not run there. This helper is for operator-side enrichment on a workstation.

**It bypasses the engine's egress guard.** The binary routes every request
through a resolver that refuses private, loopback, link-local and metadata
addresses, so a hostname cannot be rebound onto the operator's own network. A
browser subprocess does its own DNS and connection, with none of that
protection. Point it only at public URLs you intend to fetch, never at a
hostname from untrusted input.

## What it can and cannot do

- **Can:** render a JavaScript challenge page so the real content loads.
- **Cannot:** defeat an IP-reputation block (HTTP 403 at the edge) or a captcha.
  Those are reported in the JSON `status`/`text` like any other page.

## Requirements

- Node 18+.
- The `playwright` package (`npm install playwright`) and a Chromium it can
  launch. Playwright resolves its own browser under `PLAYWRIGHT_BROWSERS_PATH`.

## Usage

```sh
node tools/headless-fetch/fetch.cjs "https://example.com/search?q=..." > hits.jsonl

# Feed the rendered text into the engine's offline entity extractor:
jq -r '.text' hits.jsonl > hits.txt
huntsman-recon investigate --file hits.txt
```

Environment:

- `HEADLESS_FETCH_WAIT_MS` — settle time after load, in ms (default `5000`).
- `HEADLESS_FETCH_UA` — User-Agent override.

Exit status: `0` if any URL was fetched, `1` if all failed, `2` if `playwright`
is not installed, `3` if Chromium could not launch, `64` for no arguments.
