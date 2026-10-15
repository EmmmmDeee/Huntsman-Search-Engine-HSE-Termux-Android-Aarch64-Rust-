# web-ui-check (CI and operator tool)

`check.cjs` drives the `serve` web UI in a phone-sized headless Chromium (360x740, touch,
DPR 3) and fails when the page stops doing what it promises. CI runs it on every push and pull
request (the `web-ui` job in `.github/workflows/ci.yml`); `tests/web_ui.rs` keeps that job in
place and holds the contracts that need no browser.

It is not part of `huntsman-recon`: the engine ships no browser or JavaScript runtime.

## What it checks

- The page loads with no console error and no Content-Security-Policy violation, fits 360 px with
  no horizontal scroll, every control is at least 44 px, and it weighs at most 40 KiB.
- A cold load asks only for the page, `/api/health` and the icon; a tab that comes back into view
  asks only for `/api/health`; Status loads the module list and command contract once.
- Both system themes: the page follows the phone's light or dark setting, the browser bar takes
  the app bar's colour, the toggle overrides and is remembered, and axe-core finds no WCAG 2.2 AA
  or best-practice violation in any view, before or after the toggle.
- A phone lookup through the form lists every entity, every piece of evidence and its attributes,
  and every source with a detail column; Download JSON saves that report.
- After a reload (Android discarding the tab) the last lookup and analysis are back.
- A slow lookup shows its running time and can be stopped; with the server killed, the page says
  so with the command that starts it, and it shows `online` again once the server is back.

It never spends a key: the server runs with a scratch `HOME` and none of the caller's
`HUNTSMAN_*`, `HSE_*`, `*_KEY`, token or secret variables, and its one lookup is an offline phone
classification.

## Running it

```sh
cargo build --locked --bin huntsman-recon
(cd tools/web-ui-check && npm install --no-package-lock --ignore-scripts)
CHROME_PATH=/path/to/chromium node tools/web-ui-check/check.cjs target/debug/huntsman-recon
```

`package.json` pins `playwright-core` and `axe-core` to exact versions; neither has dependencies
of its own. Without `CHROME_PATH` (or `CHROME_BIN`) Playwright's own Chromium is used. It prints
one JSON object of measurements and exits 1 when any check fails, naming each.

## Before and after (2026-10-15)

`main` at 338f1bc against the upgrade, release builds, headless Chromium at 360x740:

| | before | after |
|---|---|---|
| axe-core violations per view (dark / light system theme) | 3 to 13 / 3 to 13 (colour contrast) | 0 / 0 |
| Light system theme | ignored (page stays dark) | followed; toggle overrides |
| Requests on a cold load | 5 (page, health, modules, command, icon) | 3 (page, health, icon) |
| Requests each time the tab comes back | 3 (21 KB) | 1 (89 B) |
| Lookup findings shown | count only | every entity, its evidence and attributes |
| Source rows | outcome and count | plus HTTP status, retry-after and detail |
| Last lookup and analysis after a reload | lost | restored |
| Stopping a slow lookup | not possible | press the button again |
| Server stopped | "TypeError: Failed to fetch" | names the server and `huntsman start`; notices its return |
| Page weight | 26.0 KB | 34.3 KB |
| Transferred on a cold load (Lighthouse) | 48 KiB | 35 KiB |
| DCL / FCP, 4x CPU throttle, median of 15 | 106 / 112 ms | 114 / 116 ms |
| 16-seed analysis, submit to rendered, median of 24 | 14.8 ms | 14.7 ms |
| Lighthouse mobile (performance / accessibility / best practices) | 100 / 95 / 100 | 100 / 100 / 100 |
