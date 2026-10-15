# web-ui-check (CI and operator tool)

`check.cjs` drives the `serve` web UI in a phone-sized headless Chromium (360x740, touch,
DPR 3) and fails when the page stops doing what it promises. CI runs it on every push and pull
request (the `web-ui` job in `.github/workflows/ci.yml`); `tests/web_ui.rs` keeps that job in
place and holds the contracts that need no browser.

It is not part of `huntsman-recon`: the engine ships no browser or JavaScript runtime.

## What it checks

- The page loads with no console error and no Content-Security-Policy violation, fits 360 px with
  no horizontal scroll in every view, every control is at least 44 px (a checkbox or radio counts
  as the label that holds it), and it weighs at most 96 KiB.
- A cold load asks only for the page, `/api/health`, the scan list and the icon, and opens on
  Scans; a tab that comes back into view with no scan running asks only for `/api/health`; About
  loads the module list and command contract once; the old `#/lookup` address opens New Scan.
- Both system themes: the page follows the phone's light or dark setting, the browser bar takes
  the app bar's colour, the toggle overrides and is remembered, and axe-core finds no WCAG 2.2 AA
  or best-practice violation in any view, before or after the toggle.
- New Scan lists every module and every data type the server has. A scan started there runs to
  FINISHED, and each section shows what the scan API holds: Summary's counters and a bar per data
  type, Browse's data types and every element of a type with its raw record and on its discovery path, a false positive
  marked on the server, every correlation, Re-run Correlations and a correlations CSV export, a graph node per element, Scan Settings naming the
  target, every log entry, a wildcard search, and CSV and JSON exports that hold the elements.
- A reload (Android discarding the tab) returns to the same section of the same scan and keeps
  the toggled theme; the last analysis comes back too.
- The scan list shows every saved scan with its element count; Settings lists every module and
  every correlation rule;
  Re-run makes a new scan of the same target and Delete removes it.
- With the server killed, the page says so with the command that starts it and shows `offline`;
  it shows `online` again once the server is back, and the saved scans are all still there.

It never spends a key: the server runs with a scratch `HOME` and none of the caller's
`HUNTSMAN_*`, `HSE_*`, `*_KEY`, token or secret variables, and its scans target a phone number,
which is classified offline.

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

## Spiderfoot layout (2026-10-15)

`main` at 91352e8 against the Spiderfoot-layout page, the same browser and phone size:

| | before | after |
|---|---|---|
| Views | Lookup, Analyze, Status | Scans, New Scan, a scan's Summary, Correlations, Browse (full, unique, discovery path), Graph, Scan Settings and Log, Settings, Analyze, About |
| Results | the last lookup, in this tab only | every saved scan, on the server, across restarts |
| Exports | none | CSV, TSV, JSON and GEXF per scan or data type; JSON for several scans |
| Requests on a cold load | 3 (page, health, icon) | 4 (page, health, scan list, icon) |
| Requests each time the tab comes back, no scan running | 1 | 1 |
| A started scan shown FINISHED | not applicable | 1.1 s (polled at 1, 2, 4 then 5 s) |
| axe-core violations in every view, both themes | 0 | 0 |
| Page weight | 34.3 KB | 82.8 KB |
| DCL / FCP, 4x CPU throttle, median of 15 | 123 / 108 ms | 180 / 116 ms |
