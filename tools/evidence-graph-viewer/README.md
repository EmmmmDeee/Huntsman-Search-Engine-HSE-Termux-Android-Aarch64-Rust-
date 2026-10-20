# Offline HSE Evidence Graph Viewer

A standalone exploratory SVG relationship viewer and conservative JSON adapter for Huntsman Recon's **offline** `GET /api/analyze` response. The viewer does not issue network requests, execute providers, validate sources, or alter the Huntsman runtime.

## Files

- `index.html` — open locally in a browser; use **Import local JSON** and **Export local JSON**.
- `hse_analysis_to_graph.py` — offline converter from native Huntsman `AnalysisView` JSON to the viewer schema.
- `fixture_analysis.json` — **synthetic** example reflecting the native response's field names; not a captured live response.
- `test_adapter.py` — deterministic conversion and error-handling tests.

## Run (offline)

```sh
# With Huntsman Recon already running on local loopback:
curl -fsS --get --data-urlencode 'seeds=example.test' \
  'http://127.0.0.1:8080/api/analyze' -o analysis.json

# Only after confirming that analysis.json is an actual /api/analyze response:
python3 tools/evidence-graph-viewer/hse_analysis_to_graph.py \
  analysis.json -o graph.json

# Open tools/evidence-graph-viewer/index.html in a modern browser.
# Click Import local JSON and select graph.json.
```

`/api/analyze` is an offline analysis endpoint: its own seed records are **not** independent external evidence. By design, the adapter labels **every native relationship as hypothetical** until sources are independently verified, does not invent dates for zero/unknown timestamps, and refuses truncated or oversized analyses instead of silently dropping records. The original source names are provenance labels, **not external document citations**. `metadata.not_source_verified=true` is carried in imported JSON.

This is a self-contained **proof of concept**, not production integration. It does not provide authentication, isolation, persistent storage, API egress, a geospatial component, or proof of an external investigation. Imported content stays in browser memory until export or reload. Keep sensitive datasets off shared machines.

## Boundaries

- Maximum native input: 8 MB; viewer import: 250 KB, 250 nodes, 700 relationships.
- Unknown dates are JSON `null` and remain visible in the year filter.
- All imported relation statuses are conservative, manually reviewable labels; score alone is not proof.
- External REST keys must never be placed in browser data.
- Current conversion was validated using Rust type definitions in `src/runtime.rs`, `src/entity.rs`, and `src/graph.rs`, plus a synthetic fixture; **no live HSE server response was exercised**.
- Source test: `python3 -m unittest discover -s tools/evidence-graph-viewer -p 'test_adapter.py'` (stdlib only).

The demo is distributed separately from Huntsman's embedded web UI so it cannot weaken its existing authentication and request-boundary invariants.