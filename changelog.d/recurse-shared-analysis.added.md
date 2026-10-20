- `scan --recurse` now runs the shared analysis spine over everything the crawl reached, so its
  text and `--json` output also carry the by-kind element and relation summary, the capability
  gaps, and the graph-pivot ranking — the same report `plan`, `serve` and `correlate` produce —
  not only the correlation findings. A new `pipeline::snapshot_from_entities` reconstructs the
  analysis snapshot from a merged entity set, deriving the relations those entities imply.
