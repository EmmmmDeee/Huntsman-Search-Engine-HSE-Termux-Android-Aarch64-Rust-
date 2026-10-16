- `scans compare EARLIER LATER`, `GET /api/scans/compare?ids=EARLIER,LATER` and the console's
  Compare view show what changed between two saved scans, which Spiderfoot cannot do: each data
  type with its earlier, later, added, removed and kept counts, every added and removed element
  in full with its module and source, and the correlations that appeared or went away. Values
  match by type and data, so a value both scans found counts as kept whatever its element id.
  The added and removed elements export as CSV, TSV, Excel or JSON in the export layout with
  `Change` and `Scan Name` first. The scan view's Compare sets a scan beside the latest earlier
  scan of its target; on Scans, Compare takes the two selected scans, earlier first.
- `/api/scans/ID/elements` looks up each element's source once instead of scanning every element
  for it, so a large scan's elements no longer take time quadratic in their number.
