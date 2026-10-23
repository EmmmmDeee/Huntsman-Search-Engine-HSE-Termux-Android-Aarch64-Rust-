- `network cell:MCC:MNC:AREA:CELL` (and `scan`, which infers it, and `/api/lookup` and the New
  Scan page through the same routing) looks up a cell site in OpenCelliD: the tower's position,
  range and sample count, with `HUNTSMAN_OPENCELLID_KEY`, and `not_configured` with no request
  without it. The OpenCelliD leg was registered with the indicator legs but no lookup ever asked
  it about a cell, so it could not run; a cell `radar cells` reports can now be investigated.
  A 5G cell's 36-bit identity is sent whole rather than refused.
