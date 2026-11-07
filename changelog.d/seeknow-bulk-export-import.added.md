- `seeknow import EXPORT.json [--json]` and the web UI file inspection read a SeekNow bulk export
  offline (no key, no request). Every row of every target block is preserved as a record with all
  fields verbatim and the export's SHA-256, id and per-block provider total; the complete uploaded
  dataset survives import. Attributed entities and pivots are the subset of rows that name their
  target in a field of the target's kind (evidence integrity); every other row is still kept as a
  record. Credential field *values* are masked and named per row in `sensitive_fields`; no other
  field is altered. Repeated targets (`Dubai`/`dubai`) attribute once but each block's rows are kept.
