- `POST /api/inspect` keeps the inspected file as a `FINISHED` saved scan when the server keeps
  scans (kind `inspect`, target the file name, type `HSE_DOCUMENT`, every embedded field as the
  target's raw evidence and an embedded GPS position as its child), names it in the report's
  `scan` and `status` with every entity stamped with that scan's id, and the Inspect tab shows
  the scan with an Open scan button; a re-run of such a scan is refused because the file's bytes
  are not kept, and a store that refuses to keep it is reported as a `scans` outcome while the
  report is still answered whole.
