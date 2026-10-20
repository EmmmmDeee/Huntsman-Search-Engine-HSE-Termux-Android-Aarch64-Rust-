- `serve`'s `GET /api/lookup` runs each lookup as a saved scan when `serve` keeps saved scans, as
  it does by default. A lookup is kept with everything it found and its log, is listed under
  Scans and in `scans list`, can be stopped there, and reads `ABORTED` after a `serve` stopped in
  the middle of it starts again. Until now a lookup left no record, could not be stopped, and lost
  what it had found when the server stopped. The report keeps its `{route, text, entities,
  outcomes}` shape and adds `scan`, the scan's id, and `status`. A request now waits at most 150
  seconds: a lookup still running then is answered `504` with its `scan` and runs on, where before
  the request waited for as long as the lookup took. Asking for the same lookup again while it
  runs, as a reloaded page does, waits on that scan instead of starting another, so reloads no
  longer use up the two lookup places and get `503`. Without saved scans, a lookup still waits at
  most 150 seconds and is then answered `504`. The Termux acceptance harness keeps its lookup's
  scan in its disposable directory and reads it back from `/api/scans/ID`.
